import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from extract_devices import (
    build_normalized_devices,
    convert_fingerbank_api_records,
    filter_fingerbank_api_records,
    load_fingerbank_input,
    load_input,
)
from oui_loader import load_oui_csv


TARGET_CATEGORIES = [
    "Camera",
    "Hub",
    "Sensor",
    "Controller",
    "Appliance",
    "VoiceAssistant",
    "Wearable",
]

COMMUNICATION_TO_PROTOCOL_HINTS = {
    "cloud_api": ["https", "tls"],
    "local_api": ["http", "https"],
    "video_stream": ["rtsp", "https"],
    "device_status": ["mqtt", "https", "coap"],
    "analytics": ["https"],
    "tracking": ["https"],
    "firmware_update": ["https"],
}

GENERIC_DOMAIN_PARTS = {
    "api",
    "cloud",
    "control",
    "device",
    "devices",
    "events",
    "example",
    "status",
    "sync",
    "telemetry",
}

VARIANT_DOMAIN_PATTERN = re.compile(r"(^|[.-])v\d+([.-]|$)")
VARIANT_PREFIX_PARTS = {"api", "control", "sync", "telemetry", "events", "device", "cloud", "status"}
SYNTHETIC_DOMAIN_MARKERS = {"example", "example.com", "example.net", "example.org"}


def collect_raw_devices(base_dir: Path):
    sample_input_path = base_dir / "input" / "sample_devices.json"
    fingerbank_path = base_dir / "input" / "fingerbank_raw.json"
    oui_csv_path = base_dir / "input" / "oui.csv"

    raw_devices = []
    if sample_input_path.exists():
        raw_devices.extend(load_input(sample_input_path))

    if fingerbank_path.exists():
        fingerbank_raw = load_fingerbank_input(fingerbank_path)
        fingerbank_devices = convert_fingerbank_api_records(fingerbank_raw)
        fingerbank_devices, rejected = filter_fingerbank_api_records(fingerbank_devices)
        raw_devices.extend(fingerbank_devices)
    else:
        rejected = []

    oui_map = load_oui_csv(oui_csv_path)
    normalized_devices = build_normalized_devices(raw_devices, oui_map)

    return normalized_devices, rejected


def load_json_if_exists(path: Path):
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def pick_top_domains(devices, limit=8):
    domain_counter = Counter()
    keyword_counter = Counter()

    for device in devices:
        for domain in device.get("domains", []):
            domain_counter[str(domain).lower()] += 1
        for keyword in device.get("domain_keywords", []):
            keyword_counter[str(keyword).lower()] += 1

    representative_domains = []
    for domain, _count in domain_counter.most_common():
        normalized_domain = normalize_domain_for_inference(domain)
        if not normalized_domain:
            continue
        if is_synthetic_domain(normalized_domain):
            continue
        representative_domains.append(normalized_domain)

    if representative_domains:
        # 順序を保ったまま重複を除く。
        return list(dict.fromkeys(representative_domains))[:limit]

    # ドメインそのものがないカテゴリは、識別に効きやすいキーワードだけ補助的に使う。
    filtered_keywords = [
        keyword
        for keyword, _count in keyword_counter.most_common()
        if keyword not in GENERIC_DOMAIN_PARTS
    ]
    return filtered_keywords[:limit]


def normalize_domain_for_inference(domain):
    """
    バリアント生成で作った人工ドメインをカテゴリ推定DB向けに正規化する。
    例:
      api-api-v01.camera-cloud.example -> camera-cloud.example
      control-hub-v02.smartthings.com -> smartthings.com
    """
    domain = str(domain).lower().strip()
    if not domain:
        return ""

    parts = domain.split(".")
    head_segments = [segment for segment in parts[0].split("-") if segment]

    if head_segments:
        filtered_segments = [
            segment
            for segment in head_segments
            if segment not in VARIANT_PREFIX_PARTS and not re.fullmatch(r"v\d+", segment)
        ]

        if len(filtered_segments) != len(head_segments):
            if filtered_segments:
                parts[0] = "-".join(filtered_segments)
            else:
                parts = parts[1:]

    normalized = ".".join(parts)
    if VARIANT_DOMAIN_PATTERN.search(normalized):
        return ""

    return normalized


def is_synthetic_domain(domain):
    domain = str(domain).lower().strip()
    if not domain:
        return True

    if domain in SYNTHETIC_DOMAIN_MARKERS:
        return True

    if domain.endswith(".example"):
        return True

    if ".example." in domain:
        return True

    parts = domain.split(".")
    return "example" in parts


def pick_protocols(devices, limit=6):
    protocol_counter = Counter()

    for device in devices:
        for protocol in device.get("protocols", []):
            protocol_counter[str(protocol).lower()] += 1

        for communication_pattern in device.get("communication_patterns", []):
            for hint in COMMUNICATION_TO_PROTOCOL_HINTS.get(communication_pattern, []):
                protocol_counter[hint] += 1

    return [protocol for protocol, _count in protocol_counter.most_common(limit)]


def build_category_entry(category, devices):
    vendor_counter = Counter()
    source_counter = Counter()
    raw_category_counter = Counter()

    for device in devices:
        vendor = str(device.get("vendor", "")).strip()
        if vendor:
            vendor_counter[vendor] += 1

        source_counter[str(device.get("source", "unknown"))] += 1

        raw_category = str(device.get("raw_category", "")).strip()
        if raw_category:
            raw_category_counter[raw_category] += 1

    representative_domains = pick_top_domains(devices)
    representative_protocols = pick_protocols(devices)

    return {
        "category": category,
        "record_count": len(devices),
        "confidence": 0.0,
        "confidence_level": "low",
        "vendor_candidates": [vendor for vendor, _count in vendor_counter.most_common(8)],
        "representative_domains": representative_domains,
        "ecosystem_domains": [],
        "representative_protocols": representative_protocols,
        "observed_device_labels": [label for label, _count in raw_category_counter.most_common(8)],
        "source_breakdown": dict(source_counter.most_common()),
    }


def compute_confidence(entry):
    record_count = int(entry.get("record_count", 0) or 0)
    vendor_count = len(entry.get("vendor_candidates", []) or [])
    domain_count = len(entry.get("representative_domains", []) or [])
    protocol_count = len(entry.get("representative_protocols", []) or [])
    official_count = len(entry.get("official_sources", []) or [])
    source_breakdown = entry.get("source_breakdown", {}) or {}
    source_type_count = len(source_breakdown)

    score = 0.0
    score += min(record_count / 40.0, 0.35)
    score += min(official_count / 6.0, 0.25)
    score += min(vendor_count / 10.0, 0.12)
    score += min(domain_count / 10.0, 0.10)
    score += min(protocol_count / 6.0, 0.05)
    score += min(source_type_count / 4.0, 0.13)

    if official_count > 0 and record_count <= 2:
        score += 0.03

    score = max(0.0, min(score, 1.0))

    if score >= 0.75:
        level = "high"
    elif score >= 0.45:
        level = "medium"
    else:
        level = "low"

    return round(score, 2), level


def build_category_inference_db(devices):
    devices_by_category = defaultdict(list)

    for device in devices:
        category = device.get("category")
        if category in TARGET_CATEGORIES:
            devices_by_category[category].append(device)

    db = {}
    for category in TARGET_CATEGORIES:
        db[category] = build_category_entry(category, devices_by_category.get(category, []))

    return {
        "categories": db,
        "metadata": {
            "categories_order": TARGET_CATEGORIES,
            "description": "Category inference database for Quarant built from normalized device observations.",
        },
    }


def merge_unique_preserving_order(base_values, override_values):
    merged = []

    for value in list(base_values) + list(override_values):
        if not value:
            continue
        if value not in merged:
            merged.append(value)

    return merged


def apply_official_overrides(db, overrides):
    categories = db.get("categories", {})
    override_categories = overrides.get("categories", {})

    for category, entry in categories.items():
        override = override_categories.get(category, {})
        if not isinstance(override, dict):
            continue

        entry["vendor_candidates"] = merge_unique_preserving_order(
            override.get("vendor_candidates", []),
            entry.get("vendor_candidates", []),
        )
        if "representative_domains" in override:
            entry["representative_domains"] = merge_unique_preserving_order(
                override.get("representative_domains", []),
                [],
            )
        else:
            entry["representative_domains"] = merge_unique_preserving_order(
                entry.get("representative_domains", []),
                [],
            )
        if "ecosystem_domains" in override:
            entry["ecosystem_domains"] = merge_unique_preserving_order(
                override.get("ecosystem_domains", []),
                [],
            )
        else:
            entry["ecosystem_domains"] = merge_unique_preserving_order(
                entry.get("ecosystem_domains", []),
                [],
            )
        entry["representative_protocols"] = merge_unique_preserving_order(
            override.get("representative_protocols", []),
            entry.get("representative_protocols", []),
        )

        official_sources = override.get("official_sources", [])
        if official_sources:
            entry["official_sources"] = official_sources

        confidence, confidence_level = compute_confidence(entry)
        entry["confidence"] = confidence
        entry["confidence_level"] = confidence_level

    if overrides.get("metadata"):
        db["metadata"]["official_overrides_loaded"] = True

    return db


def save_json(data, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    base_dir = Path(__file__).resolve().parent
    output_path = base_dir.parent / "knowledge" / "category_inference_db.json"
    overrides_path = base_dir.parent / "knowledge" / "official_overrides.json"

    normalized_devices, rejected = collect_raw_devices(base_dir)
    db = build_category_inference_db(normalized_devices)
    overrides = load_json_if_exists(overrides_path)
    db = apply_official_overrides(db, overrides)

    save_json(db, output_path)

    print(f"[OK] loaded {len(normalized_devices)} normalized devices for inference DB")
    print(f"[OK] rejected {len(rejected)} low-quality fingerbank records during build")
    print(f"[OK] loaded official overrides from {overrides_path}")
    print(f"[OK] saved category inference DB -> {output_path}")


if __name__ == "__main__":
    main()
