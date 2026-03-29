import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from oui_loader import load_oui_csv, lookup_vendor


FINGERBANK_MIN_SCORE = 15

CATEGORY_HINTS = {
    "Camera": ["camera", "surveillance", "video", "imaging", "monitor"],
    "VoiceAssistant": ["voice", "assistant", "speaker", "alexa", "echo"],
    "Appliance": ["appliance", "fridge", "refrigerator", "family hub", "ac", "hvac", "oven", "washer", "dryer", "vacuum"],
    "Controller": ["plug", "switch", "controller", "dimmer", "outlet", "relay", "light"],
    "Sensor": ["sensor", "motion", "temperature", "humidity", "air quality", "contact"],
    "Hub": ["hub", "bridge", "gateway", "coordinator"],
    "Wearable": ["wearable", "watch", "band", "fitbit", "tracker"],
}

BAD_FINGERBANK_TERMS = [
    "iphone",
    "ios",
    "android",
    "xbox",
    "linux os",
    "operating system",
    "hardware manufacturer",
    "espressif",
    "microsoft",
    "phone, tablet or wearable",
    "generic android",
    "apple mobile device",
]


def load_input(path: Path):
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if "devices" in data and isinstance(data["devices"], list):
            return data["devices"]
        return [data]

    raise ValueError("input JSON must be a list, a single object, or an object with a 'devices' list")


def load_fingerbank_input(path: Path):
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if "devices" in data and isinstance(data["devices"], list):
            return data["devices"]
        return [data]

    raise ValueError("fingerbank JSON must be a list, a single object, or an object with a 'devices' list")


def normalize_device_category(raw: str) -> str:
    s = str(raw).lower()

    mapping = {
        "camera": "Camera",
        "voice_assistant": "VoiceAssistant",
        "appliance": "Appliance",
        "plug": "Controller",
        "light": "Controller",
        "controller": "Controller",
        "sensor": "Sensor",
        "hub": "Hub",
        "wearable": "Wearable",
    }

    if s in mapping:
        return mapping[s]

    # Fingerbank API の曖昧な値や device_name 用の補助
    if "camera" in s or "video" in s:
        return "Camera"
    if "voice" in s or "alexa" in s or "assistant" in s or "speaker" in s:
        return "VoiceAssistant"
    if "plug" in s or "switch" in s or "light" in s:
        return "Controller"
    if "sensor" in s or "motion" in s or "temperature" in s:
        return "Sensor"
    if "hub" in s or "bridge" in s or "router" in s or "access point" in s:
        return "Hub"
    if "watch" in s or "wearable" in s or "fitbit" in s:
        return "Wearable"
    if "refrigerator" in s or "ac" in s or "appliance" in s:
        return "Appliance"

    return "GenericIoT"


def normalize_communication_patterns(protocols, domains):
    protocol_mapping = {
        "http": "local_api",
        "https": "cloud_api",
        "http2": "cloud_api",
        "rtsp": "video_stream",
        "tls": "encrypted_comm",
        "mqtt": "device_status",
        "coap": "device_status",
    }

    result = set()

    for p in protocols:
        key = str(p).lower()
        if key in protocol_mapping:
            result.add(protocol_mapping[key])

    for d in domains:
        domain = str(d).lower()

        if "cloud" in domain:
            result.add("cloud_api")
        if "api" in domain:
            result.add("cloud_api")
        if "video" in domain or "stream" in domain:
            result.add("video_stream")
        if "update" in domain or "firmware" in domain:
            result.add("firmware_update")
        if "analytics" in domain or "telemetry" in domain:
            result.add("analytics")
        if "track" in domain or "collect" in domain:
            result.add("tracking")

    return sorted(result)


def normalize_pii_types(pii_list):
    mapping = {
        "device_id": "device_identifier",
        "user_id": "user_identifier",
        "voice": "media_metadata",
        "email": "email",
        "phone": "phone",
        "location": "location",
        "account": "account_info",
        "account_info": "account_info",
        "usage": "usage_data",
        "health": "usage_data",
    }

    result = set()
    for p in pii_list:
        key = str(p).lower()
        if key in mapping:
            result.add(mapping[key])

    return sorted(result)


def extract_domain_keywords(domains):
    keywords = set()

    for domain in domains:
        for part in str(domain).lower().replace("-", ".").split("."):
            if not part:
                continue
            if part in {"com", "net", "org", "co", "jp"}:
                continue
            if re.fullmatch(r"v\d+", part):
                continue
            keywords.add(part)

    return sorted(keywords)


def is_good_fingerbank_match(record):
    source_category = record.get("source_category", "")
    raw_category = str(record.get("category", ""))
    device_name = str(record.get("fingerbank_device_name", ""))
    score = int(record.get("fingerbank_score", 0) or 0)

    if not source_category:
        return True

    if score < FINGERBANK_MIN_SCORE:
        return False

    raw_text = raw_category.lower()
    combined = f"{raw_category} {device_name}".lower()
    good_terms = CATEGORY_HINTS.get(source_category, [])
    raw_has_good_term = any(term in raw_text for term in good_terms)
    combined_has_bad_term = any(term in combined for term in BAD_FINGERBANK_TERMS)

    if combined_has_bad_term and not raw_has_good_term:
        return False

    if any(term in combined for term in good_terms):
        return True

    return False


def filter_fingerbank_api_records(records):
    filtered = []
    rejected = []

    for record in records:
        if is_good_fingerbank_match(record):
            filtered.append(record)
        else:
            rejected.append(record)

    return filtered, rejected


def summarize_rejected_fingerbank_records(records):
    summary = defaultdict(Counter)

    for record in records:
        category = record.get("source_category", "Unknown")
        raw_category = record.get("category", "(empty)")
        summary[category][raw_category] += 1

    return {
        category: dict(counter.most_common())
        for category, counter in summary.items()
    }


def convert_fingerbank_api_records(records):
    converted = []

    for r in records:
        if not isinstance(r, dict):
            print(f"[WARN] skipped invalid fingerbank api record: {r!r}")
            continue

        if "response" not in r:
            print(f"[WARN] skipped fingerbank record without response: {r.get('query_label') or r.get('query_name', '')}")
            continue

        response = r.get("response", {})
        payload = r.get("request_payload", {})

        manufacturer = response.get("manufacturer", {})
        vendor = manufacturer.get("name", "") if isinstance(manufacturer, dict) else ""

        device = response.get("device", {})
        raw_category = ""
        if isinstance(device, dict):
            raw_category = device.get("name", "")

        if not raw_category:
            raw_category = response.get("device_name", "")

        converted.append({
            "name": r.get("query_name") or r.get("query_label", ""),
            "vendor": vendor,
            "mac": payload.get("mac", ""),
            "category": raw_category,
            "protocols": payload.get("protocols", []),
            "domains": payload.get("destination_hosts", []),
            "pii": payload.get("pii", []),
            "source": "fingerbank_api",
            "source_category": r.get("category", ""),
            "fingerbank_score": response.get("score", 0),
            "fingerbank_device_name": response.get("device_name", ""),
        })

    return converted

def build_normalized_devices(raw_devices, oui_map):
    normalized = []

    for d in raw_devices:
        if not isinstance(d, dict):
            print(f"[WARN] skipped non-dict record: {d!r}")
            continue

        protocols = d.get("protocols", [])
        domains = d.get("domains", [])
        pii = d.get("pii", [])
        mac = d.get("mac", "")

        vendor = d.get("vendor", "").strip()
        if not vendor and mac:
            vendor = lookup_vendor(mac, oui_map)

        raw_category = d.get("category", "")
        source_category = d.get("source_category", "")

        category = normalize_device_category(raw_category)

        if d.get("source") == "fingerbank_api" and source_category:
            source_based_category = normalize_device_category(source_category)
            if source_based_category != "GenericIoT":
                category = source_based_category

        print("[DEBUG category]", d.get("name", ""), raw_category, source_category, "=>", category)

        device = {
            "name": d.get("name", ""),
            "vendor": vendor,
            "mac": mac,
            "raw_category": raw_category,
            "category": category,
            "domains": domains,
            "domain_keywords": extract_domain_keywords(domains),
            "communication_patterns": normalize_communication_patterns(protocols, domains),
            "pii_types": normalize_pii_types(pii),
            "source": d.get("source", "sample"),
        }

        if "source_category" in d:
            device["source_category"] = d.get("source_category", "")
        if "fingerbank_score" in d:
            device["fingerbank_score"] = d.get("fingerbank_score", 0)
        if "fingerbank_device_name" in d:
            device["fingerbank_device_name"] = d.get("fingerbank_device_name", "")

        normalized.append(device)

    return normalized

def build_category_stats(devices):
    stats = defaultdict(
        lambda: {
            "count": 0,
            "vendors": Counter(),
            "raw_categories": Counter(),
            "communication_patterns": Counter(),
            "domain_keywords": Counter(),
            "pii_types": Counter(),
            "sources": Counter(),
        }
    )

    for d in devices:
        category = d.get("category", "GenericIoT")
        stats[category]["count"] += 1

        vendor = d.get("vendor", "")
        if vendor:
            stats[category]["vendors"][vendor] += 1

        raw_category = d.get("raw_category", "")
        if raw_category:
            stats[category]["raw_categories"][raw_category] += 1

        for comm in d.get("communication_patterns", []):
            stats[category]["communication_patterns"][comm] += 1

        for kw in d.get("domain_keywords", []):
            stats[category]["domain_keywords"][kw] += 1

        for pii in d.get("pii_types", []):
            stats[category]["pii_types"][pii] += 1

        source = d.get("source", "unknown")
        stats[category]["sources"][source] += 1

    result = {}
    for category, data in stats.items():
        result[category] = {
            "count": data["count"],
            "vendors": dict(data["vendors"].most_common()),
            "raw_categories": dict(data["raw_categories"].most_common()),
            "communication_patterns": dict(data["communication_patterns"].most_common()),
            "domain_keywords": dict(data["domain_keywords"].most_common()),
            "pii_types": dict(data["pii_types"].most_common()),
            "sources": dict(data["sources"].most_common()),
        }

    return result


def save_json(data, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    sample_input_path = base_dir / "input" / "sample_devices.json"
    fingerbank_path = base_dir / "input" / "fingerbank_raw.json"
    oui_csv_path = base_dir / "input" / "oui.csv"

    normalized_output_path = base_dir.parent / "knowledge" / "normalized_devices.json"
    stats_output_path = base_dir.parent / "knowledge" / "category_stats.json"
    rejected_summary_output_path = base_dir.parent / "knowledge" / "fingerbank_rejected_summary.json"

    raw_devices = []
    if sample_input_path.exists():
        raw_devices = load_input(sample_input_path)

    fingerbank_devices = []
    if fingerbank_path.exists():
        fingerbank_raw = load_fingerbank_input(fingerbank_path)
        fingerbank_devices = convert_fingerbank_api_records(fingerbank_raw)
        fingerbank_devices, rejected_fingerbank_devices = filter_fingerbank_api_records(fingerbank_devices)
    else:
        rejected_fingerbank_devices = []

    all_devices = raw_devices + fingerbank_devices

    oui_map = load_oui_csv(oui_csv_path)

    devices = build_normalized_devices(all_devices, oui_map)
    stats = build_category_stats(devices)
    rejected_summary = summarize_rejected_fingerbank_records(rejected_fingerbank_devices)

    save_json(devices, normalized_output_path)
    save_json(stats, stats_output_path)
    save_json(rejected_summary, rejected_summary_output_path)

    print(f"[OK] loaded {len(raw_devices)} sample devices from {sample_input_path}")
    print(f"[OK] loaded {len(fingerbank_devices)} fingerbank api devices from {fingerbank_path}")
    print(f"[OK] rejected {len(rejected_fingerbank_devices)} low-quality fingerbank api devices")
    print(f"[OK] loaded {len(oui_map)} OUI entries from {oui_csv_path}")
    print(f"[OK] saved {len(devices)} normalized devices -> {normalized_output_path}")
    print(f"[OK] saved category stats -> {stats_output_path}")
    print(f"[OK] saved rejected fingerbank summary -> {rejected_summary_output_path}")
    if rejected_fingerbank_devices:
        print("[INFO] rejected fingerbank summary:", rejected_summary)
    print("[DEBUG] running NEW extract_devices.py")
