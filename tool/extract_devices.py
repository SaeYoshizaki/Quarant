import json
from collections import Counter, defaultdict
from pathlib import Path

from oui_loader import load_oui_csv, lookup_vendor


def load_input(path: Path):
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if "devices" in data and isinstance(data["devices"], list):
            return data["devices"]

    raise ValueError("input JSON must be a list or an object with a 'devices' list")

def normalize_device_category(raw: str) -> str:
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
    return mapping.get(str(raw).lower(), "GenericIoT")


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
            if part and part not in {"com", "net", "org", "co", "jp"}:
                keywords.add(part)

    return sorted(keywords)


def build_normalized_devices(raw_devices, oui_map):
    normalized = []

    for d in raw_devices:
        protocols = d.get("protocols", [])
        domains = d.get("domains", [])
        pii = d.get("pii", [])
        mac = d.get("mac", "")

        vendor = d.get("vendor", "").strip()
        if not vendor and mac:
            vendor = lookup_vendor(mac, oui_map)

        device = {
            "name": d.get("name", ""),
            "vendor": vendor,
            "mac": mac,
            "raw_category": d.get("category", ""),
            "category": normalize_device_category(d.get("category", "")),
            "domains": domains,
            "domain_keywords": extract_domain_keywords(domains),
            "communication_patterns": normalize_communication_patterns(protocols, domains),
            "pii_types": normalize_pii_types(pii),
        }
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

    result = {}
    for category, data in stats.items():
        result[category] = {
            "count": data["count"],
            "vendors": dict(data["vendors"].most_common()),
            "raw_categories": dict(data["raw_categories"].most_common()),
            "communication_patterns": dict(data["communication_patterns"].most_common()),
            "domain_keywords": dict(data["domain_keywords"].most_common()),
            "pii_types": dict(data["pii_types"].most_common()),
        }

    return result


def save_json(data, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    input_path = base_dir / "input" / "sample_devices.json"
    oui_csv_path = base_dir / "input" / "oui.csv"

    normalized_output_path = base_dir.parent / "knowledge" / "normalized_devices.json"
    stats_output_path = base_dir.parent / "knowledge" / "category_stats.json"

    raw_devices = load_input(input_path)
    oui_map = load_oui_csv(oui_csv_path)

    devices = build_normalized_devices(raw_devices, oui_map)
    stats = build_category_stats(devices)

    save_json(devices, normalized_output_path)
    save_json(stats, stats_output_path)

    print(f"[OK] loaded {len(raw_devices)} raw devices from {input_path}")
    print(f"[OK] loaded {len(oui_map)} OUI entries from {oui_csv_path}")
    print(f"[OK] saved {len(devices)} normalized devices -> {normalized_output_path}")
    print(f"[OK] saved category stats -> {stats_output_path}")