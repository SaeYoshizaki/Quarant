import json
from copy import deepcopy
from pathlib import Path

import requests


API_KEY = "d6c9561d1164668fc02f46e7f3d364d0beae5d8f"

INTERROGATE_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"
TIMEOUT = (10, 30)

MAX_NEW_RECORDS = 100
MAX_VARIANTS_PER_BASE = 50


queries_by_category = {
    "Camera": [
        {
            "label": "generic-ip-camera",
            "payload": {
                "destination_hosts": ["api.camera-cloud.example", "video.camera-cloud.example"],
                "hostname": "ipcamera-livingroom",
                "dhcp_fingerprint": "1,3,6,15,28,51,58,59",
                "ja3_fingerprints": ["b32309a26951912be7dba376398abc3b"],
            },
        },
        {
            "label": "outdoor-camera",
            "payload": {
                "destination_hosts": ["stream.securitycam.example"],
                "hostname": "outdoor-cam",
                "user_agents": ["IPCamera/1.0"],
            },
        },
        {
            "label": "baby-monitor-camera",
            "payload": {
                "destination_hosts": ["babycam-cloud.example", "relay.babycam-cloud.example"],
                "hostname": "nursery-camera",
                "user_agents": ["BabyMonitor/2.1"],
            },
        },
    ],
    "VoiceAssistant": [
        {
            "label": "echo-speaker",
            "payload": {
                "destination_hosts": ["alexa.amazon.com", "device-metrics-us.amazon.com"],
                "mac": "44:65:0d:44:10:01",
                "hostname": "echo-speaker",
                "dhcp_fingerprint": "1,121,3,6,15,119,252,95,44,46",
                "user_agents": ["Echo/3.2 AlexaMediaPlayer/1.0"],
            },
        },
        {
            "label": "alexa-speaker-cloud",
            "payload": {
                "destination_hosts": ["avs-alexa-4-na.amazon.com", "api.amazonalexa.com"],
                "hostname": "alexa-speaker",
                "user_agents": ["AlexaDevice/1.0"],
            },
        },
        {
            "label": "echo-show",
            "payload": {
                "destination_hosts": ["dp-gw-na-js.amazon.com", "alexa-na.amazon.com"],
                "hostname": "echo-show",
                "user_agents": ["AFTMM Build/FireOS Alexa/2.0"],
            },
        },
    ],
    "Appliance": [
        {
            "label": "connected-appliance",
            "payload": {
                "destination_hosts": ["api.appliance-cloud.example", "firmware.appliance-cloud.example"],
                "mac": "70:2c:1f:12:34:56",
                "hostname": "smart-fridge",
                "dhcp_fingerprint": "1,3,6,15,44,46,47,31,33,121,249,43",
            },
        },
        {
            "label": "smart-ac",
            "payload": {
                "destination_hosts": ["hvac-cloud.example"],
                "hostname": "livingroom-ac",
                "ja3_fingerprints": ["51c64c77e60f3980eea90869b68c58a8"],
            },
        },
        {
            "label": "robot-cleaner",
            "payload": {
                "destination_hosts": ["vacuum-cloud.example", "map-sync.example"],
                "hostname": "robo-cleaner",
                "user_agents": ["RobotCleaner/6.0"],
            },
        },
    ],
    "Controller": [
        {
            "label": "tplink-smart-plug",
            "payload": {
                "destination_hosts": ["use1-api.tplinkra.com", "n-wap-gw.tplinkcloud.com"],
                "mac": "50:c7:bf:50:10:01",
                "hostname": "tplink-smartplug",
                "dhcp_fingerprint": "1,3,6,15,119,252,95,44,46",
                "user_agents": ["TP-Link Smart Plug/1.0"],
            },
        },
        {
            "label": "switchbot-plug",
            "payload": {
                "destination_hosts": ["api.switch-bot.com", "na.switch-bot.com"],
                "hostname": "switchbot-plug",
                "user_agents": ["SwitchBotPlug/1.0"],
            },
        },
        {
            "label": "kasa-light-switch",
            "payload": {
                "destination_hosts": ["aps1-iot-auth.tplinkcloud.com", "eu-wap.tplinkcloud.com"],
                "hostname": "kasa-switch",
                "user_agents": ["KasaSmart/3.0"],
            },
        },
    ],
    "Sensor": [
        {
            "label": "aqara-sensor",
            "payload": {
                "destination_hosts": ["api.aqara.com", "data.aqara.com"],
                "mac": "54:ef:44:10:20:01",
                "hostname": "aqara-sensor",
                "dhcp_fingerprint": "1,3,6,15,26,28,51,58,59,43",
            },
        },
        {
            "label": "sensor-telemetry",
            "payload": {
                "destination_hosts": ["telemetry.sensorcloud.example", "events.sensorcloud.example"],
                "hostname": "hallway-sensor",
                "ja3_fingerprints": ["a48c0d5f95b1ef98f560f324fd275da1"],
            },
        },
        {
            "label": "motion-contact-sensor",
            "payload": {
                "destination_hosts": ["mqtt.sensorcloud.example", "telemetry.motion.example"],
                "hostname": "motion-contact-sensor",
                "user_agents": ["MotionSensor/2.1"],
            },
        },
    ],
    "Hub": [
        {
            "label": "hue-bridge",
            "payload": {
                "destination_hosts": ["discovery.meethue.com", "data.meethue.com"],
                "mac": "ec:fa:bc:10:30:01",
                "hostname": "philips-hue-bridge",
                "dhcp_fingerprint": "1,3,6,12,15,28,42,51,58,59,119",
                "user_agents": ["IpBridge/1.0"],
            },
        },
        {
            "label": "smartthings-hub",
            "payload": {
                "destination_hosts": ["api.smartthings.com", "hub.smartthings.com"],
                "hostname": "smartthings-hub",
                "user_agents": ["HubCore/2.0"],
            },
        },
        {
            "label": "aqara-hub",
            "payload": {
                "destination_hosts": ["api.aqara.com", "hub-aqara.example"],
                "hostname": "aqara-hub",
                "user_agents": ["AqaraHub/1.0"],
            },
        },
    ],
    "Wearable": [
        {
            "label": "fitbit-band",
            "payload": {
                "destination_hosts": ["client.fitbit.com", "device.fitbit.com"],
                "mac": "f0:99:b6:10:40:01",
                "hostname": "fitbit-band",
                "user_agents": ["Fitbit/5.0"],
                "ja3_fingerprints": ["6f7889f6e3d4064553f11f88f3799a37"],
            },
        },
        {
            "label": "garmin-watch",
            "payload": {
                "destination_hosts": ["connect.garmin.com", "services.garmin.com"],
                "hostname": "garmin-watch",
                "user_agents": ["GarminWearable/1.0"],
            },
        },
        {
            "label": "wear-os-watch",
            "payload": {
                "destination_hosts": ["wear.googleapis.com", "android.googleapis.com"],
                "hostname": "wear-os-watch",
                "user_agents": ["WearOS/4.0"],
            },
        },
    ],
}


def sanitize_payload(payload):
    """
    空の値を取り除き、送信 payload の形を安定させる。
    """
    sanitized = {}

    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, list) and not value:
            continue
        sanitized[key] = value

    return sanitized


def mutate_hostname(hostname, suffix):
    if not hostname:
        return hostname
    return f"{hostname}-{suffix}"


def mutate_destination_hosts(hosts, prefix, variant_suffix):
    if not hosts:
        return hosts

    mutated = []
    for host in hosts:
        parts = host.split(".", 1)
        if len(parts) == 2:
            mutated.append(f"{prefix}-{parts[0]}-{variant_suffix}.{parts[1]}")
        else:
            mutated.append(f"{prefix}-{host}-{variant_suffix}")
    return mutated


def mutate_mac(mac, mac_suffix):
    if not mac:
        return mac

    base_parts = mac.split(":")
    suffix_parts = mac_suffix.split(":")
    if len(base_parts) != 6 or len(suffix_parts) != 3:
        return mac

    return ":".join(base_parts[:3] + suffix_parts)


def mutate_user_agents(user_agents, user_agent_suffix):
    if not user_agents:
        return user_agents

    return [f"{agent} {user_agent_suffix}" for agent in user_agents]


def build_variant_profile(variant_index):
    hostname_suffixes = [
        "main",
        "kitchen",
        "bedroom",
        "office",
        "guest",
        "hall",
        "garage",
        "patio",
        "lab",
        "studio",
    ]
    destination_prefixes = [
        "api",
        "control",
        "sync",
        "telemetry",
        "events",
        "device",
        "cloud",
        "status",
    ]

    hostname_suffix = hostname_suffixes[(variant_index - 1) % len(hostname_suffixes)]
    destination_prefix = destination_prefixes[(variant_index - 1) % len(destination_prefixes)]

    octet4 = 0x10 + ((variant_index - 1) // (16 * 16)) % 16
    octet5 = ((variant_index - 1) // 16) % 16
    octet6 = variant_index % 256

    return {
        "suffix": f"v{variant_index:02d}",
        "hostname_suffix": f"{hostname_suffix}{variant_index:02d}",
        "destination_prefix": destination_prefix,
        "mac_suffix": f"{octet4:02x}:{octet5:02x}:{octet6:02x}",
        "user_agent_suffix": f"Variant{variant_index:02d}",
    }


def build_query_variant(category, base_query, variant_index):
    """
    ベース query を軽く変形してユニークな問い合わせ候補を作る。
    Fingerbank の interrogate は観測属性セットが重要なので、
    ラベルと payload を両方ユニークにして保存済み判定しやすくする。
    """
    payload = deepcopy(base_query.get("payload", {}))
    variant_profile = build_variant_profile(variant_index)

    payload["hostname"] = mutate_hostname(payload.get("hostname"), variant_profile["hostname_suffix"])
    payload["destination_hosts"] = mutate_destination_hosts(
        payload.get("destination_hosts", []),
        variant_profile["destination_prefix"],
        variant_profile["suffix"],
    )
    payload["mac"] = mutate_mac(payload.get("mac"), variant_profile["mac_suffix"])
    payload["user_agents"] = mutate_user_agents(
        payload.get("user_agents", []),
        variant_profile["user_agent_suffix"],
    )

    label = f"{base_query['label']}-{variant_profile['suffix']}"

    return {
        "category": category,
        "query_label": label,
        "request_payload": sanitize_payload(payload),
    }


def extract_base_label(query_label):
    if "-v" in query_label:
        return query_label.rsplit("-v", 1)[0]
    return query_label


def load_existing_records(output_path):
    if not output_path.exists():
        return []

    with output_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    raise ValueError(f"{output_path} must contain a JSON array")


def build_existing_keys(records):
    keys = set()

    for record in records:
        if not isinstance(record, dict):
            continue

        category = record.get("category", "")
        query_label = record.get("query_label", "")

        if category and query_label:
            keys.add((category, query_label))

    return keys


def summarize_base_query_history(records):
    summary = {}

    for category, queries in queries_by_category.items():
        for query in queries:
            summary[(category, query["label"])] = {
                "success": 0,
                "error": 0,
                "not_found": 0,
            }

    for record in records:
        if not isinstance(record, dict):
            continue

        category = record.get("category", "")
        base_label = extract_base_label(record.get("query_label", ""))
        key = (category, base_label)

        if key not in summary:
            continue

        if "response" in record:
            summary[key]["success"] += 1
        elif "error" in record:
            summary[key]["error"] += 1
            if "HTTP 404" in str(record["error"]):
                summary[key]["not_found"] += 1

    return summary


def is_base_query_allowed(base_summary):
    if base_summary["success"] > 0:
        return True
    if base_summary["not_found"] > 0 and base_summary["success"] == 0:
        return False
    return True


def build_selected_queries(existing_records, max_new_records=MAX_NEW_RECORDS):
    """
    保存済みレコードを読み、未取得の query だけを新規取得対象にする。
    返り値は「今回追加で取りにいく分」のみ。
    """
    existing_keys = build_existing_keys(existing_records)
    base_history = summarize_base_query_history(existing_records)
    pending = []

    for variant_index in range(0, MAX_VARIANTS_PER_BASE + 1):
        for category, queries in queries_by_category.items():
            for query in queries:
                base_key = (category, query["label"])
                base_summary = base_history.get(base_key, {"success": 0, "error": 0, "not_found": 0})

                if not is_base_query_allowed(base_summary):
                    continue

                if variant_index == 0:
                    item = {
                        "category": category,
                        "query_label": query["label"],
                        "request_payload": sanitize_payload(query.get("payload", {})),
                    }
                else:
                    item = build_query_variant(category, query, variant_index)

                query_key = (item["category"], item["query_label"])
                if query_key in existing_keys:
                    continue

                pending.append(item)
                if len(pending) >= max_new_records:
                    return pending

    return pending


def interrogate(payload):
    response = requests.post(
        INTERROGATE_URL,
        params={"key": API_KEY},
        json=payload,
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def build_success_record(category, query_label, request_payload, response_payload):
    return {
        "category": category,
        "query_label": query_label,
        "request_payload": request_payload,
        "response": response_payload,
        "source": "fingerbank_api",
    }


def build_error_record(category, query_label, request_payload, error_message):
    return {
        "category": category,
        "query_label": query_label,
        "request_payload": request_payload,
        "error": error_message,
        "source": "fingerbank_api",
    }


def fetch_all(selected_queries):
    results = []

    for index, item in enumerate(selected_queries, start=1):
        category = item["category"]
        query_label = item["query_label"]
        request_payload = item["request_payload"]

        try:
            response_payload = interrogate(request_payload)
            record = build_success_record(category, query_label, request_payload, response_payload)
            print(f"[OK {index}/{len(selected_queries)}] {category} / {query_label}")
        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            error_message = f"HTTP {status_code}: {exc}"
            record = build_error_record(category, query_label, request_payload, error_message)
            print(f"[ERROR {index}/{len(selected_queries)}] {category} / {query_label} -> {error_message}")
        except requests.exceptions.Timeout:
            error_message = "request timeout"
            record = build_error_record(category, query_label, request_payload, error_message)
            print(f"[ERROR {index}/{len(selected_queries)}] {category} / {query_label} -> {error_message}")
        except requests.exceptions.RequestException as exc:
            error_message = f"request failed: {exc}"
            record = build_error_record(category, query_label, request_payload, error_message)
            print(f"[ERROR {index}/{len(selected_queries)}] {category} / {query_label} -> {error_message}")
        except ValueError as exc:
            error_message = f"invalid JSON response: {exc}"
            record = build_error_record(category, query_label, request_payload, error_message)
            print(f"[ERROR {index}/{len(selected_queries)}] {category} / {query_label} -> {error_message}")

        results.append(record)

    return results


def write_output(records, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


def main():
    if not API_KEY:
        raise RuntimeError("API_KEY is empty. Set your Fingerbank API key in fetch_fingerbank.py.")

    base_dir = Path(__file__).resolve().parent
    output_path = base_dir / "input" / "fingerbank_raw.json"

    existing_records = load_existing_records(output_path)
    base_history = summarize_base_query_history(existing_records)
    blocked_base_queries = [
        f"{category}/{label}"
        for (category, label), summary in sorted(base_history.items())
        if not is_base_query_allowed(summary)
    ]
    selected_queries = build_selected_queries(existing_records, max_new_records=MAX_NEW_RECORDS)

    print(f"[INFO] existing records: {len(existing_records)}")
    print(f"[INFO] blocked base queries after 404-only history: {len(blocked_base_queries)}")
    if blocked_base_queries:
        print("[INFO] blocked list: " + ", ".join(blocked_base_queries))
    print(f"[INFO] new queries to fetch: {len(selected_queries)}")

    if not selected_queries:
        print("[INFO] no new queries to fetch")
        return

    new_records = fetch_all(selected_queries)
    combined_records = existing_records + new_records
    write_output(combined_records, output_path)

    print(f"[INFO] appended {len(new_records)} new records")
    print(f"[INFO] total records saved: {len(combined_records)} -> {output_path}")


if __name__ == "__main__":
    main()
