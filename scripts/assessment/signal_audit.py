#!/usr/bin/env python3
"""C2: which passive signals each UNSW device actually emits (development
days only, D11).

Inputs per capture day:
  RUNS_DIR/DAY/device_inventory.json  - Quarant's identity evidence per device
  SHAPE_DIR/DAY.json                  - scripts/assessment/trafficshape output

For every device in the ground truth it reports, over the days it was seen:
  - self-description: DHCP hostname, mDNS instance/service, SSDP device type
    and server, HomeKit category (ci= in mDNS TXT)
  - DHCP fingerprint (vendor class, parameter request list), OUI vendor
  - destinations: distinct DNS names
  - traffic shape: medians over days of the trafficshape features
  - Quarant's current category per day
  - on which days each self-description / DHCP attribute appeared

usage: signal_audit.py TRUTH_JSON RUNS_DIR SHAPE_DIR OUT_JSON
OUT_JSON holds the per-device dossier; the tiers in
docs/assessment/signal-audit.md are judged by hand from it.
"""
import collections
import glob
import json
import os
import re
import statistics
import sys

SELF_ATTRS = ["hostname", "mdns_instance", "mdns_service", "ssdp_device_type", "ssdp_server", "ssdp_search_agent"]
SHAPE_KEYS = [
    "wan_bytes_out", "wan_bytes_in", "lan_bytes_out", "wan_upload_ratio",
    "mean_pkt_out", "big_pkt_out_frac", "active_minutes", "wan_active_minutes",
    "active_hours", "wan_minute_out_p50", "wan_minute_out_p95", "wan_minute_out_max",
    "remote_ips", "wan_flows", "max_flow_seconds", "flow_start_interval_p50",
    "flow_start_interval_cv",
]


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def main():
    truth_path, runs_dir, shape_dir, out_json = sys.argv[1:5]
    truth = {d["mac"].lower(): d for d in json.load(open(truth_path))["devices"]}
    dossier = {mac: {
        "name": t["name"],
        "truth": "non_iot" if t.get("non_iot") else "outside" if t.get("outside_taxonomy") else "/".join(t["accept"]),
        "days": set(),
        "self": collections.defaultdict(collections.Counter),
        "homekit_ci": collections.Counter(),
        "dhcp_vendor_class": collections.Counter(),
        "dhcp_prl": collections.Counter(),
        "oui": collections.Counter(),
        "dns": collections.Counter(),
        "category": collections.Counter(),
        "shape": collections.defaultdict(list),
        "ports": collections.Counter(),
        "sustained": collections.defaultdict(list),
        "signal_days": collections.defaultdict(set),
    } for mac, t in truth.items()}

    for inv in sorted(glob.glob(os.path.join(runs_dir, "*", "device_inventory.json"))):
        day = os.path.basename(os.path.dirname(inv))
        seen_today = set()
        for d in json.load(open(inv)).get("devices") or []:
            mac = (d.get("mac_address") or "").lower()
            if mac not in dossier or not d.get("observed_protocols"):
                continue
            x = dossier[mac]
            x["days"].add(day)
            if mac not in seen_today:
                x["category"][f'{d.get("category_candidate")}/{d.get("category_confidence")}'] += 1
                seen_today.add(mac)
            if d.get("dns_queries"):
                x["signal_days"]["dns"].add(day)
            for q in d.get("dns_queries") or []:
                x["dns"][q] += 1
            for ev in d.get("identity_evidence") or []:
                a, v = ev.get("attribute"), ev.get("value") or ""
                if a in SELF_ATTRS or a in ("mdns_txt", "dhcp_vendor_class", "dhcp_param_request_list"):
                    x["signal_days"][a].add(day)
                if a in SELF_ATTRS:
                    x["self"][a][v] += 1
                elif a == "mdns_txt":
                    for m in re.finditer(r"(?:^|[\s,;])ci=(\d+)", v):
                        x["homekit_ci"][m.group(1)] += 1
                elif a == "dhcp_vendor_class":
                    x["dhcp_vendor_class"][v] += 1
                elif a == "dhcp_param_request_list":
                    x["dhcp_prl"][v] += 1
                elif a == "mac_vendor":
                    x["oui"][v] += 1

    for p in sorted(glob.glob(os.path.join(shape_dir, "*.json"))):
        day = os.path.splitext(os.path.basename(p))[0]
        if not re.fullmatch(r"\d\d-\d\d-\d\d", day):
            continue
        for mac, s in json.load(open(p)).items():
            if mac not in dossier:
                continue
            x = dossier[mac]
            x["days"].add(day)
            for k in SHAPE_KEYS:
                x["shape"][k].append(s.get(k))
            for k, v in (s.get("sustained_upload_minutes") or {}).items():
                x["sustained"][k].append(v)
            for port in s.get("top_ports") or {}:
                x["ports"][port] += 1

    out = {}
    for mac, x in dossier.items():
        out[mac] = {
            "name": x["name"],
            "truth": x["truth"],
            "days": len(x["days"]),
            "signal_days": {a: sorted(v) for a, v in sorted(x["signal_days"].items())},
            "self_description": {a: dict(c.most_common(5)) for a, c in x["self"].items()},
            "homekit_ci": dict(x["homekit_ci"]),
            "dhcp_vendor_class": dict(x["dhcp_vendor_class"].most_common(3)),
            "dhcp_param_request_list": dict(x["dhcp_prl"].most_common(3)),
            "oui": dict(x["oui"].most_common(2)),
            "dns_names": len(x["dns"]),
            "dns_top": [n for n, _ in x["dns"].most_common(8)],
            "quarant_category": dict(x["category"]),
            "shape_median": {k: median(v) for k, v in x["shape"].items()},
            "sustained_upload_minutes_median": {k: median(v) for k, v in x["sustained"].items()},
            "top_ports_days": dict(x["ports"].most_common(6)),
        }
    with open(out_json, "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
