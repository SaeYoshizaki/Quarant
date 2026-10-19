#!/usr/bin/env python3
"""OSS integration step 4: compare, provision by provision, the devices with
evidence from Quarant's own parser and from the Zeek path
(`quarant zeek evidence`). Same counting as evidence_rates.py: devices by
MAC within a dataset group, signals and filters from evidence-map.json,
device ownership from the Quarant run's device_inventory.json.

Writes a Markdown table (both / Quarant only / Zeek only per group) and a
JSON file with the devices on each side, for checking by hand.

usage: compare_sources.py EVIDENCE_MAP QUARANT_RUNS ZEEK_RUNS EXCLUDE_MACS OUT_MD OUT_JSON
       QUARANT_RUNS may be a comma-separated list of run roots.
"""
import collections
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import evidence_rates as er  # noqa: E402


def inventory(d):
    inv = {}
    p = os.path.join(d, "device_inventory.json")
    if os.path.exists(p):
        for dev in json.load(open(p)).get("devices") or []:
            inv[dev["ip"]] = dev
    return inv


def events(d):
    with open(os.path.join(d, "events.jsonl")) as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not e.get("debug"):
                yield e


def main():
    emap, qroots, zroot, excl, out_md, out_json = sys.argv[1:7]
    provs = [p for p in json.load(open(emap))["provisions"]
             if p["signals"] and not p["signals"][0].startswith("identity_evidence")]
    exclude = {l.strip().lower() for l in open(excl) if l.strip() and not l.startswith("#")}
    seen = collections.defaultdict(set)
    hit = {s: collections.defaultdict(lambda: collections.defaultdict(set)) for s in ("quarant", "zeek")}
    names = {}
    for qd in sorted(d for r in qroots.split(",") for d in glob.glob(os.path.join(r, "*"))):
        name = os.path.basename(qd)
        zd = os.path.join(zroot, name)
        if not os.path.exists(os.path.join(qd, "events.jsonl")) or not os.path.exists(os.path.join(zd, "events.jsonl")):
            continue
        group = next((g for p, g in er.GROUPS.items() if name.startswith(p)), None)
        if group is None:
            continue
        inv = inventory(qd)
        qev = list(events(qd))
        keys = {e.get("device_key") for e in qev}
        for ip, dev in inv.items():
            mac = er.device_id(inv, ip)
            if (dev.get("observed_protocols") or ip in keys) and mac not in exclude:
                seen[group].add(mac)
                names.setdefault(mac, dev.get("display_name") or dev.get("hostname") or dev.get("vendor") or "")
        for side, evs in (("quarant", qev), ("zeek", events(zd))):
            for e in evs:
                mac = er.device_id(inv, e.get("device_key") or e.get("src_ip", ""))
                if mac in exclude or mac not in seen[group]:
                    continue
                for p in provs:
                    if er.matches(p, e):
                        hit[side][group][p["provision"]].add(mac)

    groups = [g for g in er.GROUPS.values() if g in seen]
    L = ["# Quarant と Zeek 経由の比較（要件ごとの機器数）", "",
         "`scripts/assessment/compare_sources.py` で生成。各セルは「両方 / Quarant だけ / Zeek だけ」。機器は MAC で数える。",
         "", "| 要件 | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups),
         "| （通信が観測された機器） | " + " | ".join(str(len(seen[g])) for g in groups) + " |"]
    detail = {}
    for p in provs:
        cells = []
        for g in groups:
            q, z = hit["quarant"][g][p["provision"]], hit["zeek"][g][p["provision"]]
            cells.append(f"{len(q & z)} / {len(q - z)} / {len(z - q)}" if q or z else "—")
            if q ^ z:
                detail.setdefault(p["provision"], {})[g] = {
                    "quarant_only": sorted(f"{m} {names.get(m, '')}".strip() for m in q - z),
                    "zeek_only": sorted(f"{m} {names.get(m, '')}".strip() for m in z - q)}
        L.append(f"| {p['provision']} | " + " | ".join(cells) + " |")
    open(out_md, "w").write("\n".join(L) + "\n")
    json.dump(detail, open(out_json, "w"), ensure_ascii=False, indent=1)
    print("\n".join(L))


if __name__ == "__main__":
    main()
