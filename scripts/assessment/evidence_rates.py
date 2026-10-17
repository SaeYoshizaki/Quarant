#!/usr/bin/env python3
"""E4: how often does violation evidence for the Model-N-reachable ETSI
provisions actually appear in real traffic, per dataset era?

For every analysis run (events.jsonl + device_inventory.json) the devices
are identified by MAC (falling back to IP), so a device seen on several days
of one dataset counts once. For each provision in evidence-map.json the
script counts devices with at least one matching signal, and writes a random
sample of matching events per signal for the precision audit.

usage: evidence_rates.py EVIDENCE_MAP RUNS_DIR[,RUNS_DIR...] OUT_MD SAMPLES_JSON [EXCLUDE_MACS]
EXCLUDE_MACS: optional file with one MAC per line (e.g. phones, laptops and the
gateway from a dataset's ground truth) that are not IoT devices.
Dataset groups are derived from run directory prefixes (see GROUPS).
"""
import collections
import glob
import ipaddress
import json
import os
import random
import re
import sys

GROUPS = {"unsw-": "UNSW traces 2016", "unswatk-": "UNSW attacks 2018", "iot23-": "IoT-23 2018-19",
          "cic-1-power-": "CIC IoT 2022 power-on", "cic-2-idle-": "CIC IoT 2022 idle",
          "cic-3-interactions-": "CIC IoT 2022 interactions", "laptop-": "Laptop 2026 (not IoT)"}
VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")


def local(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def load_run(d):
    events = []
    with open(os.path.join(d, "events.jsonl")) as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not e.get("debug"):
                events.append(e)
    inv = {}
    p = os.path.join(d, "device_inventory.json")
    if os.path.exists(p):
        for dev in json.load(open(p)).get("devices") or []:
            inv[dev["ip"]] = dev
    return events, inv


def device_id(inv, ip):
    dev = inv.get(ip) or {}
    return (dev.get("mac_address") or ip).lower()


def matches(prov, e):
    if e["type"] not in prov["signals"]:
        return False
    ev = e.get("evidence") or ""
    if prov.get("require_pattern") and not re.search(prov["require_pattern"], ev):
        return False
    if prov.get("exclude_pattern") and re.search(prov["exclude_pattern"], ev):
        return False
    f = prov.get("filter", "")
    dst = e.get("dst_ip", "")
    if "server is external" in f or "destination is external" in f:
        return bool(dst) and not local(dst)
    return True


def main():
    emap, runs_dir, out_md, samples_out = sys.argv[1:5]
    provs = json.load(open(emap))["provisions"]
    exclude = set()
    if len(sys.argv) > 5:
        exclude = {l.strip().lower() for l in open(sys.argv[5]) if l.strip() and not l.startswith("#")}
    random.seed(20261017)
    seen = collections.defaultdict(set)            # group -> devices with traffic
    hit = collections.defaultdict(lambda: collections.defaultdict(set))  # group -> provision -> devices
    pool = collections.defaultdict(list)           # signal -> events (for samples)
    run_dirs = sorted(d for root in runs_dir.split(",") for d in glob.glob(os.path.join(root, "*")))
    for d in run_dirs:
        if not os.path.isdir(d) or not os.path.exists(os.path.join(d, "events.jsonl")):
            continue
        name = os.path.basename(d)
        group = next((g for p, g in GROUPS.items() if name.startswith(p)), None)
        if group is None:
            continue
        events, inv = load_run(d)
        for ip, dev in inv.items():
            if dev.get("observed_protocols") and device_id(inv, ip) not in exclude:
                seen[group].add(device_id(inv, ip))
        for e in events:
            dev_ip = e.get("device_key") or e.get("src_ip", "")
            if device_id(inv, dev_ip) in exclude or device_id(inv, dev_ip) not in seen[group]:
                continue
            for prov in provs:
                if prov["signals"] and not prov["signals"][0].startswith("identity_evidence") and matches(prov, e):
                    hit[group][prov["provision"]].add(device_id(inv, dev_ip))
                    pool[e["type"]].append({"run": name, "provision": prov["provision"], "type": e["type"],
                                            "severity": e.get("severity"), "device": dev_ip, "dst": f"{e.get('dst_ip','')}:{e.get('dst_port','')}",
                                            "evidence": (e.get("evidence") or "")[:300]})
        # identity-based signals (5.6-2): versions disclosed in discovery traffic
        for prov in provs:
            sig = [s.split(":", 1)[1] for s in prov["signals"] if s.startswith("identity_evidence:")]
            if not sig:
                continue
            for ip, dev in inv.items():
                if device_id(inv, ip) in exclude or device_id(inv, ip) not in seen[group]:
                    continue
                for ev in dev.get("identity_evidence") or []:
                    if ev.get("attribute") in sig and VERSION_RE.search(ev.get("value", "")):
                        hit[group][prov["provision"]].add(device_id(inv, ip))
                        pool["identity:" + ev["attribute"]].append({"run": name, "provision": prov["provision"], "type": ev["attribute"],
                                                                    "device": ip, "evidence": ev["value"][:200]})
    samples = {k: random.sample(v, min(15, len(v))) for k, v in pool.items()}
    json.dump(samples, open(samples_out, "w"), ensure_ascii=False, indent=1)

    groups = [g for g in GROUPS.values() if g in seen]
    L = ["# E4：違反の証拠が実際の通信に現れる率", "",
         "`scripts/assessment/evidence_rates.py` で生成。値は「証拠が 1 回以上現れた機器数 / 通信が観測された機器数」。機器は MAC で数える（同じデータセットの複数日に現れても 1 台）。",
         "状態 candidate_only の行は候補の数（上限）であり、違反の確定ではない。", "",
         "| 要件 | 状態 | " + " | ".join(groups) + " |", "|---|---|" + "---|" * len(groups),
         "| （通信が観測された機器） | | " + " | ".join(str(len(seen[g])) for g in groups) + " |"]
    for prov in provs:
        cells = []
        for g in groups:
            n = len(hit[g][prov["provision"]])
            cells.append(f"{n} ({100 * n / max(1, len(seen[g])):.0f}%)" if prov["status"] != "not_implemented" else "—")
        L.append(f"| {prov['provision']} | {prov['status']} | " + " | ".join(cells) + " |")
    open(out_md, "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
