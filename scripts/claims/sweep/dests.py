#!/usr/bin/env python3
"""Public servers each product talks to, by name, marked against the Disconnect tracker list.

usage: dests.py <devices.tsv> <sweep dir> <disconnect services.json> <out dir> [dataset...]

Reads the "dest" records of expose.py (server names from the TLS SNI, the HTTP Host header or the
device's own DNS answers) and writes:
  dests.tsv     one line per product, device and server name: flows, bytes, payload kinds, how the
                name was found, the Disconnect company and category when the name or one of its
                parent domains is listed, and the first evidence
  trackers.tsv  only the names listed in the categories Advertising, Analytics, Social,
                FingerprintingInvasive or FingerprintingGeneral
The Disconnect list (github.com/disconnectme/disconnect-tracking-protection, services.json) names
companies; whether a listed company is the product's own maker is left to the reader.
"""
import collections
import csv
import json
import sys
from pathlib import Path

TRACKING = {"Advertising", "Analytics", "Social", "FingerprintingInvasive", "FingerprintingGeneral"}


def load_disconnect(path):
    out = {}
    for cat, entries in json.load(open(path))["categories"].items():
        for e in entries:
            for company, sites in e.items():
                for _, domains in sites.items():
                    if isinstance(domains, list):
                        for d in domains:
                            out.setdefault(d.lower(), set()).add((company, cat))
    return out


def lookup(name, listed):
    parts = name.split(".")
    for i in range(len(parts) - 1):
        hit = listed.get(".".join(parts[i:]))
        if hit:
            return ".".join(parts[i:]), hit
    return None, set()


def main():
    devices, sweep, services, out = sys.argv[1:5]
    only = set(sys.argv[5:])
    listed = load_disconnect(services)
    names = {}
    for r in csv.DictReader(open(devices), delimiter="\t"):
        names[(r["dataset"], r["mac"].lower())] = " ".join(x for x in (r["vendor"], r["product"], r["model"]) if x)
    agg = {}
    for dsdir in sorted(p for p in Path(sweep).iterdir() if p.is_dir()):
        ds = dsdir.name
        if (only and ds not in only) or not any(k[0] == ds for k in names):
            continue
        for jf in sorted(dsdir.glob("*.jsonl")):
            for line in open(jf):
                if '"r": "dest"' not in line:
                    continue
                r = json.loads(line)
                key = (ds, r["dev"], r["name"])
                a = agg.setdefault(key, {"flows": 0, "bytes": 0, "kinds": collections.Counter(), "how": set(),
                                         "file": r["file"], "frame": r["frame"]})
                a["flows"] += r["flows"]
                a["bytes"] += r["bytes"]
                a["kinds"][f'{r["proto"]}/{r["port"]} {r["kind"]}'] += r["bytes"]
                a["how"].add(r["how"])
    Path(out).mkdir(parents=True, exist_ok=True)
    cols = ["dataset", "product", "mac", "name", "how", "flows", "bytes", "kinds", "listed_domain", "company",
            "category", "first_file", "first_frame"]
    with open(f"{out}/dests.tsv", "w") as fa, open(f"{out}/trackers.tsv", "w") as ft:
        wa, wt = csv.writer(fa, delimiter="\t", lineterminator="\n"), csv.writer(ft, delimiter="\t", lineterminator="\n")
        wa.writerow(cols)
        wt.writerow(cols)
        for (ds, dev, name), a in sorted(agg.items(), key=lambda kv: (kv[0][0], names.get(kv[0][:2], ""), -kv[1]["bytes"])):
            dom, hit = (None, set()) if name.replace(".", "").replace(":", "").isalnum() and name[0].isdigit() \
                else lookup(name, listed)
            row = [ds, names.get((ds, dev), dev), dev, name, ",".join(sorted(a["how"])), a["flows"], a["bytes"],
                   "; ".join(f"{k}:{v}" for k, v in a["kinds"].most_common(3)), dom or "",
                   ",".join(sorted({c for c, _ in hit})), ",".join(sorted({t for _, t in hit})), a["file"], a["frame"]]
            wa.writerow(row)
            if {t for _, t in hit} & TRACKING:
                wt.writerow(row)


if __name__ == "__main__":
    main()
