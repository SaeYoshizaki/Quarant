#!/usr/bin/env python3
"""Run verify.py for every candidate of one prior-work class and collect the output.

usage: verify_all.py <devices.tsv> <prior-ids.tsv> <class> <sweep dir> <out.txt> <capture root>...

For each candidate, the capture to open is chosen from the expose.py records in <sweep dir>: a capture
file that holds the same field and server (or, for id-other, the device's MAC on the same port; for
fw-http, the same download) and that is found under one of the roots, preferring UNSW-IoTraffic, CIC
and Deakin, then the file with the most occurrences. For a field that matched a LAN value, the LAN
value is read from a capture where the device announced it. Candidates without a capture at hand are
listed as skipped.
"""
import collections
import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREFER = ["iotraffic", "cic2022", "deakin", "unsw2016", "yourthings"]


def finder(roots):
    index = {}
    for r in roots:
        for p in Path(r).rglob("*"):
            if p.is_file():
                index.setdefault(p.name, str(p))
    return index


def path_of(index, ds, name):
    base = {"cic2022": name.split("__")[-1], "iotraffic": name.replace("pcaps__", ""),
            "deakin": name.replace("pcapFull__", "")}.get(ds, name)
    return index.get(base)


def main():
    devices_tsv, prior, cls, sweep, out, *roots = sys.argv[1:]
    index = finder(roots)
    devs = collections.defaultdict(dict)
    for r in csv.DictReader(open(devices_tsv), delimiter="\t"):
        devs[(r["vendor"], " ".join(x for x in (r["product"], r["model"]) if x) or r["label"])][r["dataset"]] = r["mac"].lower()
    rows = [r for r in csv.DictReader(open(prior), delimiter="\t", quoting=csv.QUOTE_NONE) if r["class"] == cls]
    wanted = {(ds, mac) for r in rows for ds, mac in devs[(r["vendor"], r["product"])].items()}
    recs = collections.defaultdict(list)
    for ds in {d for d, _ in wanted}:
        for jf in Path(sweep, ds).glob("*.jsonl"):
            for line in open(jf):
                x = json.loads(line)
                if (ds, x.get("dev")) in wanted and x["r"] in ("field", "macout", "dl", "ident"):
                    recs[(ds, x["dev"], x["r"])].append(x)
    with open(out, "w") as o:
        for r in rows:
            first = r["detail"].split("; ")[0]
            head = f'### {r["vendor"]} {r["product"]} | {r["kind"]} | {first}'
            choice = None
            for ds in PREFER:
                mac = devs[(r["vendor"], r["product"])].get(ds)
                if not mac or ds not in r["datasets"]:
                    continue
                if r["kind"] in ("id-plain", "cred-plain"):
                    m = re.match(r"(.+?)(?:=(.+?))? -> (\S+) \(\d+\)$", first)
                    key, what, host = m.group(1), m.group(2) or "", m.group(3)
                    cands = [x for x in recs[(ds, mac, "field")] if x["key"] == key and
                             ((x["host"] or x["peer"]) if ":" in (x["host"] or x["peer"]) else f'{x["host"] or x["peer"]}:{x["port"]}') == host]
                    if what == "MAC":
                        cands = [x for x in cands if x["mac"]] or cands
                    hostarg = host[:-3] if host.endswith(":80") else host
                    keyarg = "h:authorization" if key.startswith("h:authorization") else key
                    lan = None
                    if what.startswith(("upnp:", "mdns_txt:", "mdns_name")):
                        lan_kind = "upnp" if what.startswith("upnp:") else what
                        ids = [path_of(index, ds, x["file"]) for x in recs[(ds, mac, "ident")] if x["kind"] == what]
                        ids = [p for p in ids if p]
                        lan = (lan_kind, ids[0] if ids else None)
                    make = lambda p, x: ["http", p, mac, hostarg, keyarg] + ([f"{lan[0]}@{lan[1]}" if lan[1] and lan[1] != p else lan[0]] if lan else [])
                elif r["kind"] == "id-other":
                    m = re.search(r"in (tcp|udp)/(\d+) payload", first)
                    cands = [x for x in recs[(ds, mac, "macout")] if x["proto"] == m.group(1) and str(x["port"]) == m.group(2)]
                    make = lambda p, x: ["payload", p, mac, str(x["frame"])]
                else:
                    cands = [x for x in recs[(ds, mac, "dl")] if (x["host"] or x["peer"]) in first]
                    make = lambda p, x: ["dl", p, mac, str(x["frame"])]
                for x in sorted(cands, key=lambda x: -x["n"]):
                    p = path_of(index, ds, x["file"])
                    if p:
                        choice = (ds, x, make(p, x))
                        break
                if choice:
                    break
            if not choice:
                o.write(head + "\n  skipped: no capture at hand that holds it\n\n")
                continue
            ds, x, args = choice
            env = {**os.environ, "VERIFY_DECODE": f'tcp.port=={x["port"]},http'} if args[0] == "http" and x.get("port") not in (80, None) else os.environ
            p = subprocess.run([sys.executable, str(HERE / "verify.py"), *args], capture_output=True, text=True, env=env)
            o.write(f'{head}\n  evidence {ds}:{x["file"]}#{x["frame"]}\n{p.stdout}{p.stderr[-300:]}\n')
            o.flush()
            print(head[:100], "done", flush=True)


if __name__ == "__main__":
    main()
