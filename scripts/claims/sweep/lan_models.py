#!/usr/bin/env python3
"""What each device says about itself on the LAN: model strings from its UPnP description, mDNS names and TXT
records, and DHCP host name and vendor class. Reads only the frames expose.py already found (one per device and kind).

usage: lan_models.py <devices.tsv> <sweep dir> <raw dir> <out.tsv> [dataset...]

YourThings and UNSW 2016 are left out (their captures are archives). Values are printed as they are; these are
identifiers, not credentials.
"""
import collections
import concurrent.futures
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

SOURCES = {
    "iotraffic": ["unsw-iotraffic/pcaps"],
    "unsw2018": ["unsw-iot-2018/benign"],
    "cic2022": ["cic-iot-2022/1-Power", "cic-iot-2022/2-Idle", "cic-iot-2022/3-Interactions",
                "cic-iot-2022/4-Scenarios", "cic-iot-2022/2021_11_02_Active.pcap"],
    "deakin": ["deakin-iot/pcapFull"],
    "iot23": ["iot-23-benign"],
    "pms": ["passive-mode-2025/Percom116Dataset", "passive-mode-2025/ExtendedPaperDataset"],
}
KINDS = ("upnp", "mdns_name", "mdns_txt", "dhcp_hostname", "dhcp")
UPNP = ("modelName", "modelNumber", "modelDescription", "friendlyName", "manufacturer")


def resolve(raw, ds, name):
    """expose.py names a file <source basename>__<path below it with / as __>."""
    for s in SOURCES[ds]:
        src = Path(raw) / s
        if name == src.name:
            return src
        if name.startswith(src.name + "__"):
            return src / name[len(src.name) + 2:].replace("__", "/")
    return None


def read(path, frame):
    out = subprocess.run(["tshark", "-r", str(path), "-c", str(frame), "-Y", f"frame.number == {frame}", "-T", "fields",
                          "-E", "separator=\t", "-e", "dns.resp.name", "-e", "dns.txt", "-e", "dhcp.option.hostname",
                          "-e", "dhcp.option.vendor_class_id", "-e", "http.file_data", "-e", "tcp.payload"],
                         capture_output=True, text=True).stdout
    vals = []
    for line in out.splitlines():
        names, txt, host, vclass, data, payload = (line.split("\t") + [""] * 6)[:6]
        body = data or payload
        if body and re.fullmatch(r"[0-9a-fA-F:]+", body):
            body = bytes.fromhex(body.replace(":", "")).decode("latin-1")
        for tag in UPNP:
            for v in re.findall(rf"<{tag}>([^<]{{1,120}})</{tag}>", body or ""):
                vals.append(f"{tag}={v.strip()}")
        for n in names.split(","):
            if n and not n.endswith((".arpa", "_services._dns-sd._udp.local")):
                vals.append(f"mdns={n}")
        for t in txt.split(","):
            if re.match(r"(md|model|mdl|ty|fn|am|product|usb_MDL|serialNumber)=", t, re.I):
                vals.append(f"txt:{t}")
        if host:
            vals.append(f"dhcp_hostname={host}")
        if vclass:
            vals.append(f"dhcp_vendor_class={vclass}")
    return list(dict.fromkeys(vals))


def main():
    devices, sweep, raw, out = sys.argv[1:5]
    only = set(sys.argv[5:]) or set(SOURCES)
    devs = {(d["dataset"], d["mac"].lower()): d for d in csv.DictReader(open(devices), delimiter="\t")
            if d["dataset"] in only and d["dataset"] in SOURCES}
    first = {}
    for ds in sorted({k[0] for k in devs}):
        for f in sorted(Path(sweep, ds).glob("*.jsonl")):
            for line in open(f):
                if '"kind": "upnp' not in line and '"kind": "mdns' not in line and '"kind": "dhcp' not in line:
                    continue
                r = json.loads(line)
                kind = r["kind"].split(":")[0]
                key = (ds, r["dev"].lower(), kind)
                if kind in KINDS and key[:2] in devs and r.get("frame") and key not in first:
                    first[key] = (r["file"], int(r["frame"]))
    jobs = {}
    for (ds, mac, kind), (name, frame) in first.items():
        path = resolve(raw, ds, name)
        if path and path.exists():
            jobs[(ds, mac, kind)] = (path, frame, name)
    found = collections.defaultdict(list)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:  # the external disk is the bottleneck
        futs = {ex.submit(read, p, fr): k for k, (p, fr, _) in jobs.items()}
        for fut in concurrent.futures.as_completed(futs):
            ds, mac, kind = futs[fut]
            found[(ds, mac)].append((kind, jobs[futs[fut]][2], jobs[futs[fut]][1], fut.result()))
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh, delimiter="\t")
        w.writerow(["dataset", "mac", "label", "vendor", "product", "model", "kind", "file", "frame", "values"])
        for (ds, mac), d in sorted(devs.items()):
            for kind, name, frame, vals in sorted(found.get((ds, mac), [])):
                w.writerow([ds, mac, d["label"], d["vendor"], d["product"], d["model"], kind, name, frame, "; ".join(vals)])
    print(len(jobs), "frames read,", len(found), "devices")


if __name__ == "__main__":
    main()
