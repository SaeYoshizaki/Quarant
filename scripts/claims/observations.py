#!/usr/bin/env python3
"""Summarise, per device, what a passive observer saw that claims can be checked against.

Usage: observations.py <devices.tsv> <dataset> <zeek gt dir> <quarant runs dir> <out.json>

Reads the Zeek ground-truth records (gt.log: TLS version/cipher/SNI, HTTP request
shape without values, FTP) and the Quarant events of each run, and groups them by
the MAC addresses listed for <dataset> in devices.tsv. Only names and counts are
kept, never values, so the output can be shared.
"""
import collections
import csv
import json
import sys
from pathlib import Path

# Quarant events that bear on claim types T3 (credentials), T4 (media), T5 (updates).
QUARANT_TYPES = {
    "INSECURE_HTTP_AUTH": "T3", "INSECURE_HTTP_TOKEN": "T3", "INSECURE_FTP_CREDENTIALS": "T3",
    "INSECURE_MQTT_CREDENTIALS": "T3", "INSECURE_TELNET": "T3", "INSECURE_UDP_CREDENTIALS": "T3",
    "I6_MEDIA_UPLOAD_CLEARTEXT": "T4", "I6_MEDIA_CLEARTEXT_TCP": "T4",
    "INSECURE_HTTP_COOKIE": "T3", "INSECURE_HTTP_RESPONSE_SECRET": "T3", "I3_AUTH_TOKEN_IN_URL": "T3",
    "I4_FIRMWARE_UPDATE_OBSERVED": "T5", "I4_INSECURE_FIRMWARE_UPDATE_HTTP": "T5", "I4_WEAK_UPDATE_VISIBILITY": "T5",
}


def pfs(cipher):
    return cipher.startswith(("TLS_ECDHE_", "TLS_DHE_")) or cipher.startswith("TLS_AES_") or cipher.startswith("TLS_CHACHA20")


def lan(ip):
    return ip.startswith(("192.168.", "10.", "172.16.", "169.254.", "224.", "239.", "255.")) or ip.startswith("ff") or ip.startswith("fe80")


def main():
    devices_tsv, dataset, gt_dir, runs_dir, out = sys.argv[1:6]
    macs = {}
    for r in csv.DictReader(open(devices_tsv), delimiter="\t"):
        if r["dataset"] == dataset and r["mac"] not in ("", "-"):
            macs[r["mac"].lower()] = f"{r['vendor']} {r['product']}"
    obs = {m: {"product": p, "tls": collections.Counter(), "tls_no_handshake": 0, "sni": collections.Counter(),
               "http": collections.Counter(), "ftp": collections.Counter(), "quarant": collections.Counter(),
               "days": set()} for m, p in macs.items()}

    for log in sorted(Path(gt_dir).glob("*/gt.log")):
        day = log.parent.name
        for line in open(log):
            e = json.loads(line)
            o = obs.get((e.get("orig_mac") or "").lower())
            if not o:
                continue
            o["days"].add(day)
            if e["kind"] == "tls":
                if e.get("cipher"):
                    o["tls"][(e.get("version"), e["cipher"], "pfs" if pfs(e["cipher"]) else "no-pfs")] += 1
                else:
                    o["tls_no_handshake"] += 1
                o["sni"][e.get("sni") or "-"] += 1
            elif e["kind"] == "http":
                where = "lan" if lan(e["resp_h"]) else "external"
                auth = "authorization" in (e.get("req_headers") or [])
                o["http"][(where, e.get("method"), e.get("host") if where == "external" else "lan", e.get("resp_p"),
                           ",".join(e.get("uri_params") or []), "body" if e.get("req_body_len", 0) > 0 else "no-body",
                           "auth-header" if auth else "")] += 1
            elif e["kind"] == "ftp":
                o["ftp"][("lan" if lan(e["resp_h"]) else "external", "user" if e.get("has_username") else "",
                          "pass" if e.get("has_password") else "")] += 1

    ip2mac = {}
    for inv in sorted(Path(runs_dir).glob("*/device_inventory.json")):
        for d in json.loads(inv.read_text()).get("devices", []):
            if (d.get("mac_address") or "").lower() in obs:
                ip2mac[(inv.parent.name, d["ip"])] = d["mac_address"].lower()
    for ev_file in sorted(Path(runs_dir).glob("*/events.jsonl")):
        run = ev_file.parent.name
        for line in open(ev_file):
            e = json.loads(line)
            if e.get("type") not in QUARANT_TYPES:
                continue
            mac = ip2mac.get((run, e.get("src_ip")))
            if mac:
                obs[mac]["quarant"][(e["type"], "lan" if lan(e.get("dst_ip") or "") else "external")] += 1

    result = []
    for mac, o in obs.items():
        result.append({
            "mac": mac, "product": o["product"], "days": sorted(o["days"]),
            "tls": [{"version": k[0], "cipher": k[1], "forward_secrecy": k[2] == "pfs", "count": n} for k, n in o["tls"].most_common()],
            "tls_no_handshake": o["tls_no_handshake"],
            "sni": dict(o["sni"].most_common(10)),
            "http": [{"scope": k[0], "method": k[1], "host": k[2], "port": k[3], "params": k[4], "body": k[5] == "body",
                      "auth_header": bool(k[6]), "count": n} for k, n in o["http"].most_common(15)],
            "http_total": sum(o["http"].values()),
            "ftp": [{"scope": k[0], "username": bool(k[1]), "password": bool(k[2]), "count": n} for k, n in o["ftp"].items()],
            "quarant": [{"type": k[0], "claim_type": QUARANT_TYPES[k[0]], "scope": k[1], "count": n} for k, n in o["quarant"].most_common()],
        })
    json.dump(result, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
