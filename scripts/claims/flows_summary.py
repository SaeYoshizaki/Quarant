#!/usr/bin/env python3
"""Per product: all flows by label (flowscan.py) and the server certificate keys (Zeek).

Usage: flows_summary.py <devices.tsv> <dataset> <flows dir> <out.json> [<excluded peer IP>,...] [<test issuer>]

<flows dir> holds one directory per day from run_flows.sh (flows.jsonl,
conn.log, ssl.log, x509.log). Certificates are visible only in TLS 1.2 and
earlier; in TLS 1.3 they are encrypted. Client certificates (the device's
own key) are counted apart. Only counts and labels are written.

Flows with an excluded peer are left out: in YourThings, 192.168.0.200 (a
Docker host of the collection setup, MAC 02:42:c0:a8:00:c8) port-scanned
every device twice on 2018-03-20; those flows are the scanner's, not the
devices' own behaviour. They are counted under "excluded_flows".
Server certificates whose issuer contains <test issuer> (the dataset
authors' man-in-the-middle proxy, see mitm_sessions.py) are counted as
"test proxy", not by their key.
"""
import collections
import csv
import json
import sys
from pathlib import Path

# Plaintext by design and not about the product's own data; kept apart from the rest.
NETWORK = {"dns", "mdns", "ntp", "dhcp", "netbios", "llmnr", "ssdp"}


def jsonl(path):
    if path.exists():
        for line in open(path):
            yield json.loads(line)


def main():
    devices_tsv, dataset, flows_dir, out = sys.argv[1:5]
    excluded = set(sys.argv[5].split(",")) if len(sys.argv) > 5 else set()
    test_issuer = sys.argv[6] if len(sys.argv) > 6 else None
    prod = {}
    for r in csv.DictReader(open(devices_tsv), delimiter="\t"):
        if r["dataset"] == dataset and r["mac"] not in ("", "-"):
            prod[r["mac"]] = f"{r['vendor']} {r['product']}"
    res = collections.defaultdict(lambda: {"macs": set(), "flows": collections.Counter(), "bytes": collections.Counter(),
                                           "certs": collections.Counter(), "client_certs": collections.Counter(), "tls_versions": collections.Counter(),
                                           "excluded_flows": 0})
    for day in sorted(p for p in Path(flows_dir).iterdir() if (p / "done").exists()):
        for r in jsonl(day / "flows.jsonl"):
            p = res[prod[r["mac"]]]
            p["macs"].add(r["mac"])
            if r["peer_ip"] in excluded:
                p["excluded_flows"] += r["flows"]
                continue
            scope = "external" if r["external"] else "lan"
            key = f"{scope}|{r['role']}|{r['proto']}/{r['port']}|{r['kind']}|{r['class']}"
            p["flows"][key] += r["flows"]
            p["bytes"][key] += r["bytes"]
        mac_of = {}
        for c in jsonl(day / "conn.log"):
            m = c.get("orig_l2_addr")
            if m in prod and c["id.resp_h"] not in excluded:
                mac_of[c["uid"]] = m
        keys = {x["fingerprint"]: ("test", "proxy") if test_issuer and test_issuer in x.get("certificate.issuer", "")
                else (x.get("certificate.key_type"), x.get("certificate.key_length"))
                for x in jsonl(day / "x509.log") if x.get("host_cert") or x.get("client_cert")}
        for s in jsonl(day / "ssl.log"):
            m = mac_of.get(s["uid"])
            if not m:
                continue
            p = res[prod[m]]
            p["tls_versions"][s.get("version", "?")] += 1
            fps = s.get("cert_chain_fps") or []
            if fps and fps[0] in keys:
                t, n = keys[fps[0]]
                p["certs"][f"{t}-{n}"] += 1
            elif s.get("version") == "TLSv13":
                p["certs"]["hidden (TLS 1.3)"] += 1
            elif s.get("resumed"):
                p["certs"]["none (resumed)"] += 1
            else:
                p["certs"]["not seen"] += 1
            # the device's own certificate, if it authenticates with one
            cfps = s.get("client_cert_chain_fps") or []
            if cfps and cfps[0] in keys:
                t, n = keys[cfps[0]]
                p["client_certs"][f"{t}-{n}"] += 1
    rows = []
    for name, p in sorted(res.items()):
        rows.append({"product": name, "macs": sorted(p["macs"]), "flows": dict(p["flows"]), "bytes": dict(p["bytes"]),
                     "certs": dict(p["certs"]), "client_certs": dict(p["client_certs"]), "tls_versions": dict(p["tls_versions"]),
                     "excluded_flows": p["excluded_flows"]})
    json.dump(rows, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
