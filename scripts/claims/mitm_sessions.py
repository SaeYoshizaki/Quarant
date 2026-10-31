#!/usr/bin/env python3
"""TLS sessions in which the server showed the dataset authors' own test certificate.

Usage: mitm_sessions.py <devices.tsv> <dataset> <flows dir> <issuer substring> <out.tsv>

YourThings ran man-in-the-middle tests during the capture (Alrawi et al.,
S&P 2019): a proxy answered some TLS connections with a certificate issued
by "thing-catcher.gtisc.gatech.edu". Those sessions are with the proxy, not
with the vendor's server, so their version, cipher and key say nothing about
the vendor; observations.py leaves them out. They also show, passively, how
each device reacted to a forged certificate:
- client-alert: the device sent a TLS alert during the handshake (rejected it);
- handshake-only: no alert, but the device sent no application-data record
  (it may have checked the certificate after the handshake, or closed);
- data-sent: the device sent application-data records after the handshake
  (it went on using the connection, so it likely accepted the certificate).
  Records are counted by tls_records.zeek (content type 23); their contents
  are encrypted and not known.
Writes one row per session, with addresses and counts only.
"""
import csv
import json
import sys
from pathlib import Path


def jsonl(path):
    if path.exists():
        for line in open(path):
            yield json.loads(line)


def main():
    devices_tsv, dataset, flows_dir, issuer, out = sys.argv[1:6]
    label = {r["mac"]: r["label"] for r in csv.DictReader(open(devices_tsv), delimiter="\t")
             if r["dataset"] == dataset and r["mac"] not in ("", "-")}
    with open(out, "w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["day", "mac", "label", "ts", "orig_h", "orig_p", "resp_h", "resp_p", "sni", "version",
                    "established", "outcome", "client_records", "client_record_bytes", "server_records"])
        for day in sorted(p for p in Path(flows_dir).iterdir() if (p / "done").exists()):
            conn = {c["uid"]: c for c in jsonl(day / "conn.log") if c.get("orig_l2_addr") in label}
            recs = {r["uid"]: r for r in jsonl(day / "tls_records.log")}
            fake = {x["fingerprint"] for x in jsonl(day / "x509.log") if issuer in x.get("certificate.issuer", "")}
            for s in jsonl(day / "ssl.log"):
                c = conn.get(s["uid"])
                fps = s.get("cert_chain_fps") or []
                if not c or not fps or fps[0] not in fake:
                    continue
                r = recs.get(s["uid"], {})
                n = r.get("client_records", 0)
                outcome = "client-alert" if "L" in s.get("ssl_history", "") and not n else \
                    "data-sent" if n else "handshake-only"
                w.writerow([day.name, c["orig_l2_addr"], label[c["orig_l2_addr"]], s["ts"], s["id.orig_h"],
                            s["id.orig_p"], s["id.resp_h"], s["id.resp_p"], s.get("server_name") or "",
                            s.get("version", ""), s.get("established", False), outcome, n, r.get("client_bytes", 0),
                            r.get("server_records", 0)])


if __name__ == "__main__":
    main()
