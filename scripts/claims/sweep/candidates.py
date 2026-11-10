#!/usr/bin/env python3
"""One line per product and kind of problem, from the report.py tables, for the prior-work check.

usage: candidates.py <devices.tsv> <report dir> <out.tsv>

Kinds:
  id-plain   an identifier of the device (its MAC, a value it announced on the LAN, or a field named
             like an identifier whose value stayed the same) sent in plaintext to a public address
  id-other   the device's MAC inside a payload that is not HTTP (custom protocols, SIP, UDP)
  cred-plain a credential-like field (Authorization, auth, token, password) sent in plaintext
  fw-http    a download of 1 MB or more, or of a binary type, over plaintext HTTP from a firmware-like path
  tls-old    TLS 1.0/1.1 chosen with a public server, or the device offered nothing newer
  tls-weak   RC4, DES, export, NULL or anonymous suites offered or chosen (3DES alone is left out)
  tls-nofs   no handshake with a public server used forward secrecy
  tls-cert   a public server certificate with an RSA key under 2048 bits, SHA-1/MD5, self-signed or expired
Products are matched across datasets by vendor and product name.
"""
import collections
import csv
import re
import sys
from pathlib import Path

FW = re.compile(r"(?i)fw|firm|update|upgrade|ota|\.bin|\.img|\.upd|\.pkg|\.pup|\.rom|\.hex|\.tar|\.gz|\.zip|/image")
REQ_ID = re.compile(r"(?i)request|session|playback|nonce|guid$|^q:guid|cookie:")


def rows(p):
    return list(csv.DictReader(open(p), delimiter="\t", quoting=csv.QUOTE_NONE))


def main():
    devices_tsv, rdir, out = sys.argv[1:4]
    names = {}
    for r in rows(devices_tsv):
        names[(r["dataset"], r["mac"].lower())] = (r["vendor"], " ".join(x for x in (r["product"], r["model"]) if x) or r["label"])
    cand = collections.defaultdict(lambda: {"items": collections.Counter(), "n": 0, "datasets": set(), "ev": []})

    def add(ds, mac, kind, item, n, ev):
        vendor, product = names.get((ds, mac), ("", mac))
        c = cand[(vendor, product, kind)]
        c["items"][item] += int(n or 0)
        c["n"] += int(n or 0)
        c["datasets"].add(ds)
        c["ev"].append(f'{ds}:{ev}')

    for r in rows(Path(rdir) / "ids.tsv"):
        cats, ev = set(r["cats"].split(",")), f'{r["first_file"]}#{r["first_frame"]}'
        host = r["where"].split(" ")[0]
        stable = int(r["values"]) <= 2 or int(r["values"]) * 4 <= int(r["count"])
        if "id-mac" in cats or "id-lan" in cats or ("id-key" in cats and stable and not REQ_ID.search(r["key"])):
            if "id-lan" in cats and "id-mac" not in cats and "id-key" not in cats and r["key"] in ("q:model",):
                continue
            what = "MAC" if "id-mac" in cats else (r["lan_ids"] or "named " + r["key"])
            add(r["dataset"], r["mac"], "id-plain", f'{r["key"]}={what} -> {host}', r["count"], ev)
        if "cred" in cats and not r["key"].startswith("cookie:"):
            add(r["dataset"], r["mac"], "cred-plain", f'{r["key"]} -> {host}', r["count"], ev)
    for r in rows(Path(rdir) / "findings.tsv"):
        if r["cat"] == "id-mac" and "payload" in r["detail"] and not re.search(r"in tcp/(80|8080|8899) payload", r["detail"]):
            add(r["dataset"], r["mac"], "id-other", re.sub(r" -> .*", "", r["detail"]), r["count"], f'{r["first_file"]}#{r["first_frame"]}')
    for r in rows(Path(rdir) / "dl.tsv"):
        size = int(r["size"] or 0)
        if FW.search(r["path"] or "") and (size >= 1_000_000 or "octet" in r["ctype"]):
            add(r["dataset"], r["mac"], "fw-http", f'{r["host"]}{r["path"]} ({size} B)', r["count"], f'{r["first_file"]}#{r["first_frame"]}')
    for r in rows(Path(rdir) / "findings.tsv"):
        if not r["cat"].startswith("tls-") or not r["detail"].startswith("client-public"):
            continue
        d = r["detail"].split(": ", 1)[1]
        ev = f'{r["first_file"]}#{r["first_frame"]}'
        if r["cat"] == "tls-version":
            add(r["dataset"], r["mac"], "tls-old", d, r["count"], ev)
        elif r["cat"] == "tls-suite":
            weak = set(re.sub(r"^(offered|chosen) ", "", d).split("+")) - {"3des", "md5"} if d.startswith("offered") else {d}
            if d.startswith("chosen") or weak:
                add(r["dataset"], r["mac"], "tls-weak", d, r["count"], ev)
        elif r["cat"] == "tls-cert":
            add(r["dataset"], r["mac"], "tls-cert", d, r["count"], ev)
    # forward secrecy: only when no handshake with a public server chose it
    for r in rows(Path(rdir) / "tls.tsv"):
        if r["side"] == "client-public" and r["chosen_fs"] and "True" not in r["chosen_fs"]:
            add(r["dataset"], r["mac"], "tls-nofs", r["top_suites"], r["handshakes"], f'{r["first_file"]}#{r["first_frame"]}')

    with open(out, "w") as o:
        o.write("vendor\tproduct\tkind\tdatasets\tcount\tdetail\tevidence\n")
        for (vendor, product, kind), c in sorted(cand.items()):
            detail = "; ".join(f"{k} ({v})" for k, v in c["items"].most_common(6))
            o.write(f'{vendor}\t{product}\t{kind}\t{",".join(sorted(c["datasets"]))}\t{c["n"]}\t{detail}\t{"; ".join(sorted(set(c["ev"]))[:3])}\n')
    kinds = collections.Counter(k[2] for k in cand)
    print(len(cand), "candidates in", len({k[:2] for k in cand}), "products:", dict(kinds))


if __name__ == "__main__":
    main()
