#!/usr/bin/env python3
"""Accuracy step 4b: were the events counted for each criterion of the human
review (docs/assessment/human-review-accuracy.md) really of that criterion's
form? Every IoT event that a criterion counts is looked up, by connection,
in the independent ground truth of E11 (Zeek's gt.log, rawscan's raw.jsonl)
and confirmed or not. Only names are compared, never values.

usage: check_application.py QUARANT_RUNS GT_DIR EXCLUDE_MACS OUT_JSON
"""
import collections
import glob
import ipaddress
import json
import os
import random
import re
import sys

OLD = {"SSLv3", "TLSv10", "TLSv11"}
ORDER = ["SSLv3", "TLSv10", "TLSv11", "TLSv12", "TLSv13"]
SIG = {"aws4-hmac-sha256", "aws", "oss", "digest", "wsse"}
IDENT = {"serial", "device_id", "sonosid", "householdid", "id", "uuid", "mac"}


def private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def endpoints(flow_key):
    """'tcp|a:1<->b:2' -> frozenset({('a', 1), ('b', 2)})."""
    try:
        _, rest = flow_key.split("|", 1)
        out = []
        for side in rest.split("<->"):
            ip, port = side.rsplit(":", 1)
            out.append((ip.strip("[]"), int(port)))
        return frozenset(out)
    except ValueError:
        return None


def criterion(e):
    """The review criterion an event counts for, or None."""
    t, ev = e["type"], e.get("evidence") or ""
    if t == "I7_TLS_WEAK_VERSION_OBSERVED":
        return "T"  # T1-T4 are told apart from the ground truth below
    if t == "I7_TLS_WEAK_CIPHER_SELECTED":
        return "T6" if re.search(r"risk_kind=(rc4|3des|des|null|export|anonymous|md5)_cipher", ev) else "T5"
    if t == "INSECURE_HTTP_AUTH":
        m = re.match(r"Authorization: (\S+)", ev)
        if not m:
            return "S7"
        s = m.group(1)
        return {"Basic": "S1", "Bearer": "S7", "***": "S2"}.get(s, "S3" if s.lower() in ("aws4-hmac-sha256", "aws", "oss") else "S4")
    if t in ("INSECURE_HTTP_TOKEN", "I3_AUTH_TOKEN_IN_URL", "INSECURE_HTTP_BODY_SECRET"):
        keys = [k.lower() for k in re.findall(r"([A-Za-z0-9_.\-]+)=\*\*\*", ev)]
        if any(k in IDENT for k in keys):
            return "S8"
        if any(k == "sid" for k in keys):
            return "S6"
        if any("session" in k for k in keys):
            return "S5"
        return "S7"
    if t == "INSECURE_HTTP_COOKIE":
        return "S9"
    if t == "INSECURE_MQTT_CREDENTIALS":
        return "S10"
    if t == "INSECURE_UDP_CREDENTIALS":
        return "S11"
    if t == "INSECURE_FTP_CREDENTIALS":
        return "S17"
    if t == "INSECURE_HTTP_RESPONSE_SECRET":
        return "S13"
    if t == "I6_MEDIA_UPLOAD_CLEARTEXT":
        return "P2" if "unparsed_tcp" in ev else "P1"
    if t in ("I6_HTTP_PRIVACY_EXPOSURE", "I6_HTTP_UNEXPECTED_PII", "I6_PII_TO_UNEXPECTED_DESTINATION"):
        return "P3"
    return None


def load_gt(d):
    zeek = collections.defaultdict(list)
    p = os.path.join(d, "gt.log")
    if os.path.exists(p):
        for line in open(p):
            r = json.loads(line)
            zeek[frozenset({(r["orig_h"], r["orig_p"]), (r["resp_h"], r["resp_p"])})].append(r)
    raw = collections.defaultdict(list)
    p = os.path.join(d, "raw.jsonl")
    if os.path.exists(p):
        for line in open(p):
            r = json.loads(line)
            # rawscan keeps the destination port only; key by address pair
            raw[frozenset({r["src_ip"], r["dst_ip"]})].append(r)
    return zeek, raw


def cmax(r):
    vs = [v for v in (r.get("client_versions") or "").replace("max=", "").split(",") if v in ORDER]
    return max(vs, key=ORDER.index) if vs else None


def confirm(crit, e, eps, zeek, raw):
    """(criterion as confirmed, True/False/None). None = no independent record."""
    rows = zeek.get(eps, []) if eps else []
    ev = e.get("evidence") or ""
    if crit == "T":
        tls = [r for r in rows if r["kind"] == "tls"]
        if not tls:
            return "T", None
        for r in tls:
            v, c = r.get("version"), cmax(r)
            if v in OLD and c in OLD:
                return "T1", True
            if v in OLD and c and c not in OLD:
                server_local = private(r["resp_h"])
                return ("T3" if server_local and e.get("device_key") == r["resp_h"] else "T2"), True
            if not v and c in OLD:
                return "T4", True
        return "T", False
    if crit in ("T5", "T6"):
        tls = [r for r in rows if r["kind"] == "tls" and r.get("cipher")]
        if not tls:
            return crit, None
        name = re.search(r"cipher_suite_name=(\S+)", ev)
        return crit, any(name and r["cipher"] == name.group(1) for r in tls)
    http = [r for r in rows if r["kind"] == "http"]
    if crit in ("S1", "S2", "S3", "S4"):
        if not http:
            return crit, None
        schemes = {(r.get("auth_scheme") or "").lower() for r in http} - {""}
        want = {"S1": lambda s: s == "basic", "S3": lambda s: s in ("aws4-hmac-sha256", "aws", "oss"),
                "S4": lambda s: s in ("digest", "wsse"), "S2": lambda s: s not in SIG | {"basic", "bearer"}}[crit]
        return crit, any(want(s) for s in schemes)
    if crit in ("S5", "S6", "S7", "S8"):
        if not http:
            return crit, None
        keys = [k.lower() for k in re.findall(r"([A-Za-z0-9_.\-]+)=\*\*\*", ev)]
        names = set()
        for r in http:
            names |= {x.lower() for x in (r.get("uri_params") or []) + (r.get("req_body_keys") or []) + (r.get("req_headers") or [])}
        if re.match(r"([A-Za-z0-9\-]+): \*\*\*", ev):
            keys.append(ev.split(":")[0].lower())
        # Zeek keeps body keys only when the name looks like a secret, so an
        # identifier key in a body has no independent record.
        if not keys:
            return crit, None
        hit = any(k in names for k in keys)
        if not hit and crit == "S8" and e["type"] == "INSECURE_HTTP_BODY_SECRET":
            return crit, None
        return crit, hit
    if crit == "S9":
        if not http:
            return crit, None
        return crit, any("cookie" in (r.get("req_headers") or []) for r in http)
    if crit == "S10":
        m = [r for r in rows if r["kind"] == "mqtt"]
        return crit, (any(r.get("has_password") for r in m) if m else None)
    if crit == "S17":
        f = [r for r in rows if r["kind"] == "ftp"]
        return crit, (any(r.get("has_password") for r in f) if f else None)
    if crit == "S13":
        if not http:
            return crit, None
        keys = [k.lower() for k in re.findall(r"([A-Za-z0-9_.\-]+)=\*\*\*", ev)]
        names = {x.lower() for r in http for x in (r.get("resp_body_keys") or [])}
        return crit, (any(k in names for k in keys) if names else None)
    if crit in ("S11", "P2"):
        pair = frozenset({e.get("src_ip"), e.get("dst_ip")})
        rr = raw.get(pair, [])
        if crit == "S11":
            return crit, any(r["proto"] == "udp" and r["cls"] == "secret_key" and r["name"] in ("pwd", "password", "passwd", "pass", "token") for r in rr)
        return crit, any(r["cls"] == "media_signature" for r in rr)
    if crit == "P1":
        if not http:
            return crit, None
        return crit, any(m.split("/")[0] in ("image", "video", "audio") for r in http for m in (r.get("orig_mime") or []))
    if crit == "P3":
        if not http:
            return crit, None
        keys = [k.lower() for k in re.findall(r"([A-Za-z0-9_.\-]+)=\*\*\*", ev)]
        return crit, None if not keys else any(k in {x.lower() for r in http for x in (r.get("uri_params") or [])} for k in keys) or None
    return crit, None


def main():
    qruns, gtdir, excl, out_json = sys.argv[1:5]
    exclude = {l.strip().lower() for l in open(excl) if l.strip() and not l.startswith("#")}
    random.seed(20261018)
    stats = collections.defaultdict(lambda: collections.Counter())
    devices = collections.defaultdict(lambda: collections.defaultdict(set))
    unconfirmed = collections.defaultdict(list)
    for d in sorted(glob.glob(os.path.join(qruns, "*", "events.jsonl"))):
        d = os.path.dirname(d)
        run = os.path.basename(d)
        g = os.path.join(gtdir, run)
        if not os.path.exists(os.path.join(g, "done")):
            continue
        inv = {}
        p = os.path.join(d, "device_inventory.json")
        if os.path.exists(p):
            for dev in json.load(open(p)).get("devices") or []:
                inv[dev["ip"]] = (dev.get("mac_address") or "").lower()
        zeek, raw = load_gt(g)
        for line in open(os.path.join(d, "events.jsonl")):
            if '"debug":true' in line:
                continue
            e = json.loads(line)
            crit = criterion(e)
            mac = inv.get(e.get("device_key"), "")
            if not crit or not mac or mac in exclude:
                continue
            got, ok = confirm(crit, e, endpoints(e.get("flow_key") or ""), zeek, raw)
            state = {True: "confirmed", False: "not_confirmed", None: "no_record"}[ok]
            stats[got][state] += 1
            devices[got][state].add(mac)
            if ok is False:
                unconfirmed[got].append({"run": run, "mac": mac, "type": e["type"], "dst": f"{e.get('dst_ip')}:{e.get('dst_port')}",
                                         "evidence": re.sub(r"=[^ &]*", "=…", e.get("evidence") or "")[:120]})
    out = {c: {"events": dict(s), "devices": {k: len(v) for k, v in devices[c].items()},
               "unconfirmed_sample": random.sample(unconfirmed[c], min(8, len(unconfirmed[c])))} for c, s in stats.items()}
    json.dump(out, open(out_json, "w"), ensure_ascii=False, indent=1)
    for c in sorted(out):
        o = out[c]
        print(f"{c:4s} events {o['events']}  devices {o['devices']}")


if __name__ == "__main__":
    main()
