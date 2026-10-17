#!/usr/bin/env python3
"""Accuracy step 1: compare Quarant's evidence with the independent ground
truth (run_gt.sh) device by device, and list what Quarant missed.

Devices are identified by MAC inside each run (device_inventory.json gives
Quarant's IP -> MAC; the ground truth carries MACs itself), never by IP
across runs. Non-IoT hosts (EXCLUDE_MACS) are left out, as in E4.

Ground-truth classes (what the standard asks about, not how Quarant finds it):
  tls      a TLS session of the device whose selected version (or, without a
           ServerHello, the client's highest offered version) is TLS 1.1 or
           older, or whose selected suite is broken (RC4, DES, 3DES, NULL,
           EXPORT, anonymous, MD5). Same definition as 5.5-1 in evidence-map.
  csp      a credential or token in cleartext: an Authorization header with a
           reusable scheme (Basic, Bearer, token, ...; per-request signatures
           such as AWS SigV4 and Alibaba OSS are listed apart), a header, URL
           parameter or body key named like a secret, an MQTT CONNECT with a
           password, an FTP PASS, or a login prompt answered on a cleartext
           channel. Name matches are candidates; the report lists them for
           review.
  media    an image, video or audio body sent by the device to a public
           address over cleartext (Zeek's content sniffing of HTTP bodies, or
           a media signature / Content-Type in a raw packet).
The Quarant side uses evidence-map.json exactly as evidence_rates.py does.

With JUDGMENTS (docs/assessment/miss-judgments.json) the script also prints
the judged result: candidates judged "real" form the ground truth, "not" and
"undecided" ones are left out, and candidates without a judgment are listed
as unjudged so that a re-measurement cannot silently count them.

usage: compare_misses.py EVIDENCE_MAP QUARANT_RUNS GT_DIR EXCLUDE_MACS OUT_JSON [JUDGMENTS]
"""
import collections
import glob
import ipaddress
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "assessment"))
import evidence_rates as er  # noqa: E402

OLD_TLS = {"SSLv2", "SSLv3", "TLSv10", "TLSv11"}
BROKEN = re.compile(r"RC4|_DES_|DES40|3DES|_NULL_|EXPORT|_anon_|_MD5")
SIG_SCHEMES = {"aws4-hmac-sha256", "aws", "oss", "digest"}
SECRET = re.compile(r"pass|pwd|token|secret|api_?key|apikey|auth|session|^sid$|sign")
# Header names that match SECRET but carry no secret by definition. SID is the
# UPnP GENA subscription identifier (UPnP Device Architecture 4.1).
BENIGN_HEADERS = {"www-authenticate", "proxy-authenticate", "authentication-info", "sid"}
HTTP_PORTS = {80, 8000, 8080, 8888}
TLS_PORTS = {443, 8443, 8883, 993, 995, 5223, 5228, 9443, 10443}
# Quarant signals that report secrets but are not mapped to 5.5-6 in
# evidence-map.json; a miss with one of these is a mapping gap, not a
# detection gap.
UNMAPPED_SECRET = {"INSECURE_HTTP_BODY_SECRET", "INSECURE_MQTT_PAYLOAD_SECRET", "INSECURE_TELNET_PAYLOAD_SECRET"}


def public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global
    except ValueError:
        return False


def private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local
    except ValueError:
        return False


def iot_side(iot, mac, ip):
    return (mac or "").lower() in iot and private(ip)


def gt_rows(d):
    p = os.path.join(d, "gt.log")
    if os.path.exists(p):
        for line in open(p):
            try:
                yield "zeek", json.loads(line)
            except json.JSONDecodeError:
                pass
    p = os.path.join(d, "raw.jsonl")
    if os.path.exists(p):
        for line in open(p):
            yield "raw", json.loads(line)


def classify(src, r, iot, tls_flows=frozenset()):
    """Yield (class, device_mac, detail) for one ground-truth row."""
    if src == "zeek":
        om, rm = (r.get("orig_mac") or "").lower(), (r.get("resp_mac") or "").lower()
        oh, rh, rp = r["orig_h"], r["resp_h"], r["resp_p"]
        devs = [m for m, ip in ((om, oh), (rm, rh)) if iot_side(iot, m, ip)]
        peer = f"{r.get('sni') or r.get('host') or rh}:{rp}"
        if r["kind"] == "tls":
            ver = r.get("version")
            basis = "selected"
            if not ver:
                cv = r.get("client_versions") or ""
                vs = [v for v in cv.replace("max=", "").split(",") if v.startswith(("TLS", "SSL"))]
                ver = max(vs, key=lambda v: ("SSLv2", "SSLv3", "TLSv10", "TLSv11", "TLSv12", "TLSv13").index(v)
                          if v in ("SSLv2", "SSLv3", "TLSv10", "TLSv11", "TLSv12", "TLSv13") else -1) if vs else None
                basis = "client_max"
            reasons = []
            if ver in OLD_TLS:
                reasons.append(f"{basis}={ver}")
            if r.get("cipher") and BROKEN.search(r["cipher"]):
                reasons.append(f"cipher={r['cipher']}")
            for d in devs:
                for why in reasons:
                    yield "tls", d, {"why": why, "peer": peer}
        elif r["kind"] == "http":
            reasons = []
            scheme = (r.get("auth_scheme") or "").lower()
            if scheme:
                reasons.append(("csp_sig" if scheme in SIG_SCHEMES else "csp", f"authorization:{scheme}"))
            for h in r.get("req_headers") or []:
                if h != "authorization" and h not in BENIGN_HEADERS and SECRET.search(h):
                    reasons.append(("csp", f"header:{h}"))
                if h == "cookie":
                    reasons.append(("cookie", "header:cookie"))
            for raw_k in r.get("uri_params") or []:
                # an encoded query (%26, %3d) arrives as one name; keep keys only
                for k in re.split(r"%26|&", raw_k):
                    k = re.split(r"%3d|=", k)[0]
                    if k and SECRET.search(k):
                        reasons.append(("csp", f"param:{k[:40]}"))
            for k in r.get("req_body_keys") or []:
                reasons.append(("csp", f"req_body:{k}"))
            for k in r.get("resp_body_keys") or []:
                reasons.append(("csp_resp", f"resp_body:{k}"))
            for d in devs:
                for cls, why in reasons:
                    yield cls, d, {"why": why, "peer": peer, "port": rp}
            mimes = [m for m in r.get("orig_mime") or [] if m.split("/")[0] in ("image", "video", "audio")]
            if mimes and iot_side(iot, om, oh) and public(rh):
                yield "media", om, {"why": "zeek_mime:" + ",".join(sorted(set(mimes))), "peer": peer, "port": rp}
            if iot_side(iot, om, oh) and public(rh) and rp not in HTTP_PORTS:
                yield "http_ext_nondefault_port", om, {"why": f"{r.get('method')}", "peer": peer, "port": rp}
        elif r["kind"] == "mqtt" and r.get("has_password"):
            for d in devs:
                yield "csp", d, {"why": "mqtt_password", "peer": peer, "port": rp}
        elif r["kind"] == "ftp" and r.get("has_password"):
            for d in devs:
                yield "csp", d, {"why": "ftp_pass", "peer": peer, "port": rp}
        return
    # raw packet search: only outside TLS (continuation segments of a TLS
    # stream do not start with a record header, so random bytes can match)
    sm, dm, sip, dip = r["src_mac"], r["dst_mac"], r["src_ip"], r["dst_ip"]
    if r["sport"] in TLS_PORTS or r["dport"] in TLS_PORTS or (sip, dip, r["dport"]) in tls_flows or (dip, sip, r["sport"]) in tls_flows:
        return
    devs = [m for m, ip in ((sm, sip), (dm, dip)) if iot_side(iot, m, ip)]
    cls, name = r["cls"], r["name"]
    det = {"why": f"raw:{cls}:{name}", "peer": f"{dip}:{r['dport']}" if iot_side(iot, sm, sip) else f"{sip}->{dip}:{r['dport']}",
           "port": r["dport"], "proto": r["proto"]}
    if cls == "authorization":
        for d in devs:
            yield ("raw_csp_sig" if name in SIG_SCHEMES else "raw_csp"), d, det
    elif cls == "secret_key":
        for d in devs:
            yield "raw_csp", d, det
    elif cls == "mqtt_connect" and "pass=True" in name:
        for d in devs:
            yield "raw_csp", d, det
    elif cls == "ftp_pass":
        for d in devs:
            yield "raw_csp", d, det
    elif cls == "login_prompt":
        for d in devs:
            yield "raw_login_prompt", d, det
    elif cls in ("media_signature", "media_content_type") and iot_side(iot, sm, sip) and public(dip) and r["proto"] == "tcp":
        yield "raw_media", sm, det


FAMILIES = {"tls": ["tls"], "csp": ["csp", "raw_csp", "cookie", "csp_resp"], "media": ["media", "raw_media"]}


def judged(out, judgments_path):
    J = {(j["group"], j["family"], j["mac"]): j["verdict"] for j in json.load(open(judgments_path))["judgments"]}
    res = {}
    for g, gd in out.items():
        for fam, classes in FAMILIES.items():
            cand, kinds = set(), {}
            for c in classes:
                ent = gd["classes"].get(c)
                if not ent:
                    continue
                for x in ent["gt_only"]:
                    cand.add(x["mac"])
                    kinds.setdefault(x["mac"], x["miss_kind"])
                for x in ent["both_devices"]:
                    cand.add(x["mac"])
            q = {x["mac"] for x in gd["classes"].get(fam, {}).get("both_devices", [])} | \
                {x["mac"] for x in gd["classes"].get(fam, {}).get("quarant_only", [])}
            if fam == "tls":
                real, unjudged, undecided = cand, set(), set()
            else:
                real = {m for m in cand if J.get((g, fam, m)) == "real"}
                undecided = {m for m in cand if J.get((g, fam, m)) == "undecided"}
                unjudged = {m for m in cand if (g, fam, m) not in J}
            fp = {m for m in q if J.get((g, fam + ":quarant", m)) == "not"}
            if not (real or q or unjudged):
                continue
            res[(g, fam)] = {"gt": len(real), "found": len(real & q), "missed": sorted((m, kinds.get(m, "")) for m in real - q),
                             "quarant_false": sorted(fp), "quarant_unconfirmed": sorted(q - real - fp),
                             "undecided": sorted(undecided), "unjudged": sorted(unjudged)}
    return res




def quarant_hits(events, inv, iot, provs):
    """Devices with evidence as Quarant attributes it (device_key), and the
    IoT devices on the other end of the same events (e.g. a TLS server)."""
    hits = collections.defaultdict(set)
    for e in events:
        mac = er.device_id(inv, e.get("device_key") or e.get("src_ip", ""))
        for ip in (e.get("src_ip"), e.get("dst_ip")):
            other = er.device_id(inv, ip or "")
            if other in iot and other != mac:
                if er.matches(provs["5.5-1"], e):
                    hits["tls:peer"].add(other)
                if er.matches(provs["5.5-6"], e):
                    hits["csp:peer"].add(other)
        if mac not in iot:
            continue
        if er.matches(provs["5.5-1"], e):
            hits["tls"].add(mac)
        if er.matches(provs["5.5-6"], e):
            hits["csp"].add(mac)
        if e["type"] == "I6_MEDIA_UPLOAD_CLEARTEXT":
            hits["media"].add(mac)
    return hits


def main():
    emap, qruns, gtdir, excl, out_json = sys.argv[1:6]
    judgments = sys.argv[6] if len(sys.argv) > 6 else None
    provs = {p["provision"]: p for p in json.load(open(emap))["provisions"]}
    exclude = {l.strip().lower() for l in open(excl) if l.strip() and not l.startswith("#")}
    result = {"runs": 0, "groups": {}}
    groups = collections.defaultdict(lambda: {"devices": set(), "gt": collections.defaultdict(set),
                                              "q": collections.defaultdict(set), "detail": collections.defaultdict(list),
                                              "pairs_gt": collections.defaultdict(set), "pairs_q": collections.defaultdict(set),
                                              "names": {}, "types": collections.defaultdict(collections.Counter)})
    for d in sorted(glob.glob(os.path.join(gtdir, "*", "done"))):
        d = os.path.dirname(d)
        name = os.path.basename(d)
        qd = os.path.join(qruns, name)
        if not os.path.exists(os.path.join(qd, "events.jsonl")):
            continue
        group = next((g for p, g in er.GROUPS.items() if name.startswith(p)), None)
        if group is None:
            continue
        G = groups[group]
        result["runs"] += 1
        events, inv = er.load_run(qd)
        keys = {e.get("device_key") for e in events}
        iot = set()
        for ip, dev in inv.items():
            mac = er.device_id(inv, ip)
            if (dev.get("observed_protocols") or ip in keys) and mac not in exclude and ":" in mac:
                iot.add(mac)
                G["names"].setdefault(mac, dev.get("hostname") or dev.get("mac_vendor") or "")
        G["devices"] |= iot
        for e in events:
            m = er.device_id(inv, e.get("device_key") or e.get("src_ip", ""))
            if m in iot:
                G["types"][(m, name)][e["type"]] += 1
        for cls, macs in quarant_hits(events, inv, iot, provs).items():
            for m in macs:
                G["q"][cls].add(m)
                G["pairs_q"][cls].add((name, m))
                G["detail"][(cls, m, "q")].append(name)
        rows = list(gt_rows(d))
        tls_flows = {(r["orig_h"], r["resp_h"], r["resp_p"]) for s, r in rows if s == "zeek" and r["kind"] == "tls"}
        for src, r in rows:
            for cls, mac, det in classify(src, r, iot, tls_flows):
                G["gt"][cls].add(mac)
                G["pairs_gt"][cls].add((name, mac))
                det["run"] = name
                if len(G["detail"][(cls, mac)]) < 400:
                    G["detail"][(cls, mac)].append(det)
    out = {}
    for g, G in groups.items():
        gd = {"devices": len(G["devices"]), "classes": {}}
        for cls in sorted(set(G["gt"]) | set(G["q"])):
            if cls.endswith(":peer"):
                continue
            gt, q = G["gt"][cls], G["q"][cls.replace("raw_", "")] if cls.startswith("raw_") else G["q"][cls]
            ent = {"gt": len(gt), "quarant": len(q), "both": len(gt & q), "gt_only": [], "quarant_only": [],
                   "pairs": {"gt": len(G["pairs_gt"][cls]), "both": len(G["pairs_gt"][cls] & G["pairs_q"][cls.replace("raw_", "")])},
                   "both_devices": [{"mac": m, "name": G["names"].get(m, "")} for m in sorted(gt & q)]}
            base = cls.replace("raw_", "")
            for m in sorted(gt - q):
                dets = G["detail"][(cls, m)]
                qt = sum((G["types"][(m, r)] for r in {x["run"] for x in dets}), collections.Counter())
                if m in G["q"].get(base, set()):
                    kind = "found_in_other_runs"
                elif m in G["q"].get(base + ":peer", set()):
                    kind = "attributed_to_peer"
                elif base == "csp" and UNMAPPED_SECRET & set(qt):
                    kind = "unmapped_signal"
                else:
                    kind = "not_detected"

                ent["gt_only"].append({"mac": m, "name": G["names"].get(m, ""), "miss_kind": kind,
                                       "why": sorted(collections.Counter(x["why"] for x in dets).items(), key=lambda t: -t[1])[:12],
                                       "peers": sorted(collections.Counter(x["peer"] for x in dets).items(), key=lambda t: -t[1])[:8],
                                       "runs": sorted({x["run"] for x in dets})[:5], "n_runs": len({x["run"] for x in dets}),
                                       # what Quarant did report for this device in the same runs
                                       "quarant_types": qt.most_common(12)})
            for m in sorted(q - gt):
                ent["quarant_only"].append({"mac": m, "name": G["names"].get(m, ""), "runs": sorted(set(G["detail"][(cls, m, "q")]))[:5]})
            gd["classes"][cls] = ent
        out[g] = gd
    result["groups"] = out
    if judgments:
        jr = judged(out, judgments)
        result["judged"] = [{"group": g, "family": f, **v} for (g, f), v in jr.items()]
    json.dump(result, open(out_json, "w"), ensure_ascii=False, indent=1)
    for g, gd in out.items():
        print(f"== {g} ({gd['devices']} devices)")
        for cls, ent in gd["classes"].items():
            print(f"  {cls:26s} gt={ent['gt']:3d} quarant={ent['quarant']:3d} both={ent['both']:3d} "
                  f"gt_only={len(ent['gt_only'])} q_only={len(ent['quarant_only'])}")
    if judgments:
        print("== judged (ground truth = candidates judged real)")
        for r in result["judged"]:
            print(f"  {r['group']:28s} {r['family']:5s} gt={r['gt']:2d} found={r['found']:2d} missed={r['missed']} "
                  f"quarant_false={r['quarant_false']} unconfirmed={r['quarant_unconfirmed']} undecided={r['undecided']} unjudged={r['unjudged']}")


if __name__ == "__main__":
    main()
