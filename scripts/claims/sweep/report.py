#!/usr/bin/env python3
"""Turn the expose.py records of several datasets into one list of findings per product.

usage: report.py <devices.tsv> <sweep dir> <out dir> [--exclude-issuer <substring>]...

Reads <sweep dir>/<dataset>/*.jsonl for every dataset directory. Writes, without any value:
  findings.tsv  one line per product, category and detail, with counts and the first evidence
  ids.tsv       plaintext fields to public addresses that hold an identifier
  tls.tsv       TLS per device and role (client to public servers, server on the LAN)
  dl.tsv        plaintext HTTP downloads of 1 MB or more, or of a binary type
  flows.tsv     payload bytes to public addresses per device and kind
TLS handshakes whose server certificate issuer contains an --exclude-issuer substring
(a test certificate of the dataset's authors) are left out and counted apart.
Categories (finding.tsv "cat"):
  id-mac       the device's MAC (any spelling) in a plaintext field or payload to a public address
  id-lan       a value the device announced on the LAN (UPnP serial, SSDP id, DHCP name, mDNS) sent in plaintext
  id-key       a field whose name says identifier (serial, uuid, device id, imei, account, email, location ...)
  cred         a field whose name or header says credential (password, token, session, Authorization)
  tls-version  TLS below 1.2 chosen, or the device offered nothing above 1.1
  tls-suite    RC4, 3DES, DES, export, NULL, anonymous or MD5 suites offered or chosen
  tls-nofs     no handshake with forward secrecy chosen
  tls-cert     server certificate with an RSA key under 2048 bits, SHA-1/MD5 signature, self-signed or expired
  dl-http      firmware-like download over plaintext HTTP
  plain        payload to public addresses in plaintext HTTP, MQTT or text (bytes and share)
"""
import collections
import csv
import json
import re
import sys
from pathlib import Path

ID_KEY = re.compile(r"(?i)(serial|(^|[^a-z])sn($|[^a-z])|uuid|udid|guid|device_?id|dev_?id|deviceid|hw_?id|imei|meid|"
                    r"mac(addr|_|$)|household|hhid|account|owner|e-?mail|(^|[^a-z])(lat|lon|lng|latitude|longitude)($|[^a-z])|"
                    r"geo|location|ssid|bssid|phone|zip|postal)")
CRED_KEY = re.compile(r"(?i)(pass(word|wd)?($|[^a-z])|pwd|secret|token|session|(^|[^a-z])sid($|[^a-z])|api_?key|(^|[^a-z])auth|cookie:)")
WEAK = {"rc4", "3des", "des", "export", "null", "anon", "md5"}
# LAN announcements that name a model, version or feature, not one device
NOT_ID = re.compile(r"(?i)^mdns_txt:(model|md|am|osvers|vers|ver|codever|txtvers|protovers|fv|sw|hw|fw|ff|ci|sf|c#|s#|pv|"
                    r"features|flags|srcvers|vv|sv|ty|rp|pk|ct|st|sh|ca|ve|ov|rmodel|rs|nf|dvty|dvsv|tv|vn|vs)$")
ID_LIKE = re.compile(r"(?i)^(upnp:|ssdp_uuid$|dhcp_client_id$|ssdp:.*(household|id|serial|mac))|^mdns_txt:.*(id|serial|sn|mac|uuid|guid)$")


def lan_id(kind, rec):
    """True if a LAN announcement names one device: an ID-type field, or a value with a digit and 8 or more characters."""
    if NOT_ID.search(kind):
        return False
    # without the value, a hex digit is the best sign of a number: ask for at least four
    return bool(ID_LIKE.search(kind)) or (rec["len"] >= 8 and rec["shape"].count("h") >= 4)


def clean(x):
    return re.sub(r"[^\x20-\x7e]", "?", str(x)) if x is not None else ""


def version(v):
    return {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}.get(v, str(v))


def first(a, b):
    return b if a is None or (b["file"], b["frame"]) < (a["file"], a["frame"]) else a


def main():
    args = sys.argv[1:]
    excl = [args[i + 1] for i, a in enumerate(args) if a == "--exclude-issuer"]
    devices_tsv, sweep, out = [a for i, a in enumerate(args) if a != "--exclude-issuer" and (i == 0 or args[i - 1] != "--exclude-issuer")][:3]
    labels = {}
    for r in csv.DictReader(open(devices_tsv), delimiter="\t"):
        labels[(r["dataset"], r["mac"].lower())] = " ".join(x for x in (r["vendor"], r["product"], r["model"]) if x) or r["label"]
    Path(out).mkdir(parents=True, exist_ok=True)

    findings = collections.defaultdict(lambda: {"n": 0, "files": set(), "ev": None})
    ids, tls_dev, tls_detail, dls, flows = {}, {}, {}, {}, collections.defaultdict(lambda: collections.Counter())
    excluded = collections.Counter()

    def finding(ds, dev, cat, detail, rec, n=1):
        f = findings[(ds, dev, cat, detail)]
        f["n"] += n
        f["files"].add(rec["file"])
        f["ev"] = first(f["ev"], rec)

    # only datasets listed in devices.tsv (old runs such as deakin-v1 sit in the same folder)
    for dsdir in sorted(p for p in Path(sweep).iterdir() if p.is_dir() and any(ds == p.name for ds, _ in labels)):
        ds = dsdir.name
        idx = collections.defaultdict(dict)   # dev -> hash -> kind
        recs = []
        for jf in sorted(dsdir.glob("*.jsonl")):
            for line in open(jf):
                r = json.loads(line)
                if r["r"] == "ident":
                    if not lan_id(r["kind"], r):
                        continue
                    d = idx[r["dev"]]
                    d.setdefault(r["h"], r["kind"])
                    for t in r["tok"]:
                        d.setdefault(t, r["kind"])
                elif r["r"] in ("field", "macout", "tls", "dl", "flow"):
                    recs.append(r)
        for r in recs:
            dev, kind = r["dev"], r["r"]
            if kind == "field":
                if re.search(r"[^\x20-\x7e]", r["key"]):
                    continue        # a key read out of a binary body
                pre, _, name = r["key"].partition(":")
                if pre in ("form", "q", "json", "xml", "cookie", "h") and (
                        not re.fullmatch(r"[A-Za-z0-9_.:\-\[\]]{1,80}", name)
                        or any(len(x) >= 20 and re.search(r"\d", x) for x in re.split(r"[.:\[\]]", name))):
                    r["key"] = pre + ":<unparsed>"     # part of a value, not a name: never write it
                cats = []
                if r["mac"]:
                    cats.append("id-mac")
                lan = sorted({idx[dev][x] for x in [r["h"]] + r["tok"] if x in idx[dev]})
                if lan:
                    cats.append("id-lan")
                key = r["key"].split(":", 1)[-1]
                if r["key"].startswith("h:authorization") or CRED_KEY.search(r["key"]):
                    cats.append("cred")
                elif ID_KEY.search(key) or r["email"]:
                    cats.append("id-key")
                if not cats:
                    continue
                host = r["host"] or r["peer"]
                hp = host if ":" in host else f'{host}:{r["port"]}'
                where = f'{hp} {r["method"] or r["proto"]} {r["path"] or ""}'.strip()
                k = (ds, dev, where, r["key"])
                e = ids.setdefault(k, {"cats": set(), "lan": set(), "shapes": collections.Counter(), "n": 0, "files": set(),
                                       "values": set(), "ev": None})
                e["values"].add(r["h"])
                e["cats"].update(cats)
                e["lan"].update(lan)
                e["shapes"][(r["shape"], r["len"])] += r["n"]
                e["n"] += r["n"]
                e["files"].add(r["file"])
                e["ev"] = first(e["ev"], r)
                for c in cats:
                    detail = f'{r["key"]} -> {r["host"] or r["peer"]}' + (f' ({", ".join(lan)})' if c == "id-lan" else "")
                    finding(ds, dev, c, detail, r, r["n"])
            elif kind == "macout":
                finding(ds, dev, "id-mac", f'{r["spelling"]} in {r["proto"]}/{r["port"]} payload -> {r["peer"]}', r, r["n"])
            elif kind == "tls":
                c = r.get("cert") or {}
                issuer = f'{c.get("issuer_o", "")} {c.get("issuer_cn", "")}'
                if any(x in issuer for x in excl):
                    excluded[(ds, dev)] += r["n"]
                    continue
                side = r["role"] if r["role"] == "server" else ("client-public" if r["peer_public"] else "client-lan")
                t = tls_dev.setdefault((ds, dev, side), {"n": 0, "ch_max": collections.Counter(), "ch_weak": collections.Counter(),
                                                         "ch_fs": collections.Counter(), "sh_ver": collections.Counter(),
                                                         "sh_suite": collections.Counter(), "sh_fs": collections.Counter(),
                                                         "cert": collections.Counter(), "files": set(), "ev": None})
                n = r["n"]
                t["n"] += n
                t["files"].add(r["file"])
                t["ev"] = first(t["ev"], r)
                if "ch_max" in r:
                    t["ch_max"][version(r["ch_max"])] += n
                    for w in r.get("ch_weak", []):
                        t["ch_weak"][w] += n
                    t["ch_fs"][r.get("ch_fs")] += n
                if "sh_ver" in r:
                    t["sh_ver"][version(r["sh_ver"])] += n
                    t["sh_suite"][r["sh_suite"]] += n
                    t["sh_fs"][r["sh_fs"]] += n
                if c:
                    t["cert"][(c.get("key"), c.get("bits"), c.get("sig"), c.get("self_signed"), c.get("expired"),
                               c.get("issuer_o") or c.get("issuer_cn"))] += n
                dk = (ds, dev, side, r["peer"], r["port"], r.get("sh_ver"), r.get("sh_suite"), tuple(r.get("ch_weak", [])),
                      c.get("key"), c.get("bits"), c.get("sig"), c.get("self_signed"), c.get("expired"))
                d = tls_detail.setdefault(dk, {"n": 0, "ev": None, "issuer": c.get("issuer_o") or c.get("issuer_cn")})
                d["n"] += n
                d["ev"] = first(d["ev"], r)
                # findings for TLS that the device itself chose or offered
                if "sh_ver" in r and r["sh_ver"] < 0x0303:
                    finding(ds, dev, "tls-version", f'{side}: {version(r["sh_ver"])} chosen', r, n)
                if "ch_max" in r and r["ch_max"] < 0x0303 and side != "server":
                    finding(ds, dev, "tls-version", f'{side}: offered at most {version(r["ch_max"])}', r, n)
                weak_off = sorted(set(r.get("ch_weak", [])) & WEAK)
                if weak_off and side != "server":
                    finding(ds, dev, "tls-suite", f'{side}: offered {"+".join(weak_off)}', r, n)
                if r.get("sh_weak"):
                    finding(ds, dev, "tls-suite", f'{side}: chosen {r["sh_suite"]}', r, n)
                if "sh_fs" in r and not r["sh_fs"]:
                    finding(ds, dev, "tls-nofs", f'{side}: {r["sh_suite"]}', r, n)
                if c:
                    bad = []
                    if c.get("key") == "rsa" and c.get("bits") and c["bits"] < 2048:
                        bad.append(f'RSA {c["bits"]}')
                    if c.get("sig") in ("sha1", "md5"):
                        bad.append(c["sig"])
                    if c.get("self_signed"):
                        bad.append("self-signed")
                    if c.get("expired"):
                        bad.append("expired")
                    if bad:
                        finding(ds, dev, "tls-cert", f'{side}: {", ".join(bad)} ({c.get("issuer_o") or c.get("issuer_cn")})', r, n)
            elif kind == "dl":
                k = (ds, dev, r["host"] or r["peer"], r["path"], r["size"], r["ctype"], r["ext"])
                e = dls.setdefault(k, {"n": 0, "ev": None})
                e["n"] += r["n"]
                e["ev"] = first(e["ev"], r)
                finding(ds, dev, "dl-http", f'{r["host"] or r["peer"]}{r["path"] or ""} {r["size"]} B {r["ctype"]}', r, r["n"])
            elif kind == "flow" and r["peer"] == "public":
                flows[(ds, dev)][r["kind"]] += r["bytes"]

    for (ds, dev), c in flows.items():
        total = sum(c.values())
        plain = sum(v for k, v in c.items() if k in ("http", "mqtt", "text"))
        if plain:
            rec = {"file": "", "frame": 0}
            f = findings[(ds, dev, "plain", f'{plain} of {total} B ({100 * plain / total:.1f}%) in HTTP/MQTT/text')]
            f["n"] += 1
            f["ev"] = rec

    def label(ds, dev):
        return labels.get((ds, dev), dev)

    with open(Path(out) / "findings.tsv", "w") as o:
        o.write("dataset\tproduct\tmac\tcat\tdetail\tcount\tfiles\tfirst_file\tfirst_frame\n")
        for (ds, dev, cat, detail), f in sorted(findings.items(), key=lambda x: (x[0][0], label(x[0][0], x[0][1]), x[0][2], x[0][3])):
            o.write(f'{ds}\t{label(ds, dev)}\t{dev}\t{cat}\t{clean(detail)}\t{f["n"]}\t{len(f["files"])}\t{f["ev"]["file"]}\t{f["ev"]["frame"]}\n')
    with open(Path(out) / "ids.tsv", "w") as o:
        o.write("dataset\tproduct\tmac\twhere\tkey\tcats\tlan_ids\tshape\tlen\tcount\tfiles\tvalues\tfirst_file\tfirst_frame\n")
        for (ds, dev, where, key), e in sorted(ids.items(), key=lambda x: (x[0][0], label(x[0][0], x[0][1]), x[0][2], x[0][3])):
            (sh, ln), _ = e["shapes"].most_common(1)[0]
            o.write(f'{ds}\t{label(ds, dev)}\t{dev}\t{clean(where)}\t{clean(key)}\t{",".join(sorted(e["cats"]))}\t{",".join(sorted(e["lan"]))}\t'
                    f'{clean(sh)}\t{ln}\t{e["n"]}\t{len(e["files"])}\t{len(e["values"])}\t{e["ev"]["file"]}\t{e["ev"]["frame"]}\n')
    with open(Path(out) / "tls.tsv", "w") as o:
        o.write("dataset\tproduct\tmac\tside\thandshakes\toffered_max\toffered_weak\toffered_fs\tchosen_version\tchosen_fs\ttop_suites\tcerts\texcluded_test\tfirst_file\tfirst_frame\n")
        for (ds, dev, side), t in sorted(tls_dev.items(), key=lambda x: (x[0][0], label(x[0][0], x[0][1]), x[0][2])):
            fmt = lambda c: "; ".join(f"{k}:{v}" for k, v in c.most_common(4))
            certs = "; ".join(f'{k[0]}{k[1] or ""} {k[2]}{" self" if k[3] else ""}{" expired" if k[4] else ""} [{k[5]}]:{v}'
                              for k, v in t["cert"].most_common(4))
            o.write(f'{ds}\t{label(ds, dev)}\t{dev}\t{side}\t{t["n"]}\t{fmt(t["ch_max"])}\t{fmt(t["ch_weak"])}\t{fmt(t["ch_fs"])}\t'
                    f'{fmt(t["sh_ver"])}\t{fmt(t["sh_fs"])}\t{fmt(t["sh_suite"])}\t{certs}\t{excluded.get((ds, dev), 0)}\t'
                    f'{t["ev"]["file"]}\t{t["ev"]["frame"]}\n')
    with open(Path(out) / "dl.tsv", "w") as o:
        o.write("dataset\tproduct\tmac\thost\tpath\tsize\tctype\text\tcount\tfirst_file\tfirst_frame\n")
        for (ds, dev, host, path, size, ctype, ext), e in sorted(dls.items(), key=lambda x: (x[0][0], label(x[0][0], x[0][1]))):
            o.write(f'{ds}\t{label(ds, dev)}\t{dev}\t{host}\t{path}\t{size}\t{ctype}\t{ext}\t{e["n"]}\t{e["ev"]["file"]}\t{e["ev"]["frame"]}\n')
    with open(Path(out) / "flows.tsv", "w") as o:
        kinds = sorted({k for c in flows.values() for k in c})
        o.write("dataset\tproduct\tmac\t" + "\t".join(kinds) + "\n")
        for (ds, dev), c in sorted(flows.items(), key=lambda x: (x[0][0], label(*x[0]))):
            o.write(f'{ds}\t{label(ds, dev)}\t{dev}\t' + "\t".join(str(c.get(k, 0)) for k in kinds) + "\n")
    cats = collections.Counter((k[0], k[2]) for k in findings)
    print("findings per dataset and category:")
    for (ds, cat), n in sorted(cats.items()):
        print(f"  {ds}\t{cat}\t{n}")


if __name__ == "__main__":
    main()
