#!/usr/bin/env python3
"""Check one candidate of the sweep in the packets with tshark, independently of expose.py.

usage:
  verify.py http    <capture> <device mac> <host> <key> [<lan kind>]
  verify.py payload <capture> <device mac> <frame>
  verify.py dl      <capture> <device mac> <frame>
  verify.py tls     <capture> <device mac> <frame>

http     every HTTP request the device sent to <host>: whether it has the field <key> (q:name, form:name,
         json:path, xml:tag, h:header, path[i], h:authorization:<scheme>), and for its values the length,
         shape, number of distinct values, whether a value is or holds the device's MAC, and whether it
         equals a value the device announced on the LAN (<lan kind>: upnp, mdns_txt:<key>, mdns_name)
payload  the packet <frame>: where the device's MAC sits in the payload, what the payload starts with,
         whether it is the first data of the flow, how many packets to the same port hold the MAC
dl       the HTTP response in the TCP stream of <frame>: status, length, type, file name extension,
         and the first bytes and entropy of the body
tls      the TLS handshake in the TCP stream of <frame> (versions and suites the device offered, server
         name, version and suite chosen, every certificate: key, signature hash, issuer, subject, validity),
         reading only up to 20000 packets after <frame>; with VERIFY_TLS_ALL=1 also all handshakes of the
         device in the capture by server, chosen version and suite (report.py's tls.tsv has the same count)
Values are printed as they are (2026-11-11): the most common values of the field, the decoded
Authorization parts, and the bytes around the MAC. The output can hold credentials, so keep it out of
the public repository (credentials go to quarant-results/claims). The peer's name is taken from DNS
answers in the same capture.
"""
import base64
import collections
import math
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import expose  # noqa: E402  (HTTP field parsing and shapes)


def tshark(cap, filt, fields, *extra, upto=None):
    # VERIFY_DECODE="tcp.port==8802,http" reads a non-standard port as HTTP; upto stops after that many packets
    decode = ["-d", os.environ["VERIFY_DECODE"]] if os.environ.get("VERIFY_DECODE") else []
    cmd = ["tshark", "-r", cap, *decode, *(["-c", str(upto)] if upto else []), "-Y", filt, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
           "-E", "aggregator=\x1f", *extra]
    for f in fields:
        cmd += ["-e", f]
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return [(line.split("\t") + [""] * len(fields))[:len(fields)] for line in p.stdout.splitlines()]


def src(mac):
    """Display filter for packets the device sent (Ethernet or Linux cooked captures)."""
    return f"(eth.src == {mac} || sll.src.eth == {mac})"


def unhex(s):
    s = s.replace(":", "")
    return bytes.fromhex(s) if re.fullmatch(r"[0-9a-fA-F]*", s) and len(s) % 2 == 0 else s.encode("latin-1")


def mac_forms(mac):
    hx = mac.replace(":", "").lower()
    return [mac.lower().encode(), hx.encode(), mac.lower().replace(":", "-").encode()], bytes.fromhex(hx)


def mac_relation(v, mac):
    texts, _ = mac_forms(mac)
    low = v.lower()
    if any(low == t for t in texts):
        return "equals MAC"
    if any(t in low for t in texts):
        return "holds MAC"
    return "no MAC"


def names_for(cap, ip):
    rows = tshark(cap, f"dns.a == {ip} || dns.aaaa == {ip}", ["dns.qry.name"])
    return sorted({r[0].split("\x1f")[0] for r in rows if r[0]})[:3]


def lan_values(cap, mac, kind):
    """Values the device announced on the LAN, by kind (kept in memory)."""
    out = set()
    if kind == "upnp":
        for (data,) in tshark(cap, f"{src(mac)} && http.response", ["http.file_data"]):
            b = unhex(data.split("\x1f")[0]) if data else b""
            b = re.sub(rb"\r\n[0-9A-Fa-f]{1,6}\r\n", b"", b)
            out |= {v.strip() for _, v in expose.UPNP_TAGS.findall(b)}
    elif kind.startswith("mdns"):
        for txt, names in tshark(cap, f"{src(mac)} && mdns && dns.flags.response == 1", ["dns.txt", "dns.resp.name"]):
            if kind.startswith("mdns_txt:"):
                key = kind.split(":", 1)[1].encode()
                for t in txt.split("\x1f"):
                    k, eq, v = t.encode("latin-1").partition(b"=")
                    if eq and k == key:
                        out.add(v)
            else:
                out |= {n.split(".")[0].encode() for n in names.split("\x1f") if n}
    return out


def show(v):
    return (v.decode("latin-1") if isinstance(v, bytes) else str(v))[:200]


def top_values(vals, n=5):
    return "; ".join(f"{show(v)} ({c})" for v, c in collections.Counter(vals).most_common(n))


def shape_list(vals):
    return ", ".join(f"{s} ({n})" for s, n in collections.Counter(f'{expose.shape(v)}/len {len(v)}' for v in vals).most_common(3))


def cmd_http(cap, mac, host, key, lan_kind=None):
    rows = tshark(cap, f"{src(mac)} && http.request", ["frame.number", "tcp.stream", "ip.dst", "tcp.dstport",
                  "http.host", "http.request.method", "http.request.uri", "http.request.line", "http.file_data"])
    hits, frames, peers = [], [], collections.Counter()
    for fr, st, dst, port, h, method, uri, lines, data in rows:
        if host not in (h, dst, h.removesuffix(":80")):   # some devices write the port into the Host header
            continue
        heads = "".join(x for x in lines.split("\x1f")).replace("\\r\\n", "\r\n")   # tshark prints CRLF as \r\n
        msg = f"{method} {uri} HTTP/1.1\r\n".encode("latin-1") + heads.encode("latin-1", "replace") + b"\r\n"
        body = unhex(data.split("\x1f")[0]) if data else b""
        out = []
        ctx = expose.http_fields(msg + body, out)
        for k, v, c in out:
            if k == key or (key.startswith("h:authorization") and k.startswith("h:authorization")):
                hits.append((k, v, c))
                frames.append(int(fr))
                peers[(dst, port)] += 1
    print(f"capture {Path(cap).name}: {len(rows)} HTTP requests from the device, {len(hits)} with {key} to {host}")
    if not hits:
        return
    print(f"  first frame {min(frames)}, last frame {max(frames)}; request {hits[0][2]['method']} {hits[0][2]['host']}{hits[0][2]['path']}")
    for (dst, port), n in peers.most_common(2):
        print(f"  peer {dst}:{port} ({n} requests), DNS names in the capture: {names_for(cap, dst) or 'none'}")
    vals = [v for _, v, _ in hits]
    bodies = [unhex(r[8].split("\x1f")[0]) for r in rows if r[8] and int(r[0]) in frames]
    if bodies:
        kinds = collections.Counter("JPEG" if b.startswith(b"\xff\xd8\xff") else "PNG" if b.startswith(b"\x89PNG") else
                                    "MP4" if b[4:8] == b"ftyp" else "JSON" if b[:1] in (b"{", b"[") else "other" for b in bodies)
        print(f"  request bodies: {dict(kinds)}, sizes {min(len(b) for b in bodies)}-{max(len(b) for b in bodies)} bytes")
    if key.startswith("h:authorization"):
        auth(vals, mac)
        return
    print(f"  values: {len(set(vals))} distinct over {len(vals)}; shapes: {shape_list(set(vals))}")
    print(f"  most common values: {top_values(vals)}")
    print(f"  relation to the device's MAC: {dict(collections.Counter(mac_relation(v, mac) for v in vals))}")
    if lan_kind:
        kind, _, other = lan_kind.partition("@")
        lan = lan_values(other or cap, mac, kind)
        if other:
            print(f"  LAN values read from {Path(other).name}")
        lan_kind = kind
        eq = sum(1 for v in vals if v in lan)
        inside = sum(1 for v in vals if any(x and x in v for x in lan))
        print(f"  LAN values ({lan_kind}) announced in this capture: {len(lan)}; requests whose value equals one: {eq}; holds one: {inside}")
        print(f"  LAN values: {'; '.join(sorted(show(x) for x in lan)[:5])}")


def auth(vals, mac):
    schemes = collections.Counter(v.split(b" ")[0].decode("latin-1") for v in vals)
    print(f"  Authorization schemes: {dict(schemes)}; {len(set(vals))} distinct header values over {len(vals)}")
    print(f"  most common header values: {top_values(vals, 3)}")
    v0 = vals[0]
    scheme, _, rest = v0.partition(b" ")
    if scheme.lower() == b"basic":
        users = []
        for v in vals:
            try:
                u, _, p = base64.b64decode(v.split(b" ", 1)[1]).partition(b":")
            except Exception:
                continue
            users.append((u, p))
        print(f"  Basic user:password, most common: {top_values([u + b':' + p for u, p in users], 3)}")
        us, ps = {u for u, _ in users}, {p for _, p in users}
        print(f"  Basic: user names {len(us)} distinct ({shape_list(us)}), relation to MAC {dict(collections.Counter(mac_relation(u, mac) for u, _ in users))}; "
              f"passwords {len(ps)} distinct, lengths {sorted({len(p) for p in ps})}, relation to MAC {dict(collections.Counter(mac_relation(p, mac) for p in ps))}")
    elif scheme.upper() == b"OSS":
        ids = [v.split(b" ", 1)[1].split(b":")[0] for v in vals]
        sigs = [v.split(b" ", 1)[1].split(b":")[-1] for v in vals]
        print(f"  OSS: access key id {len(set(ids))} distinct over {len(ids)} (lengths {sorted({len(i) for i in ids})}); "
              f"signatures {len(set(sigs))} distinct (lengths {sorted({len(s) for s in sigs})})")
        print(f"  OSS access key ids: {top_values(ids, 3)}")
    elif scheme.upper().startswith(b"AWS4"):
        cred = [re.search(rb"Credential=([^/,]+)/([^,]*)", v) for v in vals]
        ids = [m.group(1) for m in cred if m]
        scopes = {m.group(2).split(b"/", 1)[-1] for m in cred if m}
        print(f"  AWS4: access key id {len(set(ids))} distinct over {len(ids)} (lengths {sorted({len(i) for i in ids})}, "
              f"shape {shape_list(set(ids))}); credential scopes without the date: {sorted(s.decode('latin-1') for s in scopes)}")
        print(f"  AWS4 access key ids: {top_values(ids, 3)}")
    else:
        print(f"  {scheme.decode('latin-1')}: lengths {sorted({len(v) for v in vals})}")


def kind_of(b):
    if len(b) >= 3 and b[0] in (20, 21, 22, 23) and b[1] == 3:
        return "TLS record"
    if expose.HTTP_REQ.match(b) or expose.HTTP_RESP.match(b):
        return "HTTP"
    pr = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / max(1, len(b))
    return f"{'text' if pr >= 0.85 else 'binary'} ({pr:.0%} printable)"


def cmd_payload(cap, mac, frame, lan_kind=None):
    (row,) = tshark(cap, f"frame.number == {frame}", ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport",
                    "udp.dstport", "tcp.stream", "udp.stream", "tcp.seq", "tcp.payload", "udp.payload", "data.data"])
    sip, dst, ts, td, us, ud, tst, ust, seq, tpl, upl, data = row
    proto, port, stream = ("tcp", td, tst) if tst else ("udp", ud, ust)
    pl = unhex(tpl or upl or data)
    texts, raw = mac_forms(mac)
    low = pl.lower()
    found = [(low.find(t), "text " + ["aa:bb..", "aabb..", "aa-bb.."][i]) for i, t in enumerate(texts) if t in low]
    if raw in pl:
        found.append((pl.find(raw), "raw 6 bytes"))
    print(f"frame {frame}: {proto} {sip} -> {dst}:{port}, payload {len(pl)} bytes, starts as {kind_of(pl[:256])}")
    for off, how in found:
        before = re.search(rb"([A-Za-z_\-]{2,24})[\"'=: ]{0,3}$", pl[max(0, off - 28):off])
        print(f"  MAC as {how} at offset {off}; name just before it: {before.group(1).decode() if before else 'none'}")
        print(f"  bytes around it: {pl[max(0, off - 48):off + 60]!r}")
    if not found:
        print("  MAC not found in this packet")
    if lan_kind:
        lan = lan_values(cap, mac, lan_kind)
        hits = [(pl.find(x), len(x)) for x in lan if x and x in pl]
        print(f"  LAN values ({lan_kind}) announced: {len(lan)}; found in this payload at offset/length: {hits or 'none'}")
    first = tshark(cap, f"{proto}.stream == {stream} && {proto}.len > 0" if proto == "tcp" else f"udp.stream == {stream}",
                   ["frame.number", "eth.src", "sll.src.eth"])
    mine = [int(f) for f, e, s in first if mac.lower() in (e.lower(), s.lower())]
    print(f"  first data the device sent in this flow: frame {min(mine) if mine else '?'} ({'this frame' if mine and min(mine) == int(frame) else 'not this frame'})")
    rows = tshark(cap, f"{src(mac)} && {proto}.dstport == {port} && ip.dst == {dst}", [f"{proto}.payload"])
    n = sum(1 for (p,) in rows if p and (raw in unhex(p) or any(t in unhex(p).lower() for t in texts)))
    print(f"  packets from the device to {dst}:{port}: {len(rows)}, holding the MAC: {n}")
    print(f"  DNS names for {dst} in the capture: {names_for(cap, dst) or 'none'}")


def cmd_dl(cap, mac, frame):
    (st,) = tshark(cap, f"frame.number == {frame}", ["tcp.stream"])[0]
    req = tshark(cap, f"tcp.stream == {st} && http.request", ["http.host", "http.request.uri", "ip.dst"])
    resp = tshark(cap, f"tcp.stream == {st} && http.response", ["frame.number", "http.response.code", "http.content_length_header",
                  "http.content_type", "http.response.line", "http.file_data"])
    for h, uri, dst in req[:1]:
        path = "/".join("{id}" if len(s) >= 6 and re.search(r"\d", s) else s for s in urllib.parse.urlsplit(uri).path.split("/"))
        print(f"stream {st}: request to {h}{path}; peer {dst}, DNS names {names_for(cap, dst) or 'none'}")
        print(f"  request URI: {uri[:300]}")
    for fr, code, ln, ctype, lines, data in resp[:2]:
        disp = re.search(r"filename=\"?[^\";]*?(\.[A-Za-z0-9]{1,8})\"?", lines)
        body = unhex(data.split("\x1f")[0]) if data else b""
        magic = {b"\x1f\x8b": "gzip", b"PK": "zip", b"\x7fELF": "ELF", b"hsqs": "squashfs", b"UBI#": "UBI",
                 b"\x27\x05\x19\x56": "uImage", b"Cr24": "CRX", b"CrOD": "CRX diff"}
        kind = next((v for k, v in magic.items() if body.startswith(k)), "other")
        s = body[:65536]
        ent = -sum(c / len(s) * math.log2(c / len(s)) for c in collections.Counter(s).values()) if s else 0
        print(f"  response frame {fr}: status {code}, Content-Length {ln}, type {ctype or 'none'}, file name extension "
              f"{disp.group(1) if disp else 'none'}; body read {len(body)} bytes, starts as {kind}, entropy {ent:.2f} bits/byte")


def cert_line(der, when):
    from cryptography import x509
    try:
        c = x509.load_der_x509_certificate(der)
    except Exception as e:
        return f"unreadable ({e.__class__.__name__})"
    k = c.public_key()
    try:
        sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "none"
    except Exception:
        sig = "unknown"
    after, before = c.not_valid_after_utc, c.not_valid_before_utc
    state = "expired" if when > after.timestamp() else "not yet valid" if when < before.timestamp() else "valid"
    return (f"{k.__class__.__name__.replace('_', '').replace('PublicKey', '')} {getattr(k, 'key_size', '')}, sig {sig}, "
            f"issuer {c.issuer.rfc4514_string()[:120]}, subject {c.subject.rfc4514_string()[:120]}, "
            f"{before:%Y-%m-%d}..{after:%Y-%m-%d} ({state} at capture time){', self-signed' if c.issuer == c.subject else ''}")


def suite_names(codes):
    return [expose.SUITES.get(int(c, 0) if c.startswith("0x") else int(c), c) for c in codes if c]


def cmd_tls(cap, mac, frame):
    upto = int(frame) + 20000
    (st,) = tshark(cap, f"frame.number == {frame}", ["tcp.stream"], upto=int(frame))[0]
    rows = tshark(cap, f"tcp.stream == {st} && tls.handshake", upto=upto, fields=["frame.number", "frame.time_epoch", "ip.src", "ip.dst",
                  "tcp.dstport", "tls.handshake.type", "tls.handshake.version", "tls.handshake.extensions.supported_version",
                  "tls.handshake.ciphersuite", "tls.handshake.extensions_server_name", "tls.handshake.certificate"])
    print(f"stream {st} of {Path(cap).name}")
    for fr, t, a, b, port, types, ver, sv, suites, sni, certs in rows:
        types = types.split("\x1f")
        if "1" in types:
            print(f"  frame {fr} ClientHello {a} -> {b}:{port}: version field {ver}, supported_versions {sv.split(chr(31)) if sv else 'none'}, "
                  f"server name {sni or 'none'}")
            names = suite_names(suites.split("\x1f"))
            weak = [n for n in names if expose.suite_flags(n)]
            print(f"    {len(names)} suites offered; weak ones: {weak or 'none'}")
            print(f"    first suites: {names[:6]}")
        if "2" in types:
            v = sv.split("\x1f")[-1] if sv else ver.split("\x1f")[0]
            print(f"  frame {fr} ServerHello {a} -> {b}: version {v}, suite {suite_names(suites.split(chr(31))[:1])}")
        if "11" in types and certs:
            for i, c in enumerate(certs.split("\x1f")):
                print(f"  frame {fr} certificate {i}: {cert_line(unhex(c), float(t))}")
    if not os.environ.get("VERIFY_TLS_ALL"):
        return
    # an ICMP error quoting a packet gives a second ip.src; keep plain IPv4 addresses only
    ips = {a for r in tshark(cap, f"{src(mac)} && tls.handshake.type == 1", ["ip.src"]) for a in r[0].split("\x1f")
           if re.fullmatch(r"[0-9.]+", a)}
    if not ips:
        return
    shs = tshark(cap, f"tls.handshake.type == 2 && ip.dst in {{{' '.join(sorted(ips))}}}",
                 ["ip.src", "tls.handshake.version", "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite"])
    c = collections.Counter()
    for a, ver, sv, suite in shs:
        v = sv.split("\x1f")[-1] if sv else ver.split("\x1f")[0]
        c[(a, v, suite_names(suite.split("\x1f")[:1])[0] if suite else "")] += 1
    print(f"  all ServerHellos to the device in the capture: {sum(c.values())}")
    for (a, v, n), k in c.most_common(8):
        print(f"    {k} from {a}: {v} {n}")


def main():
    cmd, *a = sys.argv[1:]
    {"http": cmd_http, "payload": cmd_payload, "dl": cmd_dl, "tls": cmd_tls}[cmd](*a)


if __name__ == "__main__":
    main()
