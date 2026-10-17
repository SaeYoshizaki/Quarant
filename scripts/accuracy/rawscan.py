#!/usr/bin/env python3
"""Accuracy step 1: search the raw packets of one capture for cleartext
secrets, logins and media, independently of Quarant (own pcap/pcapng reader,
stdlib only, no reassembly: each packet payload is searched on its own).

Only metadata is written: addresses, ports, the kind of match and the name
that matched (e.g. the header or key name). Values never leave memory.

usage: rawscan.py PCAP OUT_JSONL
"""
import ipaddress
import json
import re
import struct
import sys

# One cheap pre-filter; packets that pass are classified below.
PRE = re.compile(rb"(?i)pass|pwd|token|secret|api[_-]?key|authorization:|sid=|session|auth=|login|user|"
                 rb"\xff\xd8\xff[\xe0\xe1]..(JFIF|Exif)|\x89PNG\r\n\x1a\n|ftyp(isom|mp4|3gp|avc1)|content-type: *(image|video|audio)/|"
                 rb"^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|SUBSCRIBE|NOTIFY) |^\x10.{1,4}\x00[\x04\x06](MQTT|MQIsdp)", re.S)
KEYED = re.compile(rb"(?i)[\"'&?\s,{]?((?:[a-z0-9_\-]{0,20})(?:passw(?:or)?d|passwd|pwd|passcode|token|secret|api[_-]?key|apikey|session[_-]?id|sessionid|sid|auth))[\"']?\s*[:=]")
AUTHZ = re.compile(rb"(?im)^authorization: *([A-Za-z0-9\-]+)")
COOKIE = re.compile(rb"(?im)^cookie: ")
PROMPT = re.compile(rb"(?i)(login|username|password)\s*:\s*$")
FTP = re.compile(rb"^(USER|PASS) ")
CTYPE = re.compile(rb"(?im)^content-type: *((?:image|video|audio)/[a-z0-9.+\-]+)")
MEDIA = [(re.compile(rb"\xff\xd8\xff[\xe0\xe1]..(?:JFIF|Exif)", re.S), "jpeg"), (re.compile(rb"\x89PNG\r\n\x1a\n"), "png"),
         (re.compile(rb"ftyp(?:isom|mp4|3gp|avc1)"), "mp4")]
HTTPREQ = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|SUBSCRIBE|NOTIFY) ")


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def packets(path):
    """Yield (ts, linktype, frame) from pcap or pcapng."""
    f = open(path, "rb")
    magic = f.read(4)
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        hdr = f.read(20)
        lt = struct.unpack(e + "I", hdr[16:20])[0]
        rec = struct.Struct(e + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            s, us, incl, _ = rec.unpack(h)
            data = f.read(incl)
            yield s + us / (1e9 if nano else 1e6), lt, data
    elif magic == b"\x0a\x0d\x0d\x0a":
        f.seek(0)
        e = "<"
        ifaces = []
        while True:
            h = f.read(8)
            if len(h) < 8:
                return
            btype, blen = struct.unpack(e + "II", h)
            if btype == 0x0A0D0D0A:
                bom = f.read(4)
                e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                blen = struct.unpack(e + "I", h[4:8])[0]
                f.read(blen - 12)
                ifaces = []
                continue
            body = f.read(blen - 8)
            if btype == 1:
                ifaces.append(struct.unpack(e + "H", body[:2])[0])
            elif btype == 6:
                iid, th, tl, cap = struct.unpack(e + "IIII", body[:16])
                yield ((th << 32) | tl) / 1e6, ifaces[iid] if iid < len(ifaces) else 1, body[20:20 + cap]
            elif btype == 3:
                yield 0.0, ifaces[0] if ifaces else 1, body[4:-4]
    else:
        raise SystemExit(f"unknown capture format: {path}")


def parse(lt, fr):
    """Return (src_mac, dst_mac, src_ip, dst_ip, proto, sport, dport, payload) or None."""
    smac = dmac = ""
    if lt == 1:
        if len(fr) < 14:
            return None
        dmac, smac = mac(fr[0:6]), mac(fr[6:12])
        et = struct.unpack("!H", fr[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8) and len(fr) >= off + 4:
            et = struct.unpack("!H", fr[off + 2:off + 4])[0]
            off += 4
    elif lt == 113:
        et = struct.unpack("!H", fr[14:16])[0]
        off = 16
    elif lt == 276:
        et = struct.unpack("!H", fr[0:2])[0]
        off = 20
    elif lt in (101, 12, 228, 229):
        et = 0x0800 if fr and fr[0] >> 4 == 4 else 0x86DD
        off = 0
    else:
        return None
    if et == 0x0800:
        ip = fr[off:]
        if len(ip) < 20:
            return None
        ihl = (ip[0] & 15) * 4
        proto = ip[9]
        total = struct.unpack("!H", ip[2:4])[0]
        src, dst = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
        l4 = ip[ihl:total] if total >= ihl else ip[ihl:]
    elif et == 0x86DD:
        ip = fr[off:]
        if len(ip) < 40:
            return None
        proto = ip[6]
        src, dst = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
        l4 = ip[40:40 + struct.unpack("!H", ip[4:6])[0]]
    else:
        return None
    if proto == 6 and len(l4) >= 20:
        sp, dp = struct.unpack("!HH", l4[:4])
        return smac, dmac, src, dst, "tcp", sp, dp, l4[(l4[12] >> 4) * 4:]
    if proto == 17 and len(l4) >= 8:
        sp, dp = struct.unpack("!HH", l4[:4])
        return smac, dmac, src, dst, "udp", sp, dp, l4[8:]
    return None


def classify(pl):
    out = []
    head = pl[:4096]
    m = HTTPREQ.match(head)
    if m:
        out.append(("http_request", m.group(1).decode()))
    for m in AUTHZ.finditer(head):
        out.append(("authorization", m.group(1).decode(errors="replace").lower()))
    if COOKIE.search(head):
        out.append(("cookie", ""))
    for m in KEYED.finditer(head):
        name = m.group(1).decode(errors="replace").lower()
        # "SID:" at the start of a header line is the UPnP GENA subscription
        # identifier (UPnP Device Architecture 4.1), not a session secret.
        if name == "sid" and (m.start(1) == 0 or head[m.start(1) - 1:m.start(1)] == b"\n"):
            continue
        out.append(("secret_key", name))
    if PROMPT.search(head[-64:]):
        out.append(("login_prompt", PROMPT.search(head[-64:]).group(1).decode().lower()))
    m = FTP.match(head)
    if m:
        out.append(("ftp_" + m.group(1).decode().lower(), ""))
    if len(pl) > 10 and pl[0] == 0x10:
        # MQTT CONNECT: fixed header, remaining length (1-4 bytes), protocol name, level, flags
        i = 1
        while i < 5 and pl[i] & 0x80:
            i += 1
        i += 1
        n = struct.unpack("!H", pl[i:i + 2])[0] if len(pl) >= i + 2 else 0
        if pl[i + 2:i + 2 + n] in (b"MQTT", b"MQIsdp") and len(pl) > i + 3 + n:
            flags = pl[i + 3 + n]
            out.append(("mqtt_connect", f"user={bool(flags & 0x80)},pass={bool(flags & 0x40)}"))
    for m in CTYPE.finditer(head):
        out.append(("media_content_type", m.group(1).decode().lower()))
    for rx, name in MEDIA:
        if rx.search(pl):
            out.append(("media_signature", name))
    return out


def main():
    path, out = sys.argv[1:3]
    seen = {}
    for ts, lt, fr in packets(path):
        p = parse(lt, fr)
        if not p or not p[7]:
            continue
        pl = p[7]
        # TLS records are opaque; skip them so random bytes cannot match.
        if len(pl) > 5 and 0x14 <= pl[0] <= 0x17 and pl[1] == 3:
            continue
        if not PRE.search(pl):
            continue
        for cls, name in classify(pl):
            k = p[:5] + (p[6], cls, name)  # per destination port, not per connection
            if k in seen:
                seen[k]["n"] += 1
            else:
                seen[k] = {"ts": round(ts, 6), "src_mac": p[0], "dst_mac": p[1], "src_ip": p[2], "dst_ip": p[3],
                           "proto": p[4], "sport": p[5], "dport": p[6], "cls": cls, "name": name, "n": 1}
    with open(out, "w") as f:
        for r in seen.values():
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()
