#!/usr/bin/env python3
"""Software and firmware version strings that the dataset's devices sent in plaintext.

Usage: versions.py <devices.tsv> <dataset> <pcap or -> <out.json>

Looks only at plaintext fields that usually carry a version: the HTTP
User-Agent (device as client) and Server (device as server) headers, the
SSDP SERVER and USER-AGENT headers, URL parameters whose name mentions a
version (version, ver, fw, firmware, swversion, build), version fields in
JSON or XML bodies that the device sent (swversion, firmwareVersion,
softwareVersion and the like), the DHCP vendor class
(option 60), and mDNS TXT entries whose key mentions a version. Identifiers
inside the values (UUIDs, MAC addresses, long hex strings) are replaced
with ***. Writes, per device, each (source, field, value) with a count and
the first and last capture time. TLS hides all of this, so a device that
speaks only TLS shows no version here.
"""
import collections
import csv
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "accuracy"))
from rawscan import packets, parse  # noqa: E402

REQ = re.compile(rb"^(GET|POST|PUT|HEAD|NOTIFY|M-SEARCH|SUBSCRIBE) (\S+) HTTP/1\.[01]\r\n")
RESP = re.compile(rb"^HTTP/1\.[01] \d{3}")
HDR = re.compile(rb"^(user-agent|server|x-user-agent):[ \t]*([^\r\n]{1,200})", re.I | re.M)
BODY = re.compile(rb'"((?:sw|fw|api|firmware|software|app)_?version|firmware_?rev(?:ision)?)"\s*:\s*"([^"]{1,40})"'
                  rb"|<((?:firmware|software)Version|fwVersion|swVersion)>([^<\r\n]{1,40})</", re.I)
VER_KEY = re.compile(r"(?i)^(.*ver(sion)?|fw|firmware.*|sw.*ver.*|build|srcvers|osxvers|vs|ve|bs|fv)$")
MASK = [re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
        re.compile(r"(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b"),
        re.compile(r"(?i)\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{12,}\b")]


def mask(v):
    for rx in MASK:
        v = rx.sub("***", v)
    return v


def dhcp_vendor_class(pl):
    if len(pl) < 240 or pl[236:240] != b"\x63\x82\x53\x63":
        return None
    i = 240
    while i < len(pl) and pl[i] != 255:
        if pl[i] == 0:
            i += 1
            continue
        code, n = pl[i], pl[i + 1] if i + 1 < len(pl) else 0
        if code == 60:
            return pl[i + 2:i + 2 + n].decode("ascii", "replace")
        i += 2 + n
    return None


def dns_name(pl, i):
    """Skip a (possibly compressed) DNS name; return the offset after it."""
    while i < len(pl):
        n = pl[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n
    return i


def mdns_txt(pl):
    """TXT strings of every TXT record in an mDNS message."""
    if len(pl) < 12:
        return
    qd, an, ns, ar = struct.unpack("!HHHH", pl[4:12])
    i = 12
    for _ in range(qd):
        i = dns_name(pl, i) + 4
    for _ in range(an + ns + ar):
        i = dns_name(pl, i)
        if i + 10 > len(pl):
            return
        rtype, _, _, rdlen = struct.unpack("!HHIH", pl[i:i + 10])
        i += 10
        if rtype == 16:
            j, end = i, i + rdlen
            while j < end and j < len(pl):
                n = pl[j]
                yield pl[j + 1:j + 1 + n].decode("utf-8", "replace")
                j += 1 + n
        i += rdlen


def main():
    devices_tsv, dataset, pcap, out = sys.argv[1:5]
    label = {r["mac"]: r["label"] for r in csv.DictReader(open(devices_tsv), delimiter="\t")
             if r["dataset"] == dataset and r["mac"] not in ("", "-")}
    seen = collections.defaultdict(lambda: {"count": 0, "first": None, "last": None})

    def add(mac, source, field, value, ts):
        value = mask(value.strip())
        if not value or not re.search(r"\d", value):
            return
        s = seen[(label[mac], source, field, value)]
        s["count"] += 1
        s["first"] = ts if s["first"] is None else min(s["first"], ts)
        s["last"] = ts if s["last"] is None else max(s["last"], ts)

    for ts, lt, fr in packets("/dev/stdin" if pcap == "-" else pcap):
        p = parse(lt, fr)
        if not p or not p[7] or p[0] not in label:
            continue
        mac, _, _, _, proto, sp, dp, pl = p
        if proto == "udp" and sp == 68 and dp == 67:
            v = dhcp_vendor_class(pl)
            if v:
                add(mac, "dhcp", "vendor-class", v, ts)
            continue
        if proto == "udp" and sp == 5353:
            for t in mdns_txt(pl):
                k, _, v = t.partition("=")
                if v and VER_KEY.match(k):
                    add(mac, "mdns", k, v, ts)
            continue
        head = pl[:2048]
        m = REQ.match(head)
        if m or RESP.match(head):
            source = "ssdp" if proto == "udp" else "http-request" if m else "http-response"
            for hm in HDR.finditer(head):
                add(mac, source, hm.group(1).decode().lower(), hm.group(2).decode("latin-1"), ts)
            for bm in BODY.finditer(pl):
                k, v = (bm.group(1), bm.group(2)) if bm.group(1) else (bm.group(3), bm.group(4))
                add(mac, "body", k.decode("latin-1"), v.decode("latin-1"), ts)
            if m and b"?" in m.group(2):
                for kv in m.group(2).split(b"?", 1)[1].split(b"&"):
                    k, _, v = kv.decode("latin-1").partition("=")
                    if v and VER_KEY.match(k):
                        add(mac, "url", k, v, ts)
    rows = [{"label": k[0], "source": k[1], "field": k[2], "value": k[3], **v} for k, v in sorted(seen.items())]
    json.dump(rows, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
