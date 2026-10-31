#!/usr/bin/env python3
"""Classify every flow of the dataset's devices as encrypted, plaintext or unknown.

Usage: flowscan.py <devices.tsv> <dataset> <pcap or -> <out.jsonl>

Covers all TCP and UDP traffic, not only HTTP, TLS and FTP (those come from
Zeek in observations.py). Each flow (5-tuple, both directions) is labelled
from the first payload bytes of each direction:
- by structure: TLS, DTLS, QUIC, SSH, HTTP, RTSP, SSDP, MQTT, STUN, the
  TP-Link LAN protocol (XOR obfuscation of JSON), LIFX LAN;
- by port, for network services that are plaintext by design: DNS, mDNS,
  NTP, DHCP, NetBIOS, LLMNR;
- otherwise by the bytes: mostly printable text, or high entropy (likely
  encrypted or compressed; inferred, not observed), or neither. Entropy is
  judged per packet (the first 200 payload packets of each direction of at
  least 64 bytes; "high" when 80% of them are), since protocol headers in a
  joined sample pull it down, and long-lived connections open with a
  handshake that is not random (Nest's tcp/11095).
A flow seen from the middle (begun before the capture) is still found to be
TLS when one of its first packets starts with a TLS record header.
Only labels, counts and entropy are written, never payload bytes. Flows are
grouped per device, peer, protocol, server port and label.
"""
import collections
import csv
import json
import math
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "accuracy"))
from rawscan import packets, parse  # noqa: E402

SAMPLE = 1024           # payload bytes kept per direction, for labelling only
FIRST = 20              # payload packets per direction checked for a TLS record header
ENTROPY_PACKETS = 200   # payload packets per direction whose entropy is measured
IDLE = {"tcp": 300, "udp": 60}
PORT_LABEL = {53: "dns", 5353: "mdns", 123: "ntp", 67: "dhcp", 68: "dhcp", 137: "netbios", 138: "netbios",
              5355: "llmnr", 547: "dhcp", 546: "dhcp"}
HTTP = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|SUBSCRIBE|UNSUBSCRIBE|NOTIFY|M-SEARCH) \S+ HTTP/1\.[01]\r?\n|^HTTP/1\.[01] \d{3}")
RTSP = re.compile(rb"^(OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|ANNOUNCE|RECORD|GET_PARAMETER|SET_PARAMETER) rtsp://|^RTSP/1\.0 \d{3}")
ENCRYPTED = {"tls", "dtls", "quic", "ssh", "high-entropy"}
PLAINTEXT = {"http", "rtsp", "ssdp", "mqtt", "stun", "tplink-xor", "lifx", "text", "dns", "mdns", "ntp", "dhcp",
             "netbios", "llmnr"}


def private(ip):
    if ":" in ip:
        return ip.startswith(("fe80", "fd", "fc", "ff")) or ip == "::1"
    a, b = (int(x) for x in ip.split(".")[:2])
    return a in (10, 127, 0) or a >= 224 or (a == 172 and 16 <= b < 32) or (a == 192 and b == 168) or (a == 169 and b == 254) \
        or ip == "255.255.255.255"


def entropy(b):
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def tplink(b, tcp):
    """TP-Link LAN protocol: JSON XORed with an autokey starting at 171 (4-byte length prefix on TCP)."""
    if tcp:
        b = b[4:]
    k, out = 171, bytearray()
    for x in b[:2]:
        out.append(x ^ k)
        k = x
    return bytes(out) == b'{"'


def high(pl):
    """A uniform source of n bytes cannot exceed log2(min(n, 256)) bits; 90% of that is "high"."""
    return entropy(pl) / math.log2(min(len(pl), 256)) >= 0.9


def label(f):
    up, down = bytes(f["s"][0]), bytes(f["s"][1])
    tcp = f["proto"] == "tcp"
    if f["tls_rec"]:
        return "tls"
    for b in (up, down):
        if len(b) >= 3 and b[0] in (0x14, 0x15, 0x16, 0x17) and b[1] == 3 and b[2] <= 4:
            return "tls"
        if len(b) >= 3 and b[0] in (0x14, 0x15, 0x16, 0x17) and b[1] == 0xFE and b[2] in (0xFD, 0xFF):
            return "dtls"
        if b.startswith(b"SSH-"):
            return "ssh"
    for b in (up, down):
        # HTTP over UDP is SSDP (M-SEARCH, NOTIFY and their unicast replies)
        if b.startswith((b"M-SEARCH * HTTP", b"NOTIFY * HTTP")) or (not tcp and HTTP.match(b)):
            return "ssdp"
        if HTTP.match(b):
            return "http"
        if RTSP.match(b):
            return "rtsp"
        if len(b) > 8 and b[0] == 0x10 and (b"MQTT" in b[2:10] or b"MQIsdp" in b[2:10]):
            return "mqtt"
        if len(b) >= 20 and b[4:8] == b"\x21\x12\xa4\x42":
            return "stun"
    if f["sport"] == 9999 and up and tplink(up, tcp):
        return "tplink-xor"
    if not tcp and f["sport"] == 56700:
        return "lifx"
    if f["sport"] in PORT_LABEL:
        return PORT_LABEL[f["sport"]]
    if not tcp and f["sport"] == 443 and up and up[0] & 0x80:
        return "quic"
    b = up + down
    if not b:
        return "no-payload"
    if len(b) < 32:
        return "too-short"
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)
    if printable >= 0.85:
        return "text"
    big, hi = f["big"], f["hi"]
    return "high-entropy" if big >= 3 and hi >= 0.8 * big else "low-entropy-binary"


def main():
    devices_tsv, dataset, pcap, out = sys.argv[1:5]
    macs = {r["mac"]: r["label"] for r in csv.DictReader(open(devices_tsv), delimiter="\t")
            if r["dataset"] == dataset and r["mac"] not in ("", "-")}
    flows = {}
    groups = collections.defaultdict(lambda: {"flows": 0, "pkts": 0, "bytes": 0, "first": None, "last": None})

    def close(k, f):
        lab = label(f)
        cls = "encrypted" if lab in ENCRYPTED else "plaintext" if lab in PLAINTEXT else "unknown"
        for dev, peer, role in ((f["cmac"], f["smac"], "client"), (f["smac"], f["cmac"], "server")):
            if dev not in macs:
                continue
            peer_ip = f["sip"] if role == "client" else f["cip"]
            g = groups[(dev, peer if peer in macs else "", peer_ip, role, f["proto"], f["sport"], lab, cls)]
            g["flows"] += 1
            g["pkts"] += f["pkts"]
            g["bytes"] += f["bytes"]
            g["first"] = f["first"] if g["first"] is None else min(g["first"], f["first"])
            g["last"] = f["last"] if g["last"] is None else max(g["last"], f["last"])

    src = "/dev/stdin" if pcap == "-" else pcap
    next_sweep = None
    for ts, lt, fr in packets(src):
        p = parse(lt, fr)
        if not p or (p[0] not in macs and p[1] not in macs):
            continue
        smac, dmac, sip, dip, proto, sp, dp, pl = p
        k = (proto, sip, sp, dip, dp)
        rk = (proto, dip, dp, sip, sp)
        f = flows.get(k)
        d = 0
        if f is None:
            f = flows.get(rk)
            d = 1
        if f is None:
            # The server is the side that receives the first packet, unless the
            # flow started before the capture and only the other side has a well-known port.
            if dp < 1024 or dp in PORT_LABEL or sp >= 1024:
                f = {"cmac": smac, "smac": dmac, "cip": sip, "sip": dip, "sport": dp}
                flows[k], d = f, 0
            else:
                f = {"cmac": dmac, "smac": smac, "cip": dip, "sip": sip, "sport": sp}
                flows[rk], d = f, 1
            f.update(proto=proto, first=ts, last=ts, pkts=0, bytes=0, s=(bytearray(), bytearray()), n=[0, 0],
                     big=0, hi=0, tls_rec=False)
        f["last"] = ts
        f["pkts"] += 1
        f["bytes"] += len(pl)
        s = f["s"][d]
        if pl and len(s) < SAMPLE:
            s += pl[:SAMPLE - len(s)]
        if pl and f["n"][d] < ENTROPY_PACKETS:
            f["n"][d] += 1
            if f["n"][d] <= FIRST and len(pl) >= 5 and pl[0] in (0x16, 0x17) and pl[1] == 3 and 1 <= pl[2] <= 4:
                f["tls_rec"] = True
            if len(pl) >= 64:
                f["big"] += 1
                f["hi"] += high(pl)
        if next_sweep is None:
            next_sweep = ts + 60
        elif ts >= next_sweep:
            for kk in [kk for kk, ff in flows.items() if ts - ff["last"] > IDLE[ff["proto"]]]:
                close(kk, flows.pop(kk))
            next_sweep = ts + 60
    for kk, ff in flows.items():
        close(kk, ff)
    with open(out, "w") as w:
        for (dev, peer, peer_ip, role, proto, port, lab, cls), g in sorted(groups.items()):
            w.write(json.dumps({"mac": dev, "label": macs[dev], "peer_mac": peer, "peer_ip": peer_ip,
                                "external": not private(peer_ip), "role": role, "proto": proto, "port": port,
                                "kind": lab, "class": cls, **g}) + "\n")


if __name__ == "__main__":
    main()
