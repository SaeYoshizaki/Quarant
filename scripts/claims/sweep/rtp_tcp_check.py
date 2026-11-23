#!/usr/bin/env python3
"""RTP carried over TCP (RFC 4571, 2-byte length before each packet): is the H.264 inside readable?

usage: rtp_tcp_check.py <capture> <camera ip> <camera tcp port>

For every TCP connection to <camera ip>:<port>, the bytes the camera sent are put together (tshark follow),
split on the 2-byte lengths, and each piece is checked: RTP version 2, payload type, and for H.264 (the
dynamic type with most packets) the NAL unit type of the payload: SPS 7, PPS 8, IDR 5, non-IDR 1, FU-A 28.
Readable H.264 shows SPS/PPS and forbidden bit 0 in every packet; encrypted payload shows random types.
"""
import collections
import re
import subprocess
import sys

cap, ip, port = sys.argv[1], sys.argv[2], sys.argv[3]
rows = subprocess.run(["tshark", "-r", cap, "-n", "-Y", f"ip.addr=={ip} && tcp.port=={port} && tcp.flags.syn==1 && tcp.flags.ack==0",
                       "-T", "fields", "-e", "tcp.stream", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "tcp.srcport"],
                      capture_output=True, text=True).stdout.splitlines()
import datetime as dt
for line in rows:
    sid, t, src, sp = line.split("\t")
    raw = subprocess.run(["tshark", "-r", cap, "-q", "-z", f"follow,tcp,raw,{sid}"], capture_output=True, text=True).stdout
    # follow output: lines starting with a tab are from the second host (the server, here the camera)
    cam = b"".join(bytes.fromhex(l.strip()) for l in raw.splitlines() if l.startswith("\t") and re.fullmatch(r"\t[0-9a-f]+", l))
    i, pts, nal, forb, n, stun = 0, collections.Counter(), collections.Counter(), 0, 0, 0
    while i + 2 <= len(cam):
        ln = int.from_bytes(cam[i:i + 2], "big"); pkt = cam[i + 2:i + 2 + ln]; i += 2 + ln
        if len(pkt) < ln or ln == 0:
            break
        if pkt[0] >> 6 == 2 and len(pkt) > 12:
            n += 1
            pt = pkt[1] & 0x7f
            pts[pt] += 1
            if pt >= 96:
                b = pkt[12]
                forb += b >> 7
                nal[b & 0x1f] += 1
        elif len(pkt) >= 20 and pkt[4:8] == b"\x21\x12\xa4\x42":
            stun += 1
    when = dt.datetime.fromtimestamp(float(t), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"{when} {src}:{sp} -> {ip}:{port} camera bytes {len(cam)}, STUN {stun}, RTP {n}, PT {dict(pts.most_common(3))}, "
          f"H.264 NAL {dict(nal.most_common(6))}, forbidden bit set {forb}")
