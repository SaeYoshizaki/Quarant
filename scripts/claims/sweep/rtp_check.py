#!/usr/bin/env python3
"""Tell plain RTP from SRTP for the UDP streams a device sends to public addresses.

usage: rtp_check.py <device mac> <capture>...

SRTP encrypts the RTP payload but leaves the RTP header in the clear, so the header alone does
not tell. The first payload bytes do: for H.264 (RFC 6184) the first byte is a NAL unit header
whose forbidden bit is 0 and whose type is 1-23, 24 (STAP-A) or 28 (FU-A); for an FU-A the second
byte holds the type of the fragmented unit (1 or 5 for slices). Encrypted payloads give these
bits at random: the forbidden bit is set in about half of the packets and the types spread over
0-31. For each stream (destination address and port) with at least 200 packets that look like
RTP version 2, prints the payload types, the share of packets whose first payload byte has the
forbidden bit set, the most common NAL types and FU-A types, and the first frame.
"""
import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from expose import frames, l3, l4, ipstr, public  # noqa: E402


def payload(pl):
    """(payload type, payload bytes) of an RTP version 2 packet, or None."""
    if len(pl) < 14 or pl[0] >> 6 != 2:
        return None
    cc, ext, pt = pl[0] & 0x0F, pl[0] & 0x10, pl[1] & 0x7F
    i = 12 + 4 * cc
    if ext:
        if len(pl) < i + 4:
            return None
        i += 4 + 4 * struct.unpack("!H", pl[i + 2:i + 4])[0]
    if pl[0] & 0x20 and pl:                       # padding
        pl = pl[:len(pl) - pl[-1]]
    return pt, pl[i:]


def main():
    mac, paths = sys.argv[1].lower(), sys.argv[2:]
    macb = bytes.fromhex(mac.replace(":", ""))
    st = collections.defaultdict(lambda: {"n": 0, "rtp": 0, "pt": collections.Counter(), "forbidden": 0,
                                          "nal": collections.Counter(), "fu": collections.Counter(), "frame": None})
    for path in paths:
        with open(path, "rb", buffering=16 << 20) as f:
            for n, (ts, lt, fr) in enumerate(frames(f), 1):
                x = l3(lt, fr)
                if not x or x[0] != macb:
                    continue
                p = l4(x[2], fr, x[3])
                if not p or p[2] != "udp" or not public(p[1]):
                    continue
                key = (ipstr(p[1]), p[4], Path(path).name)
                s = st[key]
                s["n"] += 1
                r = payload(p[7])
                if not r or not r[1]:
                    continue
                pt, body = r
                s["rtp"] += 1
                s["pt"][pt] += 1
                if s["frame"] is None:
                    s["frame"] = n
                b0 = body[0]
                s["forbidden"] += b0 >> 7
                s["nal"][b0 & 0x1F] += 1
                if b0 & 0x1F == 28 and len(body) > 1:
                    s["fu"][body[1] & 0x1F] += 1
    for (ip, port, name), s in sorted(st.items(), key=lambda kv: -kv[1]["rtp"]):
        if s["rtp"] < 200:
            continue
        print(f"{name} -> {ip}:{port} packets {s['n']}, RTP-like {s['rtp']}, first frame {s['frame']}")
        print(f"   payload types {dict(s['pt'].most_common(4))}; forbidden bit set {100 * s['forbidden'] / s['rtp']:.1f}%")
        print(f"   NAL types {dict(s['nal'].most_common(6))}; FU-A types {dict(s['fu'].most_common(4))}")


if __name__ == "__main__":
    main()
