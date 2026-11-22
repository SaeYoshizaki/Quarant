#!/usr/bin/env python3
"""Check whether a Nest device's Weave messages on tcp/11095 are encrypted, from their headers.

usage: weave_check.py <device mac> <capture>...

Weave over TCP (openweave-core, WeaveMessageLayer): each message is preceded by its length
(2 bytes, little-endian, not counting the length itself). The message starts with the header
field (2 bytes, little-endian: flags 0x0F0F, encryption type 0x00F0, version 0xF000), the
message id (4 bytes), the source node id (8 bytes, flag 0x0200), the destination node id
(8 bytes, flag 0x0100) and, when encrypted, the key id (2 bytes). Encryption type 0 is none,
1 is AES-128-CTR with an HMAC-SHA-1 integrity check.

Only connections whose SYN was captured are read, from their first byte. A direction counts
as Weave only when its messages chain from the first byte to the end of what was captured
(no gap). Prints, per direction: the number of messages by version and encryption type, the
key ids, the node ids seen in the clear, and for unencrypted messages the profile id of the
exchange header (4 is the security profile, used to set up a session).
"""
import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from expose import frames, l3, l4, ipstr  # noqa: E402

PORT = 11095
MAX = 4 << 20   # bytes kept per direction


def streams(paths, mac):
    """(client, server, upstream bytes, downstream bytes, first frame, file) for each connection."""
    macb = bytes.fromhex(mac.replace(":", ""))
    conns = {}
    for path in paths:
        with open(path, "rb", buffering=16 << 20) as f:
            for n, (ts, lt, fr) in enumerate(frames(f), 1):
                x = l3(lt, fr)
                if not x or macb not in (x[0], x[1]):
                    continue
                p = l4(x[2], fr, x[3])
                if not p or p[2] != "tcp" or PORT not in (p[3], p[4]):
                    continue
                src, dst, _, sp, dp, seq, flags, pl = p
                up = dp == PORT
                key = (src, sp, dst, dp) if up else (dst, dp, src, sp)
                c = conns.get(key)
                if flags & 0x02 and not flags & 0x10:          # SYN from the device
                    c = conns[key] = {"isn": [seq + 1, None], "seg": [{}, {}], "frame": n, "file": Path(path).name}
                    continue
                if c is None:
                    continue
                d = 0 if up else 1
                if flags & 0x12 == 0x12:                       # SYN-ACK
                    c["isn"][1] = seq + 1
                    continue
                if pl and c["isn"][d] is not None:
                    off = (seq - c["isn"][d]) & 0xFFFFFFFF
                    if off < MAX:
                        c["seg"][d].setdefault(off, pl)
    for (cip, cp, sip, sp), c in conns.items():
        out = []
        for d in (0, 1):
            buf, pos = bytearray(), 0
            for off in sorted(c["seg"][d]):
                pl = c["seg"][d][off]
                if off > pos:
                    break                                      # gap: stop here
                buf += pl[pos - off:]
                pos = len(buf)
            out.append(bytes(buf))
        yield ipstr(cip), ipstr(sip), out[0], out[1], c["frame"], c["file"]


def messages(buf):
    """Weave messages of one direction, and whether they chain to the end."""
    out, i = [], 0
    while i + 2 <= len(buf):
        ln = struct.unpack("<H", buf[i:i + 2])[0]
        if ln < 6 or i + 2 + ln > len(buf):
            break
        out.append(buf[i + 2:i + 2 + ln])
        i += 2 + ln
    return out, i == len(buf)


def header(m):
    hf, mid = struct.unpack("<HI", m[:6])
    ver, enc, flags = hf >> 12, (hf >> 4) & 0xF, hf & 0x0F0F
    i, src, dst, key = 6, None, None, None
    if flags & 0x0200:
        src = struct.unpack("<Q", m[i:i + 8])[0]
        i += 8
    if flags & 0x0100:
        dst = struct.unpack("<Q", m[i:i + 8])[0]
        i += 8
    if enc:
        key = struct.unpack("<H", m[i:i + 2])[0]
        i += 2
    profile = None
    if not enc and len(m) >= i + 8:
        profile = struct.unpack("<I", m[i + 4:i + 8])[0]
    return ver, enc, src, dst, key, profile


def main():
    mac, paths = sys.argv[1].lower(), sys.argv[2:]
    stats = {d: collections.Counter() for d in ("up", "down")}
    keys, nodes, profiles = collections.Counter(), collections.Counter(), collections.Counter()
    chained = collections.Counter()
    first_enc = None
    for cip, sip, up, down, frame, name in streams(paths, mac):
        for d, buf in (("up", up), ("down", down)):
            if not buf:
                continue
            msgs, ok = messages(buf)
            chained[(d, ok)] += 1
            if not ok:
                continue
            for m in msgs:
                ver, enc, src, dst, key, profile = header(m)
                stats[d][(ver, enc)] += 1
                if key is not None:
                    keys[key] += 1
                for nid in (src, dst):
                    if nid:
                        nodes[f"{nid:016X}"] += 1
                if not enc:
                    profiles[(d, profile)] += 1
                elif first_enc is None:
                    first_enc = (name, frame, sip)
    print("directions that chain from the first byte to the end (True) or not:", dict(chained))
    for d in ("up", "down"):
        print(d, "messages by (version, encryption type):", dict(stats[d]))
    print("key ids:", dict(keys.most_common(5)))
    print("node ids in the clear:", dict(nodes.most_common(6)))
    print("profile ids of unencrypted messages:", dict(profiles.most_common(8)))
    print("first connection with encrypted messages (file, SYN frame, server):", first_enc)


if __name__ == "__main__":
    main()
