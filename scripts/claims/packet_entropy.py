#!/usr/bin/env python3
"""Per-packet entropy of one device's traffic on one port, for protocols that flowscan.py cannot name.

Usage: packet_entropy.py <pcap or -> <out.json> <mac>@<port> [<mac>@<port> ...]

For each direction, counts the payload packets of at least 64 bytes whose
byte entropy is "high" (90% of the maximum for their length, as in
flowscan.py). A protocol whose packets are almost all high is likely
encrypted (or compressed): an inference, not an observation. Only counts
are written, never payload bytes.
"""
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "accuracy"))
from flowscan import high  # noqa: E402
from rawscan import packets, parse  # noqa: E402


def main():
    pcap, out = sys.argv[1:3]
    want = collections.defaultdict(set)
    for a in sys.argv[3:]:
        m, p = a.split("@")
        want[m].add(int(p))
    c = collections.defaultdict(collections.Counter)
    for _, lt, fr in packets("/dev/stdin" if pcap == "-" else pcap):
        p = parse(lt, fr)
        if not p or len(p[7]) < 64:
            continue
        smac, dmac, _, _, proto, sp, dp, pl = p
        for m, port, d in ((smac, dp, "from device"), (dmac, sp, "to device")):
            if port in want.get(m, ()):
                k = f"{m}@{port}/{proto} {d}"
                c[k]["packets"] += 1
                c[k]["high"] += high(pl)
    json.dump({k: dict(v) for k, v in sorted(c.items())}, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
