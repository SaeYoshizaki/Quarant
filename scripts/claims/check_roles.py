#!/usr/bin/env python3
"""Check flowscan.py's client/server guess against Zeek, where Zeek saw the TCP handshake.

Usage: check_roles.py <per-flow.tsv from flowscan.py> <Zeek conn.log> [<out examples.tsv>]

For TCP connections whose Zeek history starts with "S" (the originator's
SYN was seen), the originator is the client for certain. Each such
connection is matched to the flowscan flow with the same addresses and ports
that started closest in time, and the two guesses are compared. Prints the
agreement for flows with a handshake, and how many flows had none (begun
before the capture; the guess there cannot be checked this way).
"""
import collections
import json
import sys


def main():
    per_flow, conn_log = sys.argv[1:3]
    flows = collections.defaultdict(list)
    for line in open(per_flow):
        proto, cip, cport, sip, sport, first, lab = line.rstrip("\n").split("\t")
        if proto != "tcp":
            continue
        key = frozenset(((cip, int(cport)), (sip, int(sport))))
        flows[key].append((float(first), (cip, int(cport)), lab))
    agree = disagree = 0
    wrong = collections.Counter()
    for line in open(conn_log):
        c = json.loads(line)
        if c.get("proto") != "tcp" or not c.get("history", "").startswith("S"):
            continue
        orig = (c["id.orig_h"], c["id.orig_p"])
        key = frozenset((orig, (c["id.resp_h"], c["id.resp_p"])))
        cands = flows.get(key)
        if not cands:
            continue
        first, client, lab = min(cands, key=lambda x: abs(x[0] - c["ts"]))
        if abs(first - c["ts"]) > 5:
            continue
        if client == orig:
            agree += 1
        else:
            disagree += 1
            wrong[(lab, c["id.resp_p"])] += 1
    total = sum(len(v) for v in flows.values())
    print(f"TCP flows in flowscan: {total}; matched to a Zeek connection with a SYN: {agree + disagree}")
    print(f"client guessed right: {agree}, wrong: {disagree}")
    for (lab, port), n in wrong.most_common(10):
        print(f"  wrong: {n} flows, label {lab}, Zeek responder port {port}")


if __name__ == "__main__":
    main()
