#!/usr/bin/env python3
"""Quick view of each device's plaintext HTTP to the internet from gt.log: hosts, parameter names and body key names only.

Usage: triage_http.py <gt-yt dir> <label=mac> ...
Skips LAN peers and the dataset's scanner. Prints counts and names, never values.
"""
import collections, glob, json, os, sys
root = sys.argv[1]
devs = dict(a.split('=', 1) for a in sys.argv[2:])
stat = {k: dict(n=0, hosts=collections.Counter(), params=collections.Counter(), body=collections.Counter(), resp=collections.Counter(), withbody=0, nobody=0, days=set()) for k in devs}
mac2 = {v: k for k, v in devs.items()}
for f in sorted(glob.glob(os.path.join(root, 'yt-2018*/gt.log'))):
    day = f.split('/')[-2][3:]
    for l in open(f, errors='replace'):
        if '"kind":"http"' not in l: continue
        hit = next((m for m in mac2 if m in l), None)
        if not hit: continue
        d = json.loads(l)
        if d.get('orig_mac') != hit: continue
        if d.get('resp_h', '').startswith(('192.168.', '10.', '224.', '239.', '255.')): continue
        s = stat[mac2[hit]]; s['n'] += 1; s['days'].add(day)
        s['hosts'][d.get('host', '')[:40]] += 1
        for p in d.get('uri_params', []): s['params'][p] += 1
        for k in d.get('req_body_keys', []): s['body'][k] += 1
        for k in d.get('resp_body_keys', []): s['resp'][k] += 1
        if d.get('req_body_len', 0): s['withbody'] += 1
        else: s['nobody'] += 1
for k, s in stat.items():
    print(f"== {k}: {s['n']} plaintext requests to the internet on {len(s['days'])} days; with body {s['withbody']}")
    print('   hosts:', dict(s['hosts'].most_common(6)))
    print('   uri params:', dict(s['params'].most_common(12)))
    print('   request body keys:', dict(s['body'].most_common(12)))
    print('   response body keys:', dict(s['resp'].most_common(10)))
