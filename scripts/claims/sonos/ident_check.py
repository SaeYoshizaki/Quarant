#!/usr/bin/env python3
"""Do the identifiers in Sonos's plaintext metrics XML match those in the plaintext update URLs?

Usage: ident_check.py <day dir>...
Reads tcp/80 payloads to the internet, collects the values of the update URL parameters (serial, householdid, sonosid)
and of short XML elements in the metrics POST, and prints only lengths and which ones are equal. No value is printed.
"""
import collections, glob, os, re, subprocess, sys, urllib.parse
for day in sys.argv[1:]:
    url_vals = collections.defaultdict(set); xml_vals = collections.defaultdict(set); posts = 0
    for f in sorted(x for x in glob.glob(os.path.join(day, 'eth*')) if not x.endswith('.frames')):
        p = subprocess.run(['tshark', '-r', f, '-Y', 'tcp.dstport==80 && tcp.len>0 && !(ip.dst==192.168.0.0/16)', '-T', 'fields', '-e', 'tcp.payload'], capture_output=True, text=True)
        for line in p.stdout.splitlines():
            b = bytes.fromhex(line.replace(':', '')).decode('latin-1')
            m = re.match(r'GET (\S+) HTTP', b)
            if m:
                q = urllib.parse.parse_qs(urllib.parse.urlparse(m.group(1)).query)
                for k in ('serial', 'householdid', 'sonosid', 'hhid'):
                    for v in q.get(k, []): url_vals[k].add(v)
            if '<UsageMetrics' in b or '<hh>' in b or '<sn>' in b:
                posts += 1
                for tag in ('hh', 'sn', 'md', 'ver', 'cu'):
                    for v in re.findall(r'<%s>([^<]{1,80})</%s>' % (tag, tag), b): xml_vals[tag].add(v)
    print('==', os.path.basename(day), 'metrics bodies seen', posts)
    print('   url params (distinct values, lengths):', {k: (len(v), sorted({len(x) for x in v})) for k, v in url_vals.items()})
    print('   xml elements (distinct values, lengths):', {k: (len(v), sorted({len(x) for x in v})) for k, v in xml_vals.items()})
    for xt in xml_vals:
        for uk in url_vals:
            if xml_vals[xt] & url_vals[uk]: print(f'   xml <{xt}> shares a value with url {uk}')
    for a in url_vals:
        for b in url_vals:
            if a < b and url_vals[a] & url_vals[b]: print(f'   url {a} shares a value with url {b}')
