# Per host and per path view of http_scan.py's output. Prints no values beyond what the scan kept. usage: summary.py <http-*.tsv>...
import csv, collections, sys, time
T = lambda t: time.strftime('%m-%d %H:%M:%S', time.gmtime(float(t)))
for tsv in sys.argv[1:]:
    rows = list(csv.DictReader(open(tsv), delimiter='\t'))
    print('=====', tsv.split('/')[-1], 'rows', len(rows))
    req = [r for r in rows if r['kind'] == 'req']
    bydst = collections.Counter(('LAN' if r['dst'].startswith('192.168.') and r['src'].startswith('192.168.') else 'WAN', r['src'], r['host'][:40], r['code_or_method'], r['path'][:70], r['query'][:110]) for r in req)
    keep = {}
    for r in req:
        keep.setdefault((r['host'][:40], r['code_or_method'], r['path'][:70]), r)
    agg = collections.Counter((('LAN' if r['dst'].startswith('192.168.') else 'WAN'), r['src'] if r['dst'].startswith('192.168.') else '-', r['dst'] if r['dst'].startswith('192.168.') else '-', r['host'][:40], r['code_or_method'], r['path'][:70]) for r in req)
    for k, v in agg.most_common(30):
        ex = keep[(k[3], k[4], k[5])]
        print(' ', v, k, 'q:', ex['query'][:110], 'auth:', ex['auth'][:50], 'ua:', ex['ua'][:50], 'hdrs:', ex['hdr_names'][:80], 'ctype:', ex['ctype'][:30], 'body:', ex['body_kind'], ex['body_len'], ex['body_entropy'], 'pr', ex['printable'], 'keys:', ex['body_keys'][:80], '| first', ex['file'][5:18], ex['frame'])
    print('  auth labels', collections.Counter(r['auth'].split(':')[0] + ':' + r['auth'].split(':')[1] for r in req if r['auth']).most_common(8))
    print('  codes', collections.Counter((r['code_or_method'], r['ctype'][:24], r['body_kind']) for r in rows if r['kind'] == 'resp').most_common(10))
