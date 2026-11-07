#!/usr/bin/env python3
"""Shape of Sonos's plaintext update-check replies, without values.

Usage: resp_shape.py [--match <uri part>] <capture>...
For each reply to a GET whose URI contains <uri part> (default update.sonos.com/firmware/latest), prints the readable runs of the body (8 or more printable
characters) with their offsets, every token that has a digit or is longer than 20 characters replaced by its class and length,
and the lengths of the binary stretches between them. Tokens equal to a query value of 6 or more characters are named.
"""
import os, re, subprocess, sys, tempfile, urllib.parse
def cls(v):
    if re.fullmatch(r'[0-9]+', v): return 'dec'
    if re.fullmatch(r'[0-9a-fA-F]+', v): return 'hex'
    return 'alnum'
args = sys.argv[1:]
match = 'update.sonos.com/firmware/latest'
if args[:1] == ['--match']: match, args = args[1], args[2:]
for f in args:
    # YourThings captures hold every packet twice, which stops tshark from reassembling the reply; drop the copies first
    tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False).name
    subprocess.run(['editcap', '-D', '20', f, tmp], capture_output=True)
    p = subprocess.run(['tshark', '-r', tmp, '-Y', 'http', '-T', 'fields', '-E', 'separator=\t',
                        '-e', 'frame.number', '-e', 'http.request.full_uri', '-e', 'http.request_in', '-e', 'http.file_data'], capture_output=True, text=True)
    os.unlink(tmp)
    reqs = {}
    for line in p.stdout.splitlines():
        fr, uri, req_in, data = (line.split('\t') + ['', '', ''])[:4]
        if not req_in: reqs[fr] = uri; continue
        uri = reqs.get(req_in, uri)
        if match not in uri: continue
        body = bytes.fromhex(data).decode('latin-1') if re.fullmatch(r'[0-9a-f]+', data) else data
        q = {v: k for k, vs in urllib.parse.parse_qs(urllib.parse.urlparse(uri).query).items() for v in vs if len(v) >= 6}
        hits = set()
        def sub(m):
            t = m.group(0)
            if t in q: hits.add(q[t]); return '<=%s>' % q[t]
            if re.search(r'\d', t) or len(t) > 20: return '<%s%d>' % (cls(t), len(t))
            return t
        out, last = [], 0
        for m in re.finditer(r'[\x20-\x7e]{8,}', body):
            out.append('  [binary %d]' % (m.start() - last) if m.start() > last else '')
            out.append('  @%d %s' % (m.start(), re.sub(r'[A-Za-z0-9_]+', sub, m.group(0))))
            last = m.end()
        out.append('  [binary %d]' % (len(body) - last))
        print('==', f.rsplit('/', 1)[-1], 'frame (deduplicated file)', fr, 'body', len(body), 'query values found in body:', sorted(hits) or 'none')
        print('\n'.join(x for x in out if x))
