#!/usr/bin/env python3
"""Shape of Withings Home's plaintext POST bodies to scalews.withings.net: form keys and, per value, length and character
class; also whether a value equals the device MAC (with or without separators). No value is printed.
usage: post_shape.py <day dir> <device mac>"""
import glob, os, re, subprocess, sys, urllib.parse
day, mac = sys.argv[1], sys.argv[2].lower()
macs = {mac, mac.replace(':', ''), mac.replace(':', '-')}
def cls(v):
    return 'dec' if re.fullmatch(r'\d+', v) else 'hex' if re.fullmatch(r'[0-9a-fA-F]+', v) else 'b64like' if re.fullmatch(r'[A-Za-z0-9+/=_%.-]+', v) else 'other'
for f in sorted(x for x in glob.glob(os.path.join(day, 'eth*')) if not x.endswith('.frames')):
    frames = [int(x) for x in open(f + '.frames')]
    p = subprocess.run(['tshark', '-r', f, '-Y', 'tcp.dstport==80 && tcp.len>0 && !(ip.dst==192.168.0.0/16)', '-T', 'fields', '-e', 'frame.number', '-e', 'tcp.payload'], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        fr, pl = line.split('\t'); b = bytes.fromhex(pl.replace(':', '')).decode('latin-1')
        if 'scalews' not in b and not b.startswith(('action=', 'mac', 'sessionid')):
            continue
        body = b.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in b else (b if '=' in b and not b.startswith(('POST', 'GET')) else '')
        head = b.split('\r\n\r\n', 1)[0] if b.startswith(('POST', 'GET')) else ''
        if head:
            m = re.match(r'(POST|GET) (\S+)', head); q = urllib.parse.urlparse(m.group(2)).query
            print(os.path.basename(f), frames[int(fr)-1], 'request', m.group(1), urllib.parse.urlparse(m.group(2)).path, 'query keys', [k for k, _ in urllib.parse.parse_qsl(q)], 'query values', [(cls(v), len(v)) for _, v in urllib.parse.parse_qsl(q)], 'action is plain word', all(re.fullmatch(r'[a-z_]{1,20}', v) for k, v in urllib.parse.parse_qsl(q) if k == 'action'))
        if body:
            kv = urllib.parse.parse_qsl(body.strip(), keep_blank_values=True)
            print('   body form keys', [k for k, _ in kv], 'values', [(cls(v), len(v)) for _, v in kv], 'any value is the MAC', any(v.lower() in macs for _, v in kv))
