# The Base64 bodies returned to POST /doorbots_api/{vod,dings}: decoded length, entropy and whether it looks like JSON.
# Nothing from the body is printed. usage: blob_stats.py <http-*.tsv> <day dir>
import base64, collections, csv, math, os, subprocess, sys
tsv, day = sys.argv[1:3]
rows = list(csv.DictReader(open(tsv), delimiter='\t'))
for r in rows:
    if r['kind'] == 'resp' and r['body_note'] == 'base64-alphabet' and r['clen'].isdigit():
        srv, sp, cli, cp = r['flow'].split(':')[:4]
        f = os.path.join(day, r['file'])
        p = subprocess.run(['tshark','-r',f,'-Y',f'tcp.srcport==80 && tcp.dstport=={cp} && ip.src=={srv} && tcp.len>0','-T','fields','-e','tcp.seq_raw','-e','tcp.payload'],capture_output=True,text=True)
        seg = {}
        for l in p.stdout.splitlines():
            q, pl = l.split('\t'); seg.setdefault(int(q), bytes.fromhex(pl.replace(':','')))
        # the same client port can appear twice in one file; take the response that starts at this row's size
        st = b''.join(seg[k] for k in sorted(seg)); body = st.split(b'\r\n\r\n', 1)[1][:int(r['clen'])].strip()
        raw = base64.b64decode(body + b'=' * (-len(body) % 4))
        c = collections.Counter(raw); n = len(raw)
        H = -sum(v / n * math.log2(v / n) for v in c.values())
        print(r['file'][5:18], r['frame'], 'base64 chars', len(body), 'decoded', n, 'entropy %.2f' % H, 'json-like', raw[:1] in (b'{', b'['), 'printable-share %.2f' % (sum(32 <= b < 127 for b in raw) / n))
