# Rebuild a device's plaintext HTTP on tcp/80 from raw TCP segments for a whole day, one line per request or response, with
# original file and frame. Secrets stay out: tokens in paths and queries become lengths and labels, Authorization values become
# labels shared across days, bodies only as length, entropy and key or tag names. No body is stored.
# usage: http_scan.py <day dir> <out.tsv> <label map json>
import base64, bisect, collections, glob, hashlib, json, math, os, re, subprocess, sys
day, out, mapf = sys.argv[1:4]
files = sorted(f for f in glob.glob(os.path.join(day, 'eth*')) if not f.endswith('.frames'))
labels = json.load(open(mapf)) if os.path.exists(mapf) else {}
def label(kind, raw):
    h = hashlib.sha256(kind.encode() + b'\0' + raw).hexdigest()
    return labels.setdefault(h, '%s#%d' % (kind, sum(1 for v in labels.values() if v.startswith(kind + '#')) + 1))
def cls(v):
    if re.fullmatch(r'[0-9]+', v): return 'dec'
    if re.fullmatch(r'[0-9a-fA-F]+', v): return 'hex'
    if re.fullmatch(r'[A-Za-z0-9+/=_%-]+', v): return 'b64like'
    return 'other'
def mask_seg(s):
    if re.fullmatch(r'[A-Za-z_][A-Za-z_.-]{0,29}', s) and not re.search(r'\d', s): return s
    if re.fullmatch(r'[0-9]{1,5}', s): return s
    if re.fullmatch(r'v[0-9]{1,2}', s): return s
    return '***%s%d' % (cls(s), len(s))
def mask_path(p): return '/'.join(mask_seg(x) if x else '' for x in p.split('/'))
def mask_query(q):
    out = []
    for kv in q.split('&'):
        if not kv: continue
        k, _, v = kv.partition('=')
        out.append('%s=%s' % (k if re.fullmatch(r'[A-Za-z_][\w.-]{0,30}', k) else '***', '%s:%s%d' % (label('q-' + k[:12], v.encode()), cls(v), len(v)) if v else ''))
    return '&'.join(out)
def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())
def decoded_stats(b, kind):
    try:
        raw = bytes.fromhex(re.sub(rb'\s', b'', b).decode()) if kind == 'hex-alphabet' else base64.b64decode(re.sub(rb'\s', b'', b) + b'===') if kind == 'base64-alphabet' else b
    except Exception:
        return ''
    if not raw: return ''
    return 'n%d:m16=%d:H%.2f' % (len(raw), len(raw) % 16, entropy(raw))
def auth_shape(val):
    # one label for the Client field (identity only), length and class for every other field; never a value
    out = []
    for name, _, v in re.findall(r'([A-Za-z_][\w-]{0,20})=("?)([^",\s]*)\2', val):
        if name.lower() == 'client': out.append('Client=%s:%s%d' % (label('client', v.encode()), cls(v), len(v)))
        else: out.append('%s=%s%d' % (name, cls(v), len(v)))
    return '+'.join(out)[:220]
def body_shape(b, ctype):
    if not b: return '', ''
    t = b.lstrip()[:1]
    try:
        if t in (b'{', b'['):
            d = json.loads(b.decode('utf-8'))
            keys = set()
            def walk(x):
                if isinstance(x, dict):
                    for k, v in x.items():
                        if re.fullmatch(r'[A-Za-z_][\w.-]{0,30}', k): keys.add(k)
                        walk(v)
                elif isinstance(x, list):
                    for v in x: walk(v)
            walk(d)
            return 'json', ','.join(sorted(keys))[:300]
    except Exception:
        pass
    if t == b'<':
        tags = sorted(set(x.decode('latin-1') for x in re.findall(rb'<([A-Za-z_][\w:.-]{0,30})', b)))
        return 'xml', ','.join(tags)[:300]
    if re.fullmatch(rb'[0-9a-fA-F\r\n]+', b): return 'hex-alphabet', ''
    if re.fullmatch(rb'[A-Za-z0-9+/=\r\n]+', b[:4096]): return 'base64-alphabet', ''
    if re.fullmatch(rb'[\w.%+-]+=[^&\s]*(&[\w.%+-]+=[^&\s]*)*\s*', b[:4096]):
        return 'form', ','.join(sorted(set(x.split(b'=')[0].decode('latin-1') for x in b.split(b'&'))))[:300]
    return 'binary-or-text', ''
def dechunk(st, i):
    start = i; out = bytearray()
    while True:
        e = st.find(b'\r\n', i)
        if e < 0 or e - i > 8: return bytes(out) + st[i:], len(st) - start
        try: n = int(st[i:e], 16)
        except ValueError: return bytes(out) + st[i:], len(st) - start
        i = e + 2
        if n == 0:
            e = st.find(b'\r\n', i)
            return bytes(out), (e + 2 if e >= 0 else len(st)) - start
        out += st[i:i+n]; i += n + 2
flows = collections.defaultdict(dict); segs = dups = 0; synseq = {}; gen = collections.Counter()
WAN = os.environ.get('WAN_ONLY') == '1'
for f in files:
    frames = [int(x) for x in open(f + '.frames')]
    p = subprocess.run(['tshark','-r',f,'-Y','tcp.port==80 && (tcp.len>0 || tcp.flags.syn==1)' + (' && !(ip.src==192.168.0.0/16 && ip.dst==192.168.0.0/16)' if WAN else ''),'-T','fields','-E','separator=\t','-e','frame.number','-e','frame.time_epoch',
        '-e','ip.src','-e','tcp.srcport','-e','ip.dst','-e','tcp.dstport','-e','tcp.seq_raw','-e','tcp.flags.syn','-e','tcp.flags.ack','-e','tcp.payload'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        fr, ts, s, sp, d, dp, seq, syn, ack, pl = line.split('\t')
        cli = (s, sp, d, dp) if dp == '80' else (d, dp, s, sp)
        if syn in ('1', 'True') and ack in ('0', 'False') and synseq.get(cli) != seq:
            synseq[cli] = seq; gen[cli] += 1
        if not pl: continue
        segs += 1; seq = int(seq); key = (s, sp, d, dp, gen[cli])
        if seq in flows[key]: dups += 1; continue
        flows[key][seq] = (os.path.basename(f), frames[int(fr)-1], float(ts), bytes.fromhex(pl.replace(':', '')))
w = open(out, 'w')
cols = 'file frame time src dst dport kind code_or_method host path query ua hdr_names auth clen ctype server date body_len body_entropy body_kind body_keys printable decoded last_file last_frame gap_bytes'.split()
w.write('\t'.join(cols) + '\n')
START = re.compile(rb'(GET|POST|PUT|HEAD|DELETE|OPTIONS) \S+ HTTP/1\.[01]\r\n|HTTP/1\.[01] \d{3}')
for key, m in flows.items():
    seqs = sorted(m); stream = bytearray(); offs = []; rec = []; gap = 0; nxt = None
    for sq in seqs:
        if nxt is not None and sq > nxt: gap += sq - nxt
        d = m[sq][3]
        if nxt is not None and sq < nxt:
            d = d[nxt - sq:]
            if not d: continue
        offs.append(len(stream)); rec.append(m[sq]); stream += d; nxt = max(nxt or 0, sq + len(m[sq][3]))
    stream = bytes(stream); pos = 0
    while pos < len(stream):
        if not START.match(stream, pos): break
        hend = stream.find(b'\r\n\r\n', pos)
        if hend < 0: break
        head = stream[pos:hend].split(b'\r\n'); first = head[0].decode('latin-1'); hdr = collections.OrderedDict()
        for h in head[1:]:
            k, _, v = h.partition(b':'); hdr[k.strip().lower().decode('latin-1')] = v.strip()
        cl = hdr.get('content-length'); clen = int(cl) if cl and cl.isdigit() else None
        isresp = first.startswith('HTTP/')
        wire = None
        if hdr.get('transfer-encoding', b'').lower() == b'chunked':
            body, wire = dechunk(stream, hend + 4)
        elif clen is not None: body = stream[hend+4:hend+4+clen]
        elif isresp: body = stream[hend+4:]
        else: body = b''
        if wire is None: wire = len(body)
        i = bisect.bisect_right(offs, pos) - 1; r0 = rec[i]
        j = bisect.bisect_right(offs, hend+4+max(wire,1)-1) - 1; r1 = rec[max(j, i)]
        method = path = query = ''
        if isresp: method = first.split()[1]
        else:
            method, uri = first.split()[:2]; pth, _, q = uri.partition('?')
            path = mask_path(pth); query = mask_query(q)
        auth = ''
        a = hdr.get('authorization', b'')
        if a:
            parts = a.split(None, 1); sch = parts[0].decode('latin-1')[:12]; val = parts[1] if len(parts) > 1 else b''
            auth = '%s:%s:len%d' % (sch, label('auth', a), len(val))
            auth += ':' + auth_shape(val.decode('latin-1'))
            if sch.lower() == 'basic':
                try:
                    raw = base64.b64decode(val + b'=='); u, _, pw = raw.partition(b':')
                    auth += ':user%d%s:pass%d%s' % (len(u), cls(u.decode('latin-1')), len(pw), cls(pw.decode('latin-1')))
                except Exception: pass
        ua = re.sub(r'[0-9a-fA-F]{12,}', lambda x: '***%d' % len(x.group(0)), hdr.get('user-agent', b'').decode('latin-1'))[:60]
        kind, keys = body_shape(body, hdr.get('content-type', b''))
        names = ','.join(k for k in hdr)
        w.write('\t'.join(str(x) for x in (r0[0], r0[1], f'{r0[2]:.6f}', key[0], key[2], key[3], 'resp' if isresp else 'req', method, hdr.get('host', b'').decode('latin-1')[:60], path, query, ua, names, auth,
            '' if clen is None else clen, hdr.get('content-type', b'').decode('latin-1')[:90], hdr.get('server', b'').decode('latin-1')[:30], hdr.get('date', b'').decode('latin-1'), len(body), f'{entropy(body):.3f}', kind, keys, f'{sum(32 <= c < 127 or c in (9, 10, 13) for c in body) / max(len(body), 1):.2f}', decoded_stats(body, kind), r1[0], r1[1], gap)) + '\n')
        pos = hend + 4 + wire
w.close()
json.dump(labels, open(mapf, 'w'))
print(os.path.basename(day), 'files', len(files), 'segments', segs, 'duplicate-segments', dups, 'flows', len(flows), flush=True)
