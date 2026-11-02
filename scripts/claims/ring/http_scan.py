# Rebuild Ring's plaintext tcp/80 from raw TCP segments for a whole day (flows may span capture files), one line
# per request or response, with original file and frame. Duplicated captures are dropped by (flow, seq).
# Secrets stay out: credentials become labels shared across days plus their structure; bodies only as length,
# entropy and known container signatures; query values only for keys known not to be secret.
# usage: http_scan.py <day dir> <out.tsv> <credential label map json>
import base64, bisect, collections, glob, hashlib, json, math, os, re, subprocess, sys
day, out, mapf = sys.argv[1:4]
files = sorted(f for f in glob.glob(os.path.join(day, 'eth*')) if not f.endswith('.frames'))
creds = json.load(open(mapf)) if os.path.exists(mapf) else {}
def label(raw):
    h = hashlib.sha256(raw).hexdigest()
    return creds.setdefault(h, 'cred#%d' % (len(creds)+1))
def shape(raw):
    u, _, p = raw.partition(b':'); pc = p.rstrip(b'\0')
    t = lambda b: 'hex' if re.fullmatch(rb'[0-9a-fA-F]+', b) else 'other'
    return f"user{len(u)}{t(u)}:pass{len(pc)}{t(pc)}+nul{len(p)-len(pc)}", str(u.lower() == os.environ['RING_MAC'].encode())
def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())
SIGS = [(b'\x1f\x8b', 'gzip'), (b'PK\x03\x04', 'zip'), (b'\x7fELF', 'elf'), (b'\x27\x05\x19\x56', 'uimage'), (b'BZh', 'bzip2'), (b'\xfd7zXZ', 'xz'), (b'hsqs', 'squashfs'), (b'-----BEGIN', 'pem'), (b'{', 'json?')]
flows = collections.defaultdict(dict); segs = dups = 0; synseq = {}; gen = collections.Counter()
for f in files:
    frames = [int(x) for x in open(f + '.frames')]
    p = subprocess.run(['tshark','-r',f,'-Y','tcp.port==80 && (tcp.len>0 || tcp.flags.syn==1)','-T','fields','-E','separator=\t','-e','frame.number','-e','frame.time_epoch',
        '-e','ip.src','-e','tcp.srcport','-e','ip.dst','-e','tcp.dstport','-e','tcp.seq_raw','-e','tcp.flags.syn','-e','tcp.flags.ack','-e','tcp.payload'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        fr, ts, s, sp, d, dp, seq, syn, ack, pl = line.split('\t')
        cli = (s, sp, d, dp) if dp == '80' else (d, dp, s, sp)
        # a client SYN with a new sequence number starts a new connection on this 4-tuple (ports are reused)
        if syn in ('1', 'True') and ack in ('0', 'False') and synseq.get(cli) != seq:
            synseq[cli] = seq; gen[cli] += 1
        if not pl: continue
        segs += 1; seq = int(seq); key = (s, sp, d, dp, gen[cli])
        if seq in flows[key]: dups += 1; continue
        flows[key][seq] = (os.path.basename(f), frames[int(fr)-1], float(ts), bytes.fromhex(pl.replace(':', '')))
w = open(out, 'w')
w.write('file\tframe\ttime\tflow\tkind\tcode_or_method\thost\tpath\tquery\tdevtype\tcred\tcred_shape\tuser_is_mac\tclen\tctype\thdr_names\tserver\tdate\tbody_len\tbody_entropy\tbody_sig\tbody_note\tlast_frame_file\tlast_frame\tgap_bytes\n')
START = re.compile(rb'(GET|POST|PUT|HEAD|DELETE|OPTIONS) \S+ HTTP/1\.[01]\r\n|HTTP/1\.[01] \d{3}')
for key, m in flows.items():
    seqs = sorted(m); stream = bytearray(); offs = []; rec = []; gap = 0; nxt = None
    for sq in seqs:
        if nxt is not None and sq > nxt: gap += sq - nxt
        d = m[sq][3]
        if nxt is not None and sq < nxt:
            d = d[nxt - sq:]              # retransmission overlap
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
        if clen is not None: body = stream[hend+4:hend+4+clen]
        elif isresp: body = stream[hend+4:]
        else: body = b''
        i = bisect.bisect_right(offs, pos) - 1; r0 = rec[i]
        j = bisect.bisect_right(offs, hend+4+len(body)-1) - 1; r1 = rec[max(j, i)]
        method = path = query = ''
        if isresp: method = first.split()[1]
        else:
            method, uri = first.split()[:2]; path, _, q = uri.partition('?')
            query = '&'.join(x if x.split('=')[0] in ('api_version', 'protocol') else x.split('=')[0] + '=***len%d' % len(x.split('=',1)[-1]) for x in q.split('&') if x)
        cred = sh = ism = ''
        a = hdr.get('authorization', b'')
        if a.lower().startswith(b'basic '):
            raw = base64.b64decode(a.split()[1] + b'=='); cred = label(raw); sh, ism = shape(raw)
        elif a: cred = 'scheme:' + a.split()[0].decode('latin-1')
        sig = next((n for s, n in SIGS if body.startswith(s)), '')
        note = ''
        if body and re.fullmatch(rb'[A-Za-z0-9+/=\r\n]+', body[:4096]): note = 'base64-alphabet'
        if body == b'protocol=sip': note = 'protocol=sip'
        names = ','.join(k for k in hdr if k not in ('authorization',))
        w.write('\t'.join(str(x) for x in (r0[0], r0[1], f'{r0[2]:.6f}', ':'.join(str(x) for x in key), 'resp' if isresp else 'req', method, hdr.get('host', b'').decode('latin-1'), path, query,
            hdr.get('x-ringdevicetype', b'').decode('latin-1'), cred, sh, ism, '' if clen is None else clen, hdr.get('content-type', b'').decode('latin-1'), names,
            hdr.get('server', b'').decode('latin-1'), hdr.get('date', b'').decode('latin-1'), len(body), f'{entropy(body):.3f}', sig, note, r1[0], r1[1], gap)) + '\n')
        pos = hend + 4 + len(body)
w.close()
json.dump(creds, open(mapf, 'w'))
print(os.path.basename(day), 'files', len(files), 'segments', segs, 'duplicate-segments', dups, 'flows', len(flows), 'distinct-creds-so-far', len(creds))
