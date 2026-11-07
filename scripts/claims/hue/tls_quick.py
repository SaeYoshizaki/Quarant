# TLS handshakes on tcp/443 between the device and the internet, per day, keeping the original frame numbers. A plain Python pass
# picks out those packets first, so tshark sees only a small temporary capture. Handshake fields only. usage: tls_quick.py <day dir> <out.json>
import collections, glob, json, os, struct, subprocess, sys, tempfile
day, out = sys.argv[1:3]
files = sorted(f for f in glob.glob(os.path.join(day, 'eth*')) if not f.endswith('.frames'))
res = dict(ch=collections.Counter(), sh=collections.Counter(), cert=collections.Counter(), ex={}, packets=0)
seen = set()
LAN = b'\xc0\xa8'
for f in files:
    data = open(f, 'rb').read()
    frames = [int(x) for x in open(f + '.frames')]
    off, i, L, chunks, keep = 24, 0, len(data), [data[:24]], []
    unpack = struct.Struct('<IIII').unpack_from
    while off + 16 <= L:
        _, _, incl, _ = unpack(data, off); p = off + 16; end = p + incl
        if end > L: break
        i += 1
        if data[p+12:p+14] == b'\x08\x00' and data[p+23] == 6:
            ihl = (data[p+14] & 15) * 4; t = p + 14 + ihl
            sp, dp = int.from_bytes(data[t:t+2], 'big'), int.from_bytes(data[t+2:t+4], 'big')
            if 443 in (sp, dp) and not (data[p+26:p+28] == LAN and data[p+30:p+32] == LAN):
                chunks.append(data[off:end]); keep.append(frames[i-1])
        off = end
    del data
    if not keep: continue
    res['packets'] += len(keep)
    with tempfile.NamedTemporaryFile(suffix='.pcap') as tmp:
        tmp.write(b''.join(chunks)); tmp.flush()
        q = subprocess.run(['tshark','-r',tmp.name,'-Y','tls.handshake.type==1 or tls.handshake.type==2 or tls.handshake.type==11','-T','fields','-E','separator=\t','-E','aggregator=;','-e','frame.number','-e','frame.time_epoch','-e','ip.src','-e','tcp.srcport','-e','ip.dst','-e','tcp.dstport','-e','tcp.seq_raw','-e','tls.handshake.type','-e','tls.handshake.version','-e','tls.handshake.ciphersuite','-e','tls.handshake.extensions_server_name','-e','x509sat.uTF8String','-e','x509sat.printableString'],capture_output=True,text=True)
    base = os.path.basename(f)
    for line in q.stdout.splitlines():
        a = line.split('\t') + [''] * 13
        fr, ts, s, sp, d, dp, seq, ht, ver, cs, sni, u8, pr = a[:13]
        k = (s, sp, d, dp, seq)
        if k in seen: continue
        seen.add(k)
        hts = ht.split(';'); orig = keep[int(fr)-1]
        if '1' in hts:
            key = (d, sni, ver, cs); res['ch'][key] += 1; res['ex'].setdefault('ch:' + sni, (base, orig, ts))
        if '2' in hts:
            key = (s, ver, cs.split(';')[0]); res['sh'][key] += 1; res['ex'].setdefault('sh:' + s, (base, orig, ts))
        if '11' in hts:
            names = (u8 + ';' + pr).split(';'); res['cert'][(s, ';'.join(sorted(set(x for x in names if x)))[:220])] += 1; res['ex'].setdefault('cert:' + s, (base, orig, ts))
json.dump({k: ([[list(a), b] for a, b in v.most_common(30)] if isinstance(v, collections.Counter) else v) for k, v in res.items()}, open(out, 'w'), indent=0)
print(os.path.basename(day), 'wan-443-packets', res['packets'], 'CH', sum(res['ch'].values()), 'SH', sum(res['sh'].values()), 'cert', sum(res['cert'].values()), flush=True)
