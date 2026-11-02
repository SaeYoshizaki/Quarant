# TLS, DNS and DHCP facts per day from the Ring-only captures (dedup of doubled captures by flow+seq). No secrets involved
# beyond public handshake fields. usage: tls_scan.py <day dir> <out.json>
import collections, glob, json, os, subprocess, sys
day, out = sys.argv[1:3]
files = sorted(f for f in glob.glob(os.path.join(day, 'eth*')) if not f.endswith('.frames'))
res = dict(ch=collections.Counter(), sh=collections.Counter(), cert=collections.Counter(), dns=collections.Counter(), rcode=collections.Counter(), dhcp=collections.Counter(), ex={}, dnsans=collections.Counter(), syn=collections.Counter())
seen = set(); first = {}
for f in files:
    base = os.path.basename(f); frames = [int(x) for x in open(f + '.frames')]
    p = subprocess.run(['tshark','-r',f,'-d','tcp.port==9998,tls','-Y','tls.handshake.type==1 or tls.handshake.type==2 or tls.handshake.type==11','-T','fields','-E','separator=\t','-E','aggregator=;','-e','frame.number','-e','frame.time_epoch','-e','ip.src','-e','tcp.srcport','-e','ip.dst','-e','tcp.dstport','-e','tcp.seq_raw','-e','tls.handshake.type','-e','tls.handshake.version','-e','tls.handshake.ciphersuite','-e','tls.handshake.extensions_server_name','-e','x509sat.uTF8String','-e','x509sat.printableString','-e','x509af.utcTime'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        a = line.split('\t') + ['']*14
        fr, ts, s, sp, d, dp, seq, ht, ver, cs, sni, u8, pr, ut = a[:14]
        k = (s, sp, d, dp, seq)
        if k in seen: continue
        seen.add(k)
        hts = ht.split(';')
        if '1' in hts:
            suites = cs.split(';')
            key = (dp, sni, ver, ','.join(suites))
            res['ch'][key] += 1; res['ex'].setdefault('ch:'+dp, (base, frames[int(fr)-1], ts))
        if '2' in hts:
            key = (sp, ver, cs.split(';')[0]); res['sh'][key] += 1; res['ex'].setdefault('sh:'+sp, (base, frames[int(fr)-1], ts))
        if '11' in hts:
            names = (u8 + ';' + pr).split(';')
            res['cert'][(sp, ';'.join(sorted(set(x for x in names if x)))[:300])] += 1; res['ex'].setdefault('cert:'+sp, (base, frames[int(fr)-1], ts))
    p = subprocess.run(['tshark','-r',f,'-Y','dns && udp.port==53','-T','fields','-E','separator=\t','-E','aggregator=;','-e','frame.time_epoch','-e','ip.src','-e','udp.srcport','-e','dns.id','-e','dns.flags.response','-e','dns.qry.name','-e','dns.flags.rcode','-e','dns.a'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        ts, s, sp, did, resp, q, rc, an = (line.split('\t') + ['']*8)[:8]
        k = ('dns', s, sp, did, resp, q)
        if k in seen: continue
        seen.add(k)
        if resp in ('0', 'False'): res['dns'][q] += 1
        else:
            res['rcode'][(q, rc)] += 1
    p = subprocess.run(['tshark','-r',f,'-Y','dhcp','-T','fields','-E','separator=\t','-e','frame.number','-e','frame.time_epoch','-e','dhcp.option.dhcp','-e','dhcp.option.hostname','-e','dhcp.option.vendor_class_id','-e','dhcp.hw.mac_addr','-e','dhcp.id'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        fr, ts, ty, hn, vc, mac, did = (line.split('\t') + ['']*7)[:7]
        k = ('dhcp', ty, did)
        if k in seen: continue
        seen.add(k)
        res['dhcp'][(ty, hn, vc)] += 1; res['ex'].setdefault('dhcp:%s'%ty, (base, frames[int(fr)-1], ts))
out_d = {k: ([[list(a) if isinstance(a, tuple) else a, b] for a, b in v.most_common(40)] if isinstance(v, collections.Counter) else v) for k, v in res.items()}
json.dump(out_d, open(out, 'w'), indent=0)
print(os.path.basename(day), 'CH', sum(res['ch'].values()), 'SH', sum(res['sh'].values()), 'cert', sum(res['cert'].values()), 'dnsq', sum(res['dns'].values()), 'dhcp', sum(res['dhcp'].values()))
