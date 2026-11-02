# Phone <-> media server flows next to doorbell sessions: UDP flows with RTP-like structure and TCP ports. Header fields and first
# payload byte only; no media rebuilt; nothing else from the phone is read. usage: phone.py <dir>
import collections, glob, os, subprocess, sys, math
d = sys.argv[1]
files = sorted(f for f in glob.glob(os.path.join(d, 'eth*')) if not f.endswith('.frames'))
fl = {}; tcp = collections.Counter(); tcpex = {}
for f in files:
    frames = [int(x) for x in open(f + '.frames')]
    p = subprocess.run(['tshark','-r',f,'-T','fields','-E','separator=\t','-e','frame.number','-e','frame.time_epoch','-e','ip.src','-e','udp.srcport','-e','ip.dst','-e','udp.dstport','-e','tcp.srcport','-e','tcp.dstport','-e','tcp.len','-e','udp.payload','-e','tcp.seq_raw'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        a = (line.split('\t') + ['']*11)[:11]
        fr, ts, s, us, dst, ud, ts_, td, tl, up, sq = a
        if us:
            k = f'{s}:{us}>{dst}:{ud}'; b = bytes.fromhex(up.replace(':',''))
            x = fl.setdefault(k, dict(file=os.path.basename(f), frame=frames[int(fr)-1], first=float(ts), last=float(ts), n=0, seen=set(), pt=collections.Counter(), fb=collections.Counter(), ver=collections.Counter(), sizes=collections.Counter(), fz=0, sip=0))
            x['last'] = float(ts)
            if b[:4] in (b'SIP/', b'INVI', b'ACK ', b'BYE ', b'REGI', b'OPTI', b'MESS'): x['sip'] += 1; continue
            if len(b) < 13: x['sizes'][len(b)] += 1; continue
            key = b[2:12]
            if key in x['seen']: continue
            x['seen'].add(key); x['n'] += 1; x['ver'][b[0]>>6] += 1; pt = b[1]&0x7f; x['pt'][pt] += 1; x['sizes'][len(b)] += 1
            if b[0]>>6 == 2:
                pay = b[12+4*(b[0]&0xf):]
                if pay and pt not in (72,73,74,75,76,77):
                    x['fb'][pay[0]] += 1; x['fz'] += pay[0]>>7
        elif ts_:
            tcp[(s, ts_, dst, td)] += 1; tcpex.setdefault((s, ts_, dst, td), (os.path.basename(f), frames[int(fr)-1], float(ts)))
import time
T = lambda t: time.strftime('%m-%d %H:%M:%S', time.gmtime(t))
for k, x in sorted(fl.items(), key=lambda z: z[1]['first']):
    print(k, x['file'][5:18], x['frame'], T(x['first']), 'dur %.1f' % (x['last']-x['first']), 'rtp-like', x['n'], 'sip', x['sip'], 'ver', dict(x['ver']), 'pt', x['pt'].most_common(4), 'distinct_first', len(x['fb']), 'fz', x['fz'], 'top_first', [(hex(a), b) for a, b in x['fb'].most_common(4)], 'sizes', x['sizes'].most_common(3))
for k, v in tcp.most_common(10): print('TCP', k, v, tcpex[k][0][5:18], tcpex[k][1], T(tcpex[k][2]))
