# Bridge version strings per day with file and frame: SSDP Server header (first and last frame of each value) and, from one LAN
# response, the model fields of description.xml. Serial numbers, bridge IDs and UDNs are never printed. usage: versions_scan.py <day dir>...
import glob, os, re, subprocess, sys, time
T = lambda t: time.strftime('%m-%d %H:%M:%S', time.gmtime(float(t)))
for day in sys.argv[1:]:
    files = sorted(f for f in glob.glob(os.path.join(day, 'eth*')) if not f.endswith('.frames'))
    seen = {}; model = None
    for f in files:
        frames = [int(x) for x in open(f + '.frames')]
        base = os.path.basename(f)
        p = subprocess.run(['tshark','-r',f,'-Y','udp.port==1900 && ip.src==192.168.0.5','-T','fields','-E','separator=\t','-e','frame.number','-e','frame.time_epoch','-e','udp.payload'],capture_output=True,text=True)
        for line in p.stdout.splitlines():
            fr, ts, pl = line.split('\t')
            t = bytes.fromhex(pl.replace(':','')).decode('latin-1')
            m = re.search(r'(?i)server:\s*([^\r\n]+)', t)
            if not m: continue
            v = m.group(1).strip()
            s = seen.setdefault(v, [base, frames[int(fr)-1], ts, base, frames[int(fr)-1], ts, 0])
            s[3:6] = [base, frames[int(fr)-1], ts]; s[6] += 1
        if model is None:
            p = subprocess.run(['tshark','-r',f,'-Y','ip.src==192.168.0.5 && tcp.srcport==80 && tcp.len>0 && frame contains "modelNumber"','-c','200000','-T','fields','-e','frame.number','-e','tcp.payload'],capture_output=True,text=True)
            for line in p.stdout.splitlines():
                fr, pl = line.split('\t')
                t = bytes.fromhex(pl.replace(':','')).decode('latin-1')
                got = {k: re.search(r'<%s>([^<]{0,60})<' % k, t) for k in ('friendlyNameX', 'manufacturer', 'modelName', 'modelNumber', 'modelDescription')}
                if got['modelNumber']:
                    model = (base, frames[int(fr)-1], {k: v.group(1) for k, v in got.items() if v}); break
    print(os.path.basename(day), 'model', model)
    for v, s in seen.items():
        print('  ssdp', v, 'count', s[6], 'first', s[0][5:18], s[1], T(s[2]), 'last', s[3][5:18], s[4], T(s[5]))
