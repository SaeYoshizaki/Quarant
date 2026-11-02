# Count HTTP request lines the way handoff.md did: segments that begin with a method, deduplicated by (destination, source port,
# absolute sequence number). Prints counts only. usage: count_reqlines.py <day dir>
import collections, glob, os, subprocess, sys
files = sorted(f for f in glob.glob(os.path.join(sys.argv[1], 'eth*')) if not f.endswith('.frames'))
seen = set(); c = collections.Counter()
for f in files:
    p = subprocess.run(['tshark','-r',f,'-Y','tcp.dstport==80 && tcp.len>0','-T','fields','-E','separator=\t','-e','ip.dst','-e','tcp.srcport','-e','tcp.seq_raw','-e','tcp.payload'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        d, sp, seq, pl = line.split('\t')
        k = (d, sp, seq)
        if k in seen: continue
        seen.add(k)
        head = bytes.fromhex(pl.replace(':','')[:16])
        for m in (b'GET ', b'POST ', b'HEAD ', b'PUT '):
            if head.startswith(m): c[m.decode().strip()] += 1
print(os.path.basename(sys.argv[1]), dict(c))
