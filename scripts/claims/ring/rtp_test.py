# Is the RTP video payload structured H.264 or opaque? Compares the sessions by firmware, using header fields and first
# payload bytes only. Media is never rebuilt or saved. usage: rtp_test.py <file[:after_epoch[:before_epoch]]> <flow src port> ...
import collections, json, math, os, subprocess, sys, glob
def chi2_uniform(c, n, k=256):
    e = n / k
    return sum((c.get(i, 0) - e) ** 2 / e for i in range(k))
def analyse(files, srv, t0, t1, label):
    seen = set(); first = collections.Counter(); second = collections.Counter(); sizes = collections.Counter(); ent_sum = 0.0; n = 0; pts = collections.Counter(); ssrc = collections.Counter(); hdr_ext = 0; pad = 0; marker = 0; tot_bytes = 0
    all_bytes = collections.Counter()
    fbit = 0; rts = []
    for f in files:
        p = subprocess.Popen(['tshark','-r',f,'-Y',f'udp.srcport==51504 && ip.dst=={srv} && frame.time_epoch>={t0} && frame.time_epoch<{t1} && !icmp','-T','fields','-e','udp.payload'],stdout=subprocess.PIPE,text=True,bufsize=1<<20)
        for line in p.stdout:
            b = bytes.fromhex(line.strip().replace(':',''))
            if len(b) < 13: continue
            if (b[1] & 0x7f) != 97: continue
            k = b[2:12]
            if k in seen: continue
            seen.add(k); n += 1
            cc = b[0] & 0x0f; off = 12 + 4 * cc
            if (b[0] >> 4) & 1: hdr_ext += 1; off += 4 + 4 * int.from_bytes(b[off+2:off+4], 'big')
            if (b[0] >> 5) & 1: pad += 1
            marker += b[1] >> 7
            pay = b[off:]
            if not pay: continue
            first[pay[0]] += 1; fbit += pay[0] >> 7
            if len(pay) > 1: second[pay[1]] += 1
            sizes[len(b)] += 1; tot_bytes += len(pay)
            c = collections.Counter(pay); m = len(pay)
            ent_sum += -sum(v / m * math.log2(v / m) for v in c.values())
            all_bytes.update(pay)
            ssrc[int.from_bytes(b[8:12],'big')] += 1; rts.append(int.from_bytes(b[4:8],'big'))
        p.wait()
    nts = len(set(rts))
    ta = sum(all_bytes.values()); H = -sum(v/ta*math.log2(v/ta) for v in all_bytes.values()) if ta else 0
    print(f"{label}: rtp_pkts={n} payload_bytes={tot_bytes} distinct_first_bytes={len(first)} forbidden_zero_bit_set={fbit} ({fbit/max(n,1):.3f}) chi2_first_byte_vs_uniform={chi2_uniform(first,n):.0f} (df=255, 0.1% crit~330) distinct_second_bytes={len(second)} chi2_second={chi2_uniform(second,n):.0f} mean_pkt_entropy={ent_sum/max(n,1):.3f} all_payload_entropy={H:.4f} marker={marker} ext={hdr_ext} pad={pad} ssrc_count={len(ssrc)} distinct_rtp_ts={nts} top_sizes={sizes.most_common(3)} top_first={[(hex(a),b) for a,b in first.most_common(4)]}")
R=os.environ.get('RING13',os.path.expanduser('~/datasets/claims/ring13'))+'/'
def fl(day, *names): return [os.path.join(R,day,'eth1-'+n) for n in names]
g=lambda day,pat: sorted(x for x in glob.glob(os.path.join(R,day,'eth1-'+pat+'*')) if not x.endswith('.frames'))
analyse(g('20180321','20180321.1750'),'52.206.247.65',0,9e9,'03-21 17:50 UA 1.10.70 vod ')
analyse(g('20180411','20180411.20'),'35.174.122.165',0,9e9,'04-11 20:04 UA 1.19.217 ding')
analyse(g('20180413','20180413.15')+g('20180413','20180413.16'),'35.174.122.57',0,9e9,'04-13 15:41 UA 1.10.70 ding')
analyse(g('20180413','20180413.15'),'35.174.122.130',0,9e9,'04-13 15:48 UA 1.10.70 vod ')
analyse(g('20180413','20180413.15')+g('20180413','20180413.16'),'35.174.122.92',0,9e9,'04-13 15:55 UA 1.19.217 ding')
