# RTP structure on Ring's UDP flows other than SIP/DNS/NTP/DHCP: header fields and H.264 NAL structure only. Never rebuilds
# or stores media. Dedup by (flow, rtp seq, ts). usage: rtp_scan.py <day dir> <out.json>
import collections, glob, json, math, os, subprocess, sys
day, out = sys.argv[1:3]
files = sorted(f for f in glob.glob(os.path.join(day, 'eth*')) if not f.endswith('.frames'))
flows = {}
for f in files:
    frames = [int(x) for x in open(f + '.frames')]
    p = subprocess.Popen(['tshark','-r',f,'-Y','udp && not udp.port==53 && not udp.port==123 && not udp.port==67 && not udp.port==68 && not udp.port==15063 && not udp.port==15064 && not udp.port==161 && not udp.port==5353 && not udp.port==1900','-T','fields','-E','separator=\t','-e','frame.number','-e','frame.time_epoch','-e','ip.src','-e','udp.srcport','-e','ip.dst','-e','udp.dstport','-e','udp.length','-e','udp.payload'],stdout=subprocess.PIPE,text=True,bufsize=1<<20)
    for line in p.stdout:
        fr, ts, s, sp, d, dp, ul, pl = line.rstrip('\n').split('\t')
        key = f'{s}:{sp}>{d}:{dp}'; b = bytes.fromhex(pl.replace(':',''))
        fl = flows.setdefault(key, dict(file=os.path.basename(f), first_frame=frames[int(fr)-1], first=float(ts), last=float(ts), pkts=0, dup=0, bytes=0, ver=collections.Counter(), pt=collections.Counter(), ssrc=collections.Counter(), nal=collections.Counter(), fu_type=collections.Counter(), fu_s=0, fu_e=0, fu_both=0, marker=0, sps=collections.Counter(), pps=0, seen=set(), seqs=[], tsdeltas=collections.Counter(), lastts=None, sps_frame=None, last_file=None, last_frame=None, first_bytes=collections.Counter(), fu_seq_ok=0, fu_seq_bad=0, open_fu=None))
        fl['last']=float(ts); fl['last_file']=os.path.basename(f); fl['last_frame']=frames[int(fr)-1]
        if len(b) < 12: fl['ver']['short']+=1; continue
        ver=b[0]>>6; pt=b[1]&0x7f; mk=b[1]>>7; seq=int.from_bytes(b[2:4],'big'); rts=int.from_bytes(b[4:8],'big'); ssrc=int.from_bytes(b[8:12],'big')
        kk=(seq,rts,ssrc)
        if kk in fl['seen']: fl['dup']+=1; continue
        fl['seen'].add(kk); fl['pkts']+=1; fl['bytes']+=len(b); fl['ver'][ver]+=1; fl['pt'][pt]+=1; fl['ssrc'][ssrc]+=1; fl['marker']+=mk; fl['seqs'].append(seq)
        cc=b[0]&0x0f; ext=(b[0]>>4)&1; off=12+4*cc
        if ext and len(b)>=off+4: off+=4+4*int.from_bytes(b[off+2:off+4],'big')
        pay=b[off:]
        if ver==2 and pt==97 and pay:
            nt=pay[0]&0x1f; fl['nal'][nt]+=1; fl['first_bytes'][pay[0]]+=1
            if nt==28 and len(pay)>=2:
                st=pay[1]>>7; en=(pay[1]>>6)&1; ft=pay[1]&0x1f; fl['fu_type'][ft]+=1; fl['fu_s']+=st; fl['fu_e']+=en; fl['fu_both']+=int(st and en)
                if st:
                    if fl['open_fu'] is not None: fl['fu_seq_bad']+=1
                    fl['open_fu']=ft
                elif fl['open_fu'] is None: fl['fu_seq_bad']+=1
                else:
                    if ft!=fl['open_fu']: fl['fu_seq_bad']+=1
                if en:
                    if fl['open_fu'] is not None: fl['fu_seq_ok']+=1
                    fl['open_fu']=None
            if nt==7 and len(pay)>=4:
                fl['sps'][(pay[1],pay[2],pay[3])]+=1
                if fl['sps_frame'] is None: fl['sps_frame']=(os.path.basename(f),frames[int(fr)-1])
            if nt==8: fl['pps']+=1
    p.wait()
res=[]
for k,v in sorted(flows.items(),key=lambda x:x[1]['first']):
    v.pop('seen'); seqs=v.pop('seqs'); v.pop('lastts'); v.pop('tsdeltas'); v.pop('open_fu')
    miss=0
    for a,b in zip(seqs,seqs[1:]):
        dlt=(b-a)&0xffff
        if 1<dlt<1000: miss+=dlt-1
    v['seq_gaps']=miss
    v['flow']=k
    for c in ('ver','pt','nal','fu_type','first_bytes'): v[c]={str(a):b for a,b in v[c].most_common(12)}
    v['ssrc_count']=len(v['ssrc']); v['ssrc']=[str(x) for x,_ in v['ssrc'].most_common(2)]
    v['sps']={f'profile={a[0]},constraints={a[1]},level={a[2]}':n for a,n in v['sps'].items()}
    res.append(v)
json.dump(res,open(out,'w'),indent=0)
print(os.path.basename(day),'udp flows',len(res))
