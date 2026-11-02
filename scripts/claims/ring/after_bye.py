# How long does the doorbell keep sending video after the server's BYE? Counts only.
import csv,glob,os,subprocess,time
R=os.environ.get('RING13',os.path.expanduser('~/datasets/claims/ring13'))+'/'
S=[('20180321','52.206.247.65','vod'),('20180411','35.174.122.165','ding'),('20180413','35.174.122.57','ding'),('20180413','35.174.122.130','vod'),('20180413','35.174.122.92','ding')]
for day,srv,kind in S:
    rows=list(csv.DictReader(open(R+f'out/sip-{day}.tsv'),delimiter='\t'))
    bye=[float(r['time']) for r in rows if r['first'].startswith('BYE') and r['src'].startswith(srv)]
    inv=[float(r['time']) for r in rows if r['first'].startswith('INVITE') and r['dst'].startswith(srv)]
    uas=[r['ua'] for r in rows if r['first'].startswith('INVITE') and r['dst'].startswith(srv)]
    files=[f for f in sorted(glob.glob(R+day+'/eth*')) if not f.endswith('.frames')]
    bt=bye[0]; n_after=n_before=0; last=None; seen=set(); icmp=0
    for f in files:
        base=os.path.basename(f); hhmm=base.split('.')[1]
        t0=int(hhmm[:2])*3600+int(hhmm[2:])*60; day0=int(bt)-int(bt)%86400
        if not (bt-1200 < day0+t0 < bt+900): continue
        p=subprocess.run(['tshark','-r',f,'-Y',f'ip.dst=={srv} && udp.srcport==51504 && !icmp','-T','fields','-e','frame.time_epoch','-e','rtp.seq','-e','udp.length','-d','udp.port==51504,rtp'],capture_output=True,text=True)
        for l in p.stdout.splitlines():
            a=l.split('\t'); t=float(a[0]); k=(a[1],a[2],round(t,1))
            if k in seen: continue
            seen.add(k)
            if t>bt: n_after+=1; last=t
            else: n_before+=1
        q=subprocess.run(['tshark','-r',f,'-Y',f'icmp.type==3 && ip.src=={srv}','-T','fields','-e','frame.number'],capture_output=True,text=True)
        icmp+=len(q.stdout.splitlines())
    print(day,kind,uas[0][-8:],'invite-to-bye %.1fs'%(bt-inv[0]),'rtp before bye',n_before,'after bye',n_after,'last rtp +%.1fs'%((last-bt) if last else 0),'icmp unreachable frames (doubled)',icmp)
