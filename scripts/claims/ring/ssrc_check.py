# Does the X-SSRC-V header in the INVITE equal the SSRC of the video RTP? Prints booleans only.
import os,re,subprocess
R=os.environ.get('RING13',os.path.expanduser('~/datasets/claims/ring13'))+'/'
S=[('20180321','eth1-20180321.1750.1521672600','52.206.247.65'),('20180411','eth1-20180411.2000.1523494800','35.174.122.165'),('20180413','eth1-20180413.1540.1523652000','35.174.122.57'),('20180413','eth1-20180413.1545.1523652300','35.174.122.130'),('20180413','eth1-20180413.1555.1523652900','35.174.122.92')]
for day,name,srv in S:
    f=R+day+'/'+name
    p=subprocess.run(['tshark','-r',f,'-Y',f'ip.dst=={srv} && udp.dstport==15063 && udp.srcport==15063','-T','fields','-e','udp.payload'],capture_output=True,text=True)
    hdr=None
    for l in p.stdout.splitlines():
        t=bytes.fromhex(l.replace(':','')).decode('latin-1')
        if t.startswith('INVITE'):
            hdr=dict(re.findall(r'(X-SSRC-[AV]): (\d+)',t)); hs=re.search(r'X-Session-Hash:\s*(\S+)',t); break
    q=subprocess.run(['tshark','-r',f,'-Y',f'ip.dst=={srv} && udp.srcport==51504 && !icmp','-T','fields','-e','udp.payload'],capture_output=True,text=True)
    b=bytes.fromhex(q.stdout.splitlines()[0].replace(':',''))
    print(name[5:18],'x-ssrc-v==rtp ssrc:',int(hdr['X-SSRC-V'])==int.from_bytes(b[8:12],'big'),'x-session-hash:',('len%d'%len(hs.group(1)),'charset-hex' if re.fullmatch(r'[0-9a-f]+',hs.group(1)) else 'mixed') if hs else None)
