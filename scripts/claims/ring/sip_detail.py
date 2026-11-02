# Structure of each INVITE and MESSAGE: per header value length and class, SDP line prefixes. No values.
import glob,os,re,subprocess,sys
R=os.environ.get('RING13',os.path.expanduser('~/datasets/claims/ring13'))+'/'
targets=[('20180321','eth1-20180321.1750.1521672600'),('20180411','eth1-20180411.2000.1523494800'),('20180413','eth1-20180413.1540.1523652000'),('20180413','eth1-20180413.1545.1523652300'),('20180413','eth1-20180413.1555.1523652900')]
for day,name in targets:
    f=R+day+'/'+name
    p=subprocess.run(['tshark','-r',f,'-Y','udp.port==15063','-T','fields','-E','separator=\t','-e','frame.number','-e','udp.payload'],capture_output=True,text=True)
    seen=set()
    for l in p.stdout.splitlines():
        fr,pl=l.split('\t'); b=bytes.fromhex(pl.replace(':',''))
        if b in seen: continue
        seen.add(b)
        t=b.decode('latin-1')
        if t.startswith('INVITE') or t.startswith('MESSAGE'):
            head,_,body=t.partition('\r\n\r\n')
            hs=head.split('\r\n')[1:]
            print('---',name[5:18],'extract-frame',fr,t[:7],'total',len(b),'body',len(body))
            print('   hdrs:',[(h.split(':')[0],len(h.split(':',1)[1].strip())) for h in hs])
            if t.startswith('INVITE'):
                print('   sdp line types:',[ln.split(':')[0] if ln.startswith('a=') else ln[:2] for ln in body.split('\r\n') if ln])
            else:
                kind='json' if body.strip().startswith('{') else 'other'
                keys=re.findall(r'"([A-Za-z_]+)"\s*:',body) if kind=='json' else []
                print('   message body kind',kind,'len',len(body),'charset printable',all(32<=ord(c)<127 or c in '\r\n' for c in body),'json keys',keys[:20],'words',len(body.split()))
