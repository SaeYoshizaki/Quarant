# Statistics of the two plaintext-HTTP firmware responses on 04-13; the body is never printed or saved.
# Prints response header names with safe values, block entropy and whether given version/product markers occur (counts only).
import bisect, collections, glob, math, os, re, subprocess
R=os.environ.get('RING13',os.path.expanduser('~/datasets/claims/ring13'))+'/20180413/'
files=[R+'eth1-20180413.1545.1523652300',R+'eth1-20180413.1550.1523652600']
SERVERS={'52.54.195.144':'63724','54.164.34.110':'63725'}  # server -> client port of the firmware GET
segs=collections.defaultdict(dict); req=collections.defaultdict(dict)
for f in files:
    p=subprocess.run(['tshark','-r',f,'-Y','tcp.len>0 && tcp.port==80','-T','fields','-E','separator=\t','-e','ip.src','-e','tcp.srcport','-e','tcp.dstport','-e','tcp.seq_raw','-e','tcp.payload'],capture_output=True,text=True)
    for l in p.stdout.splitlines():
        s,sp,dp,seq,pl=l.split('\t'); b=bytes.fromhex(pl.replace(':',''))
        if s in SERVERS and dp==SERVERS[s]: segs[dp].setdefault(int(seq),b)
        elif sp in SERVERS.values(): req[sp].setdefault(int(seq),b)
def H(b):
    c=collections.Counter(b);n=len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values()) if n else 0
for port,m in segs.items():
    st=b''; nxt=None; gap=0
    for sq in sorted(m):
        d=m[sq]
        if nxt is not None and sq>nxt: gap+=sq-nxt
        if nxt is not None and sq<nxt: d=d[nxt-sq:]
        st+=d; nxt=max(nxt or 0,sq+len(m[sq]))
    he=st.find(b'\r\n\r\n'); head=st[:he].decode('latin-1').split('\r\n'); body=st[he+4:]
    rq=b''.join(req[port][k] for k in sorted(req[port])) if port in req else b''
    first=rq.split(b'\r\n')[0].decode('latin-1')
    print('--- client port',port,'request:',re.sub(r'component=(\w+)',lambda x:'component='+x.group(1),first))
    print('   other request headers:',[x.split(b':')[0].decode() for x in rq.split(b'\r\n')[1:] if x and not x.lower().startswith(b'authorization')])
    print('   status:',head[0]); 
    for h in head[1:]:
        k,_,v=h.partition(':')
        if k.lower() in('content-disposition','content-transfer-encoding','content-type','cache-control','server','date','x-request-id','etag'):
            print('    ',k,':',v.strip() if k.lower() not in('x-request-id','etag') else '***len%d'%len(v.strip()))
    print('   body bytes',len(body),'gaps',gap,'overall entropy %.3f'%H(body))
    blk=[H(body[i:i+4096]) for i in range(0,len(body),4096)]
    hist=collections.Counter(int(x) for x in blk)
    print('   4 KiB block entropy histogram (floor bits: blocks):',sorted(hist.items()),'blocks>=7.9:',sum(x>=7.9 for x in blk))
    sigs={'gzip':b'\x1f\x8b\x08','zip':b'PK\x03\x04','elf':b'\x7fELF','uimage':b'\x27\x05\x19\x56','xz':b'\xfd7zXZ','squashfs':b'hsqs','pem':b'-----BEGIN'}
    print('   container signatures at start:',[n for n,s in sigs.items() if body.startswith(s)],'anywhere (count):',{n:body.count(s) for n,s in sigs.items() if body.count(s)})
    marks=[b'1.19.217',b'1.10.70',b'dpdv2',b'Device/',b'ring.com',b'vod.ring.com',b'fw.ring.com',b'/doorbots_api/',b'protocol=sip',b'GainSpan',b'Gainspan',b'gainspan',b'GS2K',b'GS2000',b'H264',b'SRTP',b'srtp',b'AES',b'SIP/2.0',b'Zero Cool',b'BEGIN CERTIFICATE',b'9998',b'SSL',b'RSA',b'SHA256',b'signature',b'Signature']
    print('   marker counts:',{m.decode():body.count(m) for m in marks if body.count(m)})
    strs=re.findall(rb'[\x20-\x7e]{6,}',body)
    print('   printable runs >=6:',len(strs),'covering bytes',sum(len(x) for x in strs),'of',len(body))
