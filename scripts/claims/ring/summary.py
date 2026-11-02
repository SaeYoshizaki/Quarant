# Per-day table of ring-prior-work.md 3.2 from the outputs of http_scan.py, sip_scan.py and tls_scan.py.
import csv,json,os,glob,collections,statistics,time
BASE=os.environ.get('RING13',os.path.expanduser('~/datasets/claims/ring13'))
R=BASE+'/out/'
days='20180320 20180321 20180328 20180410 20180411 20180412 20180413 20180414 20180415 20180416 20180417 20180418 20180419'.split()
T=lambda t:time.strftime('%H:%M:%S',time.gmtime(float(t)))
tot_poll=tot_ch=0
allsuites=collections.Counter(); allsh=collections.Counter(); certs=collections.Counter()
for d in days:
    scan=[l.split('\t') for l in open(f'{BASE}/{d}/scan.tsv')]
    kept=sum(int(x[2]) for x in scan if len(x)>2 and x[2].strip().isdigit())
    rows=list(csv.DictReader(open(R+f'http-{d}.tsv'),delimiter='\t'))
    req=[r for r in rows if r['kind']=='req']
    poll=[r for r in req if r['path'].endswith('vod/ready')]
    posts=collections.Counter(r['path'].split('/')[-1] for r in req if r['code_or_method']=='POST')
    fw=[r for r in req if 'firmwares' in r['path']]
    creds=collections.Counter(r['cred'] for r in req if r['cred'])
    code=collections.Counter(r['code_or_method'] for r in rows if r['kind']=='resp')
    sip=list(csv.DictReader(open(R+f'sip-{d}.tsv'),delimiter='\t'))
    ua=collections.Counter(r['ua'] for r in sip if r['ua'].startswith('Device/'))
    t=json.load(open(R+f'tls-{d}.json'))
    ch=sum(v for k,v in t['ch']); sh=sum(v for k,v in t['sh'])
    for k,v in t['ch']: allsuites[(k[0],k[2],k[3],k[1])]+=v
    for k,v in t['sh']: allsh[tuple(k)]+=v
    for k,v in t['cert']: certs[k[1][:120]]+=v
    tot_poll+=len(poll); tot_ch+=ch
    dt=[float(r['time']) for r in sorted(poll,key=lambda r:float(r['time']))]; gaps=[b-a for a,b in zip(dt,dt[1:])]
    print(d,'pkts',kept,'poll',len(poll),'median %.2f'%statistics.median(gaps) if gaps else 'median -','codes',dict(code),'posts',dict(posts),'fw',len(fw),'creds',dict(creds),'ua',dict(ua),'CH',ch,'SH',sh,'dnsq',sum(v for k,v in t['dns']),'dnsresp',sum(v for k,v in t['rcode']),'dhcp',sum(v for k,v in t['dhcp']))
print('poll total',tot_poll,'CH total',tot_ch)
print('suites',allsuites.most_common()); print('sh',allsh.most_common()); print('certs',certs.most_common())
