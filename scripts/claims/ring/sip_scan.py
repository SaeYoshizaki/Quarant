# Plaintext SIP/SDP on udp/15063, one line per message with original file and frame. Only protocol structure is
# printed: identifiers (Call-ID, tags, branch, SIP URIs, session ids) become lengths. usage: sip_scan.py <day dir> <out.tsv>
import glob, os, re, subprocess, sys
day, out = sys.argv[1:3]
files = sorted(f for f in glob.glob(os.path.join(day, 'eth*')) if not f.endswith('.frames'))
w = open(out, 'w'); w.write('file\tframe\ttime\tsrc\tdst\tfirst\tcseq\tua\tsubject\tctype\tsdp\tsec_markers\thdr_names\n')
seen = set(); n = dup = 0
for f in files:
    frames = [int(x) for x in open(f + '.frames')]
    p = subprocess.run(['tshark','-r',f,'-Y','udp.port==15063 or udp.port==15064 or tcp.port==15063 or tcp.port==15064','-T','fields','-E','separator=\t','-e','frame.number','-e','frame.time_epoch','-e','ip.src','-e','udp.srcport','-e','ip.dst','-e','udp.dstport','-e','udp.payload','-e','tcp.payload','-e','tcp.srcport','-e','tcp.dstport'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        a = line.split('\t')
        fr, ts, s, sp, d, dp, up, tp = a[:8]
        pl = bytes.fromhex((up or tp).replace(':', ''))
        if not pl: continue
        k = (s, d, pl)
        if k in seen: dup += 1; continue
        seen.add(k); n += 1
        txt = pl.decode('latin-1')
        lines = txt.split('\r\n'); first = lines[0]
        if not re.match(r'(SIP/2\.0 \d|[A-Z]+ sip:)', first):
            w.write('\t'.join((os.path.basename(f), str(frames[int(fr)-1]), ts, f'{s}:{sp or a[8]}', f'{d}:{dp or a[9]}', 'non-sip len=%d' % len(pl), '', '', '', '', '', '', '')) + '\n'); continue
        first = re.sub(r'sip:[^ ;>]+', lambda m: 'sip:***len%d' % (len(m.group(0))-4), first)
        hdr = {}
        for l in lines[1:]:
            if not l: break
            kk, _, v = l.partition(':'); hdr[kk.strip().lower()] = v.strip()
        sdp = ' ; '.join(re.sub(r'IN IP4 \S+', 'IN IP4 ***', l) for l in txt.split('\r\n\r\n', 1)[-1].split('\r\n') if re.match(r'(m=|a=rtpmap|a=sendonly|a=recvonly|a=sendrecv|a=rtcp-mux|s=|a=ptime)', l)) if '\r\n\r\n' in txt else ''
        markers = ','.join(x for x in ('RTP/SAVP','a=crypto','a=fingerprint','a=key-mgmt','a=setup','a=ice','srtp') if x.lower() in txt.lower())
        w.write('\t'.join((os.path.basename(f), str(frames[int(fr)-1]), ts, f'{s}:{sp or a[8]}', f'{d}:{dp or a[9]}', first[:80], hdr.get('cseq',''), hdr.get('user-agent','').replace('\t',' '), hdr.get('subject',''), hdr.get('content-type',''), sdp, markers, ','.join(hdr))) + '\n')
w.close(); print(os.path.basename(day), 'sip messages', n, 'dropped duplicates', dup)
