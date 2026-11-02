# Copy only the phone's packets to or from the SIP/media servers seen with the doorbell. usage: extract_phone.py <tgz> <outdir>
import ipaddress, os, struct, sys, tarfile
tgz, outdir = sys.argv[1:3]; os.makedirs(outdir, exist_ok=True)
PHONE = bytes.fromhex(os.environ['PHONE_MAC'])
NET = [ipaddress.ip_network(x) for x in ('35.174.122.0/24','35.174.123.0/24','52.206.247.65/32')]
ips = set()
for n in NET: ips.update(a.packed for a in n)
log = open(os.path.join(outdir,'scan.tsv'),'w')
with tarfile.open(tgz,'r|gz') as t:
    for m in t:
        if not m.isfile(): continue
        name = os.path.basename(m.name)
        if name.startswith('._') or not name.startswith('eth'): continue
        data = t.extractfile(m).read()
        off, n, chunks, frames, L = 24, 0, [data[:24]], [], len(data)
        unpack = struct.Struct('<IIII').unpack_from
        while off + 16 <= L:
            _,_,incl,_ = unpack(data, off); p = off+16; end = p+incl
            if end > L: break
            n += 1
            if (data[p:p+6]==PHONE or data[p+6:p+12]==PHONE) and data[p+12:p+14]==b'\x08\x00':
                if data[p+26:p+30] in ips or data[p+30:p+34] in ips:
                    chunks.append(data[off:end]); frames.append(n)
            off = end
        if frames:
            open(os.path.join(outdir,name),'wb').write(b''.join(chunks))
            open(os.path.join(outdir,name+'.frames'),'w').write(''.join(f'{x}\n' for x in frames))
            log.write(f'{name}\t{n}\t{len(frames)}\n'); log.flush()
print('done',tgz,flush=True)
