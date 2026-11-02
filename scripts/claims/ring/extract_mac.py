# Copy one MAC's packets out of a YourThings day tgz, one output PCAP per input file, and keep a
# sidecar with the original frame number of each copied packet, so that evidence can cite the
# original file and frame. usage: extract.py <tgz> <outdir> <mac hex without colons>
import os, struct, sys, tarfile, time
tgz, outdir, mac = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3])
os.makedirs(outdir, exist_ok=True)
start = time.time(); nfiles = total = kept = 0
log = open(os.path.join(outdir, 'scan.tsv'), 'w')
with tarfile.open(tgz, 'r|gz') as t:
    for m in t:
        if not m.isfile(): continue
        name = os.path.basename(m.name)
        if name.startswith('._'): continue
        if not name.startswith('eth'):
            log.write(f'{name}\tskipped-not-eth\t{m.size}\n'); continue
        data = t.extractfile(m).read()
        if len(data) < 24:
            log.write(f'{name}\tshort\t{len(data)}\n'); continue
        magic = data[:4]
        e = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
        off, n, chunks, frames, L = 24, 0, [data[:24]], [], len(data)
        unpack = struct.Struct(e + 'IIII').unpack_from
        while off + 16 <= L:
            _, _, incl, _ = unpack(data, off)
            p = off + 16; end = p + incl
            if end > L: log.write(f'{name}\ttruncated-at-frame\t{n+1}\n'); break
            n += 1
            if data[p:p+6] == mac or data[p+6:p+12] == mac:
                chunks.append(data[off:end]); frames.append(n)
            off = end
        with open(os.path.join(outdir, name), 'wb') as o: o.write(b''.join(chunks))
        with open(os.path.join(outdir, name + '.frames'), 'w') as o: o.write(''.join(f'{x}\n' for x in frames))
        log.write(f'{name}\t{n}\t{len(frames)}\n'); log.flush()
        nfiles += 1; total += n; kept += len(frames)
        del data, chunks
print(f'{os.path.basename(tgz)} files={nfiles} packets={total} kept={kept} minutes={(time.time()-start)/60:.1f}', flush=True)
