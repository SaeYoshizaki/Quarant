#!/usr/bin/env python3
"""Download a capture and keep only the packets of some devices, without storing the whole file.

usage:
  fetchfilter.py pcap   <url> <out.pcap> <tcpdump filter>            stream one pcap through tcpdump
  fetchfilter.py tgz    <url> <out dir>  <tcpdump filter> [--dedupe]  stream a .tgz/.tar.gz; filter each pcap member
  fetchfilter.py tgzfile <url> <out dir> <tcpdump filter> [--dedupe]  same, but download the archive first (resumable)
  fetchfilter.py get    <url> <out> [parts]                         download with parallel ranges (resumable parts)
  fetchfilter.py zipls  <url>                                         list the members of a remote zip (HTTP ranges)
  fetchfilter.py zip    <url> <member> <out.pcap> <tcpdump filter>    filter one member of a remote zip (HTTP ranges)

The filter is a tcpdump expression, e.g. "ether host 00:16:6c:ab:6b:88 or ether host 70:88:6b:10:0f:c6".
--dedupe removes adjacent duplicate packets (editcap -D 16), for captures that hold every packet twice.
Members with no matching packet are not written. Progress goes to stderr.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) research-download"
SLOW = ["--speed-limit", "20000", "--speed-time", "90"]   # give up on a stalled connection (then resume)
TMP = os.path.expanduser("~/qlocal/tmp")


def curl(url):
    return subprocess.Popen(["curl", "-s", "-L", "--retry", "5", "-A", UA] + SLOW + [url], stdout=subprocess.PIPE)


def tcpdump(src, out, flt):
    """Filter the capture src ('-' for stdin) to out; drop out when nothing matched."""
    r = subprocess.run(["tcpdump", "-r", src, "-w", out, flt], stdin=sys.stdin if src == "-" else None,
                       stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        print("tcpdump:", r.stderr.strip()[-300:], file=sys.stderr)
    if os.path.exists(out) and os.path.getsize(out) <= 24:
        os.remove(out)


def dedupe(path):
    tmp = path + ".dd"
    subprocess.run(["editcap", "-D", "16", path, tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(tmp):
        os.replace(tmp, path)


def cmd_pcap(url, out, flt):
    # tcpdump reads pcapng only from a file, not from stdin, so the capture is kept until filtered
    with tempfile.NamedTemporaryFile(dir=TMP, delete=False) as t:
        pass
    total = size_of(url)
    for attempt in range(40):
        r = subprocess.run(["curl", "-s", "-L", "--retry", "5", "-C", "-", "-A", UA] + SLOW + ["-o", t.name, url])
        if total is None or os.path.getsize(t.name) >= total:
            break
    if total and os.path.getsize(t.name) < total:
        print(f"{out}: incomplete download {os.path.getsize(t.name)}/{total}", file=sys.stderr)
        os.remove(t.name)
        return
    tcpdump(t.name, out, flt)
    size = os.path.getsize(t.name)
    os.remove(t.name)
    print(f"{out}: curl {r.returncode}, {size} bytes read, kept {os.path.getsize(out) if os.path.exists(out) else 0}",
          file=sys.stderr)


def size_of(url):
    r = subprocess.run(["curl", "-s", "-L", "-A", UA, "-r", "0-0", "-D", "-", "-o", "/dev/null", url], capture_output=True, text=True)
    m = re.findall(r"content-range: bytes 0-0/(\d+)", r.stdout, re.I)
    return int(m[-1]) if m else None


def cmd_get(url, out, parts=4):
    """Parallel ranges; each part is resumed with curl -C - until it has its full length."""
    total = size_of(url)
    if not total:
        subprocess.run(["curl", "-s", "-L", "--retry", "10", "-C", "-", "-A", UA] + SLOW + ["-o", out, url])
        return
    step = -(-total // parts)
    procs = []
    for i in range(parts):
        a, b = i * step, min(total, (i + 1) * step) - 1
        procs.append((f"{out}.part{i}", a, b))

    def fetch(pp):
        name, a, b = pp
        for attempt in range(30):
            have = os.path.getsize(name) if os.path.exists(name) else 0
            if have >= b - a + 1:
                return True
            subprocess.run(["curl", "-s", "-L", "--retry", "5", "-A", UA] + SLOW + ["-r", f"{a + have}-{b}", url],
                           stdout=open(name, "ab"))
        return False
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(parts) as ex:
        ok = list(ex.map(fetch, procs))
    if all(ok):
        with open(out, "wb") as o:
            for name, _, _ in procs:
                with open(name, "rb") as f:
                    shutil.copyfileobj(f, o, 4 << 20)
                os.remove(name)
    print(f"{out}: {'done' if all(ok) else 'incomplete'} {total} bytes", file=sys.stderr)


def cmd_tgz(url, outdir, flt, dd, local=None):
    os.makedirs(outdir, exist_ok=True)
    p = subprocess.Popen(["cat", local], stdout=subprocess.PIPE) if local else curl(url)
    g = subprocess.Popen(["gzip", "-dc"], stdin=p.stdout, stdout=subprocess.PIPE)
    n = kept = 0
    with tarfile.open(fileobj=g.stdout, mode="r|") as tf:
        for m in tf:
            if not m.isfile():
                continue
            n += 1
            base = os.path.basename(m.name)
            out = os.path.join(outdir, base + ".pcap")
            if os.path.exists(out):
                continue
            try:
                with tempfile.NamedTemporaryFile(dir=TMP, delete=False) as t:
                    shutil.copyfileobj(tf.extractfile(m), t, 1 << 20)
                tcpdump(t.name, out, flt)
                os.remove(t.name)
            except OSError as e:
                print(f"{outdir}: member {m.name} failed: {e}", file=sys.stderr)
                continue
            if os.path.exists(out):
                kept += 1
                if dd:
                    dedupe(out)
            if n % 24 == 0:
                print(f"{outdir}: {n} members, {kept} kept, last {m.name}", file=sys.stderr, flush=True)
    g.wait(); p.wait()
    print(f"{outdir}: done, {n} members, {kept} kept, curl {p.returncode}, gzip {g.returncode}", file=sys.stderr)
    if p.returncode == 0 and g.returncode == 0:
        open(os.path.join(outdir, ".done"), "w").write(f"{n} members\n")


class Ranged(io.RawIOBase):
    """Read-only file over HTTP range requests, with a read-ahead buffer."""
    def __init__(self, url, block=16 << 20):
        self.url, self.block, self.pos, self.buf, self.bufpos = url, block, 0, b"", -1
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Range": "bytes=0-0"})
        with urllib.request.urlopen(req, timeout=120) as r:
            self.size = int(r.headers["Content-Range"].split("/")[1])
            self.url = r.geturl()

    def seekable(self): return True
    def readable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.size + off
        return self.pos

    def _fetch(self, start, end):
        for attempt in range(6):
            try:
                req = urllib.request.Request(self.url, headers={"User-Agent": UA, "Range": f"bytes={start}-{end}"})
                with urllib.request.urlopen(req, timeout=300) as r:
                    return r.read()
            except Exception as e:
                print("range retry", attempt, e, file=sys.stderr)
        raise IOError("range fetch failed")

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0:
            return b""
        if not (self.bufpos <= self.pos and self.pos + n <= self.bufpos + len(self.buf)):
            want = max(n, self.block)
            self.buf = self._fetch(self.pos, min(self.size, self.pos + want) - 1)
            self.bufpos = self.pos
        i = self.pos - self.bufpos
        out = self.buf[i:i + n]
        self.pos += len(out)
        return out

    def readinto(self, b):
        d = self.read(len(b)); b[:len(d)] = d; return len(d)


def cmd_zipls(url):
    z = zipfile.ZipFile(Ranged(url, 1 << 20))
    for i in z.infolist():
        print(i.file_size, i.compress_size, i.filename)


def cmd_zip(url, member, out, flt):
    z = zipfile.ZipFile(Ranged(url))
    with tempfile.NamedTemporaryFile(dir=TMP, delete=False) as t, z.open(member) as src:
        shutil.copyfileobj(src, t, 4 << 20)
    tcpdump(t.name, out, flt)
    os.remove(t.name)
    print(f"{out}: {os.path.getsize(out) if os.path.exists(out) else 0} bytes", file=sys.stderr)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[0] == "pcap": cmd_pcap(a[1], a[2], a[3])
    elif a[0] == "tgz": cmd_tgz(a[1], a[2], a[3], "--dedupe" in a)
    elif a[0] == "tgzfile":
        os.makedirs(a[2], exist_ok=True)
        arch = os.path.join(TMP, os.path.basename(a[2].rstrip("/")) + ".tgz")
        cmd_get(a[1], arch, 4)
        if os.path.exists(arch):
            cmd_tgz(a[1], a[2], a[3], "--dedupe" in a, local=arch)
            os.remove(arch)
    elif a[0] == "get": cmd_get(a[1], a[2], int(a[3]) if len(a) > 3 else 4)
    elif a[0] == "zipls": cmd_zipls(a[1])
    elif a[0] == "zip": cmd_zip(a[1], a[2], a[3], a[4])
