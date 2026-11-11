#!/usr/bin/env python3
"""Sweep captures for identifiers sent in plaintext and for how traffic is encrypted.

usage: expose.py <devices.tsv> <dataset> <out dir> <source>...
  source: a pcap/pcapng file, a directory (searched for captures), or a tar archive
  (its members are read in order without extracting them)

Writes <out dir>/<capture>.jsonl for each capture file. Values never leave memory:
a value is written as a keyed hash (HMAC-SHA256, key in ~/datasets/claims/sweep/.key,
outside the repo), its shape (h for a hex digit, a for another letter or digit,
other characters kept, cut at 40) and its length. Tokens of 8 or more letters and
digits that contain a digit are hashed too, so that an identifier inside a longer
value can still be matched.

Records (one JSON object per line, "r" is the record type):
  ident   a value the device announced on the LAN: DHCP host name and client id,
          SSDP USN uuid and X- headers, UPnP serialNumber/serialNum/UDN/MACAddress,
          mDNS instance names and TXT values
  field   a value the device sent in plaintext to a public address: HTTP query
          parameter, path segment, header, form/JSON/XML body value; MQTT client id,
          user name and topic; words of other text protocols
  macout  the device's own MAC (any spelling, or its 6 raw bytes) in a plaintext
          payload to a public address
  tls     one TLS handshake: versions and suites offered, version and suite chosen,
          first server certificate (key type and size, signature hash, self-signed,
          expired at capture time, issuer)
  dl      an HTTP response from a public address to the device with a body of
          1 MB or more, or a binary content type
  flow    per device, peer kind (lan or public), protocol, server port and payload
          kind: number of flows and payload bytes
Frame numbers count every packet of the capture file from 1, as Wireshark does.
TCP payloads are put in order by sequence number, so duplicated packets
(YourThings holds every packet twice) and retransmissions are dropped.
"""
import collections
import csv
import hashlib
import hmac
import io
import json
import math
import os
import re
import socket
import struct
import subprocess
import sys
import tarfile
import warnings
import urllib.parse
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

warnings.filterwarnings("ignore", module="cryptography")
warnings.filterwarnings("ignore", message=".*serial number.*")
KEYFILE = Path.home() / "datasets/claims/sweep/.key"
CAP = 32768            # payload bytes kept per direction of a flow
IDLE = {"tcp": 300, "udp": 60}
MIN_TOKEN = 8
TOKEN = re.compile(rb"[A-Za-z0-9]{8,}")
HTTP_REQ = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS) (\S+) HTTP/1\.[01]\r?\n")
HTTP_RESP = re.compile(rb"^HTTP/1\.[01] (\d{3})")
SKIP_HEADERS = {b"host", b"accept", b"accept-encoding", b"accept-language", b"accept-charset", b"connection",
                b"content-length", b"content-type", b"cache-control", b"pragma", b"date", b"range", b"expect", b"te",
                b"transfer-encoding", b"upgrade", b"if-modified-since", b"if-none-match", b"if-range", b"keep-alive",
                b"referer", b"origin", b"content-encoding"}
UPNP_TAGS = re.compile(rb"<(serialNumber|serialNum|UDN|MACAddress|macAddress|deviceID|DeviceID|deviceId)>\s*([^<]{4,120}?)\s*</", re.I)
XML_LEAF = re.compile(rb"<([A-Za-z_][\w.\-:]{0,40})>([^<>]{1,200})</\1>")
FORM_KEY = re.compile(rb"[A-Za-z0-9_.\-\[\]]{1,60}")
EMAIL = re.compile(rb"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}")
BINARY_TYPES = ("application/octet-stream", "application/x-binary", "application/binary", "application/x-gzip",
                "application/gzip", "application/zip", "application/x-tar", "application/vnd.android")


def load_key():
    KEYFILE.parent.mkdir(parents=True, exist_ok=True)
    if not KEYFILE.exists():
        KEYFILE.write_bytes(os.urandom(32))
        KEYFILE.chmod(0o600)
    return KEYFILE.read_bytes()


KEY = load_key()


def h(v):
    return hmac.new(KEY, v, hashlib.sha256).hexdigest()[:20]


def shape(v):
    s = v.decode("latin-1")
    return "".join("h" if c in "0123456789abcdefABCDEF" else "a" if c.isalnum() else c for c in s[:40])


def tokens(v):
    return sorted({h(t) for t in TOKEN.findall(v) if any(48 <= c <= 57 for c in t) and t != v})[:20]


def val(v):
    """Hash, shape, length and token hashes of a value (bytes)."""
    return {"h": h(v), "shape": shape(v), "len": len(v), "tok": tokens(v)}


def public(ip):
    if len(ip) == 4:
        a, b = ip[0], ip[1]
        return not (a in (0, 10, 127) or a >= 224 or (a == 172 and 16 <= b < 32) or (a == 192 and b == 168)
                    or (a == 169 and b == 254) or (a == 100 and 64 <= b < 128))
    return not (ip[0] == 0xFF or ip[0] & 0xFE == 0xFC or ip[:2] == b"\xfe\x80" or ip == bytes(15) + b"\x01")


def ipstr(ip):
    return socket.inet_ntop(socket.AF_INET if len(ip) == 4 else socket.AF_INET6, ip)


def frames(f):
    """Yield (ts, linktype, frame) from a pcap or pcapng file object."""
    magic = f.read(4)
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        lt = struct.unpack(e + "I", f.read(20)[16:20])[0]
        rec = struct.Struct(e + "IIII")
        while True:
            hd = f.read(16)
            if len(hd) < 16:
                return
            s, us, incl, _ = rec.unpack(hd)
            yield s + us / div, lt, f.read(incl)
    elif magic == b"\x0a\x0d\x0d\x0a":
        e, ifaces, first = "<", [], True
        while True:
            hd = magic + f.read(4) if first else f.read(8)
            first = False
            if len(hd) < 8:
                return
            btype = struct.unpack(e + "I", hd[:4])[0]
            if btype == 0x0A0D0D0A:
                rest = f.read(4)
                e = "<" if rest == b"\x4d\x3c\x2b\x1a" else ">"
                blen = struct.unpack(e + "I", hd[4:8])[0]
                f.read(blen - 12)
                ifaces = []
                continue
            blen = struct.unpack(e + "I", hd[4:8])[0]
            body = f.read(blen - 8)
            if btype == 1:
                ifaces.append(struct.unpack(e + "H", body[:2])[0])
            elif btype == 6:
                iid, th, tl, cap = struct.unpack(e + "IIII", body[:16])
                yield ((th << 32) | tl) / 1e6, ifaces[iid] if iid < len(ifaces) else 1, body[20:20 + cap]
            elif btype == 3:
                yield 0.0, ifaces[0] if ifaces else 1, body[4:-4]
    else:
        raise ValueError("unknown capture format")


def l3(lt, fr):
    """(src mac, dst mac, ethertype offset) for Ethernet and Linux cooked captures."""
    if lt == 1 and len(fr) >= 14:
        et, off = struct.unpack("!H", fr[12:14])[0], 14
        while et in (0x8100, 0x88A8) and len(fr) >= off + 4:
            et, off = struct.unpack("!H", fr[off + 2:off + 4])[0], off + 4
        return fr[6:12], fr[0:6], et, off
    if lt == 113 and len(fr) >= 16:
        return fr[6:12], b"", struct.unpack("!H", fr[14:16])[0], 16
    return None


def l4(et, fr, off):
    """(src ip, dst ip, proto, sport, dport, seq, flags, payload) or None."""
    if et == 0x0800:
        ip = fr[off:]
        if len(ip) < 20:
            return None
        ihl, proto = (ip[0] & 15) * 4, ip[9]
        if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:
            return None
        total = struct.unpack("!H", ip[2:4])[0]
        src, dst, seg = ip[12:16], ip[16:20], ip[ihl:total] if total >= ihl else ip[ihl:]
    elif et == 0x86DD:
        ip = fr[off:]
        if len(ip) < 40:
            return None
        proto, src, dst = ip[6], ip[8:24], ip[24:40]
        seg = ip[40:40 + struct.unpack("!H", ip[4:6])[0]]
    else:
        return None
    if proto == 6 and len(seg) >= 20:
        sp, dp, seq = struct.unpack("!HHI", seg[:8])
        return src, dst, "tcp", sp, dp, seq, seg[13], seg[(seg[12] >> 4) * 4:]
    if proto == 17 and len(seg) >= 8:
        sp, dp = struct.unpack("!HH", seg[:4])
        return src, dst, "udp", sp, dp, 0, 0, seg[8:]
    return None


# ---------------------------------------------------------------- TLS

def load_suites():
    out = {}
    p = subprocess.run(["tshark", "-G", "values"], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        x = line.split("\t")
        if len(x) == 4 and x[0] == "V" and x[1] == "tls.handshake.ciphersuite":
            out[int(x[2])] = x[3]
    return out


SUITES = load_suites()


def suite_flags(name):
    flags = set()
    for k, f in (("RC4", "rc4"), ("3DES", "3des"), ("DES_CBC", "des"), ("EXPORT", "export"), ("NULL", "null"),
                 ("_anon_", "anon"), ("_MD5", "md5")):
        if k in name:
            flags.add(f)
    return flags


def forward_secret(name, version):
    return version == 0x0304 or "DHE_" in name or "ECDHE_" in name


def tls_records(buf):
    """Handshake messages (type, body) from the start of one direction of a TLS stream."""
    out, hs, i = [], b"", 0
    while i + 5 <= len(buf):
        ctype, ln = buf[i], struct.unpack("!H", buf[i + 3:i + 5])[0]
        if ctype not in (20, 21, 22, 23) or buf[i + 1] != 3:
            break
        if ctype == 22:
            hs += buf[i + 5:i + 5 + ln]
        elif ctype in (20, 23):
            break
        i += 5 + ln
    j = 0
    while j + 4 <= len(hs):
        t, ln = hs[j], int.from_bytes(hs[j + 1:j + 4], "big")
        if j + 4 + ln > len(hs):
            out.append((t, hs[j + 4:], True))
            break
        out.append((t, hs[j + 4:j + 4 + ln], False))
        j += 4 + ln
    return out


def exts(b, i):
    out = {}
    if i + 2 > len(b):
        return out
    end = min(len(b), i + 2 + struct.unpack("!H", b[i:i + 2])[0])
    i += 2
    while i + 4 <= end:
        t, ln = struct.unpack("!HH", b[i:i + 4])
        out[t] = b[i + 4:i + 4 + ln]
        i += 4 + ln
    return out


def client_hello(b):
    try:
        ver = struct.unpack("!H", b[0:2])[0]
        i = 34
        i += 1 + b[i]
        n = struct.unpack("!H", b[i:i + 2])[0]
        suites = [struct.unpack("!H", b[i + 2 + k:i + 4 + k])[0] for k in range(0, n, 2)]
        i += 2 + n
        i += 1 + b[i]
        e = exts(b, i)
    except (IndexError, struct.error):
        return None
    versions = [ver]
    if 43 in e and e[43]:
        sv = e[43][1:]
        versions = [struct.unpack("!H", sv[k:k + 2])[0] for k in range(0, len(sv) - 1, 2)]
    real = [s for s in suites if s & 0x0F0F != 0x0A0A and s not in (0x00FF, 0x5600)]
    flags = set()
    for s in real:
        flags |= suite_flags(SUITES.get(s, ""))
    fs_offered = any(forward_secret(SUITES.get(s, ""), 0) or 0x1301 <= s <= 0x1305 for s in real)
    return {"ch_max": max((v for v in versions if v & 0x0F0F != 0x0A0A), default=ver), "ch_suites": len(real),
            "ch_weak": sorted(flags), "ch_fs": fs_offered, "sni": 0 in e}


def server_hello(b):
    try:
        ver = struct.unpack("!H", b[0:2])[0]
        i = 34
        i += 1 + b[i]
        suite = struct.unpack("!H", b[i:i + 2])[0]
        e = exts(b, i + 3)
    except (IndexError, struct.error):
        return None
    if 43 in e and len(e[43]) == 2:
        ver = struct.unpack("!H", e[43])[0]
    name = SUITES.get(suite, f"0x{suite:04x}")
    return {"sh_ver": ver, "sh_suite": name, "sh_weak": sorted(suite_flags(name)), "sh_fs": forward_secret(name, ver)}


def certificate(b, ts):
    try:
        ln = int.from_bytes(b[3:6], "big")
        der = b[6:6 + ln]
        c = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    k = c.public_key()
    kt = ("rsa" if isinstance(k, rsa.RSAPublicKey) else "ec" if isinstance(k, ec.EllipticCurvePublicKey)
          else "dsa" if isinstance(k, dsa.DSAPublicKey) else "ed" if isinstance(k, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey))
          else "other")
    size = getattr(k, "key_size", None)
    try:
        sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else None
    except Exception:
        sig = None
    try:
        after, before = c.not_valid_after_utc.timestamp(), c.not_valid_before_utc.timestamp()
    except Exception:
        after = before = None

    def attr(n, oid):
        try:
            v = n.get_attributes_for_oid(oid)
            return v[0].value[:80] if v else ""
        except Exception:
            return ""
    from cryptography.x509.oid import NameOID
    return {"key": kt, "bits": size, "sig": sig, "self_signed": c.issuer == c.subject,
            "expired": after is not None and ts > after, "not_yet": before is not None and ts < before,
            "issuer_o": attr(c.issuer, NameOID.ORGANIZATION_NAME), "issuer_cn": attr(c.issuer, NameOID.COMMON_NAME)}


# ---------------------------------------------------------------- payload parsing

def http_fields(msg, out):
    """Fields of one HTTP request (head and body bytes)."""
    head, _, body = msg.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    m = HTTP_REQ.match(lines[0] + b"\r\n")
    if not m:
        return None
    method, target = m.group(1).decode(), m.group(2)
    hdr = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        hdr.setdefault(k.strip().lower(), v.strip())
    u = urllib.parse.urlsplit(target)
    path = u.path if isinstance(u.path, bytes) else target
    segs = [s for s in path.split(b"/") if s]
    pshape = "/".join("{id}" if (len(s) >= 6 and re.search(rb"\d", s)) else s.decode("latin-1")[:30] for s in segs)
    ctx = {"method": method, "host": hdr.get(b"host", b"").decode("latin-1")[:100], "path": "/" + pshape[:200]}
    for i, s in enumerate(segs):
        if len(s) >= 6 and re.search(rb"\d", s):
            out.append(("path[%d]" % i, urllib.parse.unquote_to_bytes(s), ctx))
    for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=False):
        out.append(("q:" + k.decode("latin-1")[:60], v, ctx))
    for k, v in hdr.items():
        if k in SKIP_HEADERS or not v:
            continue
        if k == b"authorization":
            out.append(("h:authorization:" + v.split(b" ")[0].decode("latin-1")[:20].lower(), v, ctx))
        elif k == b"cookie":
            for c in v.split(b";"):
                ck, _, cv = c.strip().partition(b"=")
                if cv:
                    out.append(("cookie:" + ck.decode("latin-1")[:60], cv, ctx))
        else:
            out.append(("h:" + k.decode("latin-1")[:60], v, ctx))
    ctype = hdr.get(b"content-type", b"").lower()
    if body:
        body_fields(body, ctype, ctx, out)
    return ctx


def body_fields(body, ctype, ctx, out):
    s = body.strip()
    head = s[:2048]
    if sum(1 for x in head if 32 <= x < 127 or x in (9, 10, 13)) < 0.85 * len(head):
        return      # binary or encrypted body: nothing to read
    if s[:1] in (b"{", b"["):
        try:
            flat(json.loads(s.decode("utf-8", "replace")), "", ctx, out)
        except ValueError:
            words(s, "body", ctx, out)      # cut JSON: no key names can be trusted
        return
    if b"x-www-form-urlencoded" in ctype or (b"=" in s[:100] and b"&" in s and b" " not in s[:200]):
        for k, v in urllib.parse.parse_qsl(s, keep_blank_values=False):
            # a key that is not a plain name is part of a value: never write it
            key = k.decode("latin-1") if FORM_KEY.fullmatch(k) else "<unparsed>"
            out.append(("form:" + key, v, ctx))
        return
    if s[:1] == b"<":
        for k, v in XML_LEAF.findall(s):
            out.append(("xml:" + k.decode("latin-1")[:60], v.strip(), ctx))
        return
    words(s, "body", ctx, out)


def flat(o, path, ctx, out):
    if isinstance(o, dict):
        for k, v in list(o.items())[:200]:
            flat(v, (path + "." if path else "") + str(k)[:40], ctx, out)
    elif isinstance(o, list):
        for v in o[:50]:
            flat(v, path + "[]", ctx, out)
    elif isinstance(o, (str, int, float)) and not isinstance(o, bool):
        v = str(o).encode()
        if v:
            out.append(("json:" + path[:80], v, ctx))


def words(b, key, ctx, out):
    printable = sum(1 for x in b[:2048] if 32 <= x < 127 or x in (9, 10, 13)) / max(1, min(len(b), 2048))
    if printable < 0.85:
        return
    for t in sorted(set(re.findall(rb"[A-Za-z0-9_.:@\-]{8,80}", b[:CAP])))[:200]:
        out.append((key, t, ctx))


def mqtt_fields(b, ctx, out):
    i = 0
    while i + 2 <= len(b):
        t = b[i] >> 4
        ln, m, j = 0, 1, i + 1
        while j < len(b):
            ln += (b[j] & 127) * m
            m *= 128
            j += 1
            if not b[j - 1] & 128:
                break
        body = b[j:j + ln]
        try:
            if t == 1:
                pl = struct.unpack("!H", body[:2])[0]
                k = 2 + pl + 4
                fl = body[2 + pl + 1]
                cl = struct.unpack("!H", body[k:k + 2])[0]
                out.append(("mqtt:client_id", body[k + 2:k + 2 + cl], ctx))
                k += 2 + cl
                if fl & 4:
                    for _ in range(2):
                        n = struct.unpack("!H", body[k:k + 2])[0]
                        k += 2 + n
                if fl & 128:
                    n = struct.unpack("!H", body[k:k + 2])[0]
                    out.append(("mqtt:user", body[k + 2:k + 2 + n], ctx))
            elif t in (3, 8):
                if t == 3:
                    n = struct.unpack("!H", body[:2])[0]
                    topic = body[2:2 + n]
                else:
                    n = struct.unpack("!H", body[2:4])[0]
                    topic = body[4:4 + n]
                for lvl in topic.split(b"/"):
                    if len(lvl) >= 6:
                        out.append(("mqtt:topic", lvl, ctx))
        except (IndexError, struct.error):
            pass
        if ln == 0 and j == i + 1:
            break
        i = j + ln


def dns_names(b):
    """Names, and TXT strings, from a DNS/mDNS message (answers and additionals)."""
    def name(i, depth=0):
        labels = []
        while i < len(b) and depth < 20:
            n = b[i]
            if n == 0:
                return labels, i + 1
            if n & 0xC0 == 0xC0:
                if i + 1 >= len(b):
                    return labels, i + 2
                sub, _ = name(((n & 0x3F) << 8) | b[i + 1], depth + 1)
                return labels + sub, i + 2
            labels.append(b[i + 1:i + 1 + n])
            i += 1 + n
        return labels, i
    out = []
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", b[4:12])
        i = 12
        for _ in range(qd):
            _, i = name(i)
            i += 4
        for _ in range(an + ns + ar):
            labels, i = name(i)
            t, _, _, rl = struct.unpack("!HHIH", b[i:i + 10])
            rd = b[i + 10:i + 10 + rl]
            if labels:
                out.append(("mdns_name", labels[0]))
            if t == 16:
                k = 0
                while k < len(rd):
                    n = rd[k]
                    kv = rd[k + 1:k + 1 + n]
                    key, eq, v = kv.partition(b"=")
                    if eq and len(v) >= 4:
                        out.append(("mdns_txt:" + key.decode("latin-1")[:30], v))
                    k += 1 + n
            elif t == 12:
                sub, _ = name(i + 10)
                if sub:
                    out.append(("mdns_name", sub[0]))
            i += 10 + rl
    except (IndexError, struct.error):
        pass
    return out


def dhcp_ids(b):
    out = []
    if len(b) < 240 or b[236:240] != b"\x63\x82\x53\x63":
        return out
    i = 240
    while i + 2 <= len(b) and b[i] != 255:
        if b[i] == 0:
            i += 1
            continue
        t, ln = b[i], b[i + 1]
        v = b[i + 2:i + 2 + ln]
        if t == 12 and v:
            out.append(("dhcp_hostname", v.rstrip(b"\x00")))
        elif t == 61 and len(v) > 1:
            out.append(("dhcp_client_id", v[1:] if v[0] != 1 else v[1:]))
        elif t == 81 and len(v) > 3:
            out.append(("dhcp_fqdn", v[3:]))
        i += 2 + ln
    return out


def ssdp_ids(b):
    out = []
    for ln in b.split(b"\r\n")[1:]:
        k, _, v = ln.partition(b":")
        k, v = k.strip().lower(), v.strip()
        if k == b"usn":
            m = re.match(rb"uuid:([^:]+)", v)
            if m:
                out.append(("ssdp_uuid", m.group(1)))
        elif k.startswith(b"x-") and len(v) >= 6:
            out.append(("ssdp:" + k.decode("latin-1")[:40], v))
    return out


# ---------------------------------------------------------------- scanning

class Unit:
    def __init__(self, macs, name):
        self.macs, self.name = macs, name
        self.mac_forms = {m: forms(m) for m in macs}
        self.recs = []
        self.agg = {}
        self.flows = {}
        self.flowsum = collections.defaultdict(lambda: [0, 0])
        self.seen_ident = set()

    def add(self, kind, key, rec, frame):
        k = (kind, key)
        a = self.agg.get(k)
        if a is None:
            rec.update(r=kind, n=0, frame=frame, file=self.name)
            self.agg[k] = a = rec
        a["n"] += 1

    def ident(self, dev, kind, v, frame):
        v = v.strip()
        if len(v) < 4:
            return
        x = val(v)
        self.add("ident", (dev, kind, x["h"]), {"dev": dev, "kind": kind, **x}, frame)

    def field(self, dev, f, peer, port, proto, key, v, ctx, frame):
        if not v:
            return
        x = val(v)
        x["mac"] = any(m in v.lower() for m in self.mac_forms[dev][0])
        x["email"] = bool(EMAIL.fullmatch(v))
        c = ctx or {}
        k = (dev, peer, port, c.get("method"), c.get("host"), c.get("path"), key, x["h"])
        self.add("field", k, {"dev": dev, "peer": peer, "port": port, "proto": proto, "key": key,
                              "method": c.get("method"), "host": c.get("host"), "path": c.get("path"), **x}, frame)

    def macout(self, dev, peer, port, proto, pl, frame):
        low = pl.lower()
        forms_txt, raw = self.mac_forms[dev]
        for i, m in enumerate(forms_txt):
            if m in low:
                self.add("macout", (dev, peer, port, proto, "text%d" % i), {"dev": dev, "peer": peer, "port": port,
                         "proto": proto, "spelling": FORM_NAMES[i]}, frame)
                return
        if raw in pl:
            self.add("macout", (dev, peer, port, proto, "raw"), {"dev": dev, "peer": peer, "port": port,
                     "proto": proto, "spelling": "raw bytes"}, frame)


FORM_NAMES = ["aa:bb:cc:dd:ee:ff", "aabbccddeeff", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff"]


def forms(m):
    hx = m.replace(":", "")
    return [m.encode(), hx.encode(), m.replace(":", "-").encode(), f"{hx[:4]}.{hx[4:8]}.{hx[8:]}".encode()], bytes.fromhex(hx)


def scan(stream, name, macs, out_path):
    u = Unit(macs, name)
    macb = {bytes.fromhex(m.replace(":", "")): m for m in macs}
    ipdev = {}   # Linux cooked captures have no destination MAC: the devices' own addresses, from what they sent
    n = 0
    last_sweep = None
    for ts, lt, fr in frames(stream):
        n += 1
        x = l3(lt, fr)
        if not x:
            continue
        smac, dmac, et, off = x
        sdev, ddev = macb.get(smac), macb.get(dmac)
        if not sdev and not ddev and lt != 113:
            continue
        p = l4(et, fr, off)
        if not p:
            continue
        src, dst, proto, sp, dp, seq, flags, pl = p
        if lt == 113:
            if sdev:
                ipdev[src] = sdev
            ddev = ipdev.get(dst) if dst != src else None
            if not sdev and not ddev:
                continue
        handle(u, ts, n, sdev, ddev, src, dst, proto, sp, dp, seq, flags, pl)
        if last_sweep is None:
            last_sweep = ts
        if ts - last_sweep > 60:
            last_sweep = ts
            for k in [k for k, f in u.flows.items() if ts - f["last"] > IDLE[f["proto"]]]:
                finish(u, u.flows.pop(k))
    for f in list(u.flows.values()):
        finish(u, f)
    with open(out_path, "w") as o:
        for rec in u.agg.values():
            o.write(json.dumps(rec) + "\n")
        for (dev, peer, proto, port, kind), (c, b) in sorted(u.flowsum.items()):
            o.write(json.dumps({"r": "flow", "dev": dev, "peer": peer, "proto": proto, "port": port, "kind": kind,
                                "flows": c, "bytes": b, "file": name}) + "\n")
        o.write(json.dumps({"r": "file", "file": name, "packets": n}) + "\n")
    return name, n


def handle(u, ts, n, sdev, ddev, src, dst, proto, sp, dp, seq, flags, pl):
    # LAN announcements by the device
    if sdev and proto == "udp" and pl:
        if sp == 68 and dp == 67:
            for k, v in dhcp_ids(pl):
                u.ident(sdev, k, v, n)
        elif dp == 1900 or sp == 1900:
            if pl.startswith((b"NOTIFY", b"HTTP/1.1 200")):
                for k, v in ssdp_ids(pl):
                    u.ident(sdev, k, v, n)
        elif sp == 5353 and len(pl) > 12 and pl[2] & 0x80:
            for k, v in dns_names(pl):
                if k == "mdns_name" and len(v) >= 6:
                    u.ident(sdev, k, v, n)
                elif k != "mdns_name":
                    u.ident(sdev, k, v, n)
    key = (proto, src, sp, dst, dp)
    rkey = (proto, dst, dp, src, sp)
    f = u.flows.get(key)
    d = 0
    if f is None:
        f = u.flows.get(rkey)
        d = 1
    if f is None:
        syn = proto == "tcp" and flags & 0x12 == 0x02
        synack = proto == "tcp" and flags & 0x12 == 0x12
        client_is_src = syn or (not synack and (dp < sp or dp in (80, 443, 8080, 8443, 1883, 8883)))
        if not client_is_src and not syn and sp >= 49152 and dp < 49152:
            client_is_src = True
        if client_is_src:
            f = {"c": (src, sp, sdev), "s": (dst, dp, ddev)}
            u.flows[key], d = f, 0
        else:
            f = {"c": (dst, dp, ddev), "s": (src, sp, sdev)}
            u.flows[rkey], d = f, 1
        f.update(proto=proto, first=ts, last=ts, buf=[bytearray(), bytearray()], nxt=[None, None],
                 frame=[None, None], bytes=0, done_req=0, done_resp=0, ctx=None, tls=None)
    f["last"] = ts
    if proto == "tcp":
        if flags & 0x02:
            f["nxt"][d] = (seq + 1) & 0xFFFFFFFF
        if not pl:
            return
        nx = f["nxt"][d]
        if nx is not None and (seq - nx) & 0xFFFFFFFF >= 0x80000000:
            # starts before the next expected byte: a duplicate or a retransmission
            over = (nx - seq) & 0xFFFFFFFF
            if over >= len(pl):
                return
            pl, seq = pl[over:], nx
        f["nxt"][d] = (seq + len(pl)) & 0xFFFFFFFF
    elif not pl:
        return
    f["bytes"] += len(pl)
    if f["frame"][d] is None:
        f["frame"][d] = n
    b = f["buf"][d]
    if len(b) < CAP:
        b += pl[:CAP - len(b)]
    # the device's MAC in any packet it sends to a public address outside TLS and DTLS
    if sdev and public(dst):
        first = b[:3]
        if not (len(first) >= 3 and first[0] in (20, 21, 22, 23) and first[1] in (3, 0xFE)):
            u.macout(sdev, ipstr(dst), dp, proto, pl, n)


def kind_of(b, proto, port):
    if len(b) >= 3 and b[0] in (20, 21, 22, 23) and b[1] == 3 and b[2] <= 4:
        return "tls"
    if len(b) >= 3 and b[0] in (20, 21, 22, 23) and b[1] == 0xFE:
        return "dtls"
    if HTTP_REQ.match(b) or HTTP_RESP.match(b):
        return "http"
    if proto == "tcp" and len(b) > 8 and b[0] == 0x10 and (b"MQTT" in b[2:10] or b"MQIsdp" in b[2:10]):
        return "mqtt"
    if b.startswith(b"SSH-"):
        return "ssh"
    if port in (53, 5353, 123, 67, 68, 137, 138, 1900, 5355):
        return {53: "dns", 5353: "mdns", 123: "ntp", 67: "dhcp", 68: "dhcp", 137: "netbios", 138: "netbios",
                1900: "ssdp", 5355: "llmnr"}[port]
    if proto == "udp" and port == 443 and b and b[0] & 0x80:
        return "quic"
    if not b:
        return "none"
    if len(b) < 32:
        return "short"
    pr = sum(1 for x in b[:2048] if 32 <= x < 127 or x in (9, 10, 13)) / min(len(b), 2048)
    if pr >= 0.85:
        return "text"
    s = b[:4096]
    ent = -sum(v / len(s) * math.log2(v / len(s)) for v in collections.Counter(s).values())
    return "high-entropy" if ent / math.log2(min(len(s), 256)) >= 0.9 else "binary"


def finish(u, f):
    (cip, cport, cdev), (sip, sport, sdev) = f["c"], f["s"]
    up, down = bytes(f["buf"][0]), bytes(f["buf"][1])
    kind = kind_of(up or down, f["proto"], sport)
    if kind in ("none",) and not (up or down):
        return
    for dev, peer_ip, role in ((cdev, sip, "client"), (sdev, cip, "server")):
        if not dev:
            continue
        peer = "public" if public(peer_ip) else "lan"
        c = u.flowsum[(dev, peer, f["proto"], sport, kind)]
        c[0] += 1
        c[1] += f["bytes"]
    # TLS handshakes (device as client or server)
    if kind == "tls":
        rec = {}
        for t, body, _ in tls_records(up):
            if t == 1:
                rec.update(client_hello(body) or {})
                break
        for t, body, partial in tls_records(down):
            if t == 2:
                rec.update(server_hello(body) or {})
            elif t == 11 and not partial:
                cert = certificate(body, f["first"])
                if cert:
                    rec["cert"] = cert
                break
        if rec:
            for dev, role, peer_ip in ((cdev, "client", sip), (sdev, "server", cip)):
                if dev:
                    c = rec.get("cert") or {}
                    key = (dev, role, ipstr(peer_ip), sport, rec.get("ch_max"), tuple(rec.get("ch_weak", [])),
                           rec.get("ch_fs"), rec.get("sni"), rec.get("sh_ver"), rec.get("sh_suite"),
                           c.get("key"), c.get("bits"), c.get("sig"), c.get("self_signed"), c.get("expired"),
                           c.get("issuer_o"), c.get("issuer_cn"))
                    u.add("tls", key, {"dev": dev, "role": role, "peer": ipstr(peer_ip),
                                       "peer_public": public(peer_ip), "port": sport, **rec}, f["frame"][0] or f["frame"][1])
    # plaintext content sent by the device to a public address
    if cdev and public(sip) and kind in ("http", "mqtt", "text"):
        out = []
        if kind == "http":
            for msg in http_messages(up):
                http_fields(msg, out)
        elif kind == "mqtt":
            mqtt_fields(up, {"method": None, "host": None, "path": None}, out)
        else:
            words(up, "text", {"method": None, "host": None, "path": None}, out)
        for key, v, ctx in out:
            u.field(cdev, f, ipstr(sip), sport, kind, key, v, ctx, f["frame"][0])
    # downloads from a public address to the device over HTTP
    if cdev and public(sip) and kind == "http" and down:
        reqs = [m for m in http_messages(up)]
        resps = re.finditer(rb"HTTP/1\.[01] (\d{3})[^\r\n]*\r\n(.*?)\r\n\r\n", down, re.S)
        for i, m in enumerate(resps):
            hdr = {}
            for ln in m.group(2).split(b"\r\n"):
                k, _, v = ln.partition(b":")
                hdr[k.strip().lower()] = v.strip()
            try:
                size = int(hdr.get(b"content-length", b"0") or 0)
            except ValueError:
                size = 0
            ctype = hdr.get(b"content-type", b"").decode("latin-1").lower()
            disp = hdr.get(b"content-disposition", b"")
            ext = re.search(rb"filename=\"?[^\";]*?(\.[A-Za-z0-9]{1,8})\"?", disp)
            if size >= 1_000_000 or any(ctype.startswith(t) for t in BINARY_TYPES):
                ctx = {}
                if i < len(reqs):
                    tmp = []
                    ctx = http_fields(reqs[i], tmp) or {}
                u.add("dl", (cdev, ipstr(sip), sport, ctx.get("host"), ctx.get("path"), size, ctype),
                      {"dev": cdev, "peer": ipstr(sip), "port": sport, "host": ctx.get("host"), "path": ctx.get("path"),
                       "status": int(m.group(1)), "size": size, "ctype": ctype[:60],
                       "ext": ext.group(1).decode("latin-1") if ext else None}, f["frame"][1] or f["frame"][0])
    # UPnP descriptions served by the device on the LAN
    if sdev and kind == "http" and down and b"<" in down:
        body = re.sub(rb"\r\n[0-9A-Fa-f]{1,6}\r\n", b"", down)
        for tag, v in UPNP_TAGS.findall(body):
            v = v.strip()
            if tag.lower() == b"udn" and v.lower().startswith(b"uuid:"):
                v = v[5:]
            u.ident(sdev, "upnp:" + tag.decode(), v, f["frame"][1] or f["frame"][0])


def http_messages(b):
    out, i = [], 0
    while True:
        m = HTTP_REQ.search(b, i)
        if not m or m.start() != i and b[i:m.start()].strip():
            if m:
                i = m.start()
                continue
            break
        end = b.find(b"\r\n\r\n", m.start())
        if end < 0:
            out.append(b[m.start():])
            break
        head = b[m.start():end]
        cl = re.search(rb"(?im)^content-length:\s*(\d+)", head)
        body_end = end + 4 + (int(cl.group(1)) if cl else 0)
        out.append(b[m.start():min(body_end, len(b))])
        i = body_end
        if i >= len(b):
            break
    return out


# ---------------------------------------------------------------- driver

def units(sources):
    """(kind, path, name prefix) for each source; a directory gives its captures, named by relative path."""
    for s in sources:
        p = Path(s)
        if p.is_dir():
            for q in sorted(p.rglob("*")):
                if q.is_file() and (q.suffix.lower() in (".pcap", ".pcapng", ".cap") or q.name.startswith("eth1-")):
                    yield ("file", str(q), str(q.relative_to(p.parent)).replace("/", "__"))
        elif p.suffix in (".tgz", ".gz", ".tar") and tarfile.is_tarfile(s):
            yield ("tar", s, "")
        else:
            yield ("file", s, p.name)


def run(job):
    kind, src, name, macs, out_dir = job
    done = []
    if kind == "file":
        out = Path(out_dir) / (name + ".jsonl")
        if out.exists():
            return [(name, -1)]
        with open(src, "rb", buffering=16 << 20) as f:
            try:
                done.append(scan(f, name, macs, str(out) + ".tmp"))
            except ValueError:
                return [(name, -2)]
        os.replace(str(out) + ".tmp", out)
    else:
        # gzip runs in its own process; tarfile then reads plain tar from the pipe
        unz = subprocess.Popen(["gzip", "-dc", src], stdout=subprocess.PIPE, bufsize=1 << 20) if src.endswith(("gz", "tgz")) else None
        with tarfile.open(fileobj=unz.stdout, mode="r|") if unz else tarfile.open(src, "r|") as t:
            for m in t:
                if not m.isfile():
                    continue
                name = Path(m.name).name
                if name.endswith((".md5", ".txt", ".csv", ".json")):
                    continue
                out = Path(out_dir) / (name + ".jsonl")
                if out.exists():
                    continue
                f = io.BufferedReader(t.extractfile(m), buffer_size=1 << 20)
                try:
                    done.append(scan(f, name, macs, str(out) + ".tmp"))
                    os.replace(str(out) + ".tmp", out)
                except ValueError:
                    continue
    return done


def main():
    devices_tsv, dataset, out_dir = sys.argv[1:4]
    procs = int(os.environ.get("SWEEP_PROCS", "3"))
    macs = sorted({r["mac"].lower() for r in csv.DictReader(open(devices_tsv), delimiter="\t")
                   if r["dataset"] == dataset and re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", r["mac"].lower())})
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    jobs = [(k, s, name, macs, out_dir) for k, s, name in units(sys.argv[4:])]
    print(f"{dataset}: {len(macs)} devices, {len(jobs)} sources", flush=True)
    with Pool(procs) as pool:
        for done in pool.imap_unordered(run, jobs):
            for name, n in done:
                print(f"{datetime.now(timezone.utc):%H:%M:%S} {name} {n}", flush=True)


if __name__ == "__main__":
    main()
