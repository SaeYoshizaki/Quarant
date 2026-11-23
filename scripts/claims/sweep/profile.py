#!/usr/bin/env python3
"""Everything one device does in some captures, from the packets only (passive).

usage: profile.py --mac MAC [--ip IP ...] [--name NAME] [--decode tcp.port==8899,http ...] --out OUT.md capture...

For each capture, tshark reads the packets to or from the device (eth or Linux cooked source MAC, and the
device's own IP addresses) and the script writes one Markdown report:
  1. captures, time span, packets and bytes
  2. what the device says about itself (DHCP, mDNS, SSDP/UPnP, HTTP User-Agent, version-like URL fields)
  3. traffic by scope (LAN, multicast, broadcast, internet) and by protocol
  4. internet peers by name (TLS SNI, HTTP Host, the device's DNS answers), with encryption, bytes, days,
     first frame, and the interval between connections
  5. TLS and DTLS: versions offered and chosen, suites chosen, weak suites offered, certificates (subject,
     issuer, validity, names, key, signature hash, whether the name fits), alerts and who sent them
  6. plaintext: every HTTP request shape (method, host, path, query keys, headers that carry credentials,
     body start), FTP, MQTT, NTP, STUN/RTP, other payload starts
  7. downloads that look like firmware or updates
  8. LAN peers and what is exchanged with them
  9. errors and fallbacks: resets, unanswered connections, TLS alerts, DNS errors, HTTP errors, names
     reached both with and without TLS
Values (tokens, cookies, Authorization) are printed as they are, so keep the output out of the public
repository. Facts only: nothing here says what a payload means.
"""
import argparse
import collections
import datetime as dt
import ipaddress
import json
import re
import statistics
import subprocess
import sys

AGG = "\x1e"
FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "eth.src", "eth.dst", "sll.src.eth",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.stream", "udp.stream", "tcp.len", "udp.length", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset",
    "_ws.col.Protocol",
    "dns.flags.response", "dns.qry.name", "dns.a", "dns.aaaa", "dns.flags.rcode", "dns.resp.name", "dns.ptr.domain_name",
    "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.version",
    "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite", "tls.alert_message.level",
    "tls.alert_message.desc", "tls.record.content_type", "tls.handshake.certificate", "tls.handshake.extensions_alpn_str",
    "dtls.handshake.type", "dtls.handshake.version", "dtls.handshake.ciphersuite", "dtls.handshake.certificate",
    "http.request.method", "http.host", "http.request.uri", "http.user_agent", "http.authorization", "http.cookie",
    "http.content_type", "http.content_length_header", "http.response.code", "http.server", "http.location",
    "http.set_cookie", "http.file_data",
    "ssh.protocol", "quic.version", "mqtt.msgtype", "mqtt.topic", "mqtt.username", "mqtt.passwd",
    "ftp.request.command", "ftp.request.arg", "ftp.response.code", "ntp.flags.mode",
    "dhcp.option.hostname", "dhcp.option.vendor_class_id", "stun.type", "rtp.p_type", "data.data",
]
ONE = ["frame.number", "frame.time_epoch", "frame.len", "eth.src", "eth.dst", "sll.src.eth", "ip.src", "ip.dst",
       "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.stream", "udp.stream",
       "tcp.len", "udp.length", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "dns.flags.response", "dns.flags.rcode"]
WEAK = re.compile(r"RC4|3DES|DES_CBC|_DES_|NULL|EXPORT|anon|MD5", re.I)
FWPATH = re.compile(r"firm|fw|ota|upgrade|update|\.bin\b|\.ipk|\.img|\.pkg|\.tar|\.zip|\.gz|\.trx|\.hex", re.I)
VERKEYS = re.compile(r"(?:^|[?&;])((?:fw|firmware|sw|ver|version|build|model|hw|app|os)[A-Za-z_]*)=([^&;]{1,40})", re.I)
TLSV = {"0x0300": "SSL3", "0x0301": "TLS1.0", "0x0302": "TLS1.1", "0x0303": "TLS1.2", "0x0304": "TLS1.3",
        "0xfeff": "DTLS1.0", "0xfefd": "DTLS1.2", "0xfefc": "DTLS1.3"}


SUITES = {}


def suite_names():
    out = subprocess.run(["tshark", "-G", "values"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) >= 4 and p[1] in ("tls.handshake.ciphersuite", "dtls.handshake.ciphersuite"):
            try:
                SUITES[int(p[2], 0)] = p[3]
            except ValueError:
                pass


def sname(v):
    try:
        return SUITES.get(int(v, 0), v)
    except ValueError:
        return v


def tlsv(v):
    v = v.lower()
    return TLSV.get(v, v)


def yes(v):
    return v in ("1", "True", "true")


def no(v):
    return v in ("0", "False", "false")


def split(v):
    return [x for x in v.split(AGG) if x != ""] if v else []


def scope(ip):
    if not ip:
        return "none"
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "none"
    if a.is_multicast:
        return "multicast"
    if str(a) == "255.255.255.255" or (a.version == 4 and str(a).endswith(".255")):
        return "broadcast"
    if a.is_private or a.is_link_local or a.is_loopback or a.is_unspecified:
        return "lan"
    return "internet"


def utc(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


YT_NAMES = False


def capname(cap, tstr):
    """File name for the evidence. For YourThings days merged from 5-minute files (--yt-names), the original
    5-minute file is derived from the packet time: eth1-YYYYMMDD.HHMM.<epoch + 5 h> (the names run 5 h ahead)."""
    base = cap.split("/")[-1]
    if not YT_NAMES or not tstr:
        return base
    t = dt.datetime.strptime(tstr[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    start = t.replace(minute=t.minute - t.minute % 5, second=0)
    return f"eth1-{start.strftime('%Y%m%d.%H%M')}.{int(start.timestamp()) + 18000}"


def utcus(t):
    """Packet time with microseconds: identifies the packet in the original capture after filtering."""
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def cert_info(hexs):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    try:
        c = x509.load_der_x509_certificate(bytes.fromhex(hexs.replace(":", "")))
    except Exception as e:
        return {"error": str(e)[:80]}

    def cn(name):
        v = [a.value for a in name if a.oid == x509.NameOID.COMMON_NAME]
        o = [a.value for a in name if a.oid == x509.NameOID.ORGANIZATION_NAME]
        return (v[0] if v else "") + (f" (O={o[0]})" if o else "")
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception:
        san = []
    k = c.public_key()
    key = f"RSA {k.key_size}" if isinstance(k, rsa.RSAPublicKey) else f"EC {k.curve.name}" if isinstance(k, ec.EllipticCurvePublicKey) else type(k).__name__
    try:
        sig = c.signature_hash_algorithm.name
    except Exception:
        sig = "?"
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
    return {"subject": cn(c.subject), "issuer": cn(c.issuer), "self_signed": c.subject == c.issuer,
            "not_before": nb.strftime("%Y-%m-%d"), "not_after": na.strftime("%Y-%m-%d"),
            "not_after_ts": na.timestamp(), "not_before_ts": nb.timestamp(),
            "san": san, "key": key, "sig": sig}


def name_fits(sni, info):
    names = list(info.get("san") or [])
    s = info.get("subject", "").split(" (O=")[0]
    if s:
        names.append(s)
    for n in names:
        n = n.lower()
        if n == sni.lower() or (n.startswith("*.") and sni.lower().endswith(n[1:]) and sni.count(".") == n.count(".")):
            return True
    return False


def printable(b):
    if not b:
        return ""
    t = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mac", required=True)
    ap.add_argument("--name", default="")
    ap.add_argument("--decode", action="append", default=[])
    ap.add_argument("--ip", action="append", default=[], help="device address, for Linux cooked captures (no destination MAC)")
    ap.add_argument("--yt-names", action="store_true", help="captures are YourThings days merged from 5-minute files")
    ap.add_argument("--exclude-peer", action="append", default=[], help="leave out a peer (e.g. the dataset authors' scanner)")
    ap.add_argument("--out", required=True)
    ap.add_argument("captures", nargs="+")
    a = ap.parse_args()
    mac = a.mac.lower()
    global YT_NAMES
    YT_NAMES = a.yt_names
    suite_names()

    devips = set()
    flows = {}
    names = collections.defaultdict(set)      # ip -> names from DNS answers to the device
    selfid = collections.defaultdict(collections.Counter)
    dnsq = collections.Counter()
    dnserr = collections.Counter()
    resolvers = collections.Counter()
    http = collections.OrderedDict()
    httpresp = collections.Counter()
    ftp = []
    mqtt = collections.Counter()
    ntp = collections.Counter()
    tot = {"pkts": 0, "bytes": 0, "first": None, "last": None}
    files = []
    scope_bytes = collections.Counter()
    proto_bytes = collections.Counter()
    certs = collections.OrderedDict()
    days = set()
    excluded = collections.Counter()

    for cap in a.captures:
        flt = f"eth.addr=={mac} || sll.src.eth=={mac}" + "".join(f" || ip.addr=={x}" for x in a.ip)
        cmd = ["tshark", "-r", cap, "-n", "-o", "tcp.desegment_tcp_streams:TRUE", "-Y", flt, "-T", "fields",
               "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=" + AGG, "-E", "quote=n"]
        for d in a.decode:
            cmd += ["-d", d]
        for f in FIELDS:
            cmd += ["-e", f]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
        npk = 0
        for line in p.stdout:
            v = line.rstrip("\n").split("\t")
            if len(v) < len(FIELDS):
                v += [""] * (len(FIELDS) - len(v))
            r = dict(zip(FIELDS, v))
            for k in ONE:
                if AGG in r[k]:
                    r[k] = r[k].split(AGG)[0]    # ICMP errors carry a second IP and port header
            npk += 1
            t = float(r["frame.time_epoch"] or 0)
            ln = int(r["frame.len"] or 0)
            src_mac = (r["eth.src"] or r["sll.src.eth"]).lower()
            sip = r["ip.src"] or r["ipv6.src"]
            dip = r["ip.dst"] or r["ipv6.dst"]
            up = src_mac == mac or (sip in a.ip)
            if up and sip and sip not in ("0.0.0.0",):
                devips.add(sip)
            peer = dip if up else sip
            if peer in a.exclude_peer:
                excluded[peer] += 1
                continue
            sc = scope(peer) if peer else ("broadcast" if r["eth.dst"] == "ff:ff:ff:ff:ff:ff" else "none")
            tot["pkts"] += 1
            tot["bytes"] += ln
            tot["first"] = t if tot["first"] is None else min(tot["first"], t)
            tot["last"] = t if tot["last"] is None else max(tot["last"], t)
            days.add(utc(t)[:10])
            proto = r["_ws.col.Protocol"]
            if r["tcp.stream"]:
                l4, sid, sp, dp = "tcp", r["tcp.stream"], r["tcp.srcport"], r["tcp.dstport"]
            elif r["udp.stream"]:
                l4, sid, sp, dp = "udp", r["udp.stream"], r["udp.srcport"], r["udp.dstport"]
            else:
                l4, sid, sp, dp = "other", None, "", ""
            scope_bytes[sc] += ln
            # DNS answers to the device: names of addresses
            if yes(r["dns.flags.response"]) and not up:
                qn = split(r["dns.qry.name"])
                for ipx in split(r["dns.a"]) + split(r["dns.aaaa"]):
                    for q in qn:
                        names[ipx].add(q)
                if r["dns.flags.rcode"] not in ("", "0") and sp == "53":
                    for q in qn:
                        dnserr[(q, r["dns.flags.rcode"])] += 1
            if no(r["dns.flags.response"]) and up and dp == "53":
                for q in split(r["dns.qry.name"]):
                    dnsq[q] += 1
                resolvers[dip] += 1
            # what the device says about itself
            if up:
                for h in split(r["dhcp.option.hostname"]):
                    selfid["DHCP hostname"][h] += 1
                for h in split(r["dhcp.option.vendor_class_id"]):
                    selfid["DHCP vendor class"][h] += 1
                if sp == "5353" or dp == "5353":
                    for h in split(r["dns.resp.name"]) + split(r["dns.ptr.domain_name"]):
                        selfid["mDNS names announced/asked"][h] += 1
                    for q in split(r["dns.qry.name"]):
                        selfid["mDNS names announced/asked"][q] += 1
                if r["http.server"] and (dp == "1900" or sp == "1900"):
                    selfid["SSDP SERVER"][r["http.server"]] += 1
                if r["http.location"] and (dp == "1900" or sp == "1900"):
                    selfid["SSDP LOCATION"][r["http.location"]] += 1
                for u in split(r["http.user_agent"]):
                    selfid["HTTP User-Agent"][u] += 1
                for m in VERKEYS.finditer(r["http.request.uri"] or ""):
                    selfid["version-like URL fields"][f"{m.group(1)}={m.group(2)}"] += 1
            elif r["http.server"] and sc == "lan" and not up:
                pass
            if not sid:
                proto_bytes[(l4, proto, sc)] += ln
                continue
            key = (cap, l4, sid)
            f = flows.get(key)
            if f is None:
                # the side that sends first is taken as the client
                f = flows[key] = {"cap": cap, "l4": l4, "peer": peer, "scope": sc, "first": t, "last": t,
                                  "init": "device" if up else "peer", "sport": dp, "cport": sp, "up": 0, "down": 0, "pk": 0, "frame": utcus(t),
                                  "protos": collections.Counter(), "sni": "", "host": "", "tls": {}, "dtls": {},
                                  "alerts": [], "appdata": [0, 0], "rst": [0, 0], "synack": False, "data0": ["", ""],
                                  "http": 0}
                if l4 == "tcp" and yes(r["tcp.flags.syn"]) and no(r["tcp.flags.ack"]):
                    f["init"] = "device" if up else "peer"
            f["last"] = t
            f["pk"] += 1
            f["up" if up else "down"] += ln
            f["protos"][proto] += ln
            if l4 == "tcp" and yes(r["tcp.flags.syn"]) and yes(r["tcp.flags.ack"]):
                f["synack"] = True
            if yes(r["tcp.flags.reset"]):
                f["rst"][0 if up else 1] += 1
            dd = r["data.data"]
            if dd and not f["data0"][0 if up else 1]:
                f["data0"][0 if up else 1] = dd.split(AGG)[0][:128]
            # TLS
            ht = split(r["tls.handshake.type"])
            if r["tls.handshake.extensions_server_name"]:
                f["sni"] = split(r["tls.handshake.extensions_server_name"])[0]
            if "1" in ht and up:
                f["tls"]["ch_version"] = tlsv(split(r["tls.handshake.version"])[0]) if r["tls.handshake.version"] else ""
                f["tls"]["ch_supported"] = [tlsv(x) for x in split(r["tls.handshake.extensions.supported_version"])]
                f["tls"]["ch_suites"] = [sname(x) for x in split(r["tls.handshake.ciphersuite"])]
                f["tls"]["alpn"] = split(r["tls.handshake.extensions_alpn_str"])
                f["tls"]["ch_frame"] = utcus(t)
            if "2" in ht and not up:
                sv = [tlsv(x) for x in split(r["tls.handshake.extensions.supported_version"])]
                hv = [tlsv(x) for x in split(r["tls.handshake.version"])]
                f["tls"]["sh_version"] = sv[0] if sv else (hv[-1] if hv else "")
                cs = split(r["tls.handshake.ciphersuite"])
                f["tls"]["sh_suite"] = sname(cs[-1]) if cs else ""
                f["tls"]["sh_frame"] = utcus(t)
            if "11" in ht and r["tls.handshake.certificate"]:
                chain = split(r["tls.handshake.certificate"])
                who = "device" if up else "server"
                h = chain[0][:120]
                if h not in certs:
                    certs[h] = cert_info(chain[0])
                    certs[h]["chain_len"] = len(chain)
                f["tls"].setdefault("certs", []).append((who, h))
            if r["tls.alert_message.desc"]:
                f["alerts"].append(("device" if up else "peer", r["tls.alert_message.level"], r["tls.alert_message.desc"],
                                    utcus(t)))
            if "23" in split(r["tls.record.content_type"]):
                f["appdata"][0 if up else 1] += 1
            # DTLS
            dht = split(r["dtls.handshake.type"])
            if "1" in dht and up:
                f["dtls"]["ch_version"] = tlsv(split(r["dtls.handshake.version"])[0]) if r["dtls.handshake.version"] else ""
            if "2" in dht:
                cs = split(r["dtls.handshake.ciphersuite"])
                f["dtls"]["sh_suite"] = sname(cs[-1]) if cs else ""
                f["dtls"]["sh_by"] = "device" if up else "peer"
            if r["dtls.handshake.certificate"]:
                chain = split(r["dtls.handshake.certificate"])
                h = chain[0][:120]
                if h not in certs:
                    certs[h] = cert_info(chain[0])
                    certs[h]["chain_len"] = len(chain)
                f["dtls"].setdefault("certs", []).append(("device" if up else "peer", h))
            # HTTP
            if r["http.request.method"] and up:
                f["http"] += 1
                host = r["http.host"] or peer
                f["host"] = host
                uri = r["http.request.uri"]
                path, _, q = uri.partition("?")
                path = re.sub(r"/[0-9A-Fa-f:._-]{8,}(?=/|$)", "/{id}", path)
                qk = tuple(sorted(set(k for k, _, _ in (x.partition("=") for x in re.split(r"[&;]", q) if x))))
                k2 = (r["http.request.method"], host, f["sport"], path, qk)
                e = http.get(k2)
                if e is None:
                    e = http[k2] = {"n": 0, "frame": utcus(t), "cap": cap, "time": utcus(t), "uri": uri[:300],
                                    "ua": r["http.user_agent"][:120], "auth": r["http.authorization"][:200],
                                    "cookie": r["http.cookie"][:300], "ctype": r["http.content_type"],
                                    "body": printable(bytes.fromhex(r["http.file_data"].replace(":", "")) if re.fullmatch(r"[0-9a-fA-F:]+", r["http.file_data"] or "x") else (r["http.file_data"] or "").encode("latin1", "replace"))[:300],
                                    "scope": sc, "days": set(), "values": collections.Counter()}
                e["n"] += 1
                e["days"].add(utc(t)[:10])
                e["values"][uri[:300]] += 1
            if r["http.response.code"] and not up:
                httpresp[(f.get("host") or peer, f["sport"], r["http.response.code"], r["http.content_type"],
                          r["http.content_length_header"])] += 1
                f.setdefault("resp", []).append((r["http.response.code"], r["http.content_type"], r["http.content_length_header"], utcus(t)))
            if r["ftp.request.command"] and up:
                ftp.append((utc(t), utcus(t), cap, peer, r["ftp.request.command"], r["ftp.request.arg"][:120]))
            if r["mqtt.msgtype"]:
                mqtt[(peer, f["sport"], "up" if up else "down", r["mqtt.msgtype"], r["mqtt.topic"][:80],
                      "user" if r["mqtt.username"] else "", "pass" if r["mqtt.passwd"] else "")] += 1
            if r["ntp.flags.mode"] and up:
                ntp[(peer, r["ntp.flags.mode"])] += 1
            if r["ssh.protocol"]:
                f["ssh"] = r["ssh.protocol"][:60]
            if r["quic.version"]:
                f["quic"] = r["quic.version"]
            if r["stun.type"]:
                f["stun"] = True
            if r["rtp.p_type"]:
                f.setdefault("rtp_pt", collections.Counter())[r["rtp.p_type"]] += 1
        p.wait()
        files.append((cap, npk))

    # STARTTLS seen by tshark only when both directions are in the capture: look at the raw records
    later = collections.defaultdict(list)
    for (cap, l4, sid), f in flows.items():
        undissected = all(k in ("TCP",) for k in f["protos"]) and (f["up"] + f["down"]) > 0
        if l4 == "tcp" and not f["tls"] and (undissected or any(k in ("XMPP/XML", "XMPP", "SMTP", "IMAP", "POP", "FTP") for k in f["protos"])):
            later[cap].append(sid)
    for cap, sids in later.items():
        for i in range(0, len(sids), 200):
            part = sids[i:i + 200]
            cmd = ["tshark", "-r", cap, "-n", "-Y", f"tcp.len>0 && tcp.stream in {{{','.join(part)}}}", "-T", "fields",
                   "-e", "tcp.stream", "-e", "ip.src", "-e", "frame.time_epoch", "-e", "tcp.payload"]
            pr = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
            for line in pr.stdout.splitlines():
                sid, src, t, pl = (line.split("\t") + ["", "", "", ""])[:4]
                f = flows.get((cap, "tcp", sid))
                if not f or not pl:
                    continue
                b = bytes.fromhex(pl.replace(":", "")[:20])
                if len(b) >= 3 and b[0] in (0x16, 0x17) and b[1] == 3:
                    x = f["tls"]
                    x.setdefault("raw", True)
                    if b[0] == 0x16 and len(b) >= 6 and b[5] == 1 and "ch_frame" not in x:
                        x["ch_frame"] = utcus(float(t))
                        x["ch_version"] = "（記録 " + tlsv("0x%02x%02x" % (b[1], b[2])) + "）"
                    if b[0] == 0x17:
                        f["appdata"][0 if src in devips else 1] += 1

    # names for peers
    def pname(f):
        n = f["sni"] or (f["host"].split(":")[0] if f["host"] else "")
        if not n:
            n = ",".join(sorted(names.get(f["peer"], [])))[:80]
        return n or f["peer"]

    def kind(f):
        pr = f["protos"]
        if f["tls"].get("raw") and not f["tls"].get("sh_version"):
            return "TLS (records only)" if all(k == "TCP" for k in pr) else "TLS (after STARTTLS, records only)"
        if f["tls"].get("sh_version") or f["tls"].get("ch_version") or any(k.startswith(("TLS", "SSL")) for k in pr):
            return "TLS" + (" (after STARTTLS)" if any(k in ("XMPP", "SMTP", "IMAP", "POP", "FTP") for k in pr) else "")
        if f["dtls"] or any(k.startswith("DTLS") for k in pr):
            return "DTLS"
        if f.get("quic") or "QUIC" in pr:
            return "QUIC"
        if f.get("ssh") or "SSH" in pr or "SSHv2" in pr:
            return "SSH"
        top = [k for k, _ in pr.most_common() if k not in ("TCP", "UDP")]
        return ("plain " + top[0]) if top else ("payload " + f["l4"] if (f["up"] + f["down"]) > 0 else f["l4"])

    out = []
    w = out.append
    w(f"# {a.name or mac}（{mac}）\n")
    w("## 1. 対象\n")
    w(f"- 機器の IP：{', '.join(sorted(devips)) or '不明'}")
    w(f"- 期間（UTC）：{utc(tot['first']) if tot['first'] else '-'} 〜 {utc(tot['last']) if tot['last'] else '-'}、{len(days)} 日（{', '.join(sorted(days))}）")
    w(f"- パケット {tot['pkts']:,}、{tot['bytes']:,} バイト")
    bydir = collections.OrderedDict()
    for c, n in files:
        d = c.rsplit("/", 1)[0] if "/" in c else "."
        x = bydir.setdefault(d, [0, 0, c.split("/")[-1], c.split("/")[-1]])
        x[0] += 1; x[1] += n; x[3] = c.split("/")[-1]
    for d, (k, n, f1, f2) in bydir.items():
        w(f"  - `{d}/`：{k} ファイル（`{f1}`" + (f" 〜 `{f2}`" if k > 1 else "") + f"）、{n:,} パケット")
    if excluded:
        w("- 除いた相手：" + "、".join(f"{p}（{n:,} パケット）" for p, n in excluded.items()))
    w("\n## 2. 機器が名乗った値\n")
    for k, c in selfid.items():
        w(f"- **{k}**：" + "；".join(f"`{x}`（{n}）" for x, n in c.most_common(8)))
    w("\n## 3. 範囲とプロトコル（バイト）\n")
    w("| 範囲 | バイト |\n|---|---|")
    for s, b in scope_bytes.most_common():
        w(f"| {s} | {b:,} |")
    pk = collections.Counter()
    for f in flows.values():
        pk[(f["scope"], f["l4"], f["sport"], kind(f))] += f["up"] + f["down"]
    for k, b in proto_bytes.items():
        pk[(k[2], k[0], "", "plain " + k[1])] += b
    w("\n| 範囲 | L4 | サーバーのポート | 種類 | バイト |\n|---|---|---|---|---|")
    for (s, l4, port, kd), b in pk.most_common(40):
        w(f"| {s} | {l4} | {port} | {kd} | {b:,} |")

    w("\n## 4. インターネットの相手\n")
    w("| 名前 | アドレス | ポート | 種類 | 接続 | 上り | 下り | 日数 | 最初 | 間隔の中央値（秒） |\n|---|---|---|---|---|---|---|---|---|---|")
    agg = collections.OrderedDict()
    for f in sorted(flows.values(), key=lambda f: f["first"]):
        if f["scope"] != "internet":
            continue
        k = (pname(f), f["l4"], f["sport"], kind(f))
        e = agg.setdefault(k, {"ips": set(), "n": 0, "up": 0, "down": 0, "days": set(), "first": f, "starts": []})
        e["ips"].add(f["peer"]); e["n"] += 1; e["up"] += f["up"]; e["down"] += f["down"]
        e["days"].add(utc(f["first"])[:10]); e["starts"].append(f["first"])
    for (n, l4, port, kd), e in sorted(agg.items(), key=lambda kv: -(kv[1]["up"] + kv[1]["down"])):
        st = sorted(e["starts"])
        gaps = [b - a2 for a2, b in zip(st, st[1:]) if b - a2 > 0]
        med = f"{statistics.median(gaps):.0f}" if len(gaps) >= 3 else "-"
        ff = e["first"]
        w(f"| {n} | {','.join(sorted(e['ips']))[:60]} | {l4}/{port} | {kd} | {e['n']} | {e['up']:,} | {e['down']:,} | {len(e['days'])} | `{capname(ff['cap'], ff['frame'])}` {ff['frame']} | {med} |")

    w("\n## 5. TLS と DTLS\n")
    tl = collections.OrderedDict()
    for f in flows.values():
        if not (f["tls"] or f["dtls"]):
            continue
        x = f["tls"] or f["dtls"]
        k = (pname(f), f["sport"], "DTLS" if f["dtls"] else "TLS", x.get("ch_version", ""),
             "/".join(x.get("ch_supported", []) or []), x.get("sh_version", ""), x.get("sh_suite", ""))
        e = tl.setdefault(k, {"n": 0, "weak": set(), "first": f, "certs": collections.Counter(), "alerts": collections.Counter(),
                              "noapp": 0, "init": collections.Counter(), "nsuites": 0})
        e["n"] += 1
        e["init"][f["init"]] += 1
        for s in x.get("ch_suites", []) or []:
            if WEAK.search(s):
                e["weak"].add(s)
        e["nsuites"] = max(e["nsuites"], len(x.get("ch_suites", []) or []))
        for who, h in x.get("certs", []):
            e["certs"][(who, h)] += 1
        for al in f["alerts"]:
            e["alerts"][al[:3]] += 1
        if f["tls"] and f["appdata"] == [0, 0]:
            e["noapp"] += 1
    w("| 相手 | ポート | 種 | 機器が出した版 | supported_versions | 選ばれた版 | 選ばれた暗号 | 回数 | 弱い暗号の提示 | 最初の ClientHello |\n|---|---|---|---|---|---|---|---|---|---|")
    for (n, port, ty, chv, sup, shv, suite), e in tl.items():
        ff = e["first"]
        chf = (ff["tls"] or ff["dtls"]).get("ch_frame", ff["frame"])
        weak = ", ".join(sorted(e["weak"]))[:160]
        w(f"| {n} | {port} | {ty} | {chv} | {sup} | {shv} | {suite} | {e['n']} | {weak or 'なし'}（提示 {e['nsuites']} 種） | `{capname(ff['cap'], chf)}` {chf} |")
    w("\n**証明書**（TLS 1.3 では暗号化されて見えない）\n")
    w("| 相手 | 出した側 | 主体 | 発行者 | 期間 | 鍵 | 署名 | 名前が合うか | 期限切れで使用 | 回数 |\n|---|---|---|---|---|---|---|---|---|---|")
    seen = set()
    for (n, port, ty, *_), e in tl.items():
        for (who, h), c in e["certs"].items():
            ci = certs.get(h, {})
            if (n, h) in seen:
                continue
            seen.add((n, h))
            fit = "-" if who == "device" or not n or re.match(r"^[0-9.:]+$", n) else ("はい" if name_fits(n, ci) else "いいえ")
            exp = "はい" if ci.get("not_after_ts") and e["first"]["first"] > ci["not_after_ts"] else ""
            w(f"| {n}:{port} | {who} | {ci.get('subject','')} | {ci.get('issuer','')}{'（自己署名）' if ci.get('self_signed') else ''} | {ci.get('not_before','')}〜{ci.get('not_after','')} | {ci.get('key','')} | {ci.get('sig','')} | {fit} | {exp} | {c} |")
    w("\n**警告（alert）と、中身のない接続**\n")
    for (n, port, ty, *_), e in tl.items():
        if e["alerts"] or e["noapp"]:
            al = "；".join(f"{who} が {lvl}/{desc}（{c}）" for (who, lvl, desc), c in e["alerts"].most_common(6))
            w(f"- {n}:{port}：{al or '警告なし'}。アプリケーションデータのない接続 {e['noapp']}/{e['n']}")

    w("\n## 6. 平文\n")
    w("### HTTP の要求\n")
    w("| 方法 | 相手 | ポート | パス | 問い合わせの名前 | 回数 | 日数 | 範囲 | 最初 | 認証・Cookie | User-Agent | 本文の先頭 |\n|---|---|---|---|---|---|---|---|---|---|---|---|")
    for (m, host, port, path, qk), e in sorted(http.items(), key=lambda kv: -kv[1]["n"]):
        cred = ("Authorization: " + e["auth"][:60] if e["auth"] else "") + (" Cookie: " + e["cookie"][:80] if e["cookie"] else "")
        w(f"| {m} | {host} | {port} | `{path[:80]}` | {','.join(qk)[:100]} | {e['n']} | {len(e['days'])} | {e['scope']} | `{capname(e['cap'], e['time'])}` {e['time']} | {cred.strip()[:150]} | {e['ua'][:60]} | `{e['body'][:120]}` |")
    w("\n例（最初の URL）：\n")
    for (m, host, port, path, qk), e in list(http.items())[:60]:
        w(f"- `{m} {host}{e['uri'][:220]}`")
    if httpresp:
        w("\n### HTTP の応答\n")
        w("| 相手 | ポート | 状態 | 種類 | 長さ | 回数 |\n|---|---|---|---|---|---|")
        for (h, port, code, ct, cl), c in httpresp.most_common(40):
            w(f"| {h} | {port} | {code} | {ct} | {cl} | {c} |")
    if ftp:
        w("\n### FTP\n")
        for x in ftp[:40]:
            w(f"- `{capname(x[2], x[1])}` {x[1]} → {x[3]}：{x[4]} {x[5]}")
        if len(ftp) > 40:
            w(f"- ほか {len(ftp) - 40} 件")
    if mqtt:
        w("\n### MQTT（平文として読めたもの）\n")
        for k, c in mqtt.most_common(20):
            w(f"- {k}：{c}")
    if ntp:
        w("\n### NTP\n")
        for (pe, mode), c in ntp.most_common(10):
            w(f"- {pe}（{','.join(sorted(names.get(pe, [])))}）mode {mode}：{c}")
    w("\n### そのほかの平文・未分類の通信（最初の中身）\n")
    seen = set()
    for f in sorted(flows.values(), key=lambda f: -(f["up"] + f["down"])):
        kd = kind(f)
        if kd.startswith(("TLS", "DTLS", "QUIC", "SSH")) or f["http"]:
            continue
        k = (pname(f), f["l4"], f["sport"], kd)
        if k in seen or f["scope"] not in ("internet", "lan"):
            continue
        seen.add(k)
        u = printable(bytes.fromhex(f["data0"][0].replace(":", ""))) if f["data0"][0] else ""
        d = printable(bytes.fromhex(f["data0"][1].replace(":", ""))) if f["data0"][1] else ""
        extra = (" RTP PT " + ",".join(f"{p}:{c}" for p, c in f["rtp_pt"].most_common(3))) if f.get("rtp_pt") else ""
        extra += " STUN" if f.get("stun") else ""
        w(f"- {f['scope']} {k[0]} {f['l4']}/{f['sport']} {kd}{extra}：`{capname(f['cap'], f['frame'])}` {f['frame']}、上り `{u[:80]}`、下り `{d[:80]}`")
        if len(seen) > 40:
            break

    w("\n## 7. 更新らしいダウンロード\n")
    found = False
    for f in flows.values():
        for code, ct, cl, fr in f.get("resp", []):
            big = cl.isdigit() and int(cl) > 300000
            if big or "octet" in (ct or "") or FWPATH.search(f.get("host", "")):
                w(f"- {f.get('host') or f['peer']}:{f['sport']}：{code} {ct} {cl} バイト（`{capname(f['cap'], fr)}` {fr}）")
                found = True
    for (m, host, port, path, qk), e in http.items():
        if FWPATH.search(path):
            w(f"- 要求 `{m} {host}{e['uri'][:160]}`（{e['n']} 回、`{capname(e['cap'], e['frame'])}` {e['frame']}）")
            found = True
    if not found:
        w("- 平文では見えない（TLS の中で取っていれば見えない）")

    w("\n## 8. LAN の相手\n")
    lan = collections.Counter()
    lanfirst = {}
    for f in flows.values():
        if f["scope"] == "lan":
            k = (f["peer"], f["l4"], f["sport"], kind(f), f["init"])
            lan[k] += f["up"] + f["down"]
            lanfirst.setdefault(k, f)
    w("| 相手 | L4/ポート | 種類 | 始めた側 | バイト | 最初 |\n|---|---|---|---|---|---|")
    for (pe, l4, port, kd, ini), b in lan.most_common(30):
        ff = lanfirst[(pe, l4, port, kd, ini)]
        w(f"| {pe} | {l4}/{port} | {kd} | {ini} | {b:,} | `{capname(ff['cap'], ff['frame'])}` {ff['frame']} |")
    w("\n**DNS**：問い合わせた名前 " + str(len(dnsq)) + " 種。リゾルバ " + "、".join(f"{x}（{n}）" for x, n in resolvers.most_common(5)))
    w("\n" + "；".join(f"`{q}`（{n}）" for q, n in dnsq.most_common(60)))

    w("\n## 9. エラーと切り替え\n")
    rst_dev = sum(1 for f in flows.values() if f["rst"][0]); rst_peer = sum(1 for f in flows.values() if f["rst"][1])
    noans = [f for f in flows.values() if f["l4"] == "tcp" and f["init"] == "device" and not f["synack"] and f["down"] == 0]
    w(f"- TCP のリセット：機器から {rst_dev} 接続、相手から {rst_peer} 接続")
    na = collections.Counter((pname(f), f["sport"]) for f in noans)
    w(f"- 応答のない接続（機器からの SYN だけ）：{len(noans)}。" + "；".join(f"{n}:{p}（{c}）" for (n, p), c in na.most_common(8)))
    w("- DNS のエラー：" + ("；".join(f"{q} rcode {rc}（{c}）" for (q, rc), c in dnserr.most_common(10)) or "なし"))
    he = [(k, c) for k, c in httpresp.items() if k[2] and k[2][0] in "45"]
    w("- HTTP のエラー：" + ("；".join(f"{k[0]}:{k[1]} {k[2]}（{c}）" for k, c in sorted(he, key=lambda x: -x[1])[:10]) or "なし"))
    tlsnames = {pname(f) for f in flows.values() if kind(f).startswith("TLS")}
    plainnames = {pname(f) for f in flows.values() if f["http"]}
    both = sorted(n for n in tlsnames & plainnames if n and not re.match(r"^[0-9.:]+$", n))
    w("- TLS と平文の両方で使った名前：" + (", ".join(both) or "なし"))
    al = collections.Counter()
    for f in flows.values():
        for who, lvl, desc, fr in f["alerts"]:
            al[(pname(f), who, lvl, desc)] += 1
    w("- TLS の警告：" + ("；".join(f"{n} で {who} が {lvl}/{desc}（{c}）" for (n, who, lvl, desc), c in al.most_common(10)) or "なし"))

    open(a.out, "w").write("\n".join(out) + "\n")
    print(f"{a.out}: {tot['pkts']} packets, {len(flows)} flows, {len(http)} HTTP shapes", file=sys.stderr)


if __name__ == "__main__":
    main()
