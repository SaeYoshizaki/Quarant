#!/usr/bin/env python3
"""What are the identifiers in Sonos's plaintext update URLs? Prints only yes/no answers and lengths, never a value.

Usage: ident_meaning.py <device mac> <capture>...
Compares the URL parameters serial, householdid and sonosid (from plaintext GETs to update*.sonos.com) with the device's
own MAC address (Ethernet source), with the household and RINCON identifiers the device announces on the LAN in SSDP
(X-RINCON-HOUSEHOLD, USN uuid:RINCON_...), with <serialNum> and <MACAddress> in the UPnP device description it serves on
tcp/1400, and with <sn> in the metrics XML when there is one.
"""
import re, subprocess, sys, urllib.parse
def shape(v): return ''.join('h' if c in '0123456789abcdefABCDEF' else 'a' if c.isalnum() else c for c in v)  # every letter and digit masked
mac = sys.argv[1].replace(':', '').lower()
url = {'serial': set(), 'householdid': set(), 'sonosid': set()}; ssdp_hh = set(); rincon = set(); sn = set(); upnp_sn = set(); upnp_mac = set(); other = {}
for f in sys.argv[2:]:
    p = subprocess.run(['tshark', '-r', f, '-Y', 'eth.src==%s && ((tcp.dstport==80 && tcp.len>0) || udp.dstport==1900 || (tcp.srcport==1400 && tcp.len>0))' % sys.argv[1], '-T', 'fields', '-e', 'udp.payload', '-e', 'tcp.payload'],
                       capture_output=True, text=True)
    for line in p.stdout.splitlines():
        b = bytes.fromhex(line.replace('\t', '').replace(':', '')).decode('latin-1')
        m = re.match(r'GET (\S+) HTTP', b)
        if m and re.search(r'^Host: update[\w.-]*sonos\.com', b, re.M | re.I):
            for k, vs in urllib.parse.parse_qs(urllib.parse.urlparse(m.group(1)).query).items():
                if k in url: url[k].update(vs)
        elif m and 'serial=' in m.group(1):
            host = (re.findall(r'^Host: *(\S+)', b, re.M | re.I) or ['?'])[0]
            for v in urllib.parse.parse_qs(urllib.parse.urlparse(m.group(1)).query).get('serial', []): other.setdefault(host, set()).add(v)
        ssdp_hh.update(re.findall(r'^X-RINCON-HOUSEHOLD: *(\S+)', b, re.M | re.I))
        rincon.update(x.lower() for x in re.findall(r'uuid:RINCON_([0-9A-Fa-f]{12})', b))
        sn.update(re.findall(r'<sn>([^<]{1,40})</sn>', b))
        d = re.sub(r'\r\n[0-9A-Fa-f]{1,6}\r\n', '', b)  # the description is sent chunked; drop chunk-size lines
        upnp_sn.update(re.findall(r'<serialNum>([^<]{1,40})</serialNum>', d))
        upnp_mac.update(x.lower().replace(':', '') for x in re.findall(r'<MACAddress>([^<]{1,20})</MACAddress>', d))
def norm(v): return re.sub(r'[^0-9a-z]', '', v.lower())
print('distinct values:', {k: len(v) for k, v in url.items()}, 'ssdp household:', len(ssdp_hh), 'rincon:', len(rincon), 'xml sn:', len(sn))
for s in url['serial']:
    s = s.lower()
    print('serial: length', len(s), '| first 12 = device MAC:', s[:12] == mac, '| first 12 = RINCON id:', s[:12] in rincon,
          '| equals xml <sn> without separators:', any(norm(x) == s for x in sn),
          '| <sn> shape:', sorted({shape(x) for x in sn}),
          '| equals UPnP <serialNum> without separators:', any(norm(x) == s for x in upnp_sn) if upnp_sn else 'no description seen',
          '| <serialNum> shape:', sorted({shape(x) for x in upnp_sn}))
for h in url['householdid']:
    print('householdid: length', len(h), '| starts with "Sonos_":', h.startswith('Sonos_'), '| equals SSDP X-RINCON-HOUSEHOLD:', h in ssdp_hh)
for s in url['sonosid']:
    print('sonosid: length', len(s), '| digits only:', s.isdigit(), '| inside SSDP household or RINCON:', any(s in x for x in ssdp_hh | rincon))
ref = {norm(x) for x in upnp_sn | sn | url['serial']}
for host, vs in other.items():
    for v in vs: print('serial sent to', host, ': length', len(v), '| shape', shape(v), '| equals device serial without separators:', norm(v) in ref if ref else 'no reference seen')
print('RINCON id = device MAC:', mac in rincon, '| UPnP <MACAddress> = device MAC:', mac in upnp_mac if upnp_mac else 'not seen')
