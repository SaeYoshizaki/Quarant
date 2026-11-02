# Is the user part of the SIP From header the device MAC? Prints booleans and lengths only. usage: sip_from.py <capture file>...
import os, re, subprocess, sys
MAC = os.environ['RING_MAC']
for f in sys.argv[1:]:
    p = subprocess.run(['tshark','-r',f,'-Y','udp.port==15063 && ip.src==192.168.0.19','-T','fields','-e','udp.payload'],capture_output=True,text=True)
    for l in p.stdout.splitlines():
        t = bytes.fromhex(l.replace(':','')).decode('latin-1')
        if t.startswith('INVITE'):
            m = re.search(r'From:\s*<sip:([^@]+)@([^>]+)>', t)
            print(f.split('/')[-1][5:18], 'from user is MAC:', m.group(1).lower().replace(':','') == MAC, 'domain:', m.group(2))
            break
