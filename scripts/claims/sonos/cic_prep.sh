#!/bin/bash
# Copy one device's frames out of CIC IoT 2022 captures into <outdir>/eth-<name>, with the original frame numbers in .frames,
# so hue/http_scan.py and hue/tls_quick.py can read them. usage: cic_prep.sh <outdir> <mac> <pcap>...
set -euo pipefail
out=$1; mac=$2; shift 2
mkdir -p "$out"
for f in "$@"; do
  n=eth-$(basename "$f" .pcap)
  tshark -r "$f" -Y "eth.addr==$mac" -T fields -e frame.number > "$out/$n.frames"
  tshark -r "$f" -Y "eth.addr==$mac" -w "$out/$n"
  echo "$n $(wc -l < "$out/$n.frames")"
done
