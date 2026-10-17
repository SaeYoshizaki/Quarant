#!/bin/bash
# Accuracy step 1: build the independent ground truth for every capture that
# ~/datasets/scripts/rerun-e10.sh analysed, with the same run names.
#   gt.log     Zeek (scripts/accuracy/gt.zeek): TLS, HTTP, MQTT, FTP by content
#   raw.jsonl  rawscan.py: per-packet search of the raw payloads
# Only names and addresses are written, never values (see the two scripts).
# usage: run_gt.sh OUT_DIR [PARALLEL]
set -u
OUT=$1; PAR=${2:-4}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
jobs=$OUT/jobs.tsv; : > "$jobs"
T=$HOME/datasets/unsw-iot-traces
for tgz in "$T"/16-*.tar.gz; do d=$(basename "$tgz" .tar.gz); printf 'unsw-%s\t%s\n' "$d" "$tgz" >> "$jobs"; done
for d in "$HOME"/datasets/iot-23/*/; do p=$(ls "$d"*.pcap 2>/dev/null | head -1); [ -n "$p" ] && printf 'iot23-%s\t%s\n' "$(basename "$d")" "$p" >> "$jobs"; done
for p in "$HOME"/datasets/unsw-iot-attacks/raw/*.pcap; do printf 'unswatk-%s\t%s\n' "$(basename "$p" .pcap)" "$p" >> "$jobs"; done
C=/Volumes/Untitled/quarant-datasets/cic-iot-2022
for part in 1-Power 2-Idle 3-Interactions 4-Scenarios; do
  find "$C/$part" -type f -name "*.pcap" ! -name "._*" | sort | while IFS= read -r p; do
    printf 'cic-%s-%s\t%s\n' "$(echo $part | tr 'A-Z' 'a-z')" "$(basename "$p" .pcap)" "$p" >> "$jobs"
  done
done
find "$C/6-Attacks/6-Attacks/2-RTSP Brute Force" -type f -name "*.pcap" ! -name "._*" | sort | while IFS= read -r p; do
  printf 'cic-6-rtsp-%s\t%s\n' "$(basename "$p" .pcap)" "$p" >> "$jobs"; done
printf 'cic-5-active-2021_11_02_Active\t%s\n' /Volumes/Untitled/CIC_IOT_Dataset2022/2021_11_02_Active.pcap >> "$jobs"

one() {
  name=$1; src=$2; out=$OUT/$name
  [ -f "$out/done" ] && return
  mkdir -p "$out"
  pcap=$src
  if [[ $src == *.tar.gz ]]; then
    tmp=$OUT/.tmp-$name; mkdir -p "$tmp"; tar -xzf "$src" -C "$tmp"; pcap=$(ls "$tmp"/*.pcap | head -1)
  fi
  ( cd "$out" && zeek -C -r "$pcap" "$here/gt.zeek" LogAscii::use_json=T > zeek.stderr 2>&1; rm -f dhcp.log dns.log ntp.log packet_filter.log weird.log ssh.log smtp.log sip.log snmp.log syslog.log dpd.log analyzer.log notice.log reporter.log x509.log quic.log *.log.tmp 2>/dev/null; ls *.log | grep -v '^gt.log$' | xargs rm -f ) &
  python3 -I "$here/rawscan.py" "$pcap" "$out/raw.jsonl" 2> "$out/raw.stderr"
  wait
  sha=$(shasum -a 256 "$pcap" | cut -c1-16)
  [[ $src == *.tar.gz ]] && rm -rf "$tmp"
  echo "$sha" > "$out/done"
}
export -f one; export OUT here
cut -f1,2 "$jobs" | tr '\t\n' '\0\0' | xargs -0 -n2 -P "$PAR" bash -c 'one "$0" "$1"'
echo "$(wc -l < "$jobs") jobs; $(ls "$OUT"/*/done | wc -l) done"
