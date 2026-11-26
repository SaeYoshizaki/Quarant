#!/bin/bash
# Cut the CIC IoT 2022 captures down to the eight devices re-checked on 2026-11-26 (one tcpdump pass per file).
R=~/datasets/raw/cic-iot-2022
O=~/datasets/claims/recheck-20261126/cic
F="ether host 10:2c:6b:1b:43:be or ether host 8c:85:80:6c:b6:47 or ether host 00:17:88:60:d6:4f or ether host 50:14:79:37:80:18 or ether host f0:b4:d2:f9:60:95 or ether host cc:f4:11:9c:d0:00 or ether host 44:bb:3b:00:39:07 or ether host b0:09:da:3e:82:6c"
mkdir -p "$O"
find "$R/1-Power" "$R/2-Idle" "$R/3-Interactions" "$R/4-Scenarios" -name '*.pcap' | sort > "$O/files.txt"
echo "$R/2021_11_02_Active.pcap" >> "$O/files.txt"
while IFS= read -r f; do
  rel=${f#$R/}; out="$O/${rel//\//__}"
  [ -s "$out" ] || tcpdump -r "$f" -w "$out" "$F" 2>/dev/null
  [ -s "$out" ] && [ $(stat -f %z "$out") -le 24 ] && rm -f "$out"
done < "$O/files.txt"
echo ALLDONE $(ls "$O"/*.pcap | wc -l)
