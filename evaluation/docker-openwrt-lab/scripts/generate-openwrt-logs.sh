#!/bin/sh
set -eu

OUT_DIR="${1:-/lab/out}"

write_window() {
  window="$1"
  firewall_body="$2"

  raw_dir="$OUT_DIR/$window/openwrt/raw"
  mkdir -p "$raw_dir"

  cat >"$raw_dir/dhcp.leases" <<'EOF'
1790409600 aa:bb:cc:dd:ee:ff 192.168.8.42 camera-01 01:aa:bb:cc:dd:ee:ff
1790409600 11:22:33:44:55:66 192.168.8.77 plug-01 01:11:22:33:44:55:66
EOF

  cat >"$raw_dir/dnsmasq.log" <<'EOF'
Sep 26 12:00:01 router dnsmasq[1234]: query[A] camera-cloud.example from 192.168.8.42
Sep 26 12:00:06 router dnsmasq[1234]: query[A] pool.ntp.org from 192.168.8.77
EOF

  cat >"$raw_dir/conntrack.txt" <<'EOF'
tcp 6 431999 ESTABLISHED src=192.168.8.42 dst=198.51.100.10 sport=50000 dport=443 src=198.51.100.10 dst=203.0.113.5 sport=443 dport=50000 [ASSURED]
udp 17 29 src=192.168.8.77 dst=198.51.100.20 sport=39123 dport=123 src=198.51.100.20 dst=203.0.113.5 sport=123 dport=39123 [ASSURED]
EOF

  printf '%s\n' "$firewall_body" >"$raw_dir/firewall.log"
}

write_window before "Sep 26 12:00:02 router kern.warn kernel: [123.45] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45123 DPT=23 SYN
Sep 26 12:00:03 router kern.warn kernel: [123.46] ACCEPT IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45124 DPT=80 SYN
Sep 26 12:00:04 router kern.warn kernel: [123.47] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45125 DPT=8080 SYN
Sep 26 12:00:05 router kern.warn kernel: [123.48] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45126 DPT=554 FIN
Sep 26 12:00:07 router kern.warn kernel: [123.49] ACCEPT IN=wan OUT=br-lan SRC=198.51.100.44 DST=192.168.8.77 PROTO=UDP SPT=53000 DPT=1900"

write_window after "Sep 26 13:00:02 router kern.warn kernel: [223.45] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45123 DPT=23 SYN
Sep 26 13:00:03 router kern.warn kernel: [223.46] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45124 DPT=80 SYN
Sep 26 13:00:04 router kern.warn kernel: [223.47] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45125 DPT=8080 SYN
Sep 26 13:00:05 router kern.warn kernel: [223.48] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45126 DPT=554 FIN
Sep 26 13:00:07 router kern.warn kernel: [223.49] REJECT IN=wan OUT=br-lan SRC=198.51.100.44 DST=192.168.8.77 PROTO=UDP SPT=53000 DPT=1900"

echo "OpenWrt-compatible lab logs written to $OUT_DIR"
