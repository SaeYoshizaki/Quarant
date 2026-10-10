# OpenWrt boundary evidence demo

この directory は、OpenWrt firewall log から Quarant の `security_events.jsonl` と `attack_evidence_report.json` を生成し、precision incident、mitigation plan、before/after evaluation まで接続するための最小 demo です。

## データの意図

`before/raw/firewall.log` には、WAN 側から IoT camera への以下の境界証拠が含まれます。

- TCP/23, TCP/80, TCP/8080 への port scan 風 probe
- TCP/80 の `ACCEPT` evidence
- FIN scan 風の suspicious TCP flags

`after/raw/firewall.log` では、同じような probe は観測されますが、TCP/80 は `DROP` になっています。

重要: この demo は「外部から来る scan volume が減った」ことを主張するものではありません。Quarant は observed / blocked / accepted / exposed service attempt を分け、accepted/exposed evidence が減ったか、blocked evidence が blocked のまま維持されたかを見る設計です。

## 実行例

repo root から実行します。

```bash
go run ./cmd/quarant openwrt import \
  --dhcp-leases examples/openwrt/before/raw/dhcp.leases \
  --dns-log examples/openwrt/before/raw/dnsmasq.log \
  --firewall-log examples/openwrt/before/raw/firewall.log \
  --conntrack examples/openwrt/before/raw/conntrack.txt \
  --out-dir runs/openwrt-demo/before \
  --now 2026-09-26T12:30:00Z
```

```bash
go run ./cmd/quarant precision \
  --events runs/openwrt-demo/before/events.jsonl \
  --security-events runs/openwrt-demo/before/security_events.jsonl \
  --flows runs/openwrt-demo/before/flows.jsonl \
  --observations runs/openwrt-demo/before/observations.jsonl \
  --inventory runs/openwrt-demo/before/device_inventory.json \
  --out runs/openwrt-demo/precision_report.json \
  --incidents-out runs/openwrt-demo/incidents.jsonl
```

必要に応じて、attack evidence finding に人手ラベルを付けて detector evidence quality を評価します。

```bash
go run ./cmd/quarant attack-eval \
  --attack-evidence runs/openwrt-demo/before/attack_evidence_report.json \
  --labels runs/openwrt-demo/before/attack_evidence_labels.jsonl \
  --init-labels
```

`attack_evidence_labels.jsonl` の `label` を `true_attack`、`scanner_lab_generated`、`internet_background_noise`、`benign_admin`、`unknown` のいずれかにレビューしてから実行します。

```bash
go run ./cmd/quarant attack-eval \
  --attack-evidence runs/openwrt-demo/before/attack_evidence_report.json \
  --labels runs/openwrt-demo/before/attack_evidence_labels.jsonl \
  --out runs/openwrt-demo/before/attack_evidence_eval_report.json
```

```bash
go run ./cmd/quarant mitigate \
  --events runs/openwrt-demo/before/events.jsonl \
  --security-events runs/openwrt-demo/before/security_events.jsonl \
  --flows runs/openwrt-demo/before/flows.jsonl \
  --observations runs/openwrt-demo/before/observations.jsonl \
  --inventory runs/openwrt-demo/before/device_inventory.json \
  --out runs/openwrt-demo/mitigation_plan.json \
  --gateway-out runs/openwrt-demo/gateway_backend_plan.json \
  --rules-out runs/openwrt-demo/openwrt_mitigation_dryrun.sh \
  --rollback-out runs/openwrt-demo/openwrt_mitigation_rollback.sh
```

```bash
go run ./cmd/quarant openwrt import \
  --dhcp-leases examples/openwrt/after/raw/dhcp.leases \
  --dns-log examples/openwrt/after/raw/dnsmasq.log \
  --firewall-log examples/openwrt/after/raw/firewall.log \
  --conntrack examples/openwrt/after/raw/conntrack.txt \
  --out-dir runs/openwrt-demo/after \
  --now 2026-09-26T13:30:00Z
```

```bash
go run ./cmd/quarant mitigation-eval \
  --plan runs/openwrt-demo/mitigation_plan.json \
  --before-events runs/openwrt-demo/before/events.jsonl \
  --before-security-events runs/openwrt-demo/before/security_events.jsonl \
  --before-flows runs/openwrt-demo/before/flows.jsonl \
  --before-observations runs/openwrt-demo/before/observations.jsonl \
  --before-inventory runs/openwrt-demo/before/device_inventory.json \
  --after-events runs/openwrt-demo/after/events.jsonl \
  --after-security-events runs/openwrt-demo/after/security_events.jsonl \
  --after-flows runs/openwrt-demo/after/flows.jsonl \
  --after-observations runs/openwrt-demo/after/observations.jsonl \
  --after-inventory runs/openwrt-demo/after/device_inventory.json \
  --out runs/openwrt-demo/mitigation_eval_report.json
```

期待する見どころ:

- `before/security_events.jsonl` に DROP/ACCEPT/FIN scan evidence が出る。
- `before/attack_evidence_report.json` に port scan と suspicious TCP flag 系の finding が出る。
- `precision_report.json` に `attack_evidence_port_scan`, `attack_evidence_sensitive_service_probe`, `attack_evidence_suspicious_tcp_flags` の signal が出る。
- `mitigation_plan.json` では ACCEPT/exposed evidence があるため inbound exposure review 系の action が出る。
- `mitigation_eval_report.json` では accepted/exposed boundary evidence reduction と observed boundary evidence reduction が分離して記録される。

