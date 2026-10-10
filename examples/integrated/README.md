# Integrated evidence demo

この demo は OpenWrt boundary evidence、Suricata IDS alert、Zeek passive NSM、Snort alert を同じ Quarant run にまとめ、precision / mitigation / before-after evaluation / research package まで流すための最小例です。

## ワンコマンド実行

repo root から実行します。

```bash
go run ./cmd/quarant experiment run \
  --before-openwrt examples/integrated/before/openwrt/raw \
  --before-suricata examples/integrated/before/suricata/raw/eve.json \
  --before-zeek examples/integrated/before/zeek/raw \
  --before-snort examples/integrated/before/snort/raw/alert.fast \
  --after-openwrt examples/integrated/after/openwrt/raw \
  --after-suricata examples/integrated/after/suricata/raw/eve.json \
  --after-zeek examples/integrated/after/zeek/raw \
  --after-snort examples/integrated/after/snort/raw/alert.fast \
  --before-now 2026-09-26T12:30:00Z \
  --after-now 2026-09-26T13:30:00Z \
  --out runs/integrated
```

主な出力:

- `runs/integrated/before/assembled`
- `runs/integrated/after/assembled`
- `runs/integrated/precision_report.json`
- `runs/integrated/mitigation_plan.json`
- `runs/integrated/mitigation_eval_report.json`
- `runs/integrated/research_report.json`
- `runs/integrated/package`
- `runs/integrated/experiment_manifest.json`

以下は同じ処理を段階ごとに実行する場合の例です。

## 1. Import

```bash
go run ./cmd/quarant openwrt import \
  --dhcp-leases examples/integrated/before/openwrt/raw/dhcp.leases \
  --dns-log examples/integrated/before/openwrt/raw/dnsmasq.log \
  --firewall-log examples/integrated/before/openwrt/raw/firewall.log \
  --conntrack examples/integrated/before/openwrt/raw/conntrack.txt \
  --out-dir runs/integrated/before/openwrt \
  --now 2026-09-26T12:30:00Z

go run ./cmd/quarant suricata import \
  --eve examples/integrated/before/suricata/raw/eve.json \
  --out-dir runs/integrated/before/suricata

go run ./cmd/quarant zeek import \
  --conn examples/integrated/before/zeek/raw/conn.log \
  --dns examples/integrated/before/zeek/raw/dns.log \
  --http examples/integrated/before/zeek/raw/http.log \
  --ssl examples/integrated/before/zeek/raw/ssl.log \
  --out-dir runs/integrated/before/zeek

go run ./cmd/quarant snort import \
  --alerts examples/integrated/before/snort/raw/alert.fast \
  --out-dir runs/integrated/before/snort
```

同じ手順を `after/` 側にも実行します。

## 2. Assemble

```bash
go run ./cmd/quarant evidence assemble \
  --openwrt runs/integrated/before/openwrt \
  --suricata runs/integrated/before/suricata \
  --zeek runs/integrated/before/zeek \
  --snort runs/integrated/before/snort \
  --out runs/integrated/before/assembled
```

出力:

- `events.jsonl`
- `security_events.jsonl`
- `flows.jsonl`
- `observations.jsonl`
- `attack_evidence_report.json`
- `source_coverage_report.json`
- `evidence_manifest.json`

## 3. Precision / Mitigation

```bash
go run ./cmd/quarant precision \
  --events runs/integrated/before/assembled/events.jsonl \
  --security-events runs/integrated/before/assembled/security_events.jsonl \
  --flows runs/integrated/before/assembled/flows.jsonl \
  --observations runs/integrated/before/assembled/observations.jsonl \
  --out runs/integrated/precision_report.json \
  --incidents-out runs/integrated/incidents.jsonl

go run ./cmd/quarant mitigate \
  --events runs/integrated/before/assembled/events.jsonl \
  --security-events runs/integrated/before/assembled/security_events.jsonl \
  --flows runs/integrated/before/assembled/flows.jsonl \
  --observations runs/integrated/before/assembled/observations.jsonl \
  --out runs/integrated/mitigation_plan.json \
  --gateway-out runs/integrated/gateway_backend_plan.json \
  --rules-out runs/integrated/openwrt_mitigation_dryrun.sh \
  --rollback-out runs/integrated/openwrt_mitigation_rollback.sh
```

## 4. Before / After Evaluation

```bash
go run ./cmd/quarant mitigation-eval \
  --plan runs/integrated/mitigation_plan.json \
  --before-events runs/integrated/before/assembled/events.jsonl \
  --before-security-events runs/integrated/before/assembled/security_events.jsonl \
  --before-flows runs/integrated/before/assembled/flows.jsonl \
  --before-observations runs/integrated/before/assembled/observations.jsonl \
  --after-events runs/integrated/after/assembled/events.jsonl \
  --after-security-events runs/integrated/after/assembled/security_events.jsonl \
  --after-flows runs/integrated/after/assembled/flows.jsonl \
  --after-observations runs/integrated/after/assembled/observations.jsonl \
  --out runs/integrated/mitigation_eval_report.json
```

## 5. Research Package

```bash
go run ./cmd/quarant research-report \
  --precision runs/integrated/precision_report.json \
  --mitigation runs/integrated/mitigation_plan.json \
  --mitigation-eval runs/integrated/mitigation_eval_report.json \
  --source-coverage runs/integrated/before/assembled/source_coverage_report.json \
  --out runs/integrated/research_report.json \
  --markdown-out runs/integrated/research_report.md \
  --csv-dir runs/integrated/tables \
  --package-dir runs/integrated/package
```

見どころ:

- OpenWrt と Suricata が同じ `192.168.8.42/tcp/80` を観測し、source coverage overlap として出る。
- before では TCP/80 が accepted/exposed service attempt と IDS alert の両方に現れる。
- after では OpenWrt 側が DROP になり、IDS exposed overlap reduction を評価できる。
