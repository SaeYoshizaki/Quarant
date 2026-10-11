# Quarant

Quarant は、IoT 環境をできるだけパッシブに観測し、観測証拠から incident を整理し、OpenWrt などのルーターで仮想パッチ/緩和候補を作り、その前後で本当にリスクが下がったかを評価する研究プロトタイプです。

現在の実装では、PCAP/flow 由来の IoT 挙動だけでなく、OpenWrt の firewall log から router boundary で観測された攻撃候補も取り込み、precision incident、mitigation plan、before/after evaluation、research report に接続できます。

## 実装済みの流れ

現在実装済みの主なパイプラインは以下です。

```text
passive observation
  -> events.jsonl / flows.jsonl / observations.jsonl / device_inventory.json
  -> precision_report.json / incidents.jsonl
  -> mitigation_plan.json
  -> OpenWrt gateway backend plan / dry-run / apply script / rollback script
  -> mitigation_eval_report.json
  -> research report package
```

OpenWrt firewall log については、以下の境界証拠パイプラインも実装済みです。

```text
OpenWrt firewall log / nft-style logread output
  -> security_events.jsonl
  -> attack_evidence_report.json
  -> precision incident の attack evidence signal
  -> mitigation plan の優先度/方針
  -> before/after eval の boundary evidence metrics
  -> research report の metrics / limitations
```

## 再現 demo

OpenWrt 境界証拠の再現用 fixture と実行手順は `examples/openwrt/` にあります。

```text
examples/openwrt/before/raw/
examples/openwrt/after/raw/
examples/openwrt/README.md
```

この demo は、before window に ACCEPT された inbound service attempt を含め、after window では同じ probe が DROP される形にしています。これにより、単なる observed scan volume ではなく、accepted / exposed service attempt の before/after reduction を確認できます。

## 主要な出力ファイル

### `events.jsonl`

Quarant の既存 rule event です。PCAP 解析や OpenWrt import から、plaintext HTTP、Telnet、credential/token exposure、OpenWrt firewall block などのイベントが出力されます。

### `flows.jsonl`

通信 flow の要約です。source/destination、port、protocol、app protocol、direction、observed destination などを保持します。

### `observations.jsonl`

SOC/precision 用の passive observation です。DNS query、HTTP host/request、TLS SNI、flow snapshot、local/external connection などを保持します。

### `device_inventory.json`

観測された IoT device の inventory snapshot です。DHCP lease、hostname、MAC、観測 protocol/port/host などを含みます。

### `security_events.jsonl`

router boundary や IDS/NSM 由来の security evidence を表す Quarant native JSONL です。現在は OpenWrt firewall log と Suricata EVE alert から生成できます。

主な field:

```json
{
  "ts": "2026-09-26T12:00:02Z",
  "source": "openwrt_firewall",
  "source_format": "nft_log",
  "event_type": "firewall_dropped",
  "attack_category": "inbound_probe",
  "attack_technique": "tcp_syn_probe",
  "severity": "WARNING",
  "confidence": "medium",
  "action": "DROP",
  "verdict": "dropped",
  "direction": "inbound",
  "src_ip": "203.0.113.9",
  "src_port": 45123,
  "dst_ip": "192.168.8.42",
  "dst_port": 23,
  "protocol": "tcp",
  "tcp_flags": ["SYN"],
  "device_ip": "192.168.8.42",
  "asset_role": "iot_device"
}
```

### `attack_evidence_report.json`

`security_events.jsonl` を psad 風に集約した report です。

現在は以下を集計します。

- observed boundary evidence count
- blocked / rejected / dropped count
- accepted / allowed count
- exposed service attempt count
- port scan candidate
- host sweep candidate
- sensitive service probe
- suspicious TCP flags
- unique attack source count
- unique target port count

重要: `attack_evidence_reduction_rate` は「インターネット上の攻撃数が減った」ことを意味しません。外部 scan volume は gateway mitigation で制御できないため、Quarant では observed / blocked / accepted / exposed service attempt を分けて評価します。

### `attack_evidence_eval_report.json`

`attack_evidence_report.json` の finding に人手ラベルを付け、router-boundary detector の説明可能性を評価する report です。Suricata / Zeek / Snort importer を追加したあとも、同じラベル体系で importer 間の evidence quality を比較できます。

まず label template を作ります。

```bash
go run ./cmd/quarant attack-eval \
  --attack-evidence runs/openwrt-001/attack_evidence_report.json \
  --labels runs/openwrt-001/attack_evidence_labels.jsonl \
  --init-labels
```

`attack_evidence_labels.jsonl` の `label` をレビューしてから評価します。

```bash
go run ./cmd/quarant attack-eval \
  --attack-evidence runs/openwrt-001/attack_evidence_report.json \
  --labels runs/openwrt-001/attack_evidence_labels.jsonl \
  --out runs/openwrt-001/attack_evidence_eval_report.json
```

label は以下を想定しています。

- `true_attack`: 保護対象への実攻撃・明確な悪性 probe。
- `scanner_lab_generated`: 実験用 scanner や controlled test traffic。
- `internet_background_noise`: インターネット由来の scan noise。攻撃 traffic ではあり得るが、対象 deployment への targeted attack とは分ける。
- `benign_admin`: 管理者や正常運用由来。
- `unknown` / `unlabeled`: 判定保留。

主な metrics:

- `meaningful_evidence_count` / `meaningful_evidence_rate`: `true_attack` と `scanner_lab_generated` の合計。
- `noise_or_benign_count` / `noise_or_benign_rate`: `internet_background_noise` と `benign_admin` の合計。
- `label_coverage`: finding のうちレビュー済み label が付いた割合。

注意: `meaningful_evidence_rate` は detector の evidence quality を見るための指標で、gateway mitigation が外部 scan volume を減らしたことは意味しません。

## OpenWrt 連携

### setup plan

OpenWrt に IoT network、DHCP/DNS logging、firewall logging を設定するための script を生成します。

```bash
go run ./cmd/quarant openwrt setup-plan \
  --iot-port lan4 \
  --out openwrt-quarant-setup.sh
```

### import

OpenWrt から取得済みの raw log を Quarant 形式に変換します。

```bash
go run ./cmd/quarant openwrt import \
  --dhcp-leases raw/dhcp.leases \
  --dns-log raw/dnsmasq.log \
  --firewall-log raw/firewall.log \
  --conntrack raw/conntrack.txt \
  --out-dir runs/openwrt-001
```

出力:

```text
runs/openwrt-001/events.jsonl
runs/openwrt-001/flows.jsonl
runs/openwrt-001/observations.jsonl
runs/openwrt-001/device_inventory.json
runs/openwrt-001/security_events.jsonl
runs/openwrt-001/attack_evidence_report.json
```

### collect

SSH 経由で OpenWrt から DHCP/DNS/firewall/conntrack を収集し、そのまま import します。

```bash
go run ./cmd/quarant openwrt collect \
  --host root@192.168.50.1 \
  --out-dir runs/openwrt-001
```

## Suricata / Zeek / Snort 連携

### Suricata EVE import

Suricata `eve.json` を Quarant 形式に変換します。`event_type=alert` は `security_events.jsonl` に変換し、`alert.signature_id` / `signature` / `category` / `severity` / `action` / `flow_id` は IDS metadata として保持します。`flow` / `dns` / `http` / `tls` は passive visibility 用に `flows.jsonl` と `observations.jsonl` に変換します。

```bash
go run ./cmd/quarant suricata import \
  --eve raw/eve.json \
  --out-dir runs/suricata-001
```

出力:

```text
runs/suricata-001/security_events.jsonl
runs/suricata-001/attack_evidence_report.json
runs/suricata-001/flows.jsonl
runs/suricata-001/observations.jsonl
```

Suricata alert は precision / mitigation / before-after eval の `--security-events` としてそのまま接続できます。OpenWrt firewall evidence と同じ `security_events.jsonl` に連結すれば、accepted/exposed service attempt と IDS alert の重なりも評価できます。

### Quarant security taxonomy

`security_events.jsonl` には、各 sensor 固有の `attack_category` / `attack_technique` / `sid` / `signature` / `classtype` を残したまま、Quarant 共通語彙として `taxonomy` と `normalized_technique` も追加します。OpenWrt の SYN/FIN/XMAS/port probe、Suricata/Snort の category / classtype / signature を、以下のような横断分類に寄せます。

- `reconnaissance`
- `port_scan`
- `host_sweep`
- `sensitive_service_probe`
- `suspicious_tcp_flags`
- `exploit_attempt`
- `malware_or_c2`
- `dos`
- `policy_violation`
- `ids_alert`

この正規化は説明可能性のための grouping layer であり、侵害を直接証明するものではありません。`attack_evidence_report.json` には `taxonomy_policy` と `taxonomy_counts` が入り、precision incident の detail にも taxonomy が残ります。

default policy は JSON として出力でき、研究 artifact や再現 package に含められます。

```bash
go run ./cmd/quarant taxonomy policy \
  --out taxonomy_policy.json
```

各 importer / assemble / experiment では、必要に応じて `--taxonomy-policy taxonomy_policy.json` を指定できます。指定しない場合は built-in default policy を使います。

taxonomy coverage report は、`security_events.jsonl` から source 別・engine 別・taxonomy 別・normalized technique 別に分類の広がりを集計します。

```bash
go run ./cmd/quarant taxonomy coverage \
  --security-events runs/experiment-001/before/assembled/security_events.jsonl \
  --policy taxonomy_policy.json \
  --out taxonomy_coverage_report.json
```

`taxonomy_coverage_report.json` は classification coverage、generic `ids_alert` fallback-only rate、single taxonomy dominance を含みます。quality gate と research report に接続できます。

### Zeek import

Zeek `conn.log` / `dns.log` / `http.log` / `ssl.log` または `tls.log` を passive observation と flow に変換します。

```bash
go run ./cmd/quarant zeek import \
  --conn raw/conn.log \
  --dns raw/dns.log \
  --http raw/http.log \
  --ssl raw/ssl.log \
  --out-dir runs/zeek-001
```

出力:

```text
runs/zeek-001/flows.jsonl
runs/zeek-001/observations.jsonl
```

Zeek は IDS alert ではなく NSM 証拠として扱います。device behavior、DNS、HTTP host、TLS SNI、external/local connection の補強証拠として precision incident に接続します。

### Snort import

Snort fast alert log または JSONL alert を `security_events.jsonl` に変換します。`sid` / `msg` / `classtype` / `priority` は IDS metadata として保持します。

```bash
go run ./cmd/quarant snort import \
  --alerts raw/alert.fast \
  --rules raw/local.rules \
  --out-dir runs/snort-001
```

`--rules` は複数指定できます。Snort `.rules` から `sid` / `msg` / `classtype` / `priority` / `metadata` / `reference` を読み、alert log に不足している metadata を補完します。出力には `snort_metadata_report.json` も含まれ、`sid` missing、`classtype` missing、metadata enrichment rate、generic `ids_alert` fallback count を確認できます。

Snort JSONL は `src_ip` / `dst_ip` だけでなく、`src_addr` / `dst_addr`、`src_ap` / `dst_ap`、nested `rule.sid` / `rule.classtype` / `rule.priority` も吸収します。fast alert は port なし endpoint と bracketed IPv6 endpoint も parse します。

## Evidence assemble

OpenWrt / Suricata / Zeek / Snort など複数 sensor の run directory を統合し、Quarant の標準入力セットを作ります。

```bash
go run ./cmd/quarant evidence assemble \
  --openwrt runs/openwrt-001 \
  --suricata runs/suricata-001 \
  --zeek runs/zeek-001 \
  --snort runs/snort-001 \
  --out runs/experiment-001
```

出力:

```text
runs/experiment-001/events.jsonl
runs/experiment-001/security_events.jsonl
runs/experiment-001/flows.jsonl
runs/experiment-001/observations.jsonl
runs/experiment-001/attack_evidence_report.json
runs/experiment-001/source_coverage_report.json
runs/experiment-001/taxonomy_coverage_report.json
runs/experiment-001/evidence_manifest.json
```

`source_coverage_report.json` は OpenWrt only / Suricata only / Zeek only / overlap を、device/protocol/port tuple 単位で集計します。研究 report には `--source-coverage` で接続できます。

## Experiment run

raw evidence から paper package までを一括生成します。

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
  --taxonomy-policy taxonomy_policy.json \
  --before-now 2026-09-26T12:30:00Z \
  --after-now 2026-09-26T13:30:00Z \
  --out runs/experiment-001
```

実行内容:

- before / after の OpenWrt、Suricata、Zeek、Snort import
- before / after の evidence assemble
- before window の precision incident
- mitigation plan / gateway backend / dry-run rollback artifacts
- before/after mitigation evaluation
- source coverage 付き research report
- taxonomy coverage 付き research report
- quality gate / guarded research report
- reproducibility package
- `experiment_manifest.json`

## Experiment batch

複数 dataset / 複数 before-after window を一括実行し、研究評価用の横比較 summary を生成します。各 run は `experiment run` と同じ pipeline を使います。

```bash
go run ./cmd/quarant experiment batch \
  --config examples/integrated/experiments.yaml \
  --out runs/batch-001
```

config は小さな YAML subset または JSON で書けます。

```yaml
version: experiment-batch-v1
taxonomy_policy: taxonomy_policy.json
runs:
  - id: integrated-demo
    before_openwrt: examples/integrated/before/openwrt/raw
    before_suricata: examples/integrated/before/suricata/raw/eve.json
    before_zeek: examples/integrated/before/zeek/raw
    before_snort: examples/integrated/before/snort/raw/alert.fast
    after_openwrt: examples/integrated/after/openwrt/raw
    after_suricata: examples/integrated/after/suricata/raw/eve.json
    after_zeek: examples/integrated/after/zeek/raw
    after_snort: examples/integrated/after/snort/raw/alert.fast
    before_now: 2026-09-26T12:30:00Z
    after_now: 2026-09-26T13:30:00Z
```

出力:

```text
runs/batch-001/<run-id>/...
runs/batch-001/batch_summary_report.json
runs/batch-001/batch_summary.csv
```

`batch_summary_report.json` / `batch_summary.csv` は run ごとに incident count、mitigation action count、accepted/exposed reduction、IDS exposed overlap reduction、source coverage、taxonomy coverage、quality gate status をまとめます。

## Coverage figures

source coverage、taxonomy coverage、batch quality を SVG 図として出力します。

```bash
go run ./cmd/quarant coverage figure \
  --source-coverage runs/experiment-001/before/assembled/source_coverage_report.json \
  --taxonomy-coverage runs/experiment-001/before/assembled/taxonomy_coverage_report.json \
  --batch-summary runs/batch-001/batch_summary_report.json \
  --out-dir runs/figures
```

出力:

```text
runs/figures/source_coverage.svg
runs/figures/taxonomy_coverage.svg
runs/figures/batch_quality.svg
```

research package の `figures/` には、source coverage / taxonomy coverage の図も自動で同梱されます。

## Quality gate

研究 claim を言いすぎないための guardrail report を生成します。

```bash
go run ./cmd/quarant quality-gate \
  --experiment runs/experiment-001 \
  --taxonomy-coverage runs/experiment-001/before/assembled/taxonomy_coverage_report.json \
  --out runs/experiment-001/quality_gate_report.json \
  --research-out runs/experiment-001/guarded_research_report.json
```

主な check:

- precision label coverage が十分か。
- attack evidence label coverage が十分か。
- `attack_evidence_reduction_rate` だけで mitigation 効果を主張していないか。
- accepted / exposed service attempt や targeted signal が減っているか。
- IDS alert count を gateway mitigation 効果として扱いすぎていないか。
- normal flow preservation が低くないか。
- source coverage が single-source only になっていないか。
- taxonomy coverage が低すぎないか、IDS alert が generic `ids_alert` のまま粗く残っていないか。

`guarded_research_report.json` には、弱めるべき claim と threats to validity / next steps が反映されます。

## Precision incident

precision report は、passive event、flow、observation、inventory、security event を統合して incident を生成します。

```bash
go run ./cmd/quarant precision \
  --events runs/openwrt-001/events.jsonl \
  --security-events runs/openwrt-001/security_events.jsonl \
  --flows runs/openwrt-001/flows.jsonl \
  --observations runs/openwrt-001/observations.jsonl \
  --inventory runs/openwrt-001/device_inventory.json \
  --out precision_report.json \
  --incidents-out incidents.jsonl
```

`--security-events` を省略した場合は、`events.jsonl` と同じ directory の `security_events.jsonl` を sibling default として読みます。存在しない場合は空として扱います。

現在の attack evidence signal:

- `attack_evidence_inbound_scan`
- `attack_evidence_port_scan`
- `attack_evidence_host_sweep`
- `attack_evidence_sensitive_service_probe`
- `attack_evidence_suspicious_tcp_flags`

単発の DROP/REJECT は background noise として扱い、繰り返し、複数 port、host sweep、sensitive service probe、suspicious TCP flags などで precision signal に昇格します。

## Mitigation plan

precision incident から mitigation plan を作ります。

```bash
go run ./cmd/quarant mitigate \
  --events runs/openwrt-001/events.jsonl \
  --security-events runs/openwrt-001/security_events.jsonl \
  --flows runs/openwrt-001/flows.jsonl \
  --observations runs/openwrt-001/observations.jsonl \
  --inventory runs/openwrt-001/device_inventory.json \
  --out mitigation_plan.json \
  --gateway-out gateway_backend_plan.json \
  --rules-out openwrt_mitigation_dryrun.sh \
  --rollback-out openwrt_mitigation_rollback.sh
```

現在の方針:

- credential/token exposure や plaintext insecure service は、対象 service block を候補にします。
- DROP/REJECT 済みの default deny 証拠だけでは強い mitigation priority にしません。
- blocked boundary evidence のみなら `monitor_only` / default-deny posture confirmed 寄りにします。
- ACCEPT / exposed service attempt がある場合は、inbound exposure review / tighten gateway policy として priority を上げます。
- disruptive な isolation は、人間の review が必要な fallback として扱います。

## Mitigation evaluation

before/after window を比較して、targeted signal、incident score、normal traffic continuity、boundary evidence を評価します。

```bash
go run ./cmd/quarant mitigation-eval \
  --plan mitigation_plan.json \
  --before-events runs/before/events.jsonl \
  --before-security-events runs/before/security_events.jsonl \
  --before-flows runs/before/flows.jsonl \
  --before-observations runs/before/observations.jsonl \
  --before-inventory runs/before/device_inventory.json \
  --after-events runs/after/events.jsonl \
  --after-security-events runs/after/security_events.jsonl \
  --after-flows runs/after/flows.jsonl \
  --after-observations runs/after/observations.jsonl \
  --after-inventory runs/after/device_inventory.json \
  --out mitigation_eval_report.json
```

Boundary evidence metrics は、誤解を避けるため以下に分けています。

- `before_attack_evidence_count` / `after_attack_evidence_count`
- `before_blocked_attack_evidence_count` / `after_blocked_attack_evidence_count`
- `before_accepted_attack_evidence_count` / `after_accepted_attack_evidence_count`
- `before_exposed_service_attempt_count` / `after_exposed_service_attempt_count`
- `before_ids_alert_count` / `after_ids_alert_count`
- `before_ids_exposed_overlap_count` / `after_ids_exposed_overlap_count`
- `accepted_attack_evidence_reduction_rate`
- `exposed_service_attempt_reduction_rate`
- `ids_exposed_overlap_reduction_rate`

注意: observed boundary evidence や IDS alert count が減っても、外部から来る scan volume が mitigation によって減ったとは主張しません。研究上は、accepted/exposed service attempt が減ったか、IDS alert が exposed service attempt と重ならなくなったか、blocked evidence が blocked のまま維持されたか、normal traffic が保たれたかを分けて見ます。

## Research report

precision report、human label による precision eval、mitigation plan、mitigation eval をまとめて研究用 report / Markdown / CSV package を作ります。

```bash
go run ./cmd/quarant research-report \
  --precision precision_report.json \
  --precision-eval precision_eval_report.json \
  --mitigation mitigation_plan.json \
  --mitigation-eval mitigation_eval_report.json \
  --source-coverage source_coverage_report.json \
  --taxonomy-coverage taxonomy_coverage_report.json \
  --out research_report.json
```

research report には、以下の注意を含めています。

- passive monitoring は exploitability、compromise、firmware-level remediation を証明しない。
- before/after window は比較可能である必要がある。
- encrypted traffic や unseen local dependency は残留 risk や normal traffic breakage を隠す可能性がある。
- internet scan volume is not controlled by gateway mitigation.
- router-boundary evidence reduction は accepted/exposed service attempt reduction と分けて解釈する必要がある。

## 参考 OSS から取り込んでいる考え方

### psad 風の考え方

実装済み:

- OpenWrt firewall log を router-boundary evidence として扱う。
- 単発 block は noise 寄りに扱う。
- 同一 source / target / port / time-window 的な集約で、port scan、host sweep、sensitive service probe、suspicious TCP flags を整理する。
- DROP/REJECT と ACCEPT/exposed を分ける。

### Zeek / Suricata / Snort について

実装済み:

- Suricata EVE JSON importer
- Zeek connection/DNS/HTTP/TLS log importer
- Snort alert importer
- evidence assemble CLI
- source coverage report
- research package source coverage table
- taxonomy coverage report / taxonomy policy / research package taxonomy table
- experiment batch runner / batch summary report / batch summary CSV
- coverage figure SVGs for source coverage, taxonomy coverage, and batch quality
- Snort rule metadata enrichment / metadata quality report
- accepted/exposed service attempt と IDS alert overlap の before/after evaluation

今後の想定:

- より多様な Snort unified2 / alert_json variants の importer

Suricata / Snort alert は Quarant native `security_events.jsonl` に変換する adapter、Zeek は `flows.jsonl` / `observations.jsonl` に変換する passive visibility adapter として扱います。

## テスト

全体テスト:

```bash
go test ./...
```

現在のテストでは、以下を確認しています。

- OpenWrt import が `events.jsonl` / `flows.jsonl` / `observations.jsonl` / `device_inventory.json` / `security_events.jsonl` / `attack_evidence_report.json` を生成すること。
- OpenWrt firewall parser が DROP / REJECT / ACCEPT、TCP / UDP、SPT / DPT、TCP flags あり/なしを扱えること。
- attack evidence report が port scan candidate を検出すること。
- attack evidence label/eval が meaningful evidence、internet background noise、benign admin、unlabeled を分けて集計すること。
- Suricata EVE importer が alert metadata を `security_events.jsonl` に保持し、flow / dns / http / tls を passive evidence に変換すること。
- Zeek importer が conn / dns / http / ssl/tls log を flow / observation に変換すること。
- Snort importer が fast alert / JSONL alert を security event に変換し、rule metadata で補完できること。
- evidence assemble が複数 source を merge / dedup し、attack evidence report と source coverage report を生成すること。
- experiment run が integrated demo を raw evidence から research package まで一括生成すること。
- experiment batch が複数 run の summary JSON / CSV を生成すること。
- coverage figure CLI が source / taxonomy / batch の SVG を生成すること。
- quality gate が claim guardrails と guarded research report を生成すること。
- research package が source coverage table を出力すること。
- before/after eval が IDS alert count と exposed service attempt overlap を分けて集計すること。
- security events が precision incident の attack evidence signal に接続されること。
- mitigation / gateway backend / apply report / before-after eval / research report の既存テストが通ること。

