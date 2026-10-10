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

## Suricata / Zeek 連携

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
- accepted/exposed service attempt と IDS alert overlap の before/after evaluation

今後の想定:

- Snort alert metadata importer
- Snort の `sid` / `msg` / `classtype` / `priority` 風 metadata の security event への対応

Suricata alert は Quarant native `security_events.jsonl` に変換する adapter、Zeek は `flows.jsonl` / `observations.jsonl` に変換する passive visibility adapter として扱います。

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
- before/after eval が IDS alert count と exposed service attempt overlap を分けて集計すること。
- security events が precision incident の attack evidence signal に接続されること。
- mitigation / gateway backend / apply report / before-after eval / research report の既存テストが通ること。

