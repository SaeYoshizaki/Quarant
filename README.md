# Quarant

Quarant は、IoT 環境をできるだけ受動的に観測し、観測できた証拠から incident を整理し、ルーター側でできる緩和策を作り、その前後でリスクが本当に下がったかを確認するための研究プロトタイプです。

狙っているのは、IoT デバイスそのものを改造したり、エージェントを入れたりしなくても、ネットワーク境界で見える情報から「何が危ないのか」「どの対策が効きそうか」「対策後に何が変わったのか」を説明できるようにすることです。

現在は、PCAP や flow から得られる IoT の通信だけでなく、OpenWrt の firewall log、Suricata、Zeek、Snort のような既存 OSS の出力も Quarant の evidence として取り込めます。

## 何をするツールか

Quarant の基本的な流れは次の通りです。

```text
passive observation
  -> events / flows / observations / device inventory
  -> precision incident
  -> mitigation plan
  -> OpenWrt gateway plan
  -> before/after evaluation
  -> research report package
```

もう少し具体的には、次のような問いに答えるためのパイプラインです。

- IoT デバイスは、どの外部 host や service と通信しているか。
- Telnet、plain HTTP、露出した admin service のような危険な兆候はあるか。
- WAN 側から IoT デバイスへ scan や probe が届いているか。
- それは firewall で落ちているだけか、それとも ACCEPT されているか。
- IDS alert と router boundary evidence は同じ対象を指しているか。
- 対策後に、accepted / exposed service attempt は減ったか。
- 正常な DNS / DHCP / NTP / cloud 通信は壊れていないか。

## PCAP から機器ごとのリスクを見る

Quarant 独自の解析エンジンは、PCAP（またはライブキャプチャ）から次のものを作ります。

- 機器ごとの識別情報：MAC、OUI ベンダー、DHCP、mDNS、SSDP、DNS
- 平文での認証情報露出、TLS の弱点
- 振る舞い：スキャン、周期通信

各検出結果には、根拠の種類として `basis`（`observed`、`inferred`、`reference_match`）が付きます。

リポジトリには、正解ラベル付きの合成 PCAP（実データを含まない）が同梱されています。

```bash
go run ./cmd/quarant analyze examples/pcap/synthetic-home.pcap --out runs/demo/events.jsonl
go run ./cmd/quarant devices --in runs/demo          # 機器単位のレポート（見えなかったことも表示）
go run ./cmd/quarant label-eval --events runs/demo/events.jsonl \
  --labels examples/pcap/synthetic-home.labels.json  # 正解ラベルとの比較
```

自分のネットワークの PCAP を解析するときは、`--local-net 192.168.1.0/24` のように監視範囲を指定します。

設計、現状、計画は `docs/` にあります。

- [docs/STATUS.md](docs/STATUS.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)
- [docs/AUDIT-2026-10.md](docs/AUDIT-2026-10.md)

## なぜ OSS を取り込むのか

Quarant は研究プロトタイプなので、すべての判定を独自 heuristic だけで作ると、なぜその判断になったのか説明しにくくなります。

そのため、既存の network security tool が長く使ってきた考え方を取り込みます。ただし、Quarant はそれらの OSS を丸ごと置き換えるものでも、単に依存して実行する wrapper でもありません。

主な目的は次の通りです。

- ログ形式や schema を参考にする。
- attack taxonomy や rule metadata を参考にする。
- confidence / severity / priority の考え方を整理する。
- 既存 IDS / NSM が見た evidence を Quarant の incident や mitigation に接続する。
- 研究 report で「どの claim が、どの sensor evidence に支えられているか」を示す。

## OpenWrt を使う理由

OpenWrt は、IoT 環境の gateway として扱いやすく、firewall、DHCP、DNS、conntrack の情報を同じ場所で取れます。

Quarant では OpenWrt を、実際に対策を入れる場所であると同時に、router boundary evidence を取る場所として扱います。

OpenWrt から取りたいものは次です。

- firewall log: WAN から IoT subnet へ来た DROP / REJECT / ACCEPT。
- dnsmasq log: IoT デバイスが問い合わせた domain。
- DHCP lease: IP、MAC、hostname の対応。
- conntrack: 実際に成立している通信の要約。

特に firewall log は重要です。IoT デバイス自身の通信だけを見ていると、「外から攻撃候補が来ていたが、gateway で落ちていた」ことが見えません。OpenWrt の境界ログを入れることで、外部からの scan / probe と、それが blocked だったのか exposed だったのかを分けて扱えます。

## psad の考え方を使う理由

psad は iptables / ip6tables / firewalld のログを見て、port scan、host sweep、怪しい TCP flag などを検出する軽量 IDS です。

Quarant では psad を直接組み込むというより、次の考え方を参考にしています。

- 単発の DROP だけでは強い attack claim にしない。
- 同じ送信元が同じ宛先の複数 port を叩く場合は port scan 候補として扱う。
- 同じ送信元が複数 host に同じような probe を送る場合は host sweep 候補として扱う。
- SYN だけでなく FIN / NULL / XMAS のような TCP flag pattern を分ける。
- firewall action を evidence の一部として扱い、DROP 済みと ACCEPT 済みを同列にしない。

これにより、Quarant の `security_events.jsonl` と `attack_evidence_report.json` は、ただのログ変換ではなく、scan / sweep / suspicious flags という説明しやすい単位で整理されます。

## Suricata を使う理由

Suricata は IDS / IPS / NSM エンジンで、EVE JSON という構造化ログを出せます。

Quarant では Suricata を、既存 IDS が検出した攻撃証拠を取り込むための入力元として扱います。

現在の importer は、主に次を変換します。

- `event_type=alert`
- `signature`
- `signature_id`
- `category`
- `severity`
- `src_ip`
- `dest_ip`
- `dest_port`
- `proto`
- `flow_id`
- `alert.action`

Suricata alert は `security_events.jsonl` に入り、OpenWrt firewall evidence と同じ形式で扱えます。これにより、例えば「OpenWrt では ACCEPT されていた inbound attempt があり、同じ target/service に Suricata alert も出ている」という重なりを before/after evaluation で見られます。

この overlap は、単なる alert count よりも研究上使いやすい指標です。IDS alert が減っただけでは、攻撃量が減ったのか、観測条件が変わったのか分かりません。一方で、accepted / exposed service attempt と IDS alert が同じ対象に重なっている場合は、gateway mitigation の優先度を上げる根拠になります。

## Zeek を使う理由

Zeek は IDS alert を出すためだけのツールではなく、通信を調査しやすいログに変換する Network Security Monitor です。

Quarant では Zeek を、IoT デバイスの通常通信や周辺文脈を補強する passive evidence として扱います。

現在の importer は、次の Zeek log を `flows.jsonl` と `observations.jsonl` に変換します。

- `conn.log`
- `dns.log`
- `http.log`
- `ssl.log` / `tls.log`

Zeek の役割は、攻撃を断定することではありません。むしろ、次のような確認に使います。

- 対象 IoT が普段どの外部 service と通信しているか。
- DNS、HTTP host、TLS SNI から通信先の文脈が分かるか。
- mitigation 後も正常な cloud / NTP / DNS 通信が残っているか。
- IDS alert や firewall evidence に対応する flow があるか。

つまり Zeek は、Quarant にとって「攻撃検出器」よりも「観測の解像度を上げるための NSM evidence」です。

## Snort を使う理由

Snort は長く使われている rule-based IDS / IPS です。

Quarant では Snort を、攻撃分類や rule metadata の考え方を取り込むために使います。Suricata と同じように alert を `security_events.jsonl` に変換できますが、特に Snort では rule 側の情報が重要です。

現在の importer は、fast alert log と JSONL alert を読みます。また `.rules` を渡すと、alert log に不足している metadata を補完します。

取り込む主な情報は次です。

- `sid`
- `msg`
- `classtype`
- `priority`
- `metadata`
- `reference`
- `rev`

これにより、alert が単なる文字列ではなく、どの rule family や classification に属するかを Quarant 側で説明できます。研究 report では、generic な `ids_alert` のまま残っている割合も確認できます。

## Quarant の共通 security event

OpenWrt、Suricata、Snort はそれぞれ別の形式で evidence を出します。Quarant では、それらを `security_events.jsonl` に寄せます。

例:

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
  "asset_role": "iot_device",
  "taxonomy": ["reconnaissance", "port_scan", "sensitive_service_probe"],
  "normalized_technique": "port_scan"
}
```

IDS 由来の event では、次の metadata も保持します。

- `sid`
- `signature`
- `classtype`
- `priority`
- `engine`
- `rule_source`
- `flow_id`
- `alert_action`

## Taxonomy normalization

各 sensor の表現はばらばらです。OpenWrt は `DROP` や `DPT=23` のような firewall log、Suricata は `category` や `signature`、Snort は `classtype` や `sid` を持ちます。

Quarant では、それらを残したまま、研究 report で比較しやすい共通分類も付けます。

現在の主な taxonomy は次です。

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

この正規化は、侵害を証明するためのものではありません。複数 sensor の evidence を同じ表で比較し、「この incident はどの種類の証拠で支えられているか」を説明するための grouping layer です。

default policy は JSON として出力できます。

```bash
go run ./cmd/quarant taxonomy policy \
  --out taxonomy_policy.json
```

taxonomy coverage も確認できます。

```bash
go run ./cmd/quarant taxonomy coverage \
  --security-events runs/experiment-001/before/assembled/security_events.jsonl \
  --policy taxonomy_policy.json \
  --out taxonomy_coverage_report.json
```

## 重要な評価方針

Quarant では、境界で観測した攻撃証拠を次のように分けます。

- `observed`: 観測された security event 全体。
- `blocked`: DROP / REJECT など、gateway で止まった evidence。
- `accepted`: ACCEPT された inbound evidence。
- `exposed_service_attempt`: 保護対象 service に到達した、または到達し得る evidence。
- `ids_alert`: Suricata / Snort など IDS が出した alert。
- `ids_exposed_overlap`: accepted / exposed service attempt と IDS alert が同じ target/service に重なる evidence。

ここはとても重要です。`attack_evidence_reduction_rate` は「インターネットから来る攻撃数が減った」という意味ではありません。外部 scan volume は gateway mitigation では制御できません。

研究上見るべきなのは、主に次です。

- accepted attack evidence が減ったか。
- exposed service attempt が減ったか。
- IDS alert と exposed service attempt の overlap が減ったか。
- blocked evidence は blocked のまま維持されているか。
- 正常通信は維持されているか。

DROP 済みの default deny evidence だけで mitigation priority を強く上げないようにしています。DROP だけなら `monitor_only` や posture confirmed に近い扱いです。ACCEPT や exposed service attempt、IDS overlap がある場合に優先度を上げます。

## 主な出力

Quarant の代表的な出力は次です。

- `events.jsonl`: Quarant の rule event。plain HTTP、Telnet、credential/token exposure、OpenWrt firewall block など。
- `flows.jsonl`: 通信 flow の要約。IP、port、protocol、direction、observed destination など。
- `observations.jsonl`: DNS、HTTP host、TLS SNI、flow snapshot などの passive observation。
- `device_inventory.json`: DHCP lease、hostname、MAC、観測 port / protocol / host など。
- `security_events.jsonl`: OpenWrt / Suricata / Snort 由来の security evidence。
- `attack_evidence_report.json`: scan / sweep / sensitive service probe / TCP flags などの集約 report。
- `source_coverage_report.json`: OpenWrt only / Suricata only / Zeek only / overlap の集計。
- `taxonomy_coverage_report.json`: taxonomy の分類 coverage と fallback 状況。
- `precision_report.json`: incident の整理結果。
- `mitigation_plan.json`: 緩和候補。
- `mitigation_eval_report.json`: before/after 評価。
- `research_report.json`: 研究用 summary。

## 最小 demo

OpenWrt 境界証拠の最小 fixture は `examples/openwrt/` にあります。

```bash
go run ./cmd/quarant openwrt import \
  --dhcp-leases examples/openwrt/before/raw/dhcp.leases \
  --dns-log examples/openwrt/before/raw/dnsmasq.log \
  --firewall-log examples/openwrt/before/raw/firewall.log \
  --conntrack examples/openwrt/before/raw/conntrack.txt \
  --out-dir runs/openwrt-demo/before
```

before / after までまとめて見る場合は、integrated demo を使います。

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
  --out runs/experiment-001
```

この command は、import、evidence assemble、precision、mitigation、before/after evaluation、quality gate、research package までを一括で実行します。

## Docker OpenWrt-compatible lab

実機 OpenWrt の前段階として、Docker で OpenWrt fw4 / nftables 互換の raw firewall log を生成できます。

```bash
cd evaluation/docker-openwrt-lab
docker compose up --abort-on-container-exit
```

生成された before / after log は、Quarant の experiment pipeline に渡せます。

```bash
go run ./cmd/quarant experiment run \
  --before-openwrt evaluation/docker-openwrt-lab/out/before/openwrt/raw \
  --after-openwrt evaluation/docker-openwrt-lab/out/after/openwrt/raw \
  --before-now 2026-09-26T12:30:00Z \
  --after-now 2026-09-26T13:30:00Z \
  --out runs/docker-openwrt-lab
```

この lab は実機評価の代替ではありません。controlled dataset / regression 用です。before/after で scan volume は維持し、ACCEPT / exposed service attempt が DROP / REJECT に寄るかを確認するために使います。

## OpenWrt commands

OpenWrt に IoT network、DHCP/DNS logging、firewall logging を設定するための plan script を生成できます。

```bash
go run ./cmd/quarant openwrt setup-plan \
  --iot-port lan4 \
  --out openwrt-quarant-setup.sh
```

取得済みの raw log を import します。

```bash
go run ./cmd/quarant openwrt import \
  --dhcp-leases raw/dhcp.leases \
  --dns-log raw/dnsmasq.log \
  --firewall-log raw/firewall.log \
  --conntrack raw/conntrack.txt \
  --out-dir runs/openwrt-001
```

SSH 経由で OpenWrt から収集して、そのまま import することもできます。

```bash
go run ./cmd/quarant openwrt collect \
  --host root@192.168.50.1 \
  --out-dir runs/openwrt-001
```

## Suricata / Zeek / Snort commands

Suricata EVE JSON:

```bash
go run ./cmd/quarant suricata import \
  --eve raw/eve.json \
  --out-dir runs/suricata-001
```

Zeek logs:

```bash
go run ./cmd/quarant zeek import \
  --conn raw/conn.log \
  --dns raw/dns.log \
  --http raw/http.log \
  --ssl raw/ssl.log \
  --out-dir runs/zeek-001
```

Snort alert:

```bash
go run ./cmd/quarant snort import \
  --alerts raw/alert.fast \
  --rules raw/local.rules \
  --out-dir runs/snort-001
```

## Evidence assemble

複数 sensor の出力を統合するには `evidence assemble` を使います。

```bash
go run ./cmd/quarant evidence assemble \
  --openwrt runs/openwrt-001 \
  --suricata runs/suricata-001 \
  --zeek runs/zeek-001 \
  --snort runs/snort-001 \
  --out runs/assembled-001
```

出力には、merged evidence のほか、source coverage、taxonomy coverage、evidence manifest が含まれます。

## Experiment batch

複数 dataset / 複数 before-after window をまとめて実行する場合は batch を使います。

```bash
go run ./cmd/quarant experiment batch \
  --config examples/integrated/experiments.yaml \
  --out runs/batch-001
```

`batch_summary_report.json` と `batch_summary.csv` には、run ごとの incident count、mitigation action count、accepted/exposed reduction、IDS exposed overlap reduction、source coverage、taxonomy coverage、quality gate status が入ります。

## Quality gate

研究 claim を言いすぎないために、quality gate を用意しています。

```bash
go run ./cmd/quarant quality-gate \
  --experiment runs/experiment-001 \
  --taxonomy-coverage runs/experiment-001/before/assembled/taxonomy_coverage_report.json \
  --out runs/experiment-001/quality_gate_report.json \
  --research-out runs/experiment-001/guarded_research_report.json
```

主な check は次です。

- precision label coverage が十分か。
- attack evidence label coverage が十分か。
- `attack_evidence_reduction_rate` だけで mitigation 効果を主張していないか。
- accepted / exposed service attempt が減っているか。
- IDS alert count を gateway mitigation 効果として扱いすぎていないか。
- normal flow preservation が低くないか。
- source coverage が single-source only に偏っていないか。
- taxonomy coverage が低すぎないか。
- IDS alert が generic `ids_alert` のまま粗く残っていないか。

## Research report

研究用 report は、precision、human label eval、mitigation plan、before/after eval、source coverage、taxonomy coverage をまとめます。

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

report には、次の limitation を明示します。

- passive monitoring は exploitability、compromise、firmware-level remediation を証明しない。
- before/after window は比較可能である必要がある。
- encrypted traffic や unseen local dependency は残留 risk や normal traffic breakage を隠す可能性がある。
- internet scan volume is not controlled by gateway mitigation.
- router-boundary evidence reduction は accepted/exposed service attempt reduction と分けて解釈する必要がある。

## 現在できていること

- OpenWrt firewall / dnsmasq / DHCP / conntrack import。
- OpenWrt 境界証拠から `security_events.jsonl` と `attack_evidence_report.json` を生成。
- psad 風の port scan / host sweep / sensitive service probe / suspicious TCP flags 集約。
- Suricata EVE `alert / flow / dns / http / tls` import。
- Zeek `conn / dns / http / ssl/tls` import。
- Snort fast alert / JSONL alert import。
- Snort rule metadata enrichment。
- OpenWrt / Suricata / Zeek / Snort の evidence assemble。
- source coverage report。
- taxonomy normalization と taxonomy coverage report。
- precision incident への attack evidence 接続。
- mitigation priority への accepted/exposed/IDS overlap 反映。
- before/after mitigation evaluation。
- quality gate。
- research package。
- Docker OpenWrt-compatible lab。

## まだ研究評価として足りないこと

Docker lab と fixture は、pipeline の再現性確認には使えます。ただし、実機評価の代替にはなりません。

次に必要なのは、Raspberry Pi、mini PC、または OpenWrt router を使った小規模な実験環境です。

確認したいことは次です。

- 実 IoT device の通常通信を gateway で正しく観測できるか。
- 実 OpenWrt の `logread`、fw4、nftables prefix、interface 名の揺れを importer が扱えるか。
- mitigation 後に IoT の正常通信が壊れないか。
- firewall log、conntrack、dnsmasq、Zeek、Suricata を同じ時間窓で収集できるか。
- benign admin traffic、internet background noise、lab-generated scan、true attack をラベル分けできるか。

## テスト

全体テスト:

```bash
go test ./...
```

現在のテストでは、主に次を確認しています。

- OpenWrt parser が DROP / REJECT / ACCEPT、TCP / UDP、SPT / DPT、TCP flags あり/なしを扱えること。
- OpenWrt import が events / flows / observations / inventory / security events / attack evidence report を生成すること。
- attack evidence report が port scan、sensitive service probe、suspicious TCP flags を検出すること。
- attack evidence eval が meaningful evidence、internet background noise、benign admin、unlabeled を分けること。
- Suricata importer が IDS metadata と passive evidence を保持すること。
- Zeek importer が flow / observation を生成すること。
- Snort importer が fast alert / JSONL / IPv6 / rule metadata enrichment を扱うこと。
- evidence assemble が merge / dedup と coverage report を生成すること。
- taxonomy normalization と taxonomy coverage が動くこと。
- experiment run / batch が integrated demo から research package まで生成すること。
- mitigation eval が observed / blocked / accepted / exposed / IDS overlap を分けること。
- quality gate が claim guardrails を生成すること。
