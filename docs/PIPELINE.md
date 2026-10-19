# 外部ログの取り込みと緩和策の評価パイプライン

OpenWrt、Suricata、Zeek、Snort の出力を取り込み、インシデントの整理、緩和策の作成、前後比較を行う仕組みです。研究の中心は README の問いですが、この仕組みも Quarant の一部として維持しています。コマンドは [COMMANDS.md](COMMANDS.md) にまとめています。

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

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：Taxonomy normalization」。

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

taxonomy coverage も確認できます。

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
- `findings.json`: `events.jsonl` の要約。機器 × イベントの種類（finding）と、同じ観測事実を言い換えたイベントをまとめた機器 × 状態（condition）。
- `security_events.jsonl`: OpenWrt / Suricata / Snort 由来の security evidence。
- `attack_evidence_report.json`: scan / sweep / sensitive service probe / TCP flags などの集約 report。
- `source_coverage_report.json`: OpenWrt only / Suricata only / Zeek only / overlap の集計。
- `taxonomy_coverage_report.json`: taxonomy の分類 coverage と fallback 状況。
- `precision_report.json`: incident の整理結果。
- `mitigation_plan.json`: 緩和候補。
- `mitigation_eval_report.json`: before/after 評価。
- `research_report.json`: 研究用 summary。

## 最小 demo

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：最小 demo」。

OpenWrt 境界証拠の最小 fixture は `examples/openwrt/` にあります。

before / after までまとめて見る場合は、integrated demo を使います。

この command は、import、evidence assemble、precision、mitigation、before/after evaluation、quality gate、research package までを一括で実行します。

## Docker OpenWrt-compatible lab

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：Docker OpenWrt-compatible lab」。

実機 OpenWrt の前段階として、Docker で OpenWrt fw4 / nftables 互換の raw firewall log を生成できます。

生成された before / after log は、Quarant の experiment pipeline に渡せます。

この lab は実機評価の代替ではありません。controlled dataset / regression 用です。before/after で scan volume は維持し、ACCEPT / exposed service attempt が DROP / REJECT に寄るかを確認するために使います。

## OpenWrt commands

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：OpenWrt commands」。

OpenWrt に IoT network、DHCP/DNS logging、firewall logging を設定するための plan script を生成できます。

取得済みの raw log を import します。

SSH 経由で OpenWrt から収集して、そのまま import することもできます。

## Suricata / Zeek / Snort commands

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：Suricata / Zeek / Snort commands」。

Suricata EVE JSON:

Zeek logs:

Snort alert:

## Evidence assemble

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：Evidence assemble」。

複数 sensor の出力を統合するには `evidence assemble` を使います。

出力には、merged evidence のほか、source coverage、taxonomy coverage、evidence manifest が含まれます。

## Experiment batch

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：Experiment batch」。

複数 dataset / 複数 before-after window をまとめて実行する場合は batch を使います。

`batch_summary_report.json` と `batch_summary.csv` には、run ごとの incident count、mitigation action count、accepted/exposed reduction、IDS exposed overlap reduction、source coverage、taxonomy coverage、quality gate status が入ります。

## Quality gate

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：Quality gate」。

研究 claim を言いすぎないために、quality gate を用意しています。

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

コマンドは [COMMANDS.md](COMMANDS.md) の「外部ログのパイプライン：Research report」。

研究用 report は、precision、human label eval、mitigation plan、before/after eval、source coverage、taxonomy coverage をまとめます。

report には、次の limitation を明示します。

- passive monitoring は exploitability、compromise、firmware-level remediation を証明しない。
- before/after window は比較可能である必要がある。
- encrypted traffic や unseen local dependency は残留 risk や normal traffic breakage を隠す可能性がある。
- internet scan volume is not controlled by gateway mitigation.
- router-boundary evidence reduction は accepted/exposed service attempt reduction と分けて解釈する必要がある。
