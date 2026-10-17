# 検出の仕様（振る舞い検知と根拠の種類）

## 根拠の種類（`basis`）

| 値 | 意味 | 例 |
|---|---|---|
| `observed` | 検出のきっかけそのものが通信に現れていた。リスクの解釈は別。 | `INSECURE_HTTP_AUTH`、`I7_TLS_WEAK_VERSION_OBSERVED`、`IP_MAC_BINDING_CHANGED` |
| `inferred` | ヒューリスティック、ポート番号による推定、統計、カテゴリ方針による判断 | `I2_*_SERVICE_OBSERVED`（ポート番号のみ）、`OUTBOUND_SCAN_SUSPECTED`、I6 |
| `reference_match` | 外部や知識 DB との照合。正確さと適用可否は参照データに依存する | `I5_KNOWN_VULNERABLE_COMPONENT`、`I3_UNEXPECTED_CLOUD_ENDPOINT`、MAC ベンダー |

イベント型との対応は `analyzer/basis.go` にある。識別情報（`identity_evidence`）にも同じ値を使う。

## 振る舞い検知（`analyzer/behavior`）

**入力**：終了したローカル発の TCP フロー。1 フローを 1 件の接続試行として扱う。

**応答あり（answered）の定義**：相手が SYN/ACK かペイロードを返したこと。RST だけでは応答なしとみなす。

| 検出 | 条件（既定値） | 重大度 |
|---|---|---|
| `OUTBOUND_SCAN_SUSPECTED`、`LATERAL_SCAN_SUSPECTED`（横方向） | 同じポートについて、60 秒の窓内に異なる宛先が 20 以上あり、未応答率が 0.7 以上。宛先の過半がローカルなら LATERAL | HIGH。宛先 60 以上かつ未応答率 0.9 以上なら確信度 high |
| `PORT_SCAN_SUSPECTED`、`LATERAL_SCAN_SUSPECTED`（縦方向） | 同じ宛先について、60 秒の窓内に異なるポートが 20 以上あり、未応答率が 0.7 以上 | HIGH |
| `PERSISTENT_CONNECTION_ATTEMPTS` | 同じ外部の宛先（IP、ポート、プロトコル）に、1 時間の窓内で 30 回以上の接続試行がある。応答の有無は問わない | INFO。文脈フラグが 2 つ以上なら WARNING |
| `IP_MAC_BINDING_CHANGED` | ローカル IP の MAC が、直前の MAC から切り替わった（Ethernet、ARP、DHCP のいずれかで観測）。同じ組み合わせは 10 分に 1 回まで報告する | WARNING |
| `PERIODIC_COMMUNICATION_OBSERVED` | 同じ宛先（DNS 名または IP）、ポート、プロトコルへの応答ありの接続が 8 回以上あり、間隔の中央値が 10 秒以上で、MAD を中央値で割った値が 0.1 以下 | INFO。文脈フラグが 2 つ以上なら WARNING |

周期通信の文脈フラグ：

- `direct_ip_no_dns_observed`：DNS で名前を解決せずに外部 IP へ接続している。
- `plaintext_protocol`：平文のプロトコルを使っている。
- `non_standard_port`：443、8883、123 以外のポートを使っている。

執拗な接続試行の文脈フラグ：

- `direct_ip_no_dns_observed`
- `non_standard_port`（53、80、123、443、8883 以外）
- `mostly_unanswered`（未応答率 0.5 以上）

しきい値の 30 回／時は、UNSW の正常データ 1 日分の分布から決めた。外部の宛先 535 件のうち、30 回以上だったのは 7 件で、いずれも WARNING の条件を満たさなかった。詳しくは [EXPERIMENTS.md](EXPERIMENTS.md) E1 を参照。

**評価のタイミング**：キャプチャ時刻で 5 分ごとと、入力の終わり。同じ所見は 2 回報告しない。

**限界**

- 周期通信は、正常なテレメトリとマルウェアのビーコンを区別できない。
- スキャンに見える通信には、設定ミスや正規の探索ツールによるものもある。
- UDP は対象外（未実装）。

## 機器識別（`analyzer/discovery`）

| 属性 | 出典 | 根拠の種類 | 注意点 |
|---|---|---|---|
| `mac` | Ethernet、ARP、DHCP | observed | MAC を信用するのは、送信元 IP がローカルのフレームだけ。ルーティングされたフレームの送信元 MAC はルーターのもの |
| `mac_vendor` | IEEE MA-L（`knowledge/oui_ma_l.tsv`） | reference_match | ローカル管理（ランダム化）の MAC にはベンダーを付けない |
| `hostname` | DHCP option 12、mDNS | observed | 機器自身が名乗った名前なので、偽装できる |
| `dhcp_vendor_class`、`dhcp_param_request_list` | DHCP option 60、55 | observed | option 55 の並び順は、受動的な OS／機器の指紋として知られている |
| `mdns_*`、`ssdp_*` | mDNS の応答、SSDP の NOTIFY と応答 | observed | |

## 機器についての判断の重複抑制

次のイベントは、フローではなく機器についての判断なので、機器と照合先の組み合わせごとに 1 回だけ出す（`analyzer/basis.go` の `deviceScopedTypes`）。

- I5 と I4_I5 の知識 DB との照合
- 更新の可視性
- R1 の複合リスク
- 想定外の SNI やクラウド接続先

I5 の照合は、OUI のベンダーとファミリーのベンダーが矛盾する場合には出さない。宛先から推定したファミリーは、連携先のクラウドを機器自身と取り違えることがあるため（例：Echo→meethue.com）。Wi-Fi モジュールの製造元は、矛盾の判断に使わない。
