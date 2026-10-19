# Quarant アーキテクチャ

この文書は、これから作る構成（目標）が中心。今の仕組みは [DESIGN.md](DESIGN.md)。

## 1. 研究上の問いと設計原則

**問い**：家庭内 IoT 機器の通信を受動的に観測するだけで、セキュリティリスクをどこまで把握できるか。何が検出でき、何が検出できないか。

設計原則（これに反する変更をするときは、先に議論すること）：

1. **パッシブ監視**
   - 監視対象の機器へパケットを送らない。スキャン、認証試行、通信の改変、TLS の復号はしない。
   - 能動的な検査は、利用者が明示的に許可した場合だけ実行する別機能として扱う。
2. **根拠の種類を区別する**
   - すべての検出結果に `basis` を付ける。値は `observed`（観測事実）、`inferred`（観測からの推定）、`reference_match`（外部・知識 DB との照合）のいずれか。
   - あわせて `observed_fact`、`inference`、`limitation`、`confidence`、`evidence` を持たせる。
3. **未検出は安全の証明ではない**
   - 機器ごとのレポートに「見えなかったこと（visibility limits）」を必ず出す。
4. **根拠のない数値スコアを新たに作らない**
   - 重大度と根拠の種類ごとの件数を示し、評価基準を文書化する。
5. **既存ツールを活かす**
   - Zeek、Suricata などが得意な部分は取り込み（importer）で連携する。
   - 独自に実装するのは、研究上の価値がある部分に限る：機器への帰属、根拠の区別、相関、可視性の評価、IoT 特有の判定。
6. **オフライン解析を先に固める**
   - PCAP やログによる再現可能な解析を基盤にする。ライブ解析も同じ処理経路を通す。

## 2. 全体構成（目標）

```text
                Internet
                    |
          +-------------------+
          |  OpenWrt ルーター  |  収集のみ（軽量）
          |  - tcpdump/ring   |  - IoT 用 VLAN / SSID
          |  - fw4 log        |  - dnsmasq log, DHCP lease
          |  - conntrack      |  - (任意) softflowd/NetFlow
          +---------+---------+
                    | ミラー（ポートミラー / tee）+ ssh によるログ収集
                    v
     +--------------------------------------------+
     | 解析ホスト（Raspberry Pi 5 / ミニPC）        |
     |                                            |
     |  capture --> PCAP リングバッファ（保存期間設定）|
     |      |                                     |
     |      +--> quarant analyze/live (Go)        |  独自エンジン
     |      +--> Zeek  (任意)  -> zeek import     |  NSM ログ
     |      +--> Suricata (任意) -> suricata import|  IDS シグネチャ
     |                                            |
     |  evidence assemble  -> 統合 evidence        |
     |  correlate (Phase 2) -> 機器単位の相関       |
     |  threat-intel (Phase 2, ローカル照合)        |
     |  baseline/anomaly (Phase 3)                |
     |                                            |
     |  storage: JSONL/JSON（現在）-> SQLite（Phase 2） |
     |  viewer: ローカル API + Web UI (127.0.0.1)   |
     +--------------------------------------------+
```

### OpenWrt との連携

- **ルーターの役割は収集だけ**にする。
  - 理由：一般的な OpenWrt 機は CPU とメモリが限られ、Zeek や Suricata を常時動かすのは難しい。
  - 収集の手段：
    1. ポートミラー（DSA スイッチのミラー、または `tc mirred`）で解析ホストへ複製する。
    2. `tcpdump -w -` を ssh 経由で流し、`quarant analyze -` が標準入力から読む（実装済み）。
    3. 既存の `openwrt collect` による firewall、dnsmasq、DHCP、conntrack ログの取得（実装済み、読み取り専用のコマンドのみ）。
- **観測できない範囲がある**：
  - 同じ Wi-Fi の機器どうしの通信（AP 内でブリッジされる）
  - 同じスイッチ配下の機器どうしの通信
  - Bluetooth、Zigbee、Thread

  これらは前提として「見えない」。緩和策は、IoT 用 SSID や VLAN に分離して通信を必ずルーターを経由させる構成（client isolation と L3 ルーティング）。その場合も、分離しないときに見えない範囲を文書で明示する。
- **観測範囲の評価（Phase 3）**：
  - パケット欠落：`pcap` の統計（`ps_drop`、`ps_ifdrop`）と、ルーター側 conntrack の件数との比較で推定する。
  - 観測範囲：DHCP lease にあるのに通信が観測されない機器の割合で推定する。

### 技術の選定

| 技術 | 判断 | 理由 |
|---|---|---|
| gopacket（独自エンジン） | 中核 | 機器単位の帰属、IoT プロトコルの判定、根拠の区別を自分で制御できる。依存が軽く、ARM でも動く |
| Zeek | 任意で連携（取り込み済み） | conn、dns、http、ssl のログが標準的で、比較実験の基準になる。常時稼働はミニPC 以上が前提 |
| Suricata | 任意で連携（取り込み済み） | ET Open などのシグネチャによる既知攻撃の検出は、独自に作り直す意味がない。Pi 5 なら低帯域で動作できる見込み（要実測） |
| Snort | 取り込みのみ維持 | Suricata と役割が重なる。新規に導入しない |
| psad | 考え方のみ採用（実装済み） | firewall ログからの scan／sweep 集約を参考にした |
| RITA | 採用しない（Phase 3 で再検討） | beacon 検知は独自の説明可能な実装（`analyzer/behavior`）で行う。比較対象として使う価値はある |
| ntopng、Arkime | 採用しない | 可視化や全パケット保存は便利だが、研究の問いへの寄与が小さく、資源消費が大きい。PCAP リングと Wireshark で代わりになる |
| nDPI | Phase 2 で検討 | ポート番号に頼らないプロトコル識別は有用。cgo 依存になるため、効果を測ってから決める |
| YARA、ClamAV | 採用しない | ペイロードやファイルのマルウェア検査。平文で転送されたファイルの抽出が前提で、IoT ではまれ。パッシブ監視の範囲外とする |
| 脅威情報 | Phase 2 | 一括でダウンロードしてローカルで照合する。観測データを外部に送らない（下記） |

### 脅威情報の方針（Phase 2）

- **ローカルで照合する**：観測した IP やドメインを 1 件ずつ外部 API に問い合わせない。問い合わせ自体が利用者の通信内容を外部に漏らすため。
- **フィードの取得**：公開フィード（abuse.ch の ThreatFox、URLhaus など）を一括で取得し、ローカルで照合する。
- **API キー**：環境変数で渡し、リポジトリには保存しない。
- **記録する項目**：取得時刻、フィード名、IOC の初出と最終確認の時刻。古い IOC は確信度を下げる。
- **照合結果の扱い**：照合結果は `basis=reference_match` で、「感染の確定」とは表現しない。
- **要確認**：各サービスの API 仕様、利用規約、レート制限、更新頻度は Phase 2 着手時に一次情報で確認する（まだ確認していない）。

### CVE との関連付けの方針

- 「関連する CVE が存在する」と「この機器が脆弱である」を区別する。
  - 型番やファームウェアのバージョンが観測されなければ、`applicability=unconfirmed` とする。
  - 重大度は WARNING を上限とする（実装済み。I5 と I4_I5 を参照）。
- NVD、CISA KEV、EPSS は Phase 2 で取り込む。SBOM がない前提での限界は、レポートの visibility limits に出す。

## 3. 現在のコード構成

| パッケージ | 責務 |
|---|---|
| `analyzer` | パケットからイベント、フロー、観測、インベントリを作る。`Engine`（入力）、`FlowHandler`（処理）、`LocalNetworks`（監視範囲）、`basis.go`（根拠の分類） |
| `analyzer/rules` | フロー単位の検出ルール（プロトコル解析を含む） |
| `analyzer/discovery` | MAC／OUI、DHCP、mDNS、SSDP からの識別ヒント（純粋関数） |
| `analyzer/behavior` | 多数の接続をまたぐ振る舞い検知（スキャン、周期通信） |
| `analyzer/device` | 端末プロファイル、識別の根拠、インベントリ |
| `analyzer/knowledge` + `knowledge/` | 知識ベース（`go:embed` で組み込み。`QUARANT_KNOWLEDGE_DIR` で差し替え可能） |
| `internal/synth` | 正解ラベル付きの合成トラフィックの生成 |
| `internal/labeleval` | 正解ラベルとイベントの突き合わせ |
| `internal/devicereport` | 機器単位のレポート |
| `internal/reportapi` | 取り込み後の分析（インシデント、緩和、評価、研究レポート） |
| `internal/viewer` | ローカル API（loopback のみ許可、DNS リバインディング対策） |
| `cmd/quarant` | CLI と、外部ログの取り込み |

**処理の流れ（PCAP）**：`Engine` がパケットをキャプチャ時刻つきで `FlowHandler.HandlePacket` に渡す。

1. L2 の処理：MAC と IP の対応づけ（ARP と Ethernet）。同じ MAC のプロファイルは、名乗り（DHCP、mDNS、SSDP）を共有する。`--identity-state` で、名乗りを解析をまたいで引き継げる（D22）。
2. UDP の処理：DHCP、mDNS、SSDP、DNS（クエリと応答）の識別、活動の記録。
3. TCP の処理：
   - フロー状態を更新する。TLS は内容でも判定する。
   - ペイロードを方向ごとにシーケンス番号の順に組み立て（`analyzer/reassembly.go`）、16KB まで蓄積する。
   - 新しい情報があるパケットだけで `rules.Run` を実行する。
   - 検出結果を端末に帰属させ、`basis` を付けて出力する。
4. フローが終了、アイドル化、または入力が終わったとき：最終レコードを書き出し、`behavior` に渡す。
5. 振る舞い検知：キャプチャ時刻で 5 分ごとと、入力の終わりに評価する。
6. 解析の終わりに、`internal/findings` が `events.jsonl` を機器 × 状態にまとめて `findings.json` に書く（D19）。

### 今後の構造変更（予定）

- **ストレージ**：JSONL から SQLite に移す（Phase 2）。
  - 理由：時系列比較、機器ごとの検索、保存期間の管理が必要になるため。
  - JSONL は交換形式として残す。
- **importer の分離**：`cmd/quarant` の取り込み処理を `internal/importers/...` に分け、相関エンジンから再利用できるようにする（Phase 2）。
- **reportapi の分割**：`precision` と `mitigation` を責務ごとに分ける。共通の JSONL リーダーを作る。
- **相関**（6.1）：機器 × 時間窓 × 宛先を単位に、独自エンジン、IDS、Zeek、脅威情報の検出をまとめて「状況」にする（Phase 2）。

## 4. データの取り扱い

- **保存しないもの**：
  - 認証情報はイベントに保存しない（すべて `***` でマスクする）。
  - デバッグ出力にも生のペイロードを書かない。
- **PCAP**：`.gitignore` で除外する。リポジトリに含めるのは合成 PCAP（`examples/pcap/synthetic-*`）だけ。
- **保存期間**：リングバッファと期間の設定を Phase 2 で SQLite と一緒に設計する。現状は利用者が手動で管理する。
- **外部への送信**：現状はゼロ。脅威情報も一括ダウンロードに限る。
- **ローカル API**：既定で 127.0.0.1 にのみバインドし、CORS は loopback のオリジンにだけ許可する。
