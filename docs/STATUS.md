# 現在の開発状況

最終更新：2026-10-17

## できること（実装済み・テスト済み）

- **PCAP の解析**：`quarant analyze <pcap>`。出力は `events.jsonl`、`flows.jsonl`、`observations.jsonl`、`device_inventory.json`。
  - 時刻：キャプチャ時刻を使う。
  - 監視範囲：`--local-net` で指定できる。
  - 実行場所：リポジトリの外からでも実行できる（知識ベースを組み込み済み）。
- **機器識別**：MAC、OUI ベンダー（ランダム化された MAC を判別する）、DHCP（ホスト名、vendor class、option 55）、mDNS、SSDP、DNS クエリ。
  - 識別情報ごとに根拠の種類と出典を付ける。
- **平文での認証情報露出**：HTTP、MQTT、Telnet（値はマスクする）。
- **TLS**：古いバージョン、弱い暗号の提示と選択、証明書の異常（TLS 1.2 以下）、JA3。
  - TLS は、ポートに関係なく内容で判定する。
  - パーサは、標準実装（`crypto/tls`、`net/http`、mochi-mqtt）との差分検査で検証済み（[EXPERIMENTS.md](EXPERIMENTS.md) E2、E2b）。
- **振る舞い**：
  - 外向き、縦方向、LAN 内のスキャンの疑い
  - 周期通信（文脈フラグつき）
  - IP と MAC の対応の変化
- **根拠の種類**：すべてのイベントに `basis`（observed／inferred／reference_match）を付ける。
- **知識ベースとの照合**：I3〜I6（カテゴリ方針、脆弱性候補。適用可否は未確認として扱う）。
- **公開データセットでの評価**：`quarant dataset-eval iot23|unsw|unsw-attacks`。結果は [EXPERIMENTS.md](EXPERIMENTS.md) を参照。
  - ARP スプーフィング：27/27 を検出。
  - IoT-23：検出器のあるラベル 10 種類のうち 5 種類を検出。
  - UNSW の正常データ：誤検知候補の WARNING は 1 日あたり約 0.8 件。
- **レポート**
  - `quarant devices`：機器単位のレポート（見えなかったことも出す）。
  - `quarant label-eval`：正解ラベルとの比較。
  - `quarant synth`：合成シナリオの生成。
- **外部ログの取り込み**：OpenWrt、Suricata、Zeek（TSV と JSON）、Snort。統合、インシデント化、緩和計画（dry-run）、before/after 評価、研究レポート。
- **ローカル Web API**：loopback だけを許可する。UI は未ビルド。

## 一部だけ実装されていること

- **ライブキャプチャ**：`quarant live --iface`。動作の確認は未実施。
  - Ctrl-C を押すとフローを確定してから終了する。
  - 振る舞い検知に渡るのは、終了したかアイドルになったフローだけ。TCP の TTL が 1 時間なので、継続中の接続はライブ中の評価に入るのが遅れる。
- **UDP**：識別と活動の記録はできるが、UDP のフローは記録しない。そのため UDP のビーコンやスキャンは検出できない。
- **TCP の再組み立て**：方向ごとに、シーケンス番号の順に 16KB まで組み立てる。再送は捨て、並べ替えは直し、キャプチャ側の欠落は ACK から判定して数える（`capture_gaps`）。
  - 限界：SYN を観測しておらず、最初のセグメントが逆順に届いた通信は、まだ正しく組み立てられない。
  - HTTP は最初のリクエストしか解析しない。
- **Web UI**：Next.js の UI はあるが未ビルドで、新しい項目（basis、識別の根拠、振る舞い）は表示されない。

## 未実装

脅威情報との照合、NVD／KEV／EPSS、相関エンジン、SQLite、時系列比較、ベースライン学習、JA4、CoAP／RTSP／ONVIF の詳細解析、DNS トンネリング、パケット欠落の計測（TCP のペイロードを蓄積するフローだけは、ACK から欠落を数える）、実機 OpenWrt での検証。詳細は [ROADMAP.md](ROADMAP.md) を参照。

## 既知の問題

1. **イベントの冗長性**：同じ条件について複数のルールが発火する（合成シナリオでは 8 条件に対して 16 種類）。Phase 2 の相関で対処する。
2. **重みの根拠**：`internal/reportapi/precision.go` の加重スコアには根拠が文書化されていない。研究方針 6.4 に沿って見直しが必要。
3. **知識ベースの出典**：`knowledge/i5_vulnerable_components.json` の 14/21 件に出典がない。CVE-2023-1389 の対応づけが誤っている。キーワード照合（`amazon` など）が広すぎる。
4. **ルールの誤検知の可能性**（AUDIT にあるもののうち未修正）：
   - I4 の `ota` 部分一致
   - `I9_DEFAULT_HOSTNAME_PATTERN` が接続先のホスト名で判定している
   - 同じ弱い暗号について SELECTED と SUITE_OBSERVED の 2 件が出る
5. **合成 PCAP の再現性**：TLS 部分のバイト列は実行のたびに変わる（解析結果は同じ）。
6. **巨大ファイル**：`precision.go`、`mitigation.go`、`web/app/page.tsx`。分割は Phase 2 で行う。

7. **識別子の分類**：シリアル番号などの識別子が、`INSECURE_HTTP_TOKEN`（トークンの平文送信）として出力される。機密情報（CSP）ではなく識別子・個人データとして扱うべきで、イベントの種類を分ける必要がある（E4 の監査で判明。E4 の集計では除外している）。
8. **既定外のポートの HTTP**：UNSW では、HTTP リクエストの 52〜84% が既定の HTTP ポート（80、8000、8080、8888）以外で流れていて、既存の HTTP の検出の対象外になっている（E2b）。大半は LAN 内の UPnP の通信。外部への通信にも、8899 番ポートでの平文のログのアップロードなどが含まれる。LAN 内は D17 の範囲で扱う予定。外部への通信を対象にするかは未決定。

## 次に行う作業

[ROADMAP.md](ROADMAP.md) の Step 0〜5 の順に進める。直近の作業は次のとおり。

1. **Step 0**：問いと関連研究の整理は済み。残りは教授との合意（[RESEARCH-SUMMARY.md](RESEARCH-SUMMARY.md) を使う）。
2. **Step 1**：
   - TS 103 701 による可観測性の分類（E3）は、独立した 2 回の分類と裁定まで済み（モデル N で一致率 0.85、κ 0.52）。人による抜き取り確認（10 件）も済み。
   - E4（証拠が実際に現れる率と精度）は済み：違反を示せる 23 要件のうち、精度を確かめた検出で実際に証拠が出たのは 5 件。
   - E5（5.5-4 認証なしの機器操作、5.12-1 UPnP のポート開放の検出を追加）は済み。
   - E6（CIC IoT 2022 の起動時の通信、40 台）は済み：古い TLS は 2016 年の 48% から 10% に減った。
   - 次：CIC IoT 2022 の待機時（2-Idle）と操作時（3-Interactions）で年代比較（RQ3）を完成させる。そのあと Zeek・Suricata との比較（Step 2）に進む。
   - データの置き場所：元データは USB ドライブ（/Volumes/Untitled/quarant-datasets）にあり、~/datasets からリンクしている。
3. **Step 2**：Zeek、Suricata との比較。
