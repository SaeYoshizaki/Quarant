# 現在の開発状況

最終更新：2026-10-17（branch `phase1-foundation`、未 push）

## できること（実装済み・テスト済み）

- **PCAP の解析**：`quarant analyze <pcap>`。出力は `events.jsonl`、`flows.jsonl`、`observations.jsonl`、`device_inventory.json`。
  - 時刻：キャプチャ時刻を使う。
  - 監視範囲：`--local-net` で指定できる。
  - 実行場所：リポジトリの外からでも実行できる（知識ベースを組み込み済み）。
- **機器識別**：MAC、OUI ベンダー（ランダム化された MAC を判別する）、DHCP（ホスト名、vendor class、option 55）、mDNS、SSDP、DNS クエリ。
  - 識別情報ごとに根拠の種類と出典を付ける。
- **平文での認証情報露出**：HTTP、MQTT、Telnet（値はマスクする）。
- **TLS**：古いバージョン、弱い暗号の提示と選択、証明書の異常（TLS 1.2 以下）、JA3。
- **振る舞い**：
  - 外向き、縦方向、LAN 内のスキャンの疑い
  - 周期通信（文脈フラグつき）
  - IP と MAC の対応の変化
- **根拠の種類**：すべてのイベントに `basis`（observed／inferred／reference_match）を付ける。
- **知識ベースとの照合**：I3〜I6（カテゴリ方針、脆弱性候補。適用可否は未確認として扱う）。
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
- **TCP の再組み立て**：していない。到着順に 16KB まで蓄積するだけ。HTTP は最初のリクエストしか解析しない。
- **Web UI**：Next.js の UI はあるが未ビルドで、新しい項目（basis、識別の根拠、振る舞い）は表示されない。

## 未実装

脅威情報との照合、NVD／KEV／EPSS、相関エンジン、SQLite、時系列比較、ベースライン学習、JA4、CoAP／RTSP／ONVIF の詳細解析、DNS トンネリング、パケット欠落の計測、実機 OpenWrt での検証。詳細は [ROADMAP.md](ROADMAP.md) を参照。

## 既知の問題

1. **イベントの冗長性**：同じ条件について複数のルールが発火する（合成シナリオでは 8 条件に対して 16 種類）。Phase 2 の相関で対処する。
2. **重みの根拠**：`internal/reportapi/precision.go` の加重スコアには根拠が文書化されていない。研究方針 6.4 に沿って見直しが必要。
3. **知識ベースの出典**：`knowledge/i5_vulnerable_components.json` の 14/21 件に出典がない。CVE-2023-1389 の対応づけが誤っている。キーワード照合（`amazon` など）が広すぎる。
4. **ルールの誤検知の可能性**（AUDIT にあるもののうち未修正）：
   - I4 の `ota` 部分一致
   - `I9_DEFAULT_HOSTNAME_PATTERN` が接続先のホスト名で判定している
   - 同じ弱い暗号について SELECTED と SUITE_OBSERVED の 2 件が出る
5. **リポジトリ直下の不要ファイル**：`event.json`、`wget-log`、`.codex`、`events.old.jsonl`、`kari.json`、`report.json`、`tree.txt`、`package-lock.json`、`clab-*/`。削除するかどうかを利用者に確認中。
6. **旧ツール**：`cmd/quarant-api` と `cmd/quarant-agg` はどこからも参照されていない。`quarant-agg` には時間窓の計算バグがある。
7. **合成 PCAP の再現性**：TLS 部分のバイト列は実行のたびに変わる（解析結果は同じ）。
8. **巨大ファイル**：`precision.go`、`mitigation.go`、`web/app/page.tsx`。分割は Phase 2 で行う。

## 次に行う作業（優先順）

1. 実 IoT 機器の PCAP を入手して検証する。公開データセット（例：UNSW IoT traffic、IoT-23）の利用規約も確認する。
2. 相関エンジンの設計（Phase 2-1）と SQLite スキーマ。
3. 脅威情報フィードの仕様と規約の確認、およびローカル照合の実装。
4. Suricata と Zeek を実際に動かし、合成 PCAP と実 PCAP で比較する基盤。
5. Web UI に basis、識別の根拠、visibility limits を表示する。
