# Quarant

家庭内 IoT 機器の通信を、ゲートウェイで見るだけで、セキュリティについて何が分かり、何が分からないかを調べるための研究用ツール（Go）。

機器には何もしない。スキャン、認証の試行、通信の改変、TLS の復号はしない。

## 研究の問い

ETSI EN 303 645（消費者向け IoT のセキュリティ規格）の各要件について、通信を見るだけで「違反を示せる／推定にとどまる／判定できない」のはどれか。それを公開データ（2016〜2022 年）で確かめる。

詳しくは [docs/RESEARCH.md](docs/RESEARCH.md)、要約は [docs/RESEARCH-SUMMARY.md](docs/RESEARCH-SUMMARY.md)。

## 出力

- 機器の一覧と、識別の根拠（MAC、DHCP、mDNS、SSDP、DNS）
- 検出：平文の認証情報やトークン、古い TLS、平文の画像・映像、認証なしの操作、スキャンなど
- すべての検出に、根拠の種類（観測／推定／照合）、観測した事実、推定、限界を付ける
- 見えなかったこと（暗号化されていた割合など）

## 結果

- 解析結果：[quarant-results](https://github.com/SaeYoshizaki/quarant-results)（非公開）
- 実験の記録：[docs/EXPERIMENTS.md](docs/EXPERIMENTS.md)
- 現状と次の作業：[docs/STATUS.md](docs/STATUS.md)

## 使い方

```bash
go test ./...
go run ./cmd/quarant analyze examples/pcap/synthetic-home.pcap --out runs/demo/events.jsonl
go run ./cmd/quarant devices --in runs/demo
```

ほかのコマンドは [docs/COMMANDS.md](docs/COMMANDS.md)。

## 文書

| 文書 | 内容 |
|---|---|
| [docs/RESEARCH.md](docs/RESEARCH.md) | 研究の問い、関連研究、評価計画 |
| [docs/STATUS.md](docs/STATUS.md) | 現状、既知の問題、次の作業 |
| [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) | 実験の記録 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 研究の進め方 |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 設計判断の記録 |
| [docs/DATASETS.md](docs/DATASETS.md) | 使った公開データセット |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 設計と構成 |
| [docs/DETECTION.md](docs/DETECTION.md) | 検出の仕様 |
| [docs/TESTING.md](docs/TESTING.md) | テスト |
| [docs/COMMANDS.md](docs/COMMANDS.md) | コマンド |
| [docs/PIPELINE.md](docs/PIPELINE.md) | 外部ログ（OpenWrt、Suricata、Zeek、Snort）の取り込みと緩和策の評価 |
| [docs/review/](docs/review/) | Claude の判定の確認用シート |
