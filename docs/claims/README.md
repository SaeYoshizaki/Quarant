# 製造者の主張と通信の突き合わせ

データセットにある IoT 機器について、製造者が公開しているセキュリティの主張を集め、実際の通信（PCAP）と食い違う箇所を探す（D31、D32）。セキュリティの主張が中心で、プライバシーの主張は補助として扱う。

## 文書

| ファイル | 中身 |
|---|---|
| [method.md](method.md) | 進め方：集める文書、主張の書き方の分類、主張の型と食い違いの条件、判定、記録の列 |
| [devices.md](devices.md) | データセットの機器の一覧（7 データセット、116 製品）。元の表は [devices.tsv](devices.tsv)（手で作成）、[devices.json](devices.json) はスクリプトの出力 |
| [claims.tsv](claims.tsv) | 集めた主張。1 行が主張 1 つ |
| [pilot-yourthings.md](pilot-yourthings.md) | 試し：YourThings 2018 の 5 製品（Ring、Canary、Nest Cam、Belkin NetCam HD、Hue） |
| [related-work.md](related-work.md) | 先行研究と、本研究の位置づけ |

## スクリプト

| スクリプト | 使い方 |
|---|---|
| `scripts/claims/build_catalog.py` | `python3 scripts/claims/build_catalog.py docs/claims/devices.tsv ~/datasets docs/claims/devices.md docs/claims/devices.json`：機器の一覧に、解析結果から見えた期間を付ける |
| `scripts/claims/claim_offsets.py` | `python3 scripts/claims/claim_offsets.py docs/claims/claims.tsv docs/claims/devices.json`：主張ごとに、キャプチャの期間とアーカイブの日付のずれを付ける |
| `scripts/claims/collect_hints.py` | 解析結果から型番の手がかりを集める。シリアル番号や人の名前が入るので、出力はリポジトリの外（`~/datasets/claims/`）に置く |

## リポジトリの外にあるもの

- 取得したアーカイブの版（HTML と、取り出した文字）：`~/datasets/claims/snapshots/`。著作物なので、リポジトリには URL と引用だけを入れる。
- 通信の記録：Zeek の記録 `~/datasets/gt-yt/`（値は含まない）、Quarant の解析結果 `~/datasets/runs-yt5/`。`~/datasets` は外付けディスク QuarantData にある。

## 今の状態（2026-10-31）

- 試しの 5 製品は済んだ。主張 11 件を [claims.tsv](claims.tsv) に記録した。
- 次：YourThings の残りの製品の主張を集める。
