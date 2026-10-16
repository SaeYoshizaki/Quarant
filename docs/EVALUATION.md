# 研究としての評価方法

## 1. 正解ラベルによる評価（実装済み）

```bash
go run ./cmd/quarant synth --out runs/synth/home.pcap
go run ./cmd/quarant analyze runs/synth/home.pcap --out runs/synth/out/events.jsonl
go run ./cmd/quarant label-eval --events runs/synth/out/events.jsonl --labels runs/synth/home.labels.json
```

**ラベルの種類**

- `observable`：通信から観測できる条件。再現率（recall）の分母になる。
- `hidden`：シナリオ上は存在するが、通信には現れない条件。パッシブ監視の限界を記録するためのもの。
- 陰性対照（`benign_*`）：何も検出してはいけない機器。

**ラベルの種類とイベント型の対応**：`internal/labeleval` の `KindEventTypes` を参照。

**ラベルのない検出（unlabelled）の扱い**：誤検知とは自動判定しない。人が確認して、次のどれかに分類する。

- 同じ条件を別の角度から見た冗長な検出
- ラベルを付け忘れた本物の条件
- 誤検知

**注意**：合成シナリオは検出器を知っている側が作ったデータなので、回帰の確認にしか使えない。

## 2. 比較実験（Phase 2 で整備）

同じ PCAP を次の 4 通りで解析し、同じラベルで比較する。

| 構成 | 実行方法 |
|---|---|
| Quarant 単体 | `quarant analyze` |
| Zeek | `zeek -r x.pcap` の出力を `quarant zeek import` で取り込む |
| Suricata | `suricata -r x.pcap` の EVE を `quarant suricata import` で取り込む |
| 組み合わせ | `quarant evidence assemble`、その後に相関（Phase 2） |

**指標**

- 検出性能：
  - ラベル単位の再現率
  - 陰性対照での違反数
  - unlabelled の件数（冗長性の指標）
- 説明性：根拠の種類ごとの内訳
- 資源：処理時間と最大メモリ（`/usr/bin/time -l`）
- 可視性：暗号化されたフローの割合、識別できた機器の割合、DHCP や DNS を観測できた機器の割合

**参考値（2026-10-17、Apple Silicon）**：実 PCAP（1 時間、2.8 万パケット、29MB）の処理時間は 7.6 秒、最大 RSS は約 39MB。

## 3. 必要なデータ

- 実機の IoT 機器を、実験用のネットワークで観測したもの（Phase 3）。
- 公開データセット：利用規約とラベルの品質を確認してから使う。
- 再現性のため、各実験で PCAP の SHA-256、Quarant のコミット、`--local-net`、しきい値を記録する。
