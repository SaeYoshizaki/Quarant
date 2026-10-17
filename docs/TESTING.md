# テストと動作確認

## 自動テスト

```bash
go vet ./...
go test ./...
go test -race ./analyzer/...          # 並行処理（インベントリの書き出し）を含む
go test -fuzz FuzzParseSSDP ./analyzer/discovery -fuzztime 30s
```

| テスト | 確認していること |
|---|---|
| `analyzer/scenario_test.go` | 合成 PCAP をエンドツーエンドで解析し、次を確認する：キャプチャ時刻、ローカルの端末だけが登録されること、識別、帰属、陰性対照、振る舞い検知、`basis` |
| `analyzer/behavior` | スキャンと周期通信の、しきい値の境界 |
| `analyzer/discovery` | OUI、DHCP、mDNS、SSDP の解析 |
| `cmd/quarant/importer_formats_test.go` | 実在する形式のログ：logread、Snort 3 JSON、nf_conntrack、Zeek JSON、大きな flow_id |
| `internal/viewer` | CORS と Host ヘッダの検査 |

## 手動での動作確認

```bash
# 合成シナリオ（リポジトリに含まれている）
go run ./cmd/quarant analyze examples/pcap/synthetic-home.pcap --out runs/demo/events.jsonl
go run ./cmd/quarant devices --in runs/demo
go run ./cmd/quarant label-eval --events runs/demo/events.jsonl --labels examples/pcap/synthetic-home.labels.json

# 自分で取得した PCAP（リポジトリには入れない）
go run ./cmd/quarant analyze ~/capture.pcap --local-net 192.168.1.0/24 --out runs/real/events.jsonl
go run ./cmd/quarant devices --in runs/real
```

`runs/` と `*.pcap` は `.gitignore` で除外している。リポジトリに含める PCAP は、`quarant synth` で生成したものだけにする。

## OpenWrt と IDS の統合デモ

README の「最小 demo」と `experiment run` を参照。

## 公開データセットでの評価

データは `~/datasets/` に置く（リポジトリの外）。手順と結果は [EXPERIMENTS.md](EXPERIMENTS.md) を参照。

```bash
quarant dataset-eval iot23 --run runs/x --labels conn.log.labeled --scenario NAME
quarant dataset-eval unsw --run runs/x --devices List_Of_Devices.txt
quarant dataset-eval unsw-attacks --run runs/x --annotations annotations/
```
