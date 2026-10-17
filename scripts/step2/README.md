# Step 2：Quarant、Zeek、Suricata を同じ PCAP で比べる

結果と解釈は [docs/EXPERIMENTS.md](../../docs/EXPERIMENTS.md) の S2 と、[docs/assessment/tool-comparison.md](../../docs/assessment/tool-comparison.md) を参照。

```bash
brew install zeek suricata
suricata-update --data-dir <work>/su-data --output <work>/rules --no-test   # ET Open
go build -o <work>/quarant ./cmd/quarant
scripts/step2/run_tools.sh <work>/quarant <work>/rules <capture.pcap> <work>/out/<name>
#   <name> の接頭辞：unsw-（UNSW 2016）、unswatk-（UNSW 2018 の攻撃データ）、iot23-<シナリオ名>
python3 scripts/step2/compare_tools.py <work>/out <unsw-attacks>/annotations ~/datasets/iot-23 \
  docs/assessment/non-iot-macs.txt docs/assessment/tool-comparison.md
```

- `quarant-compare.zeek` は、Zeek に同梱の `site/local.zeek` から `frameworks/files/detect-MHR` を外し、MAC アドレスの記録を加えたもの。`detect-MHR` は、外部のハッシュ登録サービスへ DNS で問い合わせるため外した。パスワードは記録しない（Zeek の既定のまま）。
- PCAP と各ツールの出力は、リポジトリの外に置く。
