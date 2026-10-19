# 結果のまとめ

2026-10-19 時点。各実験の詳細は [EXPERIMENTS.md](EXPERIMENTS.md)。

## 全体の流れ

```text
PCAP（ファイル or 標準入力 or ライブ）
  │  gopacket で読む
  ▼
パケットの分解（Ethernet / IP / TCP / UDP）
  │
  ├─ UDP ─ DHCP・mDNS・SSDP・DNS から機器を識別
  │        印字できる key=value の認証情報を探す
  │
  └─ TCP ─ 接続ごとに組み立て（順番の並べ替え、再送の除去、16KB まで）
           │
           ▼
         プロトコルの解析（自前）
           HTTP（既定のポート ＋ 中身で判断）、TLS（中身で判断、STARTTLS を含む）、
           MQTT、Telnet、FTP、RTSP
           │
           ▼
         ルールで判定（約 40 個、analyzer/rules）
           平文の認証情報やトークン、古い TLS、平文の画像、認証なしの操作 など
           │
           ├─ 接続をまたぐ振る舞い（スキャン、周期通信、再接続、IP と MAC の対応の変化）
           └─ 知識ベースとの照合（カテゴリの方針、脆弱性の候補）
           │
           ▼
出力：events.jsonl（検出）、device_inventory.json（機器）、findings.json（機器 × 状態の要約）
```

詳細と、OSS をどこで使っているかは [DESIGN.md](DESIGN.md)。

## 使ったデータセット

| データセット | 年 | IoT 機器 | 中身 | 使った目的 |
|---|---|---|---|---|
| UNSW IoT Traffic Traces | 2016 | 25 台 | 研究室の家庭環境、20 日分 | 証拠が現れる割合、誤検知、見逃し |
| UNSW IoT Attack Traces | 2018 | 28 台 | 攻撃の時間帯つき、6 日分 | 攻撃の検出、証拠が現れる割合 |
| IoT-23 | 2018〜19 | 18 台 | マルウェア感染の 8 シナリオ | 感染時の振る舞い |
| CIC IoT Dataset 2022 | 2021〜22 | 40 台 | 起動時、待機時、操作時、総当たり攻撃、フラッド | 新しい年代、総当たりへの応答、誤反応 |
| YourThings | 2018 | 45 台 | 実際の家庭、3 日分 | 一度も使っていない機器での見逃しの確認 |

詳細と利用条件：[DATASETS.md](DATASETS.md)

## 1. 通信を見るだけで判定できる要件（E3）

- **目的**：規格 ETSI EN 303 645 の要件のうち、通信の観測だけで判定できるものを数える。
- **方法**：公式の試験仕様 TS 103 701 の各試験（131 件）が何を必要とするかを読み、「通信の観測だけで合否に届くか」を分類した。データセットは使っていない（規格の文書の分析）。
- **ルール**：[assessment/RUBRIC_FINAL.md](assessment/RUBRIC_FINAL.md)（分類の基準）、[assessment/adjudication.json](assessment/adjudication.json)（食い違いの裁定）

| 判定 | 要件 |
|---|---|
| 違反だけ示せる | 22 |
| 適合だけ示せる | 1 |
| 判定できない | 55（71%） |
| 適合も違反も示せる | 0 |

→ [assessment/ts103701-final.md](assessment/ts103701-final.md)

## 2. 違反の証拠が実際に現れる割合（E4〜E10、E15）

- **目的**：1 で「違反を示せる」とした要件について、実際の通信に証拠がどれだけ出るかを測る。
- **方法**：全データセットを Quarant で解析し、要件ごとに証拠が出た IoT 機器を数えた。
- **ルール**：どの検出を、どの要件の証拠に数えるか：[assessment/evidence-map.json](assessment/evidence-map.json)。各検出の条件：[DETECTION.md](DETECTION.md)。検出の正しさの抜き取り：[assessment/precision-audit.md](assessment/precision-audit.md)

| 要件 | UNSW 2016 | UNSW 2018 | YourThings 2018 | CIC 2022 起動時 | CIC 2022 待機時 |
|---|---|---|---|---|---|
| 5.5-1 古い暗号 | 56% | 46% | 31% | 10% | 8% |
| 5.5-6 平文の秘密情報 | 36% | 7% | 18% | 2% | 3% |
| 5.8-1 平文の個人データ | 8% | 0% | 2% | 5% | 3% |

- 古い暗号は 2022 年に大きく減った。
- 2022 年にも、画像を平文で送るカメラ（3 台）があった。
- 規格の読み方で割合は数倍変わる（厳しい読み方：[assessment/evidence-rates-strict.md](assessment/evidence-rates-strict.md)）。

→ 全要件の表：[assessment/evidence-rates.md](assessment/evidence-rates.md)

## 3. Zeek・Suricata との比較（S2）

- **目的**：既存のツールで同じことが分かるかを確かめる。
- **方法**：同じ通信（UNSW、IoT-23）を Quarant、Zeek、Suricata（ET Open）で解析した。

| | Quarant | Zeek | Suricata |
|---|---|---|---|
| 古い TLS の機器 | 違反として出す | ログに記録（警告なし） | ログに記録（警告なし） |
| 平文の秘密情報、画像 | 出す | 出さない | 出さない |
| ARP スプーフィング（27 件） | 27 | 0 | 0 |
| 反射攻撃、マルウェアの種類 | 出さない | 出さない | 出す |

→ [assessment/tool-comparison.md](assessment/tool-comparison.md)

## 4. 見逃しの確認（E11〜E14）

- **目的**：Quarant が見逃しているものを数え、直す。
- **方法**：Zeek と生パケットの検索で、Quarant とは別に正解を作って比べた。見つけた見逃しを直したあと、一度も使っていない YourThings で確かめた。
- **YourThings（45 台）の結果**：古い TLS 14/14、平文の秘密情報 8/8（修正後）

→ [assessment/miss-audit.md](assessment/miss-audit.md)

## 足りないこと・相談したいこと

1. **新しいデータがない**：2026 年の公開データセットは見つからなかった。少し古い UNSW-IoTraffic（2025 年公開）や Mon(IoT)r（申請が必要）を使うか、自分で機器を用意して取るかで迷っている。
2. **対策の効果を測っていない**：見つけた問題に対策（遮断、隔離、宛先の制限）をすると、どれだけリスクが減るかは未検証。
3. **OSS を Quarant に組み込んでいない**：今は比較と検証に使っているだけ（[DESIGN.md](DESIGN.md)）。Zeek を解析の土台に、Suricata の警告を証拠に加えて、精度を上げたい。課題：
   - Zeek を組み込むと、見逃しを測る正解に Zeek を使えなくなる。別の正解が要る。
   - Quarant の役割を、OSS の出力を規格の要件に結びつける層にするか、自前の解析も残すか。
   - どこで動かすか（ルーターでは Zeek・Suricata が重い）。
4. **通信だけでは判定できない要件が多い**：製造者の公開文書（マニュアル、脆弱性の届け出の方針など）を LLM で読めば、判定できる要件が増える見込み（32〜54 件）。LLM の API を使いたい。
5. **機器の設定が分からない**：初期パスワードのままか、などが分からないので、「判定できない」を正解つきで確かめていない。自分で機器を用意すれば確かめられる。
