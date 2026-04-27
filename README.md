# Quarant

**Quarant** は、ホームネットワーク内の IoT 通信をパッシブに観測し、  
OWASP IoT Top 10 に関連するリスクを「通信上に現れる説明可能なシグナル」として記録するセキュリティゲートウェイです。

端末へログインしたり、攻撃的なスキャンを行ったりせず、TCP フロー再構成、HTTP / TLS / MQTT / Telnet 解析、デバイス推定を組み合わせて、危険なサービス、管理 API、平文の認証情報、初期設定らしい通信、更新リスク、プライバシーリスクを検出します。

Quarant does not claim to fully diagnose all OWASP IoT Top 10 vulnerabilities.  
It converts passively observable network behavior into explainable risk signals.

---

## 作成動機

家庭内 IoT 機器では、利用者から見えにくい実装・初期設定上の問題が、通信上のリスクとして残ることがあります。

たとえば、以下のような状態です。

- 不要なサービスやポートが開いたままになっている
- 管理 API やクラウド連携が平文で使われている
- 認証情報や設定情報が URL、header、body に含まれて送信されている
- setup / onboarding / pairing などの初期設定用 endpoint が見えている
- 更新通信や既知脆弱性の文脈から、確認が必要な機器がある
- 家庭内の IoT 機器を利用者が十分に把握できていない

Quarant は、これらを「脆弱性の断定」ではなく、**パッシブ監視で観測できる risk signal** として整理し、観測事実・推定・限界・推奨アクションを分けて記録します。

---

## 主な機能

- パッシブな IoT 通信監視
- TCP フロー再構成
- HTTP request / response 解析
- TLS ClientHello / ServerHello 解析
- SNI / JA3 / TLS version / cipher suite の観測
- MQTT / Telnet の平文 credential / payload 解析
- デバイス category / vendor / family の候補推定
- OWASP IoT Top 10 に関連する risk event 出力
- `events.jsonl` による説明可能な JSONL ログ
- `device_inventory.json` による端末一覧・リスク集計

---

## 出力

### `events.jsonl`

検知されたリスクイベントを JSONL 形式で出力します。

```json
{
  "type": "I3_AUTH_TOKEN_IN_URL",
  "severity": "HIGH",
  "category": "I3",
  "owasp_tags": ["I1", "I3", "I7"],
  "evidence": "token=***",
  "confidence": "high",
  "observed_fact": "Authentication-related query parameter was observed in the URL.",
  "inference": "URL parameters may be exposed through logs, proxies, browser history, or intermediary systems.",
  "limitation": "Passive monitoring cannot determine whether the value is still valid or whether the backend has additional security controls.",
  "recommendation": "Avoid placing tokens or secrets in URLs, use headers or request bodies over HTTPS, and rotate exposed credentials if necessary."
}
```

### `device_inventory.json`

I8 向けの device inventory snapshot を別 JSON として出力できます。

```bash
sudo ./build/quarant -i <interface> -inventory-out device_inventory.json -inventory-interval 10s
```

含まれる情報の例:

- `first_seen` / `last_seen`
- observed protocols / ports / hosts / SNI
- category / vendor / family candidate
- risk event count
- severity counts
- OWASP tag counts
- last risk event
- `risk_summary` による人向けのリスク要約

`risk_summary` には、最高 severity、主要な OWASP tag、直近のリスクイベント、次に確認すべき内容がまとめられます。

```json
{
  "risk_summary": {
    "risk_event_count": 14,
    "highest_severity": "CRITICAL",
    "top_owasp_tags": ["I7", "I3", "I9", "I2", "I1"],
    "top_severities": ["WARNING", "HIGH", "CRITICAL"],
    "last_risk_event_type": "I9_DEFAULT_HOSTNAME_PATTERN",
    "recommended_next_action": "Review plaintext API usage, token handling, and ecosystem interface transport security."
  }
}
```

---

## クイックスタート

### テスト

```bash
go test ./...
```

### ビルド

```bash
go build -o build/quarant ./cmd/quarant
```

### 実行

まず監視対象の interface を確認します。

```bash
ip addr
```

Ubuntu などの Linux 上で実行する例です。

```bash
sudo ./build/quarant -i enp0s1 -inventory-out device_inventory.json -inventory-interval 10s
```

別ターミナルで通信を発生させると、`events.jsonl` と `device_inventory.json` に結果が出力されます。

```bash
curl -H "Host: api.vendor-cloud.test" "http://example.com/api/config?token=abcdef"
```

確認例:

```bash
grep -E 'I3_|I7_' events.jsonl | tail -n 20
cat device_inventory.json | jq .
```

---

## 実ネットワークでの配置

Quarant はパッシブ監視ツールであるため、観測できる通信は配置場所に依存します。

通常の Linux PC 上で実行した場合、主にその PC 自身に見える通信を観測します。家庭内 IoT 機器の通信を広く観測するには、Quarant を gateway、bridge、router など通信経路上に配置する必要があります。

containerlab は、Quarant を通信経路上に置いた場合の検知ロジックを再現性高く検証するための仮想ネットワーク環境として利用しています。

---

## デモ例

### I3 / I7: 平文 HTTP API と URL 内 token

```bash
curl -H "Host: api.vendor-cloud.test" "http://example.com/api/config?token=abcdef"
```

期待されるイベント:

- `I3_API_OVER_PLAINTEXT`
- `I3_AUTH_TOKEN_IN_URL`
- `I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL`
- `I7_HTTP_TOKEN`

`token` の値は `token=***` のようにマスクされます。

### I9: setup endpoint と default hostname-like signal

```bash
curl -H "Host: device.local" "http://example.com/setup"
```

期待されるイベント:

- `I9_SETUP_ENDPOINT_STILL_ACTIVE`
- `I9_DEFAULT_HOSTNAME_PATTERN`

より詳しいデモ手順は [docs/demo.md](docs/demo.md) にまとめています。

---

## 代表ログ

Ubuntu 上で network interface を指定して Quarant を実行し、実際の HTTP 通信から I3 / I7 / I9 の risk signal を出力できることを確認しています。

- [I3 / I7 token in URL example](examples/events-ubuntu-i3-token.jsonl)
- [I9 setup endpoint example](examples/events-ubuntu-i9-setup.jsonl)
- [device inventory sample](examples/device-inventory-ubuntu-sample.json)

---

## ドキュメント

- [Design](docs/design.md): 設計方針、アーキテクチャ、OWASP IoT Top 10 との対応、パッシブ監視の限界
- [Demo](docs/demo.md): Ubuntu / containerlab 環境での起動手順、curl による検知例、`events.jsonl` / `device_inventory.json` の確認方法

---

## Web viewer（開発中）

`events.jsonl` を確認するための簡易 Web viewer があります。ただし、現時点では開発・検証用であり、最終的な利用者向け UI ではありません。

```bash
go run ./cmd/quarant-api -in events.jsonl -addr 127.0.0.1:8080
```

```bash
cd web
npm install
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8080 npm run dev
```

```text
http://127.0.0.1:3000
```

応募や発表で説明する場合は、現時点では Web viewer よりも `events.jsonl`、`device_inventory.json`、代表イベントのログ例を中心に扱います。

---

## 現在の状態

Quarant は研究・開発中のプロトタイプです。

現在の主な到達点:

- I2 / I3 / I7 を中心に、パッシブ監視で根拠を持って観測しやすい risk signal を実装
- I6 を privacy-risk signal として実装
- I4 / I5 を update-risk / known-vulnerable-family enrichment として実装
- I8 として device inventory / per-device risk summary / `risk_summary` を実装
- I1 / I9 を関連シグナルとして整理
- Ubuntu 上で interface 指定による実行と代表イベント出力を確認

今後の改善候補:

- gateway / bridge / router 配置での実機検証
- family 推定のさらなる誤検知低減
- severity scoring の整理
- device inventory の Web viewer 統合
- CVE / KEV / vendor advisory 連携の精度向上
