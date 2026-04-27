# Quarant のデモ

このドキュメントは、Ubuntu / Linux 環境および containerlab 環境で Quarant を動かし、代表的な検知イベントを確認するための手順です。

---

## このデモで確認すること

このデモでは、以下を確認します。

- Ubuntu / Linux 上で network interface を指定して Quarant を起動できる
- 実際の HTTP 通信から I3 / I7 / I9 の risk signal が出力される
- URL 内の token が `token=***` のようにマスクされる
- `device_inventory.json` に端末単位の観測情報と `risk_summary` が出力される
- containerlab は再現性のある検証環境として利用できる

---

## 実ネットワークでの注意

Quarant はパッシブ監視ツールなので、観測できる通信は配置場所に依存します。

通常の Linux PC 上で実行した場合、主にその PC 自身に見える通信を観測します。同じ LAN 内の IoT 機器の通信を広く観測するには、Quarant を gateway、bridge、router など通信経路上に配置する必要があります。

```text
Ubuntu / Linux PC
  ├─ Quarant
  └─ curl / browser / local app traffic
        ↓
      Internet
```

家庭内 IoT 機器全体を観測する場合の想定構成は以下です。

```text
IoT devices
  ↓
Linux gateway / OpenWrt router / Raspberry Pi
  ├─ Quarant
  ↓
Home router / Internet
```

---

## containerlab での検証構成

containerlab では、以下のような構成で Quarant を通信経路上に置いた場合を再現します。

```text
pc1  →  quarant  →  pc2
```

- `pc1`: 疑似 IoT device / client
- `quarant`: パッシブ監視する gateway / monitor
- `pc2`: 疑似 server

---

## ビルド

```bash
go test ./...
rm -f build/quarant
go build -o build/quarant ./cmd/quarant
```

containerlab 内で作業する場合など、必要に応じて作業ディレクトリへ移動してください。

```bash
cd /go/src
```

---

## Quarant の実行

Linux 上で interface を確認します。

```bash
ip addr
```

Quarant を起動します。

```bash
sudo ./build/quarant -i <interface> -inventory-out device_inventory.json -inventory-interval 10s
```

Ubuntu の例:

```bash
sudo ./build/quarant -i enp0s1 -inventory-out device_inventory.json -inventory-interval 10s
```

containerlab の例:

```bash
sudo ./build/quarant -i eth1 -inventory-out device_inventory.json -inventory-interval 10s
```

---

## Demo 1: I3 / I7 平文 HTTP API と URL 内 token

別ターミナルで以下を実行します。

```bash
curl -H "Host: api.vendor-cloud.test" "http://example.com/api/config?token=abcdef"
```

Quarant 側で確認します。

```bash
grep -E 'I3_|I7_' events.jsonl | tail -n 30
```

期待されるイベント:

- `I3_API_OVER_PLAINTEXT`
- `I3_AUTH_TOKEN_IN_URL`
- `I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL`
- `I7_HTTP_PLAINTEXT`
- `I7_HTTP_TOKEN`

確認ポイント:

- `token=abcdef` ではなく `token=***` としてマスクされる
- `owasp_tags` に `I1`, `I3`, `I7` が含まれる
- `observed_fact`, `inference`, `limitation`, `recommendation` が出る
- `I3_MOBILE_APP_BACKEND_PATTERN_OBSERVED` は、curl のような CLI User-Agent では出ない

secret が漏れていないことも確認します。

```bash
grep 'abcdef' events.jsonl
```

何も表示されなければ、token の実値はログに残っていません。

---

## Demo 2: I3 / I9 平文 HTTP の管理 endpoint

別ターミナルで以下を実行します。

```bash
curl -H "Host: camera.local" "http://example.com/admin/config"
```

Quarant 側で確認します。

```bash
grep -E 'I3_|I9_' events.jsonl | tail -n 20
```

期待されるイベント:

- `I3_MANAGEMENT_API_EXPOSED`

確認ポイント:

- 管理系 endpoint らしい通信として扱われる
- 認証欠如や侵害は断定しない
- 平文 HTTP である場合、I7 とも関連する

---

## Demo 3: I9 setup endpoint と default hostname-like pattern

別ターミナルで以下を実行します。

```bash
curl -H "Host: device.local" "http://example.com/setup"
```

Quarant 側で確認します。

```bash
grep 'I9_' events.jsonl | tail -n 20
```

期待されるイベント:

- `I9_SETUP_ENDPOINT_STILL_ACTIVE`
- `I9_DEFAULT_HOSTNAME_PATTERN`

確認ポイント:

- setup / onboarding らしい endpoint として扱われる
- `device.local` は default hostname-like pattern として扱われる
- factory default のまま残っているとは断定しない

---

## Demo 4: I8 device inventory と risk_summary

上記の通信をいくつか流した後、`device_inventory.json` を確認します。

```bash
cat device_inventory.json | jq .
```

要約だけ見る場合:

```bash
jq '.devices[] | {ip, first_seen, last_seen, observed_hosts, observed_ports, risk_event_count, owasp_tag_counts, last_risk_event_type, risk_summary}' device_inventory.json
```

`risk_summary` だけを見る場合:

```bash
jq '.devices[] | select(.risk_summary != null) | {ip, risk_summary}' device_inventory.json
```

確認ポイント:

- device ごとに `first_seen` / `last_seen` が記録される
- observed hosts / ports / protocols が集約される
- severity counts / OWASP tag counts が集約される
- last risk event が確認できる
- `risk_summary.highest_severity` で最も高い severity が確認できる
- `risk_summary.top_owasp_tags` で主に関係する OWASP 項目が確認できる
- `risk_summary.recommended_next_action` で次に確認すべき内容が確認できる

secret が inventory に漏れていないことも確認します。

```bash
grep 'abcdef' device_inventory.json
```

---

## Demo 5: 汎用 host に対する誤検知確認

別ターミナルで以下を実行します。

```bash
curl -H "Host: device.local" "http://example.com/"
```

Quarant 側で確認します。

```bash
grep 'I3_API_OVER_PLAINTEXT' events.jsonl | tail -n 20
```

期待される結果:

- `Host: device.local` だけでは `I3_API_OVER_PLAINTEXT` が出ない

理由:

- I3 API 判定は host hint だけではなく、`/api`, `/v1`, `/graphql`, `/oauth/token`, `/device/register` など API らしい path を重視する

---

## 代表ログ

Ubuntu 上で network interface を指定して Quarant を実行し、実際の HTTP 通信から I3 / I7 / I9 の risk signal を出力できることを確認しています。

- [I3 / I7 token in URL example](../examples/events-ubuntu-i3-token.jsonl)
- [I9 setup endpoint example](../examples/events-ubuntu-i9-setup.jsonl)
- [device inventory sample](../examples/device-inventory-ubuntu-sample.json)

### 代表ログの読み方

`events-ubuntu-i3-token.jsonl` では、主に以下を確認します。

- `I3_API_OVER_PLAINTEXT`: API らしい endpoint が平文 HTTP で観測された
- `I3_AUTH_TOKEN_IN_URL`: URL query に token が含まれていた
- `I7_HTTP_TOKEN`: 平文 HTTP 上で token-like value が観測された
- `evidence` が `token=***` になっており、実値は保存されていない

`events-ubuntu-i9-setup.jsonl` では、主に以下を確認します。

- `I9_SETUP_ENDPOINT_STILL_ACTIVE`: setup / onboarding らしい endpoint が見えた
- `I9_DEFAULT_HOSTNAME_PATTERN`: `device.local` のような default hostname-like pattern が見えた
- factory default 状態そのものは断定していない

`device-inventory-ubuntu-sample.json` では、主に以下を確認します。

- device ごとの `first_seen` / `last_seen`
- observed hosts / ports / protocols / SNI
- `risk_event_count`
- `owasp_tag_counts`
- `last_risk_event_type`
- `risk_summary.highest_severity`
- `risk_summary.top_owasp_tags`
- `risk_summary.recommended_next_action`

---

## Web viewer（任意）

簡易 Web viewer を使う場合は、Quarant 実行後に以下を起動します。

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

現時点では開発・検証用の簡易 viewer であり、最終的な利用者向け UI ではありません。
