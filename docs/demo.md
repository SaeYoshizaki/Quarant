# Quarant のデモ

このドキュメントは、Ubuntu / Linux 環境および containerlab 環境で Quarant を動かし、代表的な検知イベントを確認するための手順です。

---

## 想定する検証構成

想定構成:

```text
pc1  →  quarant  →  pc2
```

- `pc1`: 疑似 IoT device / client
- `quarant`: パッシブ監視する gateway / monitor
- `pc2`: 疑似 server

---

## ビルド

```bash
cd /go/src
go test ./...
rm -f build/quarant
go build -o build/quarant ./cmd/quarant
```

---

## Quarant の実行

```bash
sudo ./build/quarant -i <interface> -inventory-out device_inventory.json -inventory-interval 10s
```

別の interface を監視する場合は `-i` を変更してください。

Linux 上で interface を確認する場合は、以下を使います。

```bash
ip addr
```

通常の Linux PC 上で実行した場合、主にその PC 自身に見える通信を観測します。家庭内 IoT 機器の通信を広く観測するには、Quarant を gateway、bridge、router など通信経路上に配置する必要があります。

---

## Demo 1: I3 / I7 平文 HTTP API と URL 内 token

pc1 から以下を実行します。

```bash
curl -H "Host: api.vendor-cloud.test" "http://example.com/api/config?token=abcdef"
```

Quarant 側で確認します。

```bash
grep 'I3_' events.jsonl | tail -n 20
```

期待されるイベント:

- `I3_API_OVER_PLAINTEXT`
- `I3_AUTH_TOKEN_IN_URL`
- `I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL`

確認ポイント:

- `token=abcdef` ではなく `token=***` としてマスクされる
- `owasp_tags` に `I1`, `I3`, `I7` が含まれる
- `observed_fact`, `inference`, `limitation`, `recommendation` が出る

---

## Demo 2: I3 / I9 平文 HTTP の管理 endpoint

pc1 から以下を実行します。

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

pc1 から以下を実行します。

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

## Demo 4: I8 device inventory

上記の通信をいくつか流した後、以下を確認します。

```bash
cat device_inventory.json | jq .
```

要約だけ見る場合:

```bash
jq '.devices[] | {ip, first_seen, last_seen, observed_hosts, observed_ports, risk_event_count, owasp_tag_counts, last_risk_event_type}' device_inventory.json
```

確認ポイント:

- device ごとに `first_seen` / `last_seen` が記録される
- observed hosts / ports / protocols が集約される
- severity counts / OWASP tag counts が集約される
- last risk event が確認できる

---

## Demo 5: 汎用 host に対する誤検知確認

pc1 から以下を実行します。

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
