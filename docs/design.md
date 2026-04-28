# Quarant の設計

このドキュメントは、Quarant の設計方針、アーキテクチャ、OWASP IoT Top 10 との対応、パッシブ監視の限界をまとめたものです。

---

## 設計方針

Quarant は、ホームネットワーク内の IoT 通信をパッシブに観測し、通信上に現れるリスクを説明可能なイベントとして記録します。

重要なのは、Quarant が「脆弱性を完全診断するツール」ではないという点です。パッシブ監視では、端末内部の設定、firmware の署名検証、クラウド側の認可処理、利用者の同意状況などは直接確認できません。

そのため Quarant は、以下を分けて扱います。

- `observed_fact`: 実際に通信上で観測できた事実
- `inference`: 観測事実から推定できるリスク
- `limitation`: パッシブ監視だけでは断定できないこと
- `recommendation`: 利用者や管理者が確認すべきこと

---

## アーキテクチャ概要

```text
packet capture
  ↓
TCP flow reconstruction
  ↓
protocol parsing
  - HTTP
  - TLS ClientHello / ServerHello
  - MQTT
  - Telnet
  ↓
device inference
  - category candidate
  - vendor candidate
  - family candidate
  ↓
rule engine
  - I2 / I3 / I4 / I5 / I6 / I7 / I9 signals
  - I1 related tags
  - I8 inventory support
  ↓
outputs
  - events.jsonl
  - device_inventory.json with per-device risk_summary
  - simple Web viewer
```

### 主な処理の流れ

1. `gopacket` / `pcap` で network interface から packet を取得する
2. TCP flow を再構成する
3. HTTP / TLS / MQTT / Telnet などの protocol metadata を取り出す
4. host、SNI、path、User-Agent、port などから device category / vendor / family の候補を推定する
5. OWASP IoT Top 10 に対応した rule を適用する
6. `events.jsonl` と `device_inventory.json` に結果を出力する

---

## 実ネットワークでの配置

Quarant はパッシブ監視ツールなので、観測できる通信は配置場所に依存します。

### 通常の Linux PC 上で実行する場合

```text
Ubuntu / Linux PC
  ├─ Quarant
  └─ curl / browser / local app traffic
        ↓
      Internet
```

この場合、主にその PC 自身に見える通信を観測します。同じ Wi-Fi や LAN にいる他の IoT 機器の通信が常に見えるわけではありません。

### gateway / bridge / router として配置する場合

```text
IoT devices
  ↓
Linux gateway / OpenWrt router / Raspberry Pi
  ├─ Quarant
  ↓
Home router / Internet
```

家庭内 IoT 機器の通信を広く観測するには、Quarant を gateway、bridge、router など通信経路上に配置する必要があります。

### containerlab の位置づけ

```text
pc1  →  quarant  →  pc2
```

containerlab は、Quarant を通信経路上に配置した場合の検知ロジックを再現性高く検証するための仮想ネットワーク環境です。実運用そのものではなく、開発・検証用の環境として扱います。

---

## イベントモデル

主要イベントは、以下のような情報を持ちます。

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

`owasp_tags` は、1つのイベントが複数の OWASP 項目に関係する場合に使います。たとえば、HTTP URL に token が含まれる場合、I1、I3、I7 のすべてに関係します。

---

## Device inventory と risk_summary

`device_inventory.json` は、観測した端末ごとの状態をまとめるための snapshot です。

主な情報:

- `first_seen` / `last_seen`
- observed hosts / ports / protocols / SNI
- category / vendor / family candidate
- `risk_event_count`
- `severity_counts`
- `owasp_tag_counts`
- `last_risk_event_type`
- `risk_summary`

`risk_summary` は、人が読みやすいように既存の集計情報から作る要約です。raw evidence や token / password の実値は含めません。

```json
{
  "risk_summary": {
    "risk_event_count": 14,
    "highest_severity": "CRITICAL",
    "top_owasp_tags": ["I7", "I3", "I9", "I2", "I1"],
    "top_severities": ["WARNING", "HIGH", "CRITICAL"],
    "last_risk_event_type": "I9_DEFAULT_HOSTNAME_PATTERN",
    "last_risk_event_ts": "2026-04-27T02:10:03Z",
    "recommended_next_action": "Review plaintext API usage, token handling, and ecosystem interface transport security."
  }
}
```

`risk_summary` は、詳細な診断結果ではなく、利用者や開発者が次に確認すべきポイントを短く示すための補助情報です。

---

## Severity policy

Quarant の severity は、イベント数を減らすためではなく、どの観測が本当に重いかを揃えて示すために使います。

- `CRITICAL`: 平文 HTTP / Telnet / MQTT などで password、Authorization、Cookie、token、secret のような機微値そのものが通信上に観測された場合
- `HIGH`: credential の実値までは見えていないが、plaintext API、public/external 宛の危険サービス、public/external 宛の management API など、攻撃面や運用面のリスクが高い場合
- `WARNING`: 調査推奨レベルの signal。plaintext HTTP request、local-ish な management/setup endpoint、default hostname-like pattern、cloud/backend-like plaintext 通信など
- `INFO`: debug / observation only。単体では risk event とみなさない補助観測

I3 と I7 が同じ HTTP 通信から同時に出ることはあります。この場合、I3 は interface risk、I7 は exposed secret risk として分けて扱い、`risk_summary.highest_severity` は最も重いイベントを採用します。

---

## OWASP IoT Top 10 との対応

| 項目 | 状態 | Quarant での扱い |
| --- | --- | --- |
| I1 | partial / related signal | パスワード強度やハードコード認証情報そのものは断定しません。HTTP / MQTT / Telnet などで認証情報や token が通信上に観測された場合、I1 関連シグナルとして扱います。 |
| I2 | implemented | Telnet、FTP、RTSP、MQTT、CoAP、HTTP 管理画面など、危険または古いネットワークサービスを検知します。 |
| I3 | initial implemented | API over HTTP、token in URL、管理 endpoint、弱い cloud/backend transport などを passive ecosystem-interface risk signal として扱います。 |
| I4 | implemented as update-risk signal | firmware / update らしい通信や、平文 HTTP による更新配送を検知します。ただし署名検証や rollback protection の有無は断定しません。 |
| I5 | enrichment | 既知脆弱性のある family / component 候補を knowledge DB から補足します。正確な CVE 該当性には型番・firmware version の確認が必要です。 |
| I6 | implemented as privacy-risk signal | privacy-sensitive plaintext、stable identifier、unexpected privacy destination、baseline mismatch などを privacy risk signal として扱います。同意違反や policy violation は断定しません。 |
| I7 | implemented | 平文 HTTP、Authorization、Cookie、token、secret、MQTT credentials、Telnet credentials など、転送中の機微情報露出を検知します。 |
| I8 | partial / device-management support | device inventory、unknown / low-confidence identity、per-device risk summary を提供します。デバイス管理が欠如しているとは断定しません。 |
| I9 | partial / default-setting related signal | setup / onboarding endpoint、default hostname-like pattern、危険サービスが有効な状態を I9 関連シグナルとして扱います。factory-default 状態そのものは断定しません。 |
| I10 | mostly out of scope | 物理的ハードニングはパッシブ監視では評価できません。network-visible な debug / factory endpoint のみ関連シグナルとして扱います。 |

---

## 検知カテゴリ

### I1: Weak, Guessable, or Hardcoded Passwords

Quarant は、パスワード強度、ハードコード認証情報、初期パスワードの存在を直接判定しません。

ただし、以下のような認証情報露出は I1 関連シグナルとして扱います。

- HTTP Authorization header
- token / api_key / session_id in URL
- HTTP body 内の password / token / secret
- MQTT username / password
- Telnet login / password

### I2: Insecure Network Services

危険または古いネットワークサービスを検知します。

主な対象:

- Telnet
- FTP
- RTSP
- MQTT
- CoAP
- HTTP 管理画面
- public 宛の危険サービス通信

### I3: Insecure Ecosystem Interfaces

Web / backend API / cloud / mobile backend など、IoT ecosystem interface に関する通信上のリスクを検知します。

主な対象:

- API over plaintext
- token / api_key / session_id in URL
- `/api/login`, `/api/config`, `/admin` などの管理系 endpoint
- cloud / backend らしい通信の平文利用
- mobile-like User-Agent と backend pattern の組み合わせ

対象外:

- API の認可バイパス検証
- CORS / CSRF 検査
- cloud-side scanning
- mobile app reverse engineering

### I4: Lack of Secure Update Mechanism

更新通信らしい HTTP / TLS メタデータを観測し、update risk signal として扱います。

主な対象:

- firmware / update / ota / upgrade らしい path / host / SNI
- 平文 HTTP による firmware/update-like delivery
- weak update visibility
- EOL / known vulnerable family との組み合わせ

制約:

- 署名検証、secure boot、anti-rollback は直接観測できません。
- firmware file の真正性や完全性は判断しません。

### I5: Use of Insecure or Outdated Components

ローカル knowledge DB を使い、既知脆弱性のある device family / component 候補を補足します。

扱い:

- known vulnerable family candidate
- representative CVEs
- model / firmware verification recommended

制約:

- CVE 該当性を確定するには、正確な型番と firmware version が必要です。
- Quarant は CVE の完全な自動判定器ではありません。

### I6: Insufficient Privacy Protection

機器カテゴリごとの baseline と実際の通信を比較し、privacy risk signal を検知します。

主な対象:

- category mismatch
- unexpected domain / SNI
- protocol mismatch
- stable identifier
- history / backup / sync / logs 系 upload
- unexpected PII flow signal
- stored-data signal candidate

制約:

- 同意違反や privacy policy violation は断定しません。
- at-rest の個人情報保存は直接観測できません。

### I7: Insecure Data Transfer and Storage

主に `in-transit` の機微情報露出を検知します。

主な対象:

- plaintext HTTP
- Authorization header
- Cookie / Set-Cookie
- token / api_key / session_id in URL
- sensitive JSON / form / XML body
- MQTT username / password
- Telnet login / password
- JWT-like / Base64-like / long random token-like values

制約:

- at-rest や during-processing の問題は直接観測できません。

### I8: Lack of Device Management

I8 は device-management support として扱います。Quarant は device inventory と per-device risk summary を提供しますが、デバイス管理が欠如しているとは断定しません。

主な対象:

- device inventory
- first_seen / last_seen
- observed hosts / ports / protocols / SNI
- category / vendor / family candidate
- per-device severity counts
- per-device OWASP tag counts
- last risk event
- `risk_summary` による最高 severity、主要 OWASP tag、推奨確認事項の要約

### I9: Insecure Default Settings

初期設定に関連しそうな通信上のシグナルを検知します。

主な対象:

- setup / wizard / onboarding / pairing / provisioning endpoint
- default hostname-like pattern
- Telnet / FTP / HTTP 管理画面など、危険サービスが有効な状態

制約:

- factory default のまま残っているとは断定しません。
- 初期パスワードの存在は、認証情報が通信上に露出した場合のみ関連シグナルとして扱います。

---

## TLS 解析

Quarant は TLS ClientHello と ServerHello の観測に対応しています。

できること:

- TLS ClientHello の検出
- SNI の取得
- supported_versions の取得
- JA3 fingerprint の生成
- TLS ServerHello の検出
- TLS version / selected cipher / offered cipher suites の取得
- 一部の証明書情報の取得
- ClientHello + ServerHello を組み合わせた TLS metadata 観測
- 古い TLS バージョン、弱い cipher suite、証明書異常、想定外 SNI の risk signal 化

制約:

- TLS 1.3 では、Certificate などの後続ハンドシェイクメッセージが暗号化されるため取得できない場合があります。
- Certificate 情報の取得は TLS 1.2 など一部の通信に限定されます。
- HTTPS の本文は復号しません。
- MITM / SSL stripping は行いません。

見えるもの / 見えないもの:

| 種別 | 具体例 |
| --- | --- |
| 見える | SNI, TLS version, supported_versions, selected cipher, offered cipher suites, JA3, certificate metadata |
| 見えない | HTTPS body, Cookie, Authorization header, API response, encrypted payload |

---

## パッシブ監視の限界

Quarant はパッシブ監視ツールであるため、以下は原理的に断定しません。

- パスワードが弱いこと
- 認証情報がハードコードされていること
- 初期パスワードが残っていること
- API に認証・認可不備があること
- firmware 署名検証や rollback protection の有無
- 正確な CVE 該当性
- 利用者の同意違反や privacy policy violation
- デバイス管理の欠如
- 物理的ハードニングの不足
- HTTPS の本文内容

代わりに、通信上に現れる観測可能な事実をもとに、確認すべきリスクシグナルとして記録します。
