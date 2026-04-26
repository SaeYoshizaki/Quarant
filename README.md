# Quarant

**Quarant** は、ホームネットワーク内の IoT 通信をパッシブに観測し、  
「どの機器が」「どんな通信を」「なぜ危険なのか」を説明付きで記録するセキュリティゲートウェイです。

TCP フロー再構成、HTTP / TLS 解析、デバイスカテゴリ推定を組み合わせることで、  
平文通信や危険なサービスだけでなく、機器カテゴリに合わない不自然な外向き通信も検知します。

## 何ができるか

- IoT 通信のパッシブ監視
- TCP フロー再構成によるアプリケーション層解析
- HTTP / TLS メタデータからのデバイス推定
- OWASP IoT Top 10 に対応したイベント出力
- JSONL 形式での説明可能なセキュリティログ出力
- Go API + Next.js によるイベント可視化フロントエンド

Quarant does not claim to fully diagnose all OWASP IoT Top 10 vulnerabilities.  
It converts passively observable network behavior into explainable risk signals.

## Web UI

ターミナルに流れる `events.jsonl` を、Go 側の JSON API と TypeScript/TSX + Tailwind CSS ベースの Next.js フロントで分離して確認できます。

```bash
go run ./cmd/quarant-api -in events.jsonl -addr 127.0.0.1:8080
```

別ターミナルで Next.js フロントを起動します。

```bash
cd web
npm install
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8080 npm run dev
```

その後 `http://127.0.0.1:3000` を開くと、

- severity / rule のフィルタ
- IP / evidence / message を含めた検索
- top rules / categories / source IP の要約
- 新着順イベント一覧

をまとめて確認できます。`Auto: 5s` を有効にすると、追記中の `events.jsonl` を定期更新できます。

## いまの検知の考え方

Quarant は、通信ごとに 2 段階で異常を判断します。

1. `I2 / I6 / I7`
危険なサービス、平文通信、カテゴリ不一致、想定外ドメイン、プロトコル不一致などを個別イベントとして出します。

2. `R1_COMPOSITE_RISK`
I6 の `risk_signals` をまとめて、`low / medium / high`、`risk_score`、`recommended_action` に変換します。

これにより、単に「変な通信があった」だけでなく、  
「なぜ危険か」「どの程度危険か」まで一連で確認できます。

カテゴリ推定は `known / inferred / unknown` の三層で扱います。  
強い証拠があるときだけ `known` を使い、弱い場合は `inferred`、十分な根拠がない場合は無理に分類せず `unknown` として扱います。
`confidence` はこの三層に応じた見え方になっており、`known` は strong な確定寄り、`inferred` は粗い推定の強さ、`unknown` は very_low として出力されます。  
そのため、同じ数値でも意味は一律ではなく、「どの source の推定か」と合わせて読むのが基本です。

デバッグログは `summary` と `detail` に分かれており、まず短い要約、そのあとに根拠の詳細を確認できます。  
例: `summary="known Controller device, flow classified as VoiceAssistant, ctx=VoiceAssistant"`  
`detail="local=Controller(known,strong(1.00)) flow=VoiceAssistant(known,strong(0.90)) ctx=VoiceAssistant(known,strong(0.90)) ..."`
public TLS の例では、`learned category=Controller` の端末に対して `observed SNI=alexa.amazon.com` と `flow=VoiceAssistant` が観測され、`I6_DEVICE_FLOW_CATEGORY_MISMATCH` と `category_mismatch_over_tls` によって「Controller が VoiceAssistant 系の TLS 通信をしている」ことを説明できます。
また、`observed SNI=evil-analytics.example.com` のように baseline にない TLS 通信でも、`domain_disposition=suspicious_unmatched` と `medium / investigate` によって「即 block ではないが anomaly 寄りの不一致」であることを表現できます。

通常の `events.jsonl` にはリスクイベントを出力し、開発用イベントは `severity=INFO` かつ `debug=true` として区別します。

## OWASP IoT Top 10 (2018) 対応状況

| Item | Status | Notes |
| --- | --- | --- |
| I1 | partial / related signal | Direct password strength or hardcoded credential detection is out of scope for passive monitoring. Credential exposure in traffic is handled as a related signal via I7. |
| I2 | implemented as insecure network service signal | Telnet, FTP, RTSP, MQTT, CoAP, HTTP management, and related external exposure are handled as explainable service-risk signals. |
| I3 | initial implemented / ecosystem-interface risk signal | API over plaintext, token in URL, management endpoint, weak cloud or backend transport, mobile-backend pattern, and unexpected ecosystem endpoint are handled as passive risk signals. Full API vulnerability testing, authorization testing, CORS/CSRF checks, and cloud-side scanning are out of scope. |
| I4 | implemented as update-risk signal | Firmware or update-like traffic and plaintext update delivery can be observed. Signature verification and rollback protection cannot be confirmed passively. |
| I5 | implemented as known-vulnerable-family/component candidate enrichment | Exact CVE applicability requires model and firmware confirmation. Representative CVEs are enrichment, not proof of impact. |
| I6 | implemented as privacy-risk signal | Privacy-sensitive plaintext, stable identifiers, unexpected privacy destinations, and baseline mismatch are handled as risk signals. Consent or policy violation cannot be confirmed passively. |
| I7 | implemented as insecure transfer signal | Plaintext HTTP, credentials, cookies, tokens, MQTT/Telnet secrets, and related transport exposure are covered. |
| I8 | partial / product feature direction | Device inventory, monitoring, and risk summary are partial today and may expand. |
| I9 | planned as default-setting related signal | Default credential patterns, setup endpoints, and insecure default services are future signal areas. |
| I10 | mostly out of scope | Physical hardening cannot be evaluated passively. Only network-visible debug or factory endpoints may appear as related signals. |

主要イベントは `owasp_tags`, `confidence`, `observed_fact`, `inference`, `limitation`, `recommendation` を持ち、観測事実と推定を分けて説明します。


## I2: Insecure Network Services

IoT デバイスが安全でないネットワークサービスを利用している場合に検知します。

### 検知機能

- Telnet サービスの検知
- FTP サービスの検知
- RTSP サービスの検知
- MQTT サービスの検知
- CoAP サービスの検知
- ポートベースのサービス検知
- プロトコルペイロードの解析によるサービス証拠の検出
- IPv4 / IPv6 の public 宛通信に対する危険なネットワークサービス利用の検出

## I4: Lack of Secure Update Mechanism

更新通信らしい HTTP / TLS 通信を観測し、  
外向き平文 HTTP による更新配送を I4 として検知します。
I4 v1 の考え方は、`update-like communication detection` と `plaintext external update warning` の2つです。

### 検知機能

- HTTP Host / Path の update / firmware ヒューリスティック検知
- TLS SNI の update / firmware ヒューリスティック検知
- `I4_FIRMWARE_UPDATE_OBSERVED` による更新通信観測
- `I4_INSECURE_FIRMWARE_UPDATE_HTTP` による外向き平文更新の warning
- strong / weak キーワード分離によるノイズ抑制

### 実トラフィック確認例

- `GET /firmware host=updates.example.com` では `I4_FIRMWARE_UPDATE_OBSERVED` と `I4_INSECURE_FIRMWARE_UPDATE_HTTP` が出て、外向き平文 HTTP 上の更新配送らしさを説明できます。
- `GET /download host=downloads.example.com` では weak hit のみとして扱い、I4 event は出さず、`I7_HTTP_PLAINTEXT` のみが残ります。
- `observed SNI=firmware-updates.example.com` では `I4_FIRMWARE_UPDATE_OBSERVED` が出ますが、TLS なので plaintext warning は出ません。

### 現在の到達点

- I4 は、完全な firmware 判定ではなく `update / firmware 通信らしさ` を HTTP / TLS メタデータから観測する最小実装です。
- 強いキーワードが path / host / SNI に現れたときに `I4_FIRMWARE_UPDATE_OBSERVED` を出し、外向き平文 HTTP の場合だけ `I4_INSECURE_FIRMWARE_UPDATE_HTTP` を追加で出します。
- そのため、本実装は OWASP IoT Top 10 の I4 に対して、まず `explainable network-side detection` を提供する段階にあります。

### まだ足りない部分

- 署名検証、secure boot、anti-rollback のようなデバイス内部の安全な更新機構そのものは観測できません。
- 更新ファイルの真正性、完全性、バージョン妥当性までは v1 では判断しません。
- `download` や `release` などの一般的な語を weak 扱いに抑えていますが、ベンダごとの正規更新 API まではまだ学習していません。

### 今後の改善候補

- ベンダごとの update domain / path baseline の導入
- update manifest や firmware 配送パターンの識別精度向上
- TLS 証明書や配布先カテゴリを使った secure delivery の補助判定
- 正常更新と不審更新の切り分け説明の強化

## I6: Insufficient Privacy Protection

機器カテゴリごとの通常通信ベースラインと、実際のフローを比較して、  
プライバシー上不自然な通信を検知します。
I6 は HTTP Host だけでなく TLS SNI に対しても baseline 比較を行い、TLS 通信でも想定外ドメインや ecosystem mismatch を説明可能に検知します。
また、パッシブ監視ではデバイス内部やクラウド側に保存された個人情報を直接確認できないため、I6 の at-rest は直接検知ではなく、保存データの存在を示唆する通信シグナルとして扱います。
I6 の考え方は、`baseline comparison`、`novelty vs anomaly-ish separation`、`explainable mismatch`、`stored-data signal detection`、`privacy risk signal / unexpected PII flow signal` です。

### 検知機能

- デバイスカテゴリ推定
- 端末全体カテゴリとフローカテゴリの分離
- カテゴリ不一致の検知
- 想定外ドメインの検知
- プロトコル不一致の検知
- 外向き平文通信の検知
- history / backup / sync / logs 系 endpoint への蓄積データらしい upload 候補の検知
- category に不要寄りの PII が unexpected / analytics / tracking 寄り destination に送られる場合の privacy risk signal / unexpected PII flow signal 検知
- `risk_signals` に基づく総合リスク判定 (`R1_COMPOSITE_RISK`)
- `recommended_action` による初動判断の支援

### 実トラフィック確認例

- `novelty 寄り`: baseline にないが ecosystem 内に収まる通信は `baseline_novelty` として扱い、未学習の正常通信寄りとして観察できます。
- `suspicious_unmatched`: `observed SNI=evil-analytics.example.com` では `domain_disposition=suspicious_unmatched` と `R1_COMPOSITE_RISK=medium / investigate` が出て、baseline 外だが即 block ではない anomaly 寄り通信として説明できます。
- `rooted mismatch`: `learned category=Controller` に対して `observed SNI=alexa.amazon.com` や `api.smartthings.com` が観測されると、`I6_DEVICE_FLOW_CATEGORY_MISMATCH` と `category_mismatch_over_tls` が出て、カテゴリ不一致を説明付きで示せます。
- `stored-data signal`: `POST /v1/history/upload` や `POST /backup/sync` のような保存系 keyword と一定サイズ以上の upload はまず候補として記録し、大きめの upload、同じ endpoint の再観測、stable identifier の再観測などが揃う場合に `I6_STORED_DATA_SIGNAL_OBSERVED` が出ます。privacy-sensitive category は単独では trigger せず、これらの条件に対する補助 signal として扱います。これは「保存済みデータを直接見た」ことではなく、`indirect_at_rest=true` の通信シグナルとして扱います。
- `unexpected PII flow signal`: `Sensor` が `email` や `account_info` など category に不要寄りの PII を analytics / tracking / baseline 外 destination に送る場合、identifier や PII destination の再観測などと合わせて `I6_PII_TO_UNEXPECTED_DESTINATION` が出ます。analytics / tracking は単独 trigger ではなく補助 signal として扱います。同意や許可の有無は断定せず、`consent_observed=false` の privacy risk signal として扱います。

### 現在の到達点

- I6 は、機器カテゴリごとの通信ベースラインから外れる HTTP / TLS 通信を検知し、`risk_signals` と `recommended_action` まで含めて説明できます。
- 特に TLS では、`SNI` を用いた baseline comparison、`baseline_novelty` と `suspicious_unmatched` の分離、`category_mismatch_over_tls` による rooted mismatch の説明が可能です。
- 保存データについては、`history / backup / sync / logs` などの endpoint 語、upload method、upload size、category、同じ endpoint や安定識別子の再観測を組み合わせ、直接検知ではなく保存シグナル候補として説明します。
- unexpected PII flow については、PII type と device category の不一致、baseline 外または analytics/tracking 寄り destination、同一 identifier や destination の再観測を組み合わせ、直接的な同意違反ではなく `privacy risk signal / unexpected PII flow signal` として説明します。
- I3 では、`I3_API_OVER_PLAINTEXT`、`I3_AUTH_TOKEN_IN_URL`、`I3_MANAGEMENT_API_EXPOSED`、`I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL`、`I3_MOBILE_APP_BACKEND_PATTERN_OBSERVED`、`I3_UNEXPECTED_CLOUD_ENDPOINT` を passive ecosystem-interface risk signal として扱います。
- I3 では Full API vulnerability testing、authorization testing、CORS/CSRF、cloud-side scanning は out of scope です。
- そのため、本実装は OWASP IoT Top 10 の I6 に対して、完全な防止機構というより `explainable detection / triage` の役割を果たします。

### まだ足りない部分

- 個人情報そのものの常時識別や、`without permission` に相当する同意・権限の判断まではできません。
- baseline に未登録でも正常なクラウド移行や委託先通信はありうるため、`unexpected_domain` 系 signal だけで異常を断定する設計にはしていません。
- 保存データの扱い、クラウド側での二次利用、ecosystem 全体のポリシー順守までは直接観測できません。
- `I6_STORED_DATA_SIGNAL_OBSERVED` は保存データの存在を断定せず、通信上の間接シグナルだけを示します。
- `I6_PII_TO_UNEXPECTED_DESTINATION` は同意違反やポリシー違反を断定せず、通信上の不自然な PII 利用 signal だけを示します。

### 今後の改善候補

- ベンダ単位 baseline と domain / API / 通信パターンの拡充
- `adjacent / likely-benign` のような中間層の導入
- 通信頻度や複数端末での再観測に基づく軽量スコアリング
- 同一識別子の繰り返し送信、起動直後バースト、複数 flow にまたがる backup / sync の相関
- novelty と anomaly の切り分け、および mismatch 理由の説明性のさらなる改善

## I7: Insecure Data Transfer and Storage

アプリケーション層の通信を解析し、以下を検知します。
現状の主対象は、平文 HTTP における `in-transit` の機密情報露出です。
`at rest` や `during processing` の問題は、パッシブ監視だけでは直接検知できないものがあります。

### 検知機能

- 平文 HTTP 通信の検知
- HTTP Header に含まれる認証情報の検知
  - `Authorization`
  - `Cookie`
  - `Set-Cookie`
  - `X-Api-Key`
  - `X-Auth-Token`
  - `Proxy-Authorization`
- URL Query に含まれる機密情報の検知
  - `password`
  - `token`
  - `access_token`
  - `refresh_token`
  - `session`
  - `sid`
  - `jwt`
  - `wifi_password`
  - `ssid`
  - `psk`
  - `device_id`
  - `serial`
- HTTP Body に含まれる機密情報の検知  
  - `application/x-www-form-urlencoded`
  - `application/json`
  - `multipart/form-data`
  - `text/plain`
  - `application/xml`
  - `text/xml`
- 平文 MQTT 通信の検知
- MQTT CONNECT に含まれる username / password の検知
- MQTT PUBLISH topic / payload に含まれる機密情報の検知
- 平文 Telnet 通信の検知
- Telnet login / password 入力の平文交換検知
- Telnet payload に含まれる機密情報の検知
- `Content-Type` が欠落・不正な場合の body 形式推定
  - `a=b&c=d` の form 推定
  - `{...}` / `[...]` の JSON 推定
  - `<...>` の XML 推定
- 値の特徴による追加検知
  - JWT っぽい値
  - Base64 っぽい値
  - 長いランダムトークン
  - 独自 `token` / `auth` 系キー名と値形状の組み合わせ
- 誤検知を減らすための条件付き検知
  - `session` / `sid` / `jwt` は値がトークンらしい場合に限定
  - `device_id` / `serial` は識別子らしい形式の場合に限定
  - `ssid` は `psk` / `wifi_password` と併存する場合を優先
- TLS ClientHello の解析
- JA3 フィンガープリント生成
- HTTP / TLS メタデータによるデバイス推定
- TCP フロー再構成による通信解析

## TLS解析の強化（ClientHello + ServerHello）

従来の実装では TLS ClientHello のみを解析していましたが、  
本バージョンではフローを双方向で再構成し、ServerHello の解析にも対応しました。

### 追加された機能

- TCPフローをクライアント／サーバ方向で分離
- TLS ServerHello の検出
- TLS バージョンおよび Cipher Suite の取得
- ClientHello + ServerHello の統合的なTLS観測

### 制約

- TLS 1.3 では、Certificate などの後続ハンドシェイクメッセージが暗号化されるため、
  パッシブ監視では取得できない場合があります
- Certificate 情報（subject / issuer / SAN）の取得は、TLS 1.2 など一部の通信に限定されます

このため、本ツールでは TLS 通信の識別において
ClientHello（JA3）・ServerHello・通信先情報などを組み合わせて評価します。
