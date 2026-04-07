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

## OWASP IoT Top 10 (2018) 対応状況

- [ ] I1: Weak, Guessable, or Hardcoded Passwords
- [x] I2: Insecure Network Services
- [ ] I3: Insecure Ecosystem Interfaces
- [ ] I4: Lack of Secure Update Mechanism
- [ ] I5: Use of Insecure or Outdated Components
- [x] I6: Insufficient Privacy Protection
- [x] I7: Insecure Data Transfer and Storage
- [ ] I8: Lack of Device Management
- [ ] I9: Insecure Default Settings
- [ ] I10: Lack of Physical Hardening


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
- 危険なネットワークサービス利用の検出

## I6: Insufficient Privacy Protection

機器カテゴリごとの通常通信ベースラインと、実際のフローを比較して、  
プライバシー上不自然な通信を検知します。
I6 は HTTP Host だけでなく TLS SNI に対しても baseline 比較を行い、TLS 通信でも想定外ドメインや ecosystem mismatch を説明可能に検知します。

### 検知機能

- デバイスカテゴリ推定
- 端末全体カテゴリとフローカテゴリの分離
- カテゴリ不一致の検知
- 想定外ドメインの検知
- プロトコル不一致の検知
- 外向き平文通信の検知
- `risk_signals` に基づく総合リスク判定 (`R1_COMPOSITE_RISK`)
- `recommended_action` による初動判断の支援

## I7: Insecure Data Transfer and Storage

アプリケーション層の通信を解析し、以下を検知します。

### 検知機能

- 平文 HTTP 通信の検知
- HTTP Header に含まれる認証情報の検知
- URL Query に含まれる機密情報の検知
- HTTP Body に含まれる機密情報の検知  
  - `application/x-www-form-urlencoded`
  - `application/json`
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
