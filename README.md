# Quarant

**Quarant** は、ホームネットワーク内の IoT デバイスを保護するためのカスタムセキュリティゲートウェイです。

<!-- ## Features

- IoT ネットワーク通信のパッシブ監視
- TCP フロー再構成によるアプリケーション層解析
- 平文通信の検知（OWASP IoT Top10: I7）
- 危険なネットワークサービスの検知（OWASP IoT Top10: I2）
- 観測された通信に基づく IoT デバイスのリスク推定
- JSONL 形式によるセキュリティイベント出力 -->

## OWASP IoT Top 10 (2018) 対応状況

- [ ] I1: Weak, Guessable, or Hardcoded Passwords
- [x] I2: Insecure Network Services
- [ ] I3: Insecure Ecosystem Interfaces
- [ ] I4: Lack of Secure Update Mechanism
- [ ] I5: Use of Insecure or Outdated Components
- [ ] I6: Insufficient Privacy Protection
- [x] I7: Insecure Data Transfer and Storage
- [ ] I8: Lack of Device Management
- [ ] I9: Insecure Default Settings
- [ ] I10: Lack of Physical Hardening


## I2: Insecure Network Services

IoTデバイスが安全でないネットワークサービスを利用している場合に検知します。

### 検知機能

- Telnet サービスの検知
- FTP サービスの検知
- RTSP サービスの検知
- MQTT サービスの検知
- CoAP サービスの検知
- ポートベースのサービス検知
- プロトコルペイロードの解析によるサービス証拠の検出
- 危険なネットワークサービス利用の検出
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



カテゴリ推定DB

```Fingerbank``` 
端末推定の起点に最適
DHCP, hostname, JA3, MAC から候補を出せる
404 は「その属性では一致なし」という扱いも明確
https://api.fingerbank.org/api_doc/2/combinations/interrogate.html
公式ベンダ開発者サイト
代表ドメイン、API名、クラウド依存先、製品系統を拾いやすい
例:
Philips Hue: discovery.meethue.com やローカル/HTTPS APIの情報
https://developers.meethue.com/develop/get-started-2/
SmartThings: APIやHub/Deviceイベントの構造
https://developer.smartthings.com/docs/getting-started/choose-your-tools
Garmin: Garmin Connect / wearable 系API
https://developer.garmin.com/gc-developer-program/overview/
Fitbit: Fitbit Web API
https://dev.fitbit.com/apps.
挙動ベースレイヤ
公式API / 開発者ドキュメント
「どこに通信するのが普通か」を作るのに一番使いやすい
例:
Hue: bridge discovery, local API
SmartThings: device/hub events, webhook
Garmin/Fitbit: cloud sync前提の通信
実観測データ
pcap, DNS, TLS SNI, HTTP Host, frequency
これは最終的に一番重要
リスク照合レイヤ
NVD
CVE, CVSS, CPE を機械処理しやすい
https://nvd.nist.gov/general
API: https://nvd.nist.gov/developers/vulnerabilities
CISA KEV
「実際に悪用されているか」の優先度付けに強い
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
ベンダのセキュリティアドバイザリ
NVDより製品粒度が細かいことが多い