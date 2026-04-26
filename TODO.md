## OWASP signal-based coverage

- [x] I1: partial / related signal
  - Direct password strength or hardcoded credential detection remains out of scope for passive monitoring.
  - Credential exposure in traffic is treated as a related signal via I7.

- [x] I2: implemented as insecure network service signal
  - Telnet, FTP, RTSP, MQTT, CoAP, HTTP management, and external exposure are covered as explainable service-risk signals.

- [x] I3: initial implemented / ecosystem-interface risk signal
  - API over plaintext, token in URL, management endpoint, weak cloud/backend transport, mobile-backend pattern, and unexpected ecosystem endpoint are handled as passive risk signals.
  - Full API vulnerability testing, authorization testing, CORS/CSRF, and cloud-side scanning remain out of scope.

- [x] I4: implemented as update-risk signal
  - Firmware or update-like traffic and plaintext update delivery are observable.
  - Signature verification and rollback protection cannot be confirmed passively.

- [x] I5: implemented as known-vulnerable-family/component candidate enrichment
  - Exact CVE applicability still requires model and firmware confirmation.

- [x] I6: implemented as privacy-risk signal
  - Privacy-sensitive plaintext, stable identifiers, unexpected privacy destinations, and baseline mismatch are covered.
  - Consent or policy violation cannot be confirmed passively.

- [x] I7: implemented as insecure transfer signal
  - Plaintext HTTP, credentials, cookies, tokens, MQTT/Telnet secrets, and related transport exposure are covered.

- [x] I8: partial / device-management support signal
  - Passive monitoring cannot prove that device management is absent.
  - Quarant keeps per-device inventory state, unknown or low-confidence identity candidates, and per-device risk summaries as management-supporting signals.
  - `device_inventory.json` can be exported from the passive inventory snapshot for external review.
  - Existing risk events remain the primary source; I8 organizes them per device rather than asserting a management failure.

- [x] I9: partial / default-setting related signal
  - Passive monitoring cannot confirm that a device remains in factory-default state.
  - Quarant handles setup/onboarding endpoint exposure, default hostname-like patterns, and risky services left enabled as I9-related risk signals.
  - Insecure default password detection is only handled indirectly when credentials are exposed in traffic or default credential-like patterns are observed.

- [ ] I10: mostly out of scope
  - Physical hardening cannot be evaluated passively.
  - Network-visible debug or factory endpoints may be handled as related signals only.

- [x] Event metadata cleanup
  - Major I2/I4/I5/I6/I7 events now carry `owasp_tags`, `confidence`, `observed_fact`, `inference`, `limitation`, and `recommendation`.
  - Debug events are marked with `debug=true` and kept at `INFO`.

## 判定対象の拡大
- [ ] 監視プロトコルの追加 (UPnP, ONVIF, SSDPとか)
- [ ] 各プロトコルのリスク配分(Weight)の再評価

## リスク計算ロジックの進化
- [ ] 要素同士を組み合わせた計算方法を作成
      「管理画面がある」だけなら25点だけど、「管理画面があって、かつ外部露出している」なら一気に100点にする
- [ ] Confidenceとscoreを連動させる
      「90%の確率でカメラ（0.9）」と「10%の確率（0.1）」では、リスクの重みが違うはず。Confidenceを点数に掛け算する等する

## デバイス特定の精度向上
- [ ] UserAgent と Vendor の整合性チェック
      Vendorが「Sony」なのに、UserAgentが「AppleWebKit」だったら、偽装された通信かもしれない。
- [ ] JA3 指紋による異常検知
      急にJA3が変わったら、乗っ取られた可能性がある。

## `humanizeReasons` の辞書を充実させる
- [ ] 現状は`insufficient_evidence`のみで読みにくい。`admin_suspected` や `external_exposure` など、`profile.go` で定義したフラグに対応するメッセージを追加したい。
- [ ] 一般ユーザー向けに日本語化するレイヤーをフロント側に作る

## カテゴリー不一致の検知強化
- [ ] いまは単にログに並べて出しているだけだけど、ここが食い違った時に「警告（Alert）」を出すようにしたい
      `localCategory`:プリンター
      `flowCategory`: 攻撃用サーバー
      だったら、デバイスが乗っ取られている証拠になる。

## ファームウェアが更新の確認方法の追加(i4)
- [ ] トラフィック・バースト検知
      「5分間で100MB以上のバースト通信」などの統計的パターンから、暗号化されていてもアップデートと推測するロジックの構築。
- [ ] コンボ判定の導入
      OCSPリクエスト（証明書確認）の直後に特定ドメインへの大容量通信が発生した際、信頼度の高いアップデートとしてフラグを立てる。

## ファームウェアのアップデートが行われているかの判定条件の緩和(i4)

- [ ] 条件を減らす（誤検知はしないように）
       現状の `I4_INSECURE_FIRMWARE_UPDATE_HTTP` は条件全てが揃わないと警告が出ないため、厳格すぎて一部の脆弱性を見逃している可能性がある。
       
       改善案：
       弱いキーワード（`update`, `download`）でも、送信データ量が多い場合は警告を出すとか

## I6: 今回やり終えたこと

- [x] I6 のパッシブ監視スコープを明文化した
  - デバイス内部やクラウド側に「個人情報が保存されていること」は直接観測できない
  - `without permission` や UI 上の同意状態は直接判定しない
  - 直接検知ではなく、通信上の privacy risk signal として扱う方針に整理

- [x] baseline / category mismatch による I6 検知を整理した
  - HTTP Host / TLS SNI を category baseline と比較
  - `baseline_novelty` と `suspicious_unmatched` を分離
  - `I6_DEVICE_FLOW_CATEGORY_MISMATCH` で local category と flow category の不一致を説明

- [x] stored-data signal の最小実装を追加した
  - `history / backup / sync / logs` 系 endpoint を直接保存検知ではなく保存シグナル候補として扱う
  - upload method、upload size、endpoint 再観測、stable identifier 再観測を組み合わせる
  - `I6_STORED_DATA_SIGNAL_OBSERVED` は `indirect_at_rest=true` / `direct_storage_observed=false` を evidence に残す

- [x] privacy risk signal / unexpected PII flow signal の最小実装を追加した
  - category に不要寄りの PII type と unexpected / analytics / tracking 寄り destination の組み合わせを検知
  - `I6_PII_TO_UNEXPECTED_DESTINATION` は同意違反やポリシー違反を断定せず、`consent_observed=false` / `consent_inferred=false` を evidence に残す
  - analytics / tracking は単独 trigger ではなく、identifier や destination の再観測に対する補助 signal として扱う

- [x] I6 の観測 state を privacy-preserving にした
  - raw identifier は保存せず fingerprint / endpoint / destination の軽量 count のみ保持
  - observation window と map size 上限を追加し、古い再観測が無期限に repeat 扱いされないようにした

## I6: 追加でいつかやるべきこと

- [ ] category policy の精度向上
  - `allowed_pii_types` をカテゴリごとに精査する
  - `Sensor` / `Camera` / `Wearable` / `VoiceAssistant` などで「不要寄り PII」をもう少し細かく定義する
  - 現状の policy は粗いので、実 pcap / サンプルイベントで false positive を確認しながら調整する

- [ ] analytics / tracking / ad-tech destination knowledge の追加
  - 現状は host keyword による素朴な判定
  - 小さな knowledge JSON として known analytics / ad-tech domain pattern を持たせる
  - vendor ecosystem 内の telemetry と third-party tracking を分けて説明できるようにする

- [ ] TLS で PII 本文が見えない場合の補助 signal 整理
  - HTTPS では PII 内容を見られないため、SNI / destination / frequency / size だけで扱う必要がある
  - TLS 上の `unexpected destination + repeated identifier-like flow` を低 confidence signal として扱うか検討する

- [ ] 起動直後バースト / repeated sync の時間窓を改善
  - 現状は endpoint / identifier / PII destination の軽量 count 中心
  - device first_seen 直後の burst、短時間の複数 upload、複数 destination への拡散をもう少し説明可能にする

- [ ] I7 との接続を整理する
  - 平文 HTTP 上で PII が見えている場合、I7 は in-transit の露出、I6 は privacy risk signal / unexpected PII flow signal として役割を分ける
  - event evidence に関連 event type を入れるか、report 側でまとめるか検討する

- [ ] mitigation への接続
  - `R1_COMPOSITE_RISK` の recommended action を通知 / ブロック / 隔離候補に接続する
  - ただし I6 は signal ベースなので、単独で block しすぎない運用ルールを考える

## I7: HTTP 範囲で今回やり終えたこと

- [x] I7 の現状スコープを明文化した
  - 現状は「平文 HTTP 中心の in-transit 検知」であることを README / TODO 上で明記
  - `header` / `query` / `body` の観測範囲を整理
  - `at rest` / `during processing` はパッシブ監視だけでは直接検知しにくいことを明記

- [x] 平文 HTTP の機密情報検知を拡張した
  - header: `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, `Proxy-Authorization`
  - header: 独自 `token` / `auth` 系ヘッダーも値の形と合わせて検知
## I6: 今回やり終えたこと

- [x] I6 のパッシブ監視スコープを明文化した
  - デバイス内部やクラウド側に「個人情報が保存されていること」は直接観測できない
  - `without permission` や UI 上の同意状態は直接判定しない
  - 直接検知ではなく、通信上の privacy risk signal として扱う方針に整理

- [x] baseline / category mismatch による I6 検知を整理した
  - HTTP Host / TLS SNI を category baseline と比較
  - `baseline_novelty` と `suspicious_unmatched` を分離
  - `I6_DEVICE_FLOW_CATEGORY_MISMATCH` で local category と flow category の不一致を説明

- [x] stored-data signal の最小実装を追加した
  - `history / backup / sync / logs` 系 endpoint を直接保存検知ではなく保存シグナル候補として扱う
  - upload method、upload size、endpoint 再観測、stable identifier 再観測を組み合わせる
  - `I6_STORED_DATA_SIGNAL_OBSERVED` は `indirect_at_rest=true` / `direct_storage_observed=false` を evidence に残す

- [x] privacy risk signal / unexpected PII flow signal の最小実装を追加した
  - category に不要寄りの PII type と unexpected / analytics / tracking 寄り destination の組み合わせを検知
  - `I6_PII_TO_UNEXPECTED_DESTINATION` は同意違反やポリシー違反を断定せず、`consent_observed=false` / `consent_inferred=false` を evidence に残す
  - analytics / tracking は単独 trigger ではなく、identifier や destination の再観測に対する補助 signal として扱う

- [x] I6 の観測 state を privacy-preserving にした
  - raw identifier は保存せず fingerprint / endpoint / destination の軽量 count のみ保持
  - observation window と map size 上限を追加し、古い再観測が無期限に repeat 扱いされないようにした

## I6: 追加でいつかやるべきこと

- [ ] category policy の精度向上
  - `allowed_pii_types` をカテゴリごとに精査する
  - `Sensor` / `Camera` / `Wearable` / `VoiceAssistant` などで「不要寄り PII」をもう少し細かく定義する
  - 現状の policy は粗いので、実 pcap / サンプルイベントで false positive を確認しながら調整する

- [ ] analytics / tracking / ad-tech destination knowledge の追加
  - 現状は host keyword による素朴な判定
  - 小さな knowledge JSON として known analytics / ad-tech domain pattern を持たせる
  - vendor ecosystem 内の telemetry と third-party tracking を分けて説明できるようにする

- [ ] TLS で PII 本文が見えない場合の補助 signal 整理
  - HTTPS では PII 内容を見られないため、SNI / destination / frequency / size だけで扱う必要がある
  - TLS 上の `unexpected destination + repeated identifier-like flow` を低 confidence signal として扱うか検討する

- [ ] 起動直後バースト / repeated sync の時間窓を改善
  - 現状は endpoint / identifier / PII destination の軽量 count 中心
  - device first_seen 直後の burst、短時間の複数 upload、複数 destination への拡散をもう少し説明可能にする

- [ ] I7 との接続を整理する
  - 平文 HTTP 上で PII が見えている場合、I7 は in-transit の露出、I6 は privacy risk signal / unexpected PII flow signal として役割を分ける
  - event evidence に関連 event type を入れるか、report 側でまとめるか検討する

- [ ] mitigation への接続
  - `R1_COMPOSITE_RISK` の recommended action を通知 / ブロック / 隔離候補に接続する
  - ただし I6 は signal ベースなので、単独で block しすぎない運用ルールを考える

## I7: HTTP 範囲で今回やり終えたこと

- [x] I7 の現状スコープを明文化した
  - 現状は「平文 HTTP 中心の in-transit 検知」であることを README / TODO 上で明記
  - `header` / `query` / `body` の観測範囲を整理
  - `at rest` / `during processing` はパッシブ監視だけでは直接検知しにくいことを明記

- [x] 平文 HTTP の機密情報検知を拡張した
  - header: `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, `Proxy-Authorization`
  - header: 独自 `token` / `auth` 系ヘッダーも値の形と合わせて検知
  - query: `refresh_token`, `session`, `sid`, `jwt`, `wifi_password`, `ssid`, `psk`, `device_id`, `serial` などを追加
  - body: `application/x-www-form-urlencoded`, `application/json`, `multipart/form-data`, `text/plain`, XML に対応
  - `Content-Type` が欠落・不正でも body の見た目から形式を推定

- [x] 値特徴ベースの検知を追加した
  - JWT っぽい値
  - Base64 っぽい値
  - 長いランダムトークン
  - 独自 `token` / `auth` 系キー名と値形状の組み合わせ

- [x] 誤検知抑制を追加した
  - `session` / `sid` / `jwt` は値がトークンらしい場合に限定
  - `device_id` / `serial` は識別子らしい形式の場合に限定
  - `ssid` は `psk` / `wifi_password` と併存する場合を優先
  - 正常系の header / query / body サンプルで過検知しないことをテスト

- [x] I7 HTTP の評価用サンプルを追加した
  - form body に password を含む通信
  - JSON body に token / session を含む通信
  - query に password / token / session / device_id を含む通信
  - header に Authorization / Cookie / X-Api-Key / X-Auth-Token / Proxy-Authorization を含む通信
  - 独自認証ヘッダーと誤検知確認用の正常通信

## I7: 追加でいつかやるべきこと

- [ ] HTTP 以外の平文通信
  - [x] MQTT 上の認証情報・機密情報の検知
  - FTP 上の認証情報・ファイル転送の検知
  - [x] Telnet 上の認証情報送信の検知
  - RTSP URL 内の認証情報検知
  - DNS query に機密情報が載っていないか確認
  - 独自 TCP 平文プロトコルの簡易検知を検討

- [ ] TLS / HTTPS hygiene
  - 機密通信で HTTPS が使われていないケースを整理する
  - TLS を使うべき通信先なのに平文 HTTP になっているパターンを検知する
  - 古い TLS バージョンや弱い暗号スイートの検知を検討する
  - 証明書異常や自己署名証明書の扱いを整理する

- [ ] IoT 固有の機密情報整理
  - Wi-Fi 資格情報
  - クラウド API キー
  - デバイス識別子
  - ストリーム URL
  - MQTT 認証情報
  - RTSP 認証情報
  - ファームウェア更新 URL / update token

- [ ] デバイス種別ごとの危険情報候補整理
  - カメラ
  - ルーター
  - センサー
  - ハブ
  - 音声アシスタント
