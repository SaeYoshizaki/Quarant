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
