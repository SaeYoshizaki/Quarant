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

## I7: scope と拡張方針の整理

- [x] I7 の現状スコープを明文化する
  - 現状は「平文 HTTP 中心の in-transit 検知」であることを README / TODO 上で明記する
  - `header` / `query` / `body` のどこを見ているかを整理する
  - `at rest` / `during processing` はパッシブ監視だけでは直接検知しにくいことを明記する

### 既存で実装済みのもの

- [x] 平文 HTTP 通信の検知
- [x] HTTP Header の認証情報検知
  - `Authorization`
  - `Cookie`
  - `Set-Cookie`
- [x] HTTP query の機密パラメータ検知
  - `password`
  - `token`
  - `access_token`
  - `apikey`
  - `api_key`
  - `secret`
  - `client_secret`
- [x] HTTP body の機密情報検知
  - `application/x-www-form-urlencoded`
  - `application/json`
  - `session`
  - `sid`

### 優先度高: HTTP 検知の拡張

- [x] `Content-Type` に依存しすぎない body 判定を追加する
  - `Content-Type` が欠落・不正でも body の見た目から形式を推定する
  - `a=b&c=d` なら form として扱う
  - `{...}` / `[...]` なら JSON として扱う
  - IoT 機器の雑な実装への対応を強化する

- [x] HTTP query の機密パラメータ辞書を拡張する
  - 既存 query 辞書に加えて以下を追加検討
  - `refresh_token`
  - `session`
  - `sid`
  - `jwt`
  - `wifi_password`
  - `ssid`
  - `psk`
  - `device_id`
  - `serial`

- [ ] HTTP header の追加検知を行う
  - `X-Api-Key`
  - `X-Auth-Token`
  - `Proxy-Authorization`
  - 独自認証ヘッダー候補の整理

- [x] HTTP body の対応形式を拡張する
  - `multipart/form-data`
  - `text/plain`
  - XML (`application/xml`, `text/xml`)

- [x] IoT 向け機密キーワード辞書を拡張する
  - `client_key`
  - `private_key`
  - `mqtt_user`
  - `mqtt_pass`
  - `rtsp_url`
  - `update_token`

### 優先度中: 値特徴と誤検知抑制

- [x] 値そのものの特徴による検知を追加する
  - JWT っぽい値
  - Base64 っぽい値
  - 長いランダムトークン
  - メールアドレス / 電話番号 / GPS 座標などの個人情報候補

- [x] 誤検知を減らす条件を追加する
  - キー名だけでなく値の特徴も併用する
  - `device_id` や `serial` を過剰検知しない条件を設ける
  - 検知率と誤検知率のバランスを評価する

- [x] I7 の評価用テストケースを追加する
  - form body に password を含む通信
  - JSON body に token を含む通信
  - query に password / token / session を含む通信
  - header に Authorization / Cookie / X-Api-Key を含む通信
  - IoT らしいキー名を含む通信
  - 誤検知確認用の正常通信

### 別トラック: HTTP 以外の平文通信

- [ ] MQTT 上の認証情報・機密情報の検知
- [ ] FTP 上の認証情報・ファイル転送の検知
- [ ] Telnet 上の認証情報送信の検知
- [ ] RTSP URL 内の認証情報検知
- [ ] DNS query に機密情報が載っていないか確認
- [ ] 独自 TCP 平文プロトコルの簡易検知を検討

### 別トラック: TLS / HTTPS hygiene

- [ ] 機密通信で HTTPS が使われていないケースを整理する
- [ ] TLS を使うべき通信先なのに平文 HTTP になっているパターンを検知する
- [ ] 古い TLS バージョンや弱い暗号スイートの検知を検討する
- [ ] 証明書異常や自己署名証明書の扱いを整理する

### 別トラック: IoT 固有の機密情報整理

- [ ] IoT 向け機密カテゴリを整理する
  - Wi-Fi 資格情報
  - クラウド API キー
  - デバイス識別子
  - ストリーム URL
  - MQTT 認証情報
  - RTSP 認証情報
  - ファームウェア更新 URL / update token

- [ ] デバイス種別ごとに危険情報の候補を整理する
  - カメラ
  - ルーター
  - センサー
  - ハブ
  - 音声アシスタント
