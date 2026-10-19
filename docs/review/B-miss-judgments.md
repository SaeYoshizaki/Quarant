# 確認 B：見逃しの正解の判定（E11〜E14）

見逃しを測るとき、Quarant とは独立に元の通信から作った「正解の候補」（キー名や方式名が秘密らしいもの、メディアらしいもの）を、Claude が 1 件ずつ「本物／数えない／判断できない」と判定した（`docs/assessment/miss-judgments.json`）。網羅性の数字（例：見たことのない 45 台で 8/8）の元になる。

## 確認のしかた

- 各項目の Claude の判定を読んで、**容認する**か**変更する**にチェックを付ける。変更する場合は、メモ欄にどの判定にするか（本物／数えない／判断できない）を書く。
- 値（パスワードなど）は誰も見ていない。キー名、方式名、ポート、向き、本文の形だけで判断している。
- 基準の確認（human-review-accuracy.md）で決めた読み方（文言どおり）に沿っている。利用者の厳しい読み方では「数えない」の一部（署名、識別子など）が「本物」になるが、それは出現率の表（厳しい読み方）の側で扱っている。

全 41 項目（同じ内容のものはまとめた）。

---

### B01　Withings のベビーモニター

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：平文の HTTP の本文に `sessionid`・`auth` のキーを入れて withings.net へ送る。応答にも `sessionid`
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Withings baby monitor: sessionid/auth keys in cleartext HTTP bodies to withings.net, sessionid in responses

MAC：00:24:e4:10:ee:4c, 00:24:e4:11:18:a8

</details>

### B02　Withings の体重計

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：同上
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Withings scale: sessionid/auth keys in cleartext HTTP bodies to withings.net, sessionid in responses

MAC：00:24:e4:1b:6f:96

</details>

### B03　Withings の睡眠センサー（Aura）

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：同上
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Withings Aura sleep sensor: sessionid/auth keys in cleartext HTTP bodies to withings.net, sessionid in responses

MAC：00:24:e4:20:28:c6

</details>

### B04　Insteon のカメラ

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：アプリが 34100 番ポートの平文の HTTP で、URL にユーザー名とパスワードを入れてログインする（LAN 内）。カメラの応答にもパスワードのキーがある
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Insteon camera: app logs in with user and password in the URL over HTTP on port 34100 (LAN); password keys in the camera's responses

MAC：00:62:6e:51:27:2e

</details>

### B05　iHome

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：LAN 内の平文の HTTP の本文に `evrythng.api_key`
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

iHome: evrythng.api_key in a cleartext HTTP body (LAN)

MAC：74:c6:3b:29:d7:1d

</details>

### B06　Invoxia

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：自社のサーバーへの平文の HTTP で `Authorization: Basic`
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Invoxia: Authorization Basic to its server over HTTP

MAC：18:b7:9e:02:20:44

</details>

### B07　HP のプリンタ

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：管理画面のセッションの Cookie と `X-Privet-Token`（LAN 内、平文の HTTP）。おそらく秘密
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

HP printer: management-page session cookies and X-Privet-Token over HTTP (LAN); probable

MAC：70:5a:0f:e4:9b:c0

</details>

### B08　TP-Link のカメラ

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：平文の HTTP で Basic 認証と `x-token`。設定の応答にパスワードのキー
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

TP-Link camera: Basic auth and x-token over HTTP; password keys in its config responses

MAC：f4:f2:6d:93:51:f1

</details>

### B09　Amazon の機器

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：URL の `sid=`。何のセッションか分からない
- Claude の判定：**判断できない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Amazon: sid= URL parameter; what session it is is unknown

MAC：44:65:0d:56:cc:d3

</details>

### B10　Belkin

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW traces 2016
- 観測：たまたま `pwd` を含むランダムな文字列と、UPnP のイベント購読の `SID`
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Belkin: a random string that happens to contain 'pwd'; UPnP GENA SID

MAC：ec:1a:59:79:f4:89, ec:1a:59:83:28:11

</details>

### B11　TP-Link のカメラ

- 種類：メディアの平文送信（5.8-1）
- データ：UNSW traces 2016
- 観測：tplinkcloud.com へ、平文の HTTP の multipart の POST で、h264 の映像と AAC の音声を送る
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

TP-Link camera: h264 video and AAC audio in a multipart POST to tplinkcloud.com over HTTP

MAC：f4:f2:6d:93:51:f1

</details>

### B12　Philips Hue

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 active、CIC IoT 2022 idle、CIC IoT 2022 interactions、CIC IoT 2022 power-on、IoT-23 2018-19、UNSW attacks 2018
- 観測：平文の HTTP で `Authorization: CBAuth` と `auth=`
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Philips Hue: Authorization CBAuth and auth= over HTTP

MAC：00:17:88:2b:9a:25, 00:17:88:60:d6:4f, 00:17:88:75:b3:82

</details>

### B13　Tuya の ESP 機器

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW attacks 2018
- 観測：1883 番（暗号化なし）の MQTT にパスワード付きで接続（URL の `sign` は署名なので数えない）
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Tuya ESP device: MQTT CONNECT with password on 1883 ('sign' URL parameter is a signature and not counted)

MAC：84:f3:eb:52:42:db

</details>

### B14　IoT ではない機器（PC）。除外リストから漏れていた

- 種類：平文の秘密情報（5.5-6）
- データ：UNSW attacks 2018
- 観測：IoT ではない機器（PC）。除外リストから漏れていた
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

not an IoT device (PC); missing from the exclusion list

MAC：08:2e:5f:25:88:e5, 2c:27:d7:3b:e1:05, 8c:85:90:1c:a7:d4

</details>

### B15　Zeek が、720 バイトの API の本文を音声と推定したもの。Hue にマイクはない

- 種類：メディアの平文送信（5.8-1）
- データ：UNSW attacks 2018
- 観測：Zeek が、720 バイトの API の本文を音声と推定したもの。Hue にマイクはない
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Zeek's content sniffing guessed audio for a 720-byte API body; the Hue has no microphone

MAC：00:17:88:2b:9a:25

</details>

### B16　closeli のカメラ

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 idle、CIC IoT 2022 power-on
- 観測：本文の `sign` は要求ごとの署名
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

closeli camera: 'sign' body key is a request signature

MAC：44:01:bb:ec:10:4a

</details>

### B17　Borun のカメラ

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 active、CIC IoT 2022 idle、CIC IoT 2022 power-on
- 観測：本文の `sign` は要求ごとの署名
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Borun camera: 'sign' body key is a request signature

MAC：c0:e7:bf:0a:79:d1

</details>

### B18　Amcrest

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 idle、CIC IoT 2022 interactions、CIC IoT 2022 power-on
- 観測：`Authorization: WSSE`（パスワードと乱数から作るダイジェスト）。Digest 認証と同じ扱い
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Amcrest: Authorization WSSE (per-request password digest), treated like Digest

MAC：9c:8e:cd:1d:ab:9f

</details>

### B19　Sonos

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 idle
- 観測：`sonosid`・`householdid`・`serial` は識別子。`pwd` はダウンロード中のバイナリの偶然の一致
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Sonos: sonosid/householdid/serial are identifiers; 'pwd' matched inside a binary download

MAC：48:a6:b8:f9:1b:88

</details>

### B20　Luohe のカメラ

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 interactions
- 観測：外部の相手から、UDP の P2P 通信で `user=`・`pwd=` のログイン情報が平文で届く
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Luohe camera: user=/pwd= login sent in cleartext over UDP P2P from WAN peers

MAC：7c:a7:b0:cd:18:32

</details>

### B21　Sonos

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 interactions
- 観測：ラジオ配信サーバーが渡す `AISSessionId` の Cookie
- Claude の判定：**判断できない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Sonos: AISSessionId cookie set by a radio streaming server

MAC：48:a6:b8:f9:1b:88

</details>

### B22　Sonos

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 scenarios
- 観測：TuneIn の URL の `sid=`（E8 でも判断保留）
- Claude の判定：**判断できない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Sonos: sid= in TuneIn URLs (E8: undecided)

MAC：48:a6:b8:f9:1b:88

</details>

### B23　Home Eye

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 active
- 観測：`pwd` は JPEG のデータの中の偶然の一致。`Authorization: OSS` は要求ごとの署名
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Home Eye: 'pwd' matched inside JPEG data; Authorization OSS is a request signature

MAC：34:75:63:73:f3:36

</details>

### B24　RTSP の総当たり攻撃

- 種類：平文の秘密情報（5.5-6）
- データ：CIC IoT 2022 RTSP attacks
- 観測：認証情報は攻撃者の推測で、機器自身のものではない
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

RTSP brute force: the credentials are the attacker's guesses, not the device's

MAC：10:2c:6b:1b:43:be, 44:01:bb:ec:10:4a, 7c:a7:b0:cd:18:32, 9c:8e:cd:1d:ab:9f

</details>

### B25　Home Eye

- 種類：メディアの平文送信（5.8-1）
- データ：CIC IoT 2022 active、CIC IoT 2022 idle、CIC IoT 2022 power-on
- 観測：平文の HTTP で、Alibaba OSS に JPEG を PUT
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Home Eye: JPEG PUT to Alibaba OSS over HTTP

MAC：34:75:63:73:f3:36

</details>

### B26　Borun のカメラ

- 種類：メディアの平文送信（5.8-1）
- データ：CIC IoT 2022 power-on
- 観測：独自の平文の TCP のプロトコルで、8899 番ポートに JPEG を送る
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Borun camera: JPEG inside a proprietary cleartext TCP protocol to port 8899

MAC：c0:e7:bf:0a:79:d1

</details>

### B27　SimCam

- 種類：メディアの平文送信（5.8-1）
- データ：CIC IoT 2022 active
- 観測：平文の HTTP で、S3 に JPEG を PUT
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

SimCam: JPEG PUT to S3 over HTTP

MAC：10:2c:6b:1b:43:be

</details>

### B28　Home Eye

- 種類：Quarant の検出の正誤（5.5-6）
- データ：CIC IoT 2022 active、CIC IoT 2022 idle、CIC IoT 2022 power-on
- 観測：Quarant が `Authorization: OSS`（要求ごとの署名）を秘密として数えていた（Quarant 側の誤検出）
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Home Eye: Quarant counted Authorization OSS (per-request signature) as a CSP

MAC：34:75:63:73:f3:36

</details>

### B29　Philips Hue

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：平文の HTTP で Authorization ヘッダと `auth=`
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Philips Hue: Authorization header and auth= over HTTP

MAC：00:17:88:21:f7:e4

</details>

### B30　Samsung のスマートテレビ

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：平文の HTTP の Cookie（基準 S9）。`d_visid_ver`・`mboxsession` は解析サービスの識別子
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Samsung smart TV: cookies over HTTP (criterion S9); the d_visid_ver/mboxsession parameters are analytics identifiers

MAC：7c:64:56:60:71:74

</details>

### B31　Roku 4

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：appboot.netflix.com への平文の HTTP の Cookie（S9）。応答の Netflix の MSL のトークンは、それ自体が暗号化・署名されているので数えない
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Roku 4: cookies to appboot.netflix.com over HTTP (S9); Netflix MSL tokens in responses are themselves encrypted and signed, not counted

MAC：08:05:81:ee:06:46

</details>

### B32　Roku TV

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：appboot.netflix.com への平文の HTTP の Cookie（S9）
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Roku TV: cookies to appboot.netflix.com over HTTP (S9)

MAC：30:52:cb:a3:4f:5f

</details>

### B33　MiCasaVerde VeraLite

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：外部の FTP サーバー（21 番）に、`USER` と `PASS` を平文で送る（36 回）
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

MiCasaVerde VeraLite: FTP USER and PASS in cleartext to an external FTP server (port 21), 36 sessions

MAC：94:4a:0c:08:7e:72

</details>

### B34　Logitech Harmony Hub

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：平文の HTTP の、12KB の JSON（サービスの案内）に並んだ URL の中に `?logitech-api-key=<GUID>`。全部の Hub に配られる共通のキーの可能性が高く、秘密かは通信から判断できない（最初は「本物」としたが、応答の形を値を伏せて確かめて変えた）
- Claude の判定：**判断できない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Logitech Harmony Hub: a 12 KB JSON service-discovery document from svcs.myharmony.com over HTTP lists service URLs carrying ?logitech-api-key=<GUID>. The key is part of URLs handed to every hub and is likely a shared application key, so whether it is a critical security parameter cannot be told from traffic (first judged real; revised after looking at the shape of the response, values masked).

MAC：c8:db:26:02:bb:bb

</details>

### B35　Securifi Almond

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：Google のページの中の `authuser`
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Securifi Almond: 'authuser' in a Google web page

MAC：e4:71:85:25:ce:ec

</details>

### B36　Sonos

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：`sonosid` は識別子
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Sonos: sonosid is an identifier

MAC：5c:aa:fd:6c:e0:d4

</details>

### B37　LIFX

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：mDNS の TXT レコードの `sid=`
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

LIFX: sid= in an mDNS TXT record

MAC：d0:73:d5:12:84:d1

</details>

### B38　Ring Doorbell

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：外部のサーバーへの平文の HTTP で `Authorization: Basic`（2018-04-11）
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Ring Doorbell: Authorization Basic to an external server over HTTP (2018-04-11)

MAC：00:1d:c9:23:f6:00

</details>

### B39　August Doorbell Cam

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：外部のサーバーへの平文の HTTP の URL に `auth=`（2018-04-11）
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

August Doorbell Cam: auth= in a cleartext HTTP URL to an external server (2018-04-11)

MAC：cc:b8:a8:ad:4d:04

</details>

### B40　Insteon Hub

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：LAN 内でハブへ送る平文の HTTP の URL に `pwd=`（2018-04-11）
- Claude の判定：**本物（数える）**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

Insteon Hub: pwd= in a cleartext HTTP URL sent to the hub on the LAN (2018-04-11)

MAC：54:4a:16:f9:54:18

</details>

### B41　nVidia Shield

- 種類：平文の秘密情報（5.5-6）
- データ：YourThings 2018
- 観測：配信サーバー（CDN）からのデータの中の `sid` の偶然の一致
- Claude の判定：**数えない**
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文のメモと MAC</summary>

nVidia Shield: 'sid' matched inside data from a CDN

MAC：00:04:4b:55:f6:4f

</details>
