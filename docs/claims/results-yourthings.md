# 結果：YourThings 2018 の 44 製品で、製造者の主張と通信を突き合わせた

2026-10-31（同じ日の 1 回目は、読めたページだけで行った。そのあと全製品で D1〜D6 を探し直した。D33）。進め方は [method.md](method.md)、主張の一つ一つは [claims.tsv](claims.tsv)、探した範囲は [coverage.tsv](coverage.tsv)、読めなかった文書は [unreadable.md](unreadable.md)。集計は `python3 scripts/claims/summarize.py docs/claims/claims.tsv yourthings`。

## 対象

YourThings の対応表の 66 台のうち、次の 44 製品。

| 区分 | 台数 |
|---|---|
| 対応表の機器 | 66 |
| IoT ではない（ゲートウェイ、ルーター、スマートフォン・タブレット・PC、ゲーム機） | −9 |
| 手元の 4 日分（03-20、04-10〜12）に通信が出てこない | −12（Facebook Portal、Google Home Hub、Sonos Beam など。2018 年 4 月より後に出た製品が含まれ、2018 年 3〜4 月のキャプチャには最初からいなかったとみられる） |
| 製造者が分からない（ChineseWebcam） | −1 |
| **対象** | **44** |

## 方法

- **文書**：製造者が公開した文書だけを、Wayback Machine のアーカイブから集めた。全製品で D1 製品ページ・仕様、D2 セキュリティのページ・白書、D3 プライバシーポリシー、D4 サポート記事、D5 マニュアル・データシート、D6 リリースノートを探した。
- **探した範囲**：製品 × 文書の種類ごとに、少なくとも 1 つ読めた製品の数（44 製品中）。

  | 文書 | 読めた | アーカイブにあるが読めない | アーカイブにない | 製造者が出していない |
  |---|---|---|---|---|
  | D1 製品ページ・仕様 | 43 | 1 | 0 | 0 |
  | D2 セキュリティ | 31 | 1 | 11 | 1 |
  | D3 プライバシーポリシー | 43 | 1 | 0 | 0 |
  | D4 サポート記事 | 36 | 7 | 1 | 0 |
  | D5 マニュアル | 22 | 3 | 19 | 0 |
  | D6 リリースノート | 16 | 6 | 13 | 9 |

- **引用**：保存した版の文字と機械的に照合した（`scripts/claims/check_quotes.py`、657 件すべて一致）。
- **読み落としの確認**：保存した文書から、技術的な言葉（encrypt、TLS、password、firmware、signed など）を含むのに主張の表にない文を機械的に取り出した（1,504 文）。1 文ずつ「主張／手順・画面の文言／別の製品／セキュリティと関係ない／重複」に分け、主張を 72 文加えた。そのうち通信で判定できる型は 2 文（Apple TV の LAN 内の AirPlay と HomeKit のカメラ）だけだった。主張ではないとした文から無作為に 40 文を抜いて確かめ直し、40 文とも分け方に同意した。
- **通信**：Zeek の記録（03-20、04-10〜12。TLS の版・暗号スイート、HTTP の要求の形。値は含まない）と、Quarant の解析結果（04-10〜12）。製品ごとのまとめは `scripts/claims/observations.py`。
- **判定**：method.md の型（T1〜T5）と条件で決めた。人による確認はまだしていない。

## 数

主張 657 件（ほかに「セキュリティの主張なし」の文書 129 件）。

| 判定 | 主張 | うち具体的 | うち曖昧 |
|---|---|---|---|
| 食い違いの候補（T1a：中身のある平文） | 8 | 5 | 3 |
| 食い違いの候補（T2：暗号の性質） | 1 | 1 | 0 |
| 文言の上で食い違い（T1b：中身のない平文だけ） | 5 | 5 | 0 |
| 一致（見えた範囲で） | 42 | 36 | 6 |
| 見えない | 26 | 22 | 4 |
| 判定できない | 575 | 307 | 193 |

製品ごとに、いちばん強い判定で分けると次のとおり。

| 判定 | 製品 |
|---|---|
| 食い違いの候補（6） | August Doorbell Cam、Harman Kardon Invoke、Philips Hue Bridge、Ring Video Doorbell、Sonos PLAY:1、Withings Home |
| 文言の上で食い違い（1） | Canary |
| 一致（見えた範囲で）（11） | Apple HomePod、Apple TV（第 4 世代）、Arlo（ベースステーション）、Logi Circle、Nest Cam、Nest Cam IQ、Piper nv、TP-Link HS105、TP-Link LB130、VeraLite、Wink Hub 2 |
| 見えない（6） | Caseta Smart Bridge、Google Home、Google Home Mini、Nest Protect、Nest Secure、SmartThings Hub |
| 判定できない（20） | 残りの製品 |

## 食い違いの候補

| 製品 | 主張（出典、アーカイブの日付） | 観測 | 注意 |
|---|---|---|---|
| Philips Hue Bridge | "Philips Lighting, transfers data securely (using SSL) and will encrypt some data, such as your MAC address when it is stored."（プライバシーポリシー、2017-08-18） | ブリッジから Philips のサーバー（`www.ecdinterface.philips.com`、`dcp.cpp.philips.com`、`bridge.meethue.com`）へ、本文つきの平文の HTTP の POST が 1,615 回。`Authorization` ヘッダーつきのもの（Quarant の `INSECURE_HTTP_AUTH` が 873 回）や、URL に `auth`、`sso` という名前のパラメータがあるもの。TLS は 8 回だけ | この文は、ブリッジの ID、シリアル番号、使用データ、クラッシュの情報を挙げた直後にあり、ブリッジが送るデータについての主張と読める。1 回目は範囲を「アプリ」と読んで判定できないとしていた |
| Ring Video Doorbell | "Encryption Bank-Grade"（製品ページ、2017-04-20） | 03-20 に `vod.ring.com` へ平文の GET を約 10 秒ごとに 8,372 回、すべて `Authorization: Basic` つき（ほとんど 404）。04-11 に `fw.ring.com` へ同じく 1 回（Zeek、Quarant の `INSECURE_HTTP_AUTH`） | 曖昧な主張なので、「暗号化している」だけを判定した。製品ページは 11.7 か月前で、ほかの文書に暗号化の主張はなかった |
| Sonos PLAY:1 | "Any data we transmit over the internet is protected using encryption."、ほか 2 文（プライバシーポリシー、2018-02-02） | `update.sonos.com` へ平文の GET が 11 回。URL に `householdid`、`serial`、`sonosid` という名前のパラメータ。Quarant は平文での更新の確認として検出。第三者（`legato.radiotime.com`）へ本文つきの平文の POST が 3 回 | 送っているのは機器と世帯の識別子で、「データ」に入るかは読み方による |
| Withings Home | "Communication via Secure Socket Layer (SSL)"（製品ページ、2018-04-04） | `scalews.withings.net` へ平文の POST が 3 回（`action` という名前のパラメータ、101 バイトの本文） | |
| Withings Home | "Nokia Home uses bank level technologies such as AES-256 and secure HTTP (HTTPS) to protect your data at the device, cloud and app level so that all your data is stored safely."（同上） | TLS の 1,624 回中 1,619 回が AES-128（`ECDHE_RSA_WITH_AES_128_GCM_SHA256`）。AES-256 は 5 回 | 文の終わりが「保存」なので、AES-256 は保存時の暗号化を指している可能性がある |
| August Doorbell Cam | "We follow generally-accepted industry standards to protect the PII submitted to us, both during transmission and once we receive it."（プライバシーポリシー、2018-04-07） | `august.pubnub.com` へ平文の GET が 3 回。URL に `uuid`、`auth`、`pnsdk` という名前のパラメータ（Zeek、Quarant の `INSECURE_HTTP_TOKEN`） | 曖昧な主張の最低限の中身だけを判定した。宛先は第三者のメッセージングサービスで、送っているのはトークン（PII とは限らない） |
| Harman Kardon Invoke | "Harman engages the use of numerous technological security measures to preserve the security of your information, including without limitation, encryption technologies and authentication tools."（プライバシーポリシー、2018-03-15） | `esdk-ffl.spotify.com` へ平文の GET が 5 回。URL に `key_id`、`value` という名前のパラメータ | 宛先は第三者（Spotify の SDK）で、パラメータの中身は分からない。いちばん弱い候補 |

**文言の上で食い違い**：Canary（製品ページの "Secure web transfer (SSL/TLS)"、セキュリティのページの "All parts of our system … employ … HTTPS" など 5 件に対し、本文のない平文の HEAD が 34 回）。

**一致の例**：Nest Cam は製品の仕様のページで "128-bit AES with TLS/SSL encryption, Perfect Forward Secrecy and a unique 2048-bit RSA key" と書き、観測した握手はすべて ECDHE（前方秘匿性あり）と AES-128 だった（RSA の鍵長は未確認）。Piper、Logi Circle、Arlo、Wink も、見えた範囲で主張どおりだった。

## 1 回目（読めたページだけ）との違い

| | 1 回目 | 全文書 |
|---|---|---|
| 主張 | 232 | 657 |
| 食い違いの候補がある製品 | 5 | 6（Hue が加わった） |
| 一致がある製品 | 8 | 11（Logi Circle、Piper、VeraLite が加わった） |
| 判定できる主張がない製品 | 24 | 20 |
| 判定できない主張の割合 | 87% | 88% |

1 回目に読み落とした文書（製品の仕様のページ、プライバシーポリシーの別の版、FAQ、PDF）から、判定に効く主張が見つかった。Hue のように、判定が変わった製品もある。

## 分かったこと

1. **通信で判定できる主張は少ない**。657 件のうち 575 件（88%）は判定できなかった。理由は、曖昧（何について言っているか分からない）、保証しない書き方、範囲が機器の通信ではない（Web サイト、アプリ、ストア、利用者のブラウザ）、通信では見えない（保存時の暗号化、パスワードのハッシュ化、Wi-Fi・Bluetooth・Z-Wave の暗号化、証明書のピン留め、更新のやり方）のどれか。44 製品のうち 20 製品は、判定できる主張が 1 つもなかった。
2. **具体的な主張ほど確かめられる**。具体的に書いた Nest、Apple、Piper、Logi Circle、TP-Link は、見えた範囲で主張どおりだった。食い違いの候補 9 件のうち 6 件も具体的な主張。
3. **プライバシーポリシーの一般的な文が、製品の主張として働いている**。Hue、Sonos、August、Harman の候補は、どれもプライバシーポリシーの「通信は暗号化して守る」という文と、機器の平文の通信の食い違い。
4. **平文の宛先は、製造者のサーバーとは限らない**。August（PubNub）と Harman（Spotify）は、製品に組み込まれた第三者のサービスへの平文だった。
5. **主張が文書にあっても、通信からは見えない区間がある**。Arlo のカメラとベースステーションの間、Apple TV の HomeKit や AirPlay など、LAN の中の別の暗号化は、IP の通信の記録からは確かめられなかった。
6. **観測が目立つのに、判定できる主張がない製品がある**。VeraLite（外部の FTP の宛先へのログインが 151 回で、ユーザー名とパスワードを平文で送っている。宛先は製造者のサーバーとは特定できない）、Insteon Hub Pro（URL に `mac`、`fw` などの名前のパラメータを付けた平文の GET）、Logitech Harmony Hub（PubNub への平文の GET が約 2,400 回）。食い違いには数えないが、ETSI の要件の違反の証拠としては、別に数えられる（第 1 弾の結果）。

## 限界

- **読めなかった文書**：34 件（[unreadable.md](unreadable.md)）。Nest と Belkin のサポート記事、Roku の製品ページとサポート記事、iRobot のデータセキュリティのページなど。本文を JavaScript で表示するページか、文字の層がない PDF。
- **時期**：アーカイブの日付とキャプチャのずれは `offset_months` に入れた。Piper の FAQ（37 か月前）、Logi のプライバシーの声明（26 か月前）のように古いものや、Arlo の英語版の FAQ・Canary と Piper の 2019 年のページのようにキャプチャ後のものがある。
- **型番**：Belkin NetCam は、機器の名乗りが NetCamHD（F7D7602）なのに、読んだ製品ページとマニュアルは F7D7601 のもの。August と myQ は型番が分からず、複数の型のページを読んだ。Apple の iOS Security Guide は HomePod に一度も触れていないので、HomePod への当てはめは推定。
- **観測の範囲**：まとめたのは TLS と HTTP、FTP と、Quarant の検出だけ。ほかのプロトコルは数えていない。03-20 は Zeek だけで、Quarant では解析していない。キャプチャの期間（`capture_start`、`capture_end`）は Quarant の 04-10〜12 で付けている。
- **判定**：1 人で行った。食い違いの候補と文言の上の食い違いの 14 件は、人がまだ確かめていない。
- 食い違いの候補は、主張が誤りだという意味ではない。食い違いが見つからなかった製品も、安全だという意味ではない。

## 次

1. 食い違いの候補と文言の上の食い違いの 14 件を、人が確かめる（主張の読み方と観測の両方）。
2. 読めなかった文書（[unreadable.md](unreadable.md)）をブラウザで開いて読む。
3. 同じ製品が出てくるほかのデータセット（UNSW 2016・2018、CIC 2022、Deakin 2023）に広げ、時期による変化を見る。
