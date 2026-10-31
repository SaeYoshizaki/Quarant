# 結果：YourThings 2018 の 43 製品で、製造者の主張と通信を突き合わせた

2026-10-31。進め方は [method.md](method.md)、主張の一つ一つは [claims.tsv](claims.tsv)。集計は `python3 scripts/claims/summarize.py docs/claims/claims.tsv yourthings`。

## 対象と方法

- **製品**：YourThings で通信が見えた製品のうち、製造者が分かる 44 製品。Roku TV は文書が読めず、主張が 0 件だった（下の「限界」）ので、集計は 43 製品。
- **主張**：Wayback Machine のアーカイブから、製品ページ、セキュリティのページ、プライバシーポリシー、FAQ を集めた。引用はすべて、保存した版の文字と機械的に照合した（`scripts/claims/check_quotes.py`、232 件すべて一致）。
- **通信**：Zeek の記録（2018-03-20、04-10〜12。TLS の版・暗号スイート、HTTP の要求の形。値は含まない）と、Quarant の解析結果（04-10〜12）。製品ごとのまとめは `scripts/claims/observations.py` で作った。
- **判定**：method.md の型（T1〜T5）と条件で決めた。人による確認はまだしていない。

## 数

主張 232 件（ほかに「セキュリティの主張なし」の文書 45 件）。

| 判定 | 主張 | うち具体的 | うち曖昧 |
|---|---|---|---|
| 食い違いの候補（T1a：中身のある平文） | 7 | 4 | 3 |
| 食い違いの候補（T2：暗号の性質） | 1 | 1 | 0 |
| 文言の上で食い違い（T1b：中身のない平文だけ） | 2 | 2 | 0 |
| 一致（見えた範囲で） | 11 | 10 | 1 |
| 見えない | 10 | 7 | 3 |
| 判定できない | 201 | 85 | 79 |

製品ごとに、いちばん強い判定で分けると次のとおり。

| 判定 | 製品 |
|---|---|
| 食い違いの候補（5） | August Doorbell Cam、Harman Kardon Invoke、Ring Video Doorbell、Sonos PLAY:1、Withings Home |
| 文言の上で食い違い（1） | Canary |
| 一致（見えた範囲で）（8） | Apple HomePod、Apple TV（第 4 世代）、Arlo（ベースステーション）、Nest Cam、Nest Cam IQ、TP-Link HS105、TP-Link LB130、Wink Hub 2 |
| 見えない（5） | Caseta Smart Bridge、Google Home、Google Home Mini、Nest Protect、Nest Secure |
| 判定できない（24） | 残りの製品 |

## 食い違いの候補

| 製品 | 主張（出典、アーカイブの日付） | 観測 | 注意 |
|---|---|---|---|
| Ring Video Doorbell | "Encryption Bank-Grade"（製品ページ、2017-04-20） | 03-20 に `vod.ring.com` へ平文の GET を約 10 秒ごとに 8,372 回、すべて `Authorization: Basic` つき（ほとんど 404）。04-11 に `fw.ring.com` へ同じく 1 回（Zeek、Quarant の `INSECURE_HTTP_AUTH`） | 主張は曖昧なので、「暗号化している」だけを判定した。製品ページは 11.7 か月前 |
| Sonos PLAY:1 | "Any data we transmit over the internet is protected using encryption."、ほか 2 文（プライバシーポリシー、2018-02-02） | `update.sonos.com` へ平文の GET が 11 回。URL に `householdid`、`serial`、`sonosid` という名前のパラメータ。Quarant は平文での更新の確認として検出。第三者（`legato.radiotime.com`）へ本文つきの平文の POST が 3 回 | 送っているのは機器と世帯の識別子で、個人データかは主張の読み方による |
| Withings Home | "Communication via Secure Socket Layer (SSL)"（製品ページ、2018-04-04） | `scalews.withings.net` へ平文の POST が 3 回（`action` という名前のパラメータ、101 バイトの本文） | |
| Withings Home | "Nokia Home uses bank level technologies such as AES-256 and secure HTTP (HTTPS) to protect your data at the device, cloud and app level so that all your data is stored safely."（同上） | TLS の 1,624 回中 1,619 回が AES-128（`ECDHE_RSA_WITH_AES_128_GCM_SHA256`）。AES-256 は 5 回 | 文の終わりが「保存」なので、AES-256 は保存時の暗号化を指している可能性がある |
| August Doorbell Cam | "We follow generally-accepted industry standards to protect the PII submitted to us, both during transmission and once we receive it."（プライバシーポリシー、2018-04-07） | `august.pubnub.com` へ平文の GET が 3 回。URL に `uuid`、`auth`、`pnsdk` という名前のパラメータ（Zeek、Quarant の `INSECURE_HTTP_TOKEN`） | 曖昧な主張の最低限の中身だけを判定した。宛先は第三者のメッセージングサービスで、送っているのはトークン（PII とは限らない） |
| Harman Kardon Invoke | "Harman engages the use of numerous technological security measures to preserve the security of your information, including without limitation, encryption technologies and authentication tools."（プライバシーポリシー、2018-03-15） | `esdk-ffl.spotify.com` へ平文の GET が 5 回。URL に `key_id`、`value` という名前のパラメータ | 宛先は第三者（Spotify の SDK）で、パラメータの中身は分からない。いちばん弱い候補 |

**文言の上で食い違い**：Canary（"All parts of our system … employ … HTTPS" に対し、本文のない平文の HEAD が 34 回）。

## 分かったこと

1. **通信で判定できる主張は少ない**。232 件のうち 201 件（87%）は判定できなかった。理由は、曖昧（何について言っているか分からない）、保証しない書き方、範囲が機器の通信ではない（Web サイト、アプリ、ストア）、通信では見えない（保存時の暗号化、パスワードのハッシュ化、Wi-Fi や Z-Wave の暗号化）のどれか。43 製品のうち 24 製品は、判定できる主張が 1 つもなかった。
2. **具体的な主張ほど確かめられ、食い違いも見つかる**。食い違いの候補 8 件のうち 5 件は具体的な主張。具体的に書いた Nest、Apple、TP-Link は、見えた範囲で主張どおりだった。
3. **プライバシーポリシーの一般的な文が、製品の主張として働いている**。Sonos と Harman、August の候補は、どれもプライバシーポリシーの「通信は暗号化して守る」という一般的な文と、機器の平文の通信の食い違い。
4. **平文の宛先は、製造者のサーバーとは限らない**。August（PubNub）と Harman（Spotify）は、製品に組み込まれた第三者のサービスへの平文だった。製造者の主張がそこまで含むかは、読み方による。
5. **観測が目立つのに、判定できる主張がない製品がある**。Philips Hue（クラウドへの平文の POST。`Authorization` ヘッダーつきのものを Quarant の `INSECURE_HTTP_AUTH` が 873 回検出）、VeraLite（外部への FTP でユーザー名とパスワード、各 151 回）、Insteon Hub Pro（URL に `mac`、`fw` などの名前のパラメータを付けた平文の GET）、Logitech Harmony Hub（PubNub への平文の GET が約 2,400 回）。主張がないので食い違いには数えないが、ETSI の要件の違反の証拠としては、別に数えられる（第 1 弾の結果）。

## 限界

- **読めなかった文書**：Roku（製品ページとプライバシーポリシー）と iRobot（データセキュリティのページ）は、本文を JavaScript で表示するため、アーカイブから文字が取れなかった。Apple のセキュリティの白書は PDF で、取っていない。ブラウザで見るか、PDF を読む方法が要る。
- **時期**：Arlo の具体的な主張は、キャプチャの約 16 か月後のページにしかない（`offset_months` で除ける）。Ring の製品ページは 11.7 か月前、D-Link の製品ページは 17 か月前。
- **観測の範囲**：まとめたのは TLS と HTTP、FTP と、Quarant の検出だけ。ほかのプロトコル（TP-Link の LAN 内の制御など）は、まだ数えていない。03-20 は Zeek だけで、Quarant では解析していない。キャプチャの期間（`capture_start`、`capture_end`）は Quarant の 04-10〜12 で付けている。
- **判定**：1 人で行った。食い違いの候補と文言の上の食い違いの 10 件は、人がまだ確かめていない。
- 食い違いの候補は、主張が誤りだという意味ではない。食い違いが見つからなかった製品も、安全だという意味ではない。

## 次

1. 食い違いの候補 10 件を、人が確かめる（主張の読み方と観測の両方）。
2. 読めなかった文書（Roku、iRobot、Apple の PDF）を別の方法で読む。
3. 同じ製品が出てくるほかのデータセット（UNSW 2016・2018、CIC 2022、Deakin 2023）に広げ、時期による変化を見る。
