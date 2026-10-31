# 結果：YourThings 2018 の 44 製品で、製造者の暗号化の主張と通信を突き合わせた

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

## 結果（暗号化に絞る）

主張のうち、暗号化について言っているもの（文に encrypt、SSL、TLS、HTTPS、AES などがあるもの）だけを見る。比べるのは 2 つ：

- **暗号の方法**：主張（アルゴリズム、鍵長、TLS の版、前方秘匿性）と、観測した TLS の版と暗号スイート。
- **暗号化しているか**：主張（「すべて暗号化」「SSL で送る」）と、観測した平文の通信。中身（本文、URL のパラメータ、認証ヘッダー）があるかで分ける。

表の全体は [encryption-yourthings.md](encryption-yourthings.md)（`scripts/claims/encryption_view.py` で作る。観測は 03-20、04-10〜12 の 4 日分）。

### 数

暗号化についての主張 145 件（31 製品）。13 製品には暗号化の主張がなかった（Belkin の WeMo 4 製品と NetCam、Roku 2 製品、Samsung Smart TV、Securifi Almond、Insteon Hub Pro、Koogeek、D-Link DCS-5009L、August）。

| 判定 | 暗号の方法 | 暗号化しているか | 計 |
|---|---|---|---|
| 食い違いの候補 | 1 | 7 | 8 |
| 文言の上で食い違い | 1 | 4 | 5 |
| 一致（見えた範囲で） | 9 | 27 | 36 |
| 見えない | 8 | 11 | 19 |
| 判定できない | 23 | 54 | 77 |
| 計 | 42 | 103 | 145 |

全部の主張（657 件）では 88% が判定できなかったが、暗号化の主張に絞ると 53%（77 件）。判定できない理由は、範囲がアプリや Web サイト、保存時の暗号化、Wi-Fi・Bluetooth・Z-Wave の区間のどれかが多い。

### 食い違いの候補（5 製品）

| 製品 | 軸 | 主張（出典、アーカイブの日付） | 観測（4 日分） | 注意 |
|---|---|---|---|---|
| Ring Video Doorbell | 暗号化しているか | "Encryption Bank-Grade"（製品ページ、2017-04-20） | 外部への平文の HTTP 8,374 回のうち 8,373 回が `Authorization: Basic` つき（`vod.ring.com` に約 10 秒ごと、`fw.ring.com` に 1 回）。TLS は 1,566 回すべて前方秘匿性なし（`TLS_RSA_WITH_AES_128_CBC_SHA`） | 曖昧な主張なので「暗号化している」だけを判定した |
| Philips Hue Bridge | 暗号化しているか | "Philips Lighting, transfers data securely (using SSL) …"（プライバシーポリシー、2017-08-18） | 外部への平文の HTTP で中身があるもの 1,953 回、うち 1,013 回が `Authorization` ヘッダーつき。TLS は 8 回だけ | 直前にブリッジが送るデータ（ブリッジの ID、シリアル番号、使用データ）を挙げている |
| Sonos PLAY:1 | 暗号化しているか | "Any data we transmit over the internet is protected using encryption."、ほか 2 文（プライバシーポリシー、2018-02-02） | 外部への平文の HTTP で中身があるもの 21 回。`update.sonos.com` の URL に `householdid`、`serial`、`sonosid` という名前のパラメータ | 送っているのは識別子で、「データ」に入るかは読み方による |
| Withings Home | 暗号化しているか | "Communication via Secure Socket Layer (SSL)"（製品ページ、2018-04-04） | `scalews.withings.net` へ本文つきの平文の POST が 3 回 | |
| Withings Home | 暗号の方法 | "… AES-256 and secure HTTP (HTTPS) to protect your data at the device, cloud and app level so that all your data is stored safely."（同上） | TLS の 1,624 回中 1,619 回が AES-128 | AES-256 は保存時の暗号化を指している可能性がある |
| Harman Kardon Invoke | 暗号化しているか | "… including without limitation, encryption technologies and authentication tools."（プライバシーポリシー、2018-03-15） | `esdk-ffl.spotify.com` へ平文の GET が 5 回（URL に `key_id`、`value`） | 宛先は第三者（Spotify の SDK）。いちばん弱い候補 |

**文言の上で食い違い**：Canary（"Secure web transfer (SSL/TLS)"、"All parts of our system … employ … HTTPS" など。観測は本文のない平文の HEAD が 52 回だけ）。

**一致の例**：Nest Cam は "128-bit AES with TLS/SSL encryption, Perfect Forward Secrecy and a unique 2048-bit RSA key" と書き、観測した握手はすべて ECDHE（前方秘匿性あり）と AES-128 だった（RSA の鍵長は未確認。TLS の版は 1.0 だが、主張に版は書かれていない）。Canary の "AES 256-bit data encryption" と、Piper の "AES-128 and AES-256" も、観測した暗号スイートと合っていた。

### 主張がなくても、通信から分かること

主張の有無に関係なく、44 製品すべての観測を [encryption-yourthings.md](encryption-yourthings.md) の最後の表に載せた。主なもの：

- **前方秘匿性のない TLS だけ**：Ring（1,566 回）、Belkin NetCam HD（585 回）、Logitech Harmony Hub（82 回）、LIFX（15 回）、Chamberlain myQ（11 回、TLS 1.1）。Belkin の WeMo の 4 製品は TLS 1.0 で、前方秘匿性があるのは 0〜58%。
- **古い TLS**：Nest Cam と Nest Cam IQ（すべて TLS 1.0）、Amazon Echo（90% が TLS 1.0）、Belkin の WeMo の 4 製品（すべて TLS 1.0）。
- **外部への平文で中身があるもの**：Ring（8,373）、Harmony Hub（2,468）、Hue（1,953）、Samsung Smart TV（364）、Insteon Hub Pro（29）。
- **FTP のログイン**：VeraLite（151 回。宛先は製造者のサーバーとは特定できない）。

暗号化の主張がない製品（Belkin の WeMo と NetCam、Samsung Smart TV、Insteon）や、暗号化の主張がどれも判定できない製品（Harmony Hub）にも、前方秘匿性のない TLS や、中身のある平文があった。主張がないので食い違いには数えないが、利用者は文書から暗号化について知ることができない。

## 付録：暗号化以外も含めた全部の主張

暗号化以外の主張（パスワードの決まり、更新のやり方、脆弱性の届け出の窓口など）も [claims.tsv](claims.tsv) に残している。全部で 657 件（ほかに「セキュリティの主張なし」の文書 129 件）、判定は次のとおり。

| 判定 | 主張 |
|---|---|
| 食い違いの候補 | 9（暗号化の主張と、August の「業界標準で PII を守る」） |
| 文言の上で食い違い | 5 |
| 一致（見えた範囲で） | 42 |
| 見えない | 26 |
| 判定できない | 575 |

1 回目（読めたページだけ）は主張 232 件で、食い違いの候補は 5 製品だった。全文書を読むと、Hue の判定が「判定できない」から「食い違いの候補」に変わった（1 回目は主張の範囲を「アプリ」と読んでいた）。

## 限界

- **読めなかった文書**：34 件（[unreadable.md](unreadable.md)）。Nest と Belkin のサポート記事、Roku の製品ページとサポート記事、iRobot のデータセキュリティのページなど。本文を JavaScript で表示するページか、文字の層がない PDF。
- **時期**：アーカイブの日付とキャプチャのずれは `offset_months` に入れた。Piper の FAQ（37 か月前）、Logi のプライバシーの声明（26 か月前）のように古いものや、Arlo の英語版の FAQ・Canary と Piper の 2019 年のページのようにキャプチャ後のものがある。
- **型番**：Belkin NetCam は、機器の名乗りが NetCamHD（F7D7602）なのに、読んだ製品ページとマニュアルは F7D7601 のもの。August と myQ は型番が分からず、複数の型のページを読んだ。Apple の iOS Security Guide は HomePod に一度も触れていないので、HomePod への当てはめは推定。
- **観測の範囲**：まとめたのは TLS と HTTP、FTP と、Quarant の検出だけ。ほかのプロトコルは数えていない。03-20 は Zeek だけで、Quarant では解析していない。キャプチャの期間（`capture_start`、`capture_end`）は Quarant の 04-10〜12 で付けている。
- **判定**：1 人で行った。暗号化の主張のうち、食い違いの候補と文言の上の食い違いの 13 件は、人がまだ確かめていない。
- **件数**：根拠の列（claims.tsv の evidence）の件数は判定したときの記録で、一部は 04-10〜12 の 3 日分。表の件数（encryption-yourthings.md）は 4 日分。
- 食い違いの候補は、主張が誤りだという意味ではない。食い違いが見つからなかった製品も、安全だという意味ではない。

## 次

1. 暗号化の主張のうち、食い違いの候補と文言の上の食い違いの 13 件を、人が確かめる（主張の読み方と観測の両方）。
2. 読めなかった文書（[unreadable.md](unreadable.md)）をブラウザで開いて読む。
3. 同じ製品が出てくるほかのデータセット（UNSW 2016・2018、CIC 2022、Deakin 2023）に広げ、時期による変化を見る。
