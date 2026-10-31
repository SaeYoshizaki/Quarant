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
- **通信**：4 日分（03-20、04-10〜12）。Zeek の記録（TLS の版・暗号スイート・証明書の鍵、HTTP の要求の形。値は含まない）、すべての TCP・UDP のフローの分類（`scripts/claims/flowscan.py`。HTTP・TLS・FTP 以外の独自のプロトコルも含む）、Quarant の解析結果。製品ごとのまとめは `scripts/claims/observations.py` と `flows_summary.py`。
- **データセットの作成者の検査**：YourThings の作成者は、キャプチャの中で能動的な検査をしていた。03-20 のポートスキャン（192.168.0.200 から全機器へ、約 99 万接続）と、04-10〜12 の中間者の検査（偽の証明書で TLS に応答、30 機器、1,497 接続）。どちらも機器のふるまいではないので、集計から外した（D35）。中間者の検査に機器がどう反応したかは、別の結果として使った（下）。
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
| 食い違いの候補 | 4 | 7 | 11 |
| 文言の上で食い違い | 0 | 4 | 4 |
| 一致（見えた範囲で） | 9 | 30 | 39 |
| 見えない | 7 | 7 | 14 |
| 判定できない | 23 | 54 | 77 |
| 計 | 43 | 102 | 145 |

全通信の分類を加えたことで、Nest Protect と Nest Guard の 7 件が「見えない」から「一致（暗号化はエントロピーからの推定）」に、Wink の 1 件と Canary の 2 件が「食い違いの候補」に変わった（下）。

全部の主張（657 件）では 88% が判定できなかったが、暗号化の主張に絞ると 53%（77 件）。判定できない理由は、範囲がアプリや Web サイト、保存時の暗号化、Wi-Fi・Bluetooth・Z-Wave の区間のどれかが多い。

### 食い違いの候補（7 製品）

| 製品 | 軸 | 主張（出典、アーカイブの日付） | 観測（4 日分） | 注意 |
|---|---|---|---|---|
| Ring Video Doorbell | 暗号化しているか | "Encryption Bank-Grade"（製品ページ、2017-04-20） | 外部への平文の HTTP 8,374 回のうち 8,373 回が `Authorization: Basic` つき（`vod.ring.com` に約 10 秒ごと、`fw.ring.com` に 1 回）。Quarant も `INSECURE_HTTP_AUTH` を 8,303 回出した。TLS は 1,566 回すべて前方秘匿性なし（`TLS_RSA_WITH_AES_128_CBC_SHA`） | 曖昧な主張なので「暗号化している」だけを判定した。平文はほぼ 03-20 |
| Philips Hue Bridge | 暗号化しているか | "Philips Lighting, transfers data securely (using SSL) …"（プライバシーポリシー、2017-08-18） | 外部への平文の HTTP で中身があるもの 1,953 回、うち 1,013 回が `Authorization` ヘッダーつき（Quarant `INSECURE_HTTP_AUTH` 1,003）。本物のサーバーとの TLS は 1 回だけ（ほかの 7 回は検査の接続） | 直前にブリッジが送るデータ（ブリッジの ID、シリアル番号、使用データ）を挙げている |
| Sonos PLAY:1 | 暗号化しているか | "Any data we transmit over the internet is protected using encryption."、ほか 2 文（プライバシーポリシー、2018-02-02） | 外部への平文の HTTP で中身があるもの 21 回。`update.sonos.com` の URL に `householdid`、`serial`、`sonosid` という名前のパラメータ | 送っているのは識別子で、「データ」に入るかは読み方による |
| Withings Home | 暗号化しているか | "Communication via Secure Socket Layer (SSL)"（製品ページ、2018-04-04） | `scalews.withings.net` へ本文つきの平文の POST が 3 回 | |
| Withings Home | 暗号の方法 | "… AES-256 and secure HTTP (HTTPS) to protect your data at the device, cloud and app level so that all your data is stored safely."（同上） | 本物のサーバーとの TLS の 1,621 回中 1,619 回が AES-128 | AES-256 は保存時の暗号化を指している可能性がある |
| Wink Hub 2 | 証明書の検証 | "We adopt security measures that include certificate pinning, encryption, …"（サポートの FAQ、2017-07-08） | 作成者の中間者の検査で、偽の証明書の接続 42 回のうち 21 回、握手のあとにハブがデータを送った（`hub-api.wink.com`）。YourThings の評価も「中間者が成功」（4/4） | 製造者全体の FAQ で、アプリの話か機器の話かは書いていない。データセットの検査があって初めて見えるもの（D35） |
| Canary | 暗号の方法 | "AES 256-bit data encryption"（製品ページの仕様、2018-03-23）、"… such as AES 256-bit symmetric-key encryption …"（セキュリティのページ、2018-02-27） | Canary のサーバーとの TLS 8,010 回のうち 4 回が AES-128（03-20、`o.canaryis.com`、`v.canaryis.com`）、残りは AES-256 | 弱い候補（0.05%）。仕様の欄は、通信か保存時かを書いていない |
| Harman Kardon Invoke | 暗号化しているか | "… including without limitation, encryption technologies and authentication tools."（プライバシーポリシー、2018-03-15） | `esdk-ffl.spotify.com` へ平文の GET が 5 回（URL に `key_id`、`value`） | 宛先は第三者（Spotify の SDK）。いちばん弱い候補 |

**文言の上で食い違い**：Canary（"Secure web transfer (SSL/TLS)" など。観測は本文のない平文の HEAD が `h.canaryis.com` に 50 回だけ）。

**一致の例**：
- Nest Cam は "128-bit AES with TLS/SSL encryption, Perfect Forward Secrecy and a unique 2048-bit RSA key" と書き、観測した握手はすべて ECDHE（前方秘匿性あり）と AES-128、カメラ自身の証明書の鍵は 27 回とも RSA 2048 ビットだった（TLS の版は 1.0 だが、主張に版は書かれていない）。
- Nest Protect の "a proprietary secure protocol similar to TLS"：通信はすべて独自のプロトコル（tcp/11095）で、機器が送ったパケットの 95% が高エントロピーだった。暗号化は推定で、観測ではない。前の集計（Zeek の TLS・HTTP・FTP だけ）では「通信なし」になっていた。
- Piper の "AES-128 and AES-256" も、観測した暗号スイートと合っていた。

**確かめが要る一致**：Nest の "Dropcams and Nest Cams connect … using 2048-bit RSA private keys for key exchange"。サーバーの鍵は RSA 2048 ビットだが、Nest Cam IQ 自身の証明書の鍵は ECDSA P-224 だった（114 回）。「鍵交換に使う RSA の鍵」をサーバーの鍵と読めば一致、カメラの鍵と読めば食い違い。

### データセットの作成者の中間者の検査への反応

偽の証明書の接続で、握手のあとに機器がデータを送ったもの（証明書を受け入れた疑い）は 7 製品：Wink Hub 2（42 回中 21 回）、August Doorbell Cam（10 回中 5 回）、VeraLite（5 回中 5 回）、WeMo Crock-Pot（5 回中 5 回）、Harmony Hub（4 回中 4 回）、Harman Kardon Invoke（25 回中 2 回）、Samsung Smart TV（914 回中 6 回）。ほかの 23 製品は、警告を送って拒むか、データを送らずに終えた。YourThings の作成者自身の評価で中間者が成功したのは August と Wink（ほかに、こちらの対象外の Chinese Webcam と、TLS が見えない Insteon）で、VeraLite、Crock-Pot、Harmony Hub、Harman、Samsung TV は成功していない評価だった。評価の基準は公開されていないので、どちらが正しいかは決めない。主張と比べられるのは Wink だけ（上の表）。

### 主張がなくても、通信から分かること

主張の有無に関係なく、44 製品すべての観測を [encryption-yourthings.md](encryption-yourthings.md) の最後の表に載せた。主なもの：

- **前方秘匿性のない TLS だけ**：Ring（1,566 回）、Belkin NetCam HD（584 回）、Belkin の WeMo の 4 製品（すべて TLS 1.0。前に 58% とした WeMo Switch の前方秘匿性は、すべて検査の接続だった）、Logitech Harmony Hub（78 回）、LIFX（10 回）、Chamberlain myQ（11 回、TLS 1.1）。
- **古い TLS**：Nest Cam と Nest Cam IQ（すべて TLS 1.0）、Amazon Echo（91% が TLS 1.0）、Belkin の WeMo の 4 製品（すべて TLS 1.0）。
- **短い鍵**：SmartThings Hub の通信相手のサーバー証明書は、1,051 回すべて RSA 1,024 ビット（SmartThings 自身の認証局 STCA が発行）。
- **外部への平文で中身があるもの**：Ring（8,373）、Harmony Hub（2,468）、Hue（1,953）、Samsung Smart TV（364）、Insteon Hub Pro（29）。
- **FTP**：VeraLite は、機器のログファイル（LuaUPnP.log、NetworkMonitor.log、Provision.log など。gzip で圧縮）を、暗号化しない FTP で外部（82.77.228.112）へ上げていた（04-10 だけで 36 回。ログインは 4 日で 151 回）。
- **HTTP・TLS 以外**：Belkin の WeMo の各製品と NetCam は、外部の tcp/3478（STUN）と tcp/3475（テキストのプロトコル）へ平文で通信していた。LIFX の LAN の制御（udp/56700、製造者自身が「LAN のプロトコルは盗み見られる」と書いている）は 1 回だけ見えた。TP-Link の LAN の制御（tcp/9999）は見えなかった（アプリからの操作がなかったとみられる）。

暗号化の主張がない製品（Belkin の WeMo と NetCam、Samsung Smart TV、Insteon）や、暗号化の主張がどれも判定できない製品（Harmony Hub）にも、前方秘匿性のない TLS や、中身のある平文があった。主張がないので食い違いには数えないが、利用者は文書から暗号化について知ることができない。

## 付録：暗号化以外も含めた全部の主張

暗号化以外の主張（パスワードの決まり、更新のやり方、脆弱性の届け出の窓口など）も [claims.tsv](claims.tsv) に残している。全部で 657 件（ほかに「セキュリティの主張なし」の文書 129 件）、判定は次のとおり。

| 判定 | 主張 |
|---|---|
| 食い違いの候補 | 12（暗号化の主張 11 件と、August の「業界標準で PII を守る」） |
| 文言の上で食い違い | 4 |
| 一致（見えた範囲で） | 47 |
| 見えない | 19 |
| 判定できない | 575 |

1 回目（読めたページだけ）は主張 232 件で、食い違いの候補は 5 製品だった。全文書を読むと、Hue の判定が「判定できない」から「食い違いの候補」に変わった（1 回目は主張の範囲を「アプリ」と読んでいた）。

## 限界

- **読めなかった文書**：34 件（[unreadable.md](unreadable.md)）。Nest と Belkin のサポート記事、Roku の製品ページとサポート記事、iRobot のデータセキュリティのページなど。本文を JavaScript で表示するページか、文字の層がない PDF。
- **時期**：アーカイブの日付とキャプチャのずれは `offset_months` に入れた。Piper の FAQ（37 か月前）、Logi のプライバシーの声明（26 か月前）のように古いものや、Arlo の英語版の FAQ・Canary と Piper の 2019 年のページのようにキャプチャ後のものがある。
- **型番**：Belkin NetCam は、機器の名乗りが NetCamHD（F7D7602）なのに、読んだ製品ページとマニュアルは F7D7601 のもの。August と myQ は型番が分からず、複数の型のページを読んだ。Apple の iOS Security Guide は HomePod に一度も触れていないので、HomePod への当てはめは推定。
- **観測の範囲**：HTTP・TLS・FTP 以外は、構造かエントロピーで分類しただけで、中身は読んでいない。高エントロピーは暗号化と圧縮を区別できない。03-20 の Quarant は、スキャンの端末のパケットを除いて解析した。キャプチャの期間（`capture_start`、`capture_end`）は Quarant の 04-10〜12 で付けている。
- **作成者の検査**：中間者の検査で機器が送ったデータの中身は分からない。データを送ったことを、証明書を受け入れたことの推定に使った。
- **判定**：1 人で行った。暗号化の主張のうち、食い違いの候補と文言の上の食い違いの 15 件は、人がまだ確かめていない。
- **件数**：根拠の列（claims.tsv の evidence）の TLS と Quarant の件数は、4 日分・検査の接続を除いた値にそろえた。
- 食い違いの候補は、主張が誤りだという意味ではない。食い違いが見つからなかった製品も、安全だという意味ではない。

## 次

1. 暗号化の主張のうち、食い違いの候補と文言の上の食い違いの 15 件と、確かめが要る一致（Nest の RSA）を、人が確かめる（主張の読み方と観測の両方）。
2. 読めなかった文書（[unreadable.md](unreadable.md)）をブラウザで開いて読む。
3. 同じ製品が出てくるほかのデータセット（UNSW 2016・2018、CIC 2022、Deakin 2023）に広げ、時期による変化を見る。
