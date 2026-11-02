# 結果：YourThings 2018 の 44 製品で、製造者の暗号化の主張と通信を突き合わせた

2026-11-02 版。通信は公開されている 13 日分すべて（2018-03-20、21、28、04-10〜19）。進め方は [method.md](method.md)、主張の一つ一つは [claims.tsv](claims.tsv)、探した範囲は [coverage.tsv](coverage.tsv)、読めなかった文書は [unreadable.md](unreadable.md)。集計は `python3 scripts/claims/summarize.py docs/claims/claims.tsv yourthings`、表は `scripts/claims/encryption_view.py` で作る（[encryption-yourthings.md](encryption-yourthings.md)）。

## 対象

YourThings の対応表の 66 台のうち、次の 44 製品。

| 区分 | 台数 |
|---|---|
| 対応表の機器 | 66 |
| IoT ではない（ゲートウェイ、ルーター、スマートフォン・タブレット・PC、ゲーム機） | −9 |
| 13 日分のどこにも通信が出てこない | −12（Facebook Portal、Google Home Hub、Sonos Beam など。2018 年 4 月より後に出た製品が含まれ、このキャプチャには最初からいなかったとみられる） |
| 製造者が分からない（ChineseWebcam） | −1 |
| **対象** | **44** |

## 方法

- **文書**：製造者が公開した文書だけを、Wayback Machine のアーカイブから集めた。全製品で D1 製品ページ・仕様、D2 セキュリティのページ・白書、D3 プライバシーポリシー、D4 サポート記事、D5 マニュアル・データシート、D6 リリースノートを探した。製品 × 文書の種類ごとに、少なくとも 1 つ読めた製品の数（44 製品中）：

  | 文書 | 読めた | アーカイブにあるが読めない | アーカイブにない | 製造者が出していない |
  |---|---|---|---|---|
  | D1 製品ページ・仕様 | 43 | 1 | 0 | 0 |
  | D2 セキュリティ | 32 | 0 | 11 | 1 |
  | D3 プライバシーポリシー | 44 | 0 | 0 | 0 |
  | D4 サポート記事 | 39 | 4 | 1 | 0 |
  | D5 マニュアル | 22 | 3 | 19 | 0 |
  | D6 リリースノート | 17 | 5 | 13 | 9 |

  最初の取得で読めなかった 34 文書は、ブラウザで開き直し、文字の層がない PDF は OCR にかけた。14 文書が読め、20 文書は読めなかった（D37）。
- **引用**：保存した版の文字と機械的に照合した（`scripts/claims/check_quotes.py`、687 件すべて一致）。
- **読み落としの確認**：保存した文書から、技術的な言葉（encrypt、TLS、password、firmware、signed など）を含むのに主張の表にない文を機械的に取り出した（1,504 文）。1 文ずつ分けて主張を 72 文加えた。主張ではないとした文から無作為に 40 文を抜いて確かめ直し、40 文とも分け方に同意した。
- **通信**：13 日分。Zeek の記録（TLS の版・暗号スイート・証明書の鍵、HTTP の要求の形。値は含まない）、すべての TCP・UDP のフローの分類（`flowscan.py`。独自のプロトコルも含む）、Quarant の解析結果、平文に出ている機器の版（`versions.py`）。flowscan の「どちらが接続を始めたか」の推定は、04-10 の丸 1 日で Zeek と突き合わせた（SYN が見えた 109,472 件中、外れ 1 件）。FTP のデータの接続は、制御の接続から見つけて平文に数えた。
- **データセットの作成者の検査**：YourThings の作成者は、キャプチャの中で能動的な検査をしていた。どちらも機器のふるまいではないので、集計から外した（D35）。
  - ポートスキャン：192.168.0.200（収集側の Docker の端末）から全機器へ。03-20（約 99 万接続）、03-21（約 20 万）、03-28（約 2 万）。Quarant は、この端末のパケットを除いて解析した。
  - 中間者の検査：偽の証明書（発行者 thing-catcher.gtisc.gatech.edu）で TLS に応答。04-10〜13 と 04-15、31 機器、1,570 接続。機器がどう反応したかは、別の結果として使った（下）。
- **判定**：method.md の型（T1〜T5）と条件で決めた。人による確認はまだしていない。

## 結果（暗号化に絞る）

主張のうち、暗号化について言っているもの（文に encrypt、SSL、TLS、HTTPS、AES などがあるもの）だけを見る。比べるのは 2 つ：

- **暗号の方法**：主張（アルゴリズム、鍵長、TLS の版、前方秘匿性）と、観測した TLS の版と暗号スイート。
- **暗号化しているか**：主張（「すべて暗号化」「SSL で送る」）と、観測した平文の通信。中身（本文、URL のパラメータ、認証ヘッダー）があるかで分ける。

### 数

暗号化についての主張 153 件（31 製品）。13 製品には暗号化の主張がなかった（Belkin の WeMo 4 製品と NetCam、Roku 2 製品、Samsung Smart TV、Securifi Almond、Insteon Hub Pro、Koogeek、D-Link DCS-5009L、August）。

| 判定 | 暗号の方法 | 暗号化しているか | 計 |
|---|---|---|---|
| 食い違いの候補 | 6 | 11 | 17 |
| 文言の上で食い違い | 1 | 5 | 6 |
| 一致（見えた範囲で） | 8 | 31 | 39 |
| 見えない | 7 | 5 | 12 |
| 判定できない | 23 | 56 | 79 |
| 計 | 45 | 108 | 153 |

全部の主張（687 件）では 87% が判定できなかったが、暗号化の主張に絞ると 52%（79 件）。判定できない理由は、範囲がアプリや Web サイト、保存時の暗号化、Wi-Fi・Bluetooth・Z-Wave の区間のどれかが多い。

4 日分（03-20、04-10〜12）から 13 日分にしたことで、判定が変わったのは 7 件：TP-Link の 2 製品と Apple HomePod が「一致」から「食い違いの候補」に、Piper の 2 件が「一致」から「文言の上で食い違い」に、Caseta と VeraLite（リリースノート）の 1 件ずつが「見えない」から「一致」に変わった（下）。

### 食い違いの候補（12 製品）

| 製品 | 軸 | 主張（出典、アーカイブの日付） | 観測（13 日分） | 注意 |
|---|---|---|---|---|
| Ring Video Doorbell | 暗号化しているか | "Encryption Bank-Grade"（製品ページの仕様の欄、2017-04-20。「How it works」のページ 2016-04-07 にも同じ文言） | 外部への平文の HTTP 16,749 回がすべて `Authorization: Basic` つき（`vod.ring.com` に約 10 秒ごと。03-20 に 8,372 回、03-21 に 8,364 回、ほかの日に 13 回）。Quarant も `INSECURE_HTTP_AUTH` を 16,633 回出した。TLS は 6,855 回すべて前方秘匿性なし | 曖昧な主張なので「暗号化している」だけを判定した。2016〜2018 年の Ring の公開文書（FAQ、サポート記事、ブログ、マニュアル、プライバシーポリシー）を探し直しても、機器の通信の暗号化について書いてあるのはこの一言だけで、限定も説明もなかった。サポート記事は機器が TCP 80 を使うと書いている **2026-11-02 の再確認：対象の説明がなく、2017-11-15 以降の販売ページの仕様の欄にはないので、食い違いの判定は未確認。映像は 1.10.70 で平文、1.19.217 で不透明。[ring-prior-work.md](ring-prior-work.md)** |
| Philips Hue Bridge | 暗号化しているか | "Philips Lighting, transfers data securely (using SSL) …"（プライバシーポリシー、2017-08-18） | 外部への平文の HTTP で中身があるもの 3,208 回、うち 1,905 回が `Authorization` ヘッダーつき。本物のサーバーとの TLS は 6 回だけ | 直前にブリッジが送るデータ（ブリッジの ID、シリアル番号、使用データ）を挙げている |
| Sonos PLAY:1 | 暗号化しているか | "Any data we transmit over the internet is protected using encryption."、ほか 2 文（プライバシーポリシー、2018-02-02） | `update.sonos.com` の URL に `householdid`、`serial`、`sonosid` という名前のパラメータ。ファームウェアそのものを平文の HTTP で 3 回取得（03-20 に 2 回、04-13 に 1 回、各 8〜9MB）し、そのたびに版が上がった | 送っているのは識別子と、配られたファームウェア |
| TP-Link HS105（プラグ） | 暗号化しているか | "We have implemented measures, including encryption and SSL technology, designed to secure your personal information …"（プライバシーポリシー、2018-01-31） | LAN の制御（tcp/9999）で、プラグがクラウドのアカウント名、設置場所の緯度・経度、deviceId、MAC、名前を返していた。中身は公開された鍵の XOR で隠してあるだけで、誰でも戻せる | LAN 内だけ。アプリからの操作は 04-13 と 04-15 |
| TP-Link LB130（電球） | 暗号化しているか | 同上 | 同じく LAN の制御で、アカウント名、deviceId、MAC、名前を返していた | 同上 |
| Apple HomePod | 暗号化しているか | "certain information such as your name, contacts, music you listen to, and searches is sent to Apple servers using encrypted protocols."（Apple のプライバシーのページ） | 03-21 に `streamingaudio.itunes.apple.com` から平文の HTTP で音声を 3 回取得（URL に `accesskey` という名前のパラメータ、`x-playback-session-id` ヘッダー） | 音声のデータ自体はファイルの中で暗号化されている可能性がある。どの音声を取りに行ったかの要求が平文 |
| Withings Home | 暗号化しているか | "Communication via Secure Socket Layer (SSL)"（製品ページ、2018-04-04） | `scalews.withings.net` へ本文つきの平文の POST が 4 回 | |
| Withings Home | 暗号の方法 | "… AES-256 and secure HTTP (HTTPS) to protect your data at the device, cloud and app level …"（同上） | 本物のサーバーとの TLS の 5,259 回中 5,248 回が AES-128（LAN の映像の DTLS 3 回は AES-256） | AES-256 は保存時の暗号化を指している可能性がある |
| Harman Kardon Invoke | 暗号化しているか | "… including without limitation, encryption technologies and authentication tools."（プライバシーポリシー、2018-03-15） | `esdk-ffl.spotify.com` へ平文の GET が 15 回（URL に `key_id`、`value`） | 宛先は第三者（Spotify の SDK）。いちばん弱い候補 |
| Wink Hub 2 | 証明書の検証 | "We adopt security measures that include certificate pinning, encryption, …"（サポートの FAQ、2017-07-08） | 作成者の中間者の検査で、偽の証明書の接続 42 回のうち 21 回、握手のあとにハブがデータを送った。YourThings の評価も「中間者が成功」 | アプリの話か機器の話かは書いていない（D35） |
| Canary | 暗号の方法 | "AES 256-bit data encryption"（製品ページの仕様、2018-03-23）ほか | Canary のサーバーとの TLS 26,334 回のうち 4 回が AES-128（03-20 だけ） | 弱い候補（0.02%） |
| Logi Circle | 暗号の方法 | "Logitech uses unique, random and automatically rotating AES 256 Bit Dual Layer Encryption to protect and store your audio and video content."（サポートの FAQ、2018-03-13） | 本物のサーバーとの TLS は 19 回すべて AES-128 | "Dual Layer" は TLS の内側の暗号を指す可能性があり、それは見えない |
| iRobot Roomba | 暗号の方法 | "Currently, we use AES 256-bit encryption and Transport Layer Security (TLS v1.2)."（データセキュリティのページ、2018-11-10） | iRobot 自身のサーバー `disc-prod.iot.irobotapi.com` との TLS は 17 回すべて AES-128。AES-256 は MQTT（tcp/8883）の 22 回だけ | 文書はキャプチャの 7 か月後 |

**文言の上で食い違い**（中身のない平文だけ）：Canary（`h.canaryis.com` への HEAD が 158 回）、Piper（"All connections to and from Piper … are encrypted"、"Piper encrypts all outbound communication …"。`static.getPiper.com` への中身のない GET が 04-16 に 5 回）。

**一致の例**：
- Nest Cam："128-bit AES with TLS/SSL encryption, Perfect Forward Secrecy and a unique 2048-bit RSA key"。観測した握手はすべて ECDHE と AES-128、カメラ自身の証明書の鍵は 118 回とも RSA 2048 ビット。
- Nest Protect："a proprietary secure protocol similar to TLS"。通信はすべて独自のプロトコル（tcp/11095）で、機器が送ったパケットの 93% が高エントロピー（推定）。
- Caseta："encryption of the communication between the Smart Bridge and the user"。13 日分で、スマートフォンとブリッジの LAN の接続（アプリのポートは TLS、HomeKit は暗号化）が見えた。
- VeraLite のリリースノート "change FirmwareImageUrl from http to https"：04-13 と 04-15 に、ファームウェアのサーバーへ TLS でつないでいた。

**確かめが要る一致**：Nest の "Dropcams and Nest Cams connect … using 2048-bit RSA private keys for key exchange"。サーバーの鍵は RSA 2048 ビットだが、Nest Cam IQ 自身の証明書の鍵は ECDSA P-224 だった（336 回）。

### データセットの作成者の中間者の検査への反応

偽の証明書の接続で、握手のあとに機器がデータを送ったもの（証明書を受け入れた疑い）は 7 製品：Wink Hub 2（42 回中 21 回）、August Doorbell Cam（10 回中 5 回）、VeraLite（5 回中 5 回）、WeMo Crock-Pot（5 回中 5 回）、Harmony Hub（4 回中 4 回）、Harman Kardon Invoke（25 回中 2 回）、Samsung Smart TV（914 回中 6 回）。ほかの 24 製品は、警告を送って拒むか、データを送らずに終えた。主張と比べられるのは Wink だけ（上の表）。

### 主張がなくても、通信から分かること

主張の有無に関係なく、44 製品すべての観測を [encryption-yourthings.md](encryption-yourthings.md) に載せた。主なもの：

- **前方秘匿性のない TLS だけ**：Ring（6,855 回）、Belkin NetCam HD（848 回）、Belkin の WeMo の 4 製品（すべて TLS 1.0）、Logitech Harmony Hub（208 回）、LIFX（25 回）、Chamberlain myQ（24 回、TLS 1.1）。
- **古い TLS**：Nest Cam と Nest Cam IQ（すべて TLS 1.0）、Amazon Echo（92% が TLS 1.0）、Belkin の WeMo の 4 製品（すべて TLS 1.0）。
- **短い鍵**：SmartThings Hub の通信相手のサーバー証明書は、3,390 回すべて RSA 1,024 ビット（SmartThings 自身の認証局 STCA が発行）。Withings のカメラが LAN の映像の DTLS で出す自分の証明書も RSA 1,024 ビット。
- **外部への平文で中身があるもの**：Ring（16,749）、Harmony Hub（5,692）、Hue（3,208）、Samsung Smart TV（717）、Insteon Hub Pro（197）、Sonos（165）。
- **FTP**：VeraLite は、機器のログファイル（gzip で圧縮）を、暗号化しない FTP で外部（82.77.228.112）へ上げていた（13 日で 470 回）。
- **HTTP・TLS 以外**：Belkin の WeMo の各製品と NetCam は、外部の tcp/3478（STUN）と tcp/3475（テキストのプロトコル）へ平文で通信していた。TP-Link の LAN の制御は XOR で隠しただけ（上）。LIFX の LAN の制御（製造者自身が「盗み見られる」と書いている）は 1 回だけ見えた。

### YourThings の作成者の評価との照らし合わせ

作成者の評価（yourthings.info の機器ごとの点数。[yourthings-scorecards.tsv](yourthings-scorecards.tsv)）と、こちらの観測を製品ごとに並べた。「TLS の版」「平文の認証」は、評価ではクラウド側のサーバーを能動的に調べた項目なので比べなかった。

| 項目 | 合った | 合わなかった |
|---|---|---|
| 暗号化（平文はすべて数える） | 24 | 17 |
| 暗号化（中身のある平文だけ数える） | 25 | 16 |
| HTTP を使うか | 12 | 31 |
| 中間者が成功したか | 26 | 5 |

- 合わなかったものの多くは、評価が「すべて暗号化」「HTTP を使わない」で、こちらに平文が見えたもの。**Ring（中身のある平文 16,749 回）と Hue（3,208 回）は、評価では「すべて暗号化」「HTTP を使わない」だった**。
- HTTP を使うと評価された製品は、比べた 43 製品のうち 3 つだけ（Amazon Echo、Caseta、Insteon）。こちらでは 34 製品で HTTP の要求が見えた。
- 中間者で合わなかった 5 製品（VeraLite、WeMo Crock-Pot、Harmony Hub、Harman Kardon Invoke、Samsung Smart TV）は、こちらでは偽の証明書のあとにデータを送っていたが、評価では成功していない。
- 評価の基準と、評価に使った通信は公開されていない。評価に書かれた版は、キャプチャの途中の時点のものだった（下）。どちらが正しいかは決めない。

### 機器の版

平文の通信に出ていた版を取り出した（[versions-yourthings.md](versions-yourthings.md)）。

- **キャプチャの期間中に版が変わった製品が 9 つあった**：Sonos（03-20 に 33.15 → 41.3、04-13 に 42.2）、Hue（04-11 に IpBridge 1.23、04-13 に 1.24。電球も 04-13 に更新）、Apple TV（03-28 まで tvOS 11.2.6、04-10 から 11.3）、Roku TV と Roku 4（3 月と 4 月でビルドが違う）、Caseta（06.04.03 → 06.05.08 → 06.05.09 → 06.05.10）、Google Home と Google Home Mini（Cast 1.30 → 1.31）、Wink Hub 2。どの日の通信をどの時点の文書と比べるかで、結果が変わりうる。
- **Sonos は、2 回の更新でファームウェアを 3 回とも平文の HTTP で取得していた**。Quarant の `I4_INSECURE_FIRMWARE_UPDATE_HTTP` も同じ時刻に出ていた。Hue は版が変わったが、取得の通信は見えなかった。
- **YourThings の評価に書かれた版は、キャプチャの途中の版だった**：Hue の評価の版（1802201122）が通信に初めて出たのは 04-13。Apple TV（評価は tvOS 11.3）と Roku TV（評価はビルド 4183）も、03-20 ではなく 4 月の版。評価日は 03-20〜28 と書かれている。
- 見えた版が読んだリリースノートに載っていたのは、Apple TV、Insteon、NVIDIA Shield だけ。TLS だけで通信する製品（Nest、Ring、Arlo、Piper など）は、版が見えない。

## 付録：暗号化以外も含めた全部の主張

暗号化以外の主張（パスワードの決まり、更新のやり方、脆弱性の届け出の窓口など）も [claims.tsv](claims.tsv) に残している。全部で 687 件（ほかに「セキュリティの主張なし」の文書 138 件）、判定は次のとおり。

| 判定 | 主張 |
|---|---|
| 食い違いの候補 | 18（暗号化の主張 17 件と、August の「業界標準で PII を守る」） |
| 文言の上で食い違い | 6 |
| 一致（見えた範囲で） | 49 |
| 見えない | 16 |
| 判定できない | 598 |

更新の主張（「定期的に更新される」「自動で更新する」など）は、3 週間のキャプチャでは「更新しない」ことを示せないので、判定できないとした。ただし、実際に更新が起きたもの（Sonos、Hue、Roku TV、Caseta）は根拠の欄に書いた。

## 限界

- **読めなかった文書**：20 件（[unreadable.md](unreadable.md)）。ブラウザで開いても、本文を読み込む通信がアーカイブされていない（Nest と Belkin のサポート記事、Roku のサポート記事、Apple のユーザーガイド）か、アーカイブ自体が空・404・壊れている。
- **時期**：アーカイブの日付とキャプチャのずれは `offset_months` に入れた。キャプチャの期間は、機器が見えた最初と最後の日（多くは 03-20〜04-19）で、この間にアーカイブされた文書は「期間中」（ずれ 0）になる（289 件）。古い文書（Piper の FAQ は 36 か月前）や、キャプチャ後の文書（iRobot のデータセキュリティのページ、Canary と Piper の 2019 年のページ）がある。
- **型番**：Belkin NetCam は、機器の名乗りが NetCamHD（F7D7602）なのに、読んだ製品ページとマニュアルは F7D7601 のもの。August と myQ は型番が分からず、複数の型のページを読んだ。Apple の iOS Security Guide は HomePod に一度も触れていないので、HomePod への当てはめは推定。
- **観測の範囲**：HTTP・TLS・FTP 以外は、構造かエントロピーで分類しただけ。高エントロピーは暗号化と圧縮を区別できない。TP-Link の LAN の制御だけは、公開された XOR を戻してキー名を見た（値は記録していない）。
- **作成者の検査**：スキャンの端末（192.168.0.200）は除いた。03-20 には別の端末（192.168.0.141）も高い番号のポートへ約 8 万回の接続をしていたが、機器が返したのは中身のない 60 フローだけなので、除いていない。04-15 のスマートフォン（192.168.0.159）による機器の操作は、利用者の操作として残した。中間者の検査で機器が送ったデータの中身は分からない。
- **版**：平文に出ていた版だけで、TLS の中の版は見えない。User-Agent はアプリやライブラリの版のこともある。
- **判定**：1 人で行った。暗号化の主張のうち、食い違いの候補と文言の上の食い違いの 23 件は、人がまだ確かめていない。
- 食い違いの候補は、主張が誤りだという意味ではない。食い違いが見つからなかった製品も、安全だという意味ではない。

## 次

1. 暗号化の主張のうち、食い違いの候補と文言の上の食い違いの 23 件と、確かめが要る一致（Nest の RSA）を、人が確かめる（主張の読み方と観測の両方）。
2. 同じ製品が出てくるほかのデータセット（UNSW 2016・2018、CIC 2022、Deakin 2023）に広げ、時期による変化を見る。
3. 読めなかった文書の残り 20 件は、製造者の今のサイトや別の言語の版で、同じ内容が読めるかを探す（キャプチャの時期からは離れる）。
