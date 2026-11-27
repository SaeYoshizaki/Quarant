# eufy HomeBase 2 とドアベル：公式の発表と実際の通信（CIC IoT Dataset 2022）

確かめた日：2026-11-27。時刻はすべて UTC（`tshark -t ud` と `frame.time_utc`）。前の調査の結論は読まずに、データと文書の本文だけから確かめた。
作業用のファイル：`V/out/work-eufy/`（`drw/`＝組み立てた P2P の流れ、`media/`＝取り出した音声と映像、`scripts/`＝使ったスクリプト）。認証情報やそれに近い値は `V/out/eufy-secrets.md` にだけ書いた。

---

## 1. データセット

| 項目 | 内容 |
|---|---|
| 名前 | CIC IoT Dataset 2022 |
| 作成者・論文 | S. Dadkhah, H. Mahdikhani, P. Kyei Danso, A. Zohourian, K. A. Truong, A. A. Ghorbani, "Towards the Development of a Realistic Multidimensional IoT Profiling Dataset," 2022 19th Annual International Conference on Privacy, Security & Trust (PST), Fredericton, NB, Canada, 2022-08-22〜24, pp. 1–11, DOI 10.1109/PST55820.2022.9851966（書誌は Crossref で確認。論文の本文は IEEE Xplore が開けず**未確認**） |
| 配布元 | https://www.unb.ca/cic/datasets/iotdataset-2022.html （ダウンロードはフォーム http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2022/ ） |
| 利用条件 | ページとダウンロードのフォームにライセンスの記載は**見つからない**（「Citation」欄で論文の引用を求めるだけ）。**未確認** |
| 収録の場所 | ページは「our lab」とだけ書き、国と施設の明記は見ていない（**未確認**）。通信からの推測：HomeBase の映像の時刻は UTC より 3 時間遅れ（大西洋夏時間＝ニューブランズウィック州）、P2P のサーバーの PUNCH_TO（f1 40）を読むとスマホ側の住所は 131.202.221.52（現在の whois で University of New Brunswick。住所の読み方は推測）。→ UNB（カナダ、フレデリクトン）の CIC の研究室と**推測** |
| ネットワーク | ページ：「Windows の機械に NIC が 2 つ（1 つはゲートウェイ、1 つはスイッチ）、Wireshark で両方を収録」。HomeBase は 192.168.137.0/24 にいて、相手はいつもゲートウェイ（MAC 3c:18:a0:45:da:85、のち 3c:18:a0:41:c3:a0）だけ |
| データセット全体の期間 | ページに明記なし（**未確認**）。ファイル名では Idle が 2021_11_02〜2021_12_23 の 30 本、Active は 30 日とされるが、このコピーには `2021_11_02_Active.pcap` の 1 本だけ |
| この機器の通信の最初と最後 | 最初：2021-09-23T11:55:51.202261Z（`1-Power/Home Automation/Eufy Homebase/POWER/eufyhomebasePOWER_1.pcap`）。最後：2021-12-24T09:59:44.393890Z（`2-Idle/2021_12_23_Idle.pcap`） |
| 各フェーズの日時（HomeBase の分） | Power：2021-09-23 11:55〜12:05。Interactions：2021-10-13 14:31:43〜14:50:09。Active：2021-11-02 11:15〜19:15。Idle：毎晩 22:00〜翌 09:00（11 月 7 日の夏時間の終わりの後は 23:00〜翌 10:00）、2021-11-02〜12-24 |
| 作成者がしたこと（README） | **Power**：全機器の電源を抜き、ネットワークを再起動し、機器を 1 つずつ電源を入れて単独で収録（3 回）。**Idle**：夜、人がいない状態（30 日）。**Interactions**：LAN＝同じネットワークのスマホのアプリ、WAN＝別のネットワークのスマホのアプリ、各 3 回。Eufy Homebase は「Recording：Record the video feed from the doorbell」「Watch：Watch the video feed without recording from the doorbell」「Ring：Physically ring the doorbell by pressing the button」。**Scenarios**：6 つの生活の場面（HomeBase の操作はない）。**Active**：昼、研究者が自由に出入り。**Attacks**：LOIC の Flood と RTSP の総当たり（`6-Attacks/1-Flood/Eufy Home Base` がある。今回は**除外**） |
| 渡されたファイルの事情 | 65 本。Scenarios の 18 本は HomeBase のパケットが 0。WAN_RECORDING と WAN_WATCH は元から 2 本ずつ（_1 と _3 がない）。Interactions と Power の元のファイルの大きさは切り出し後と同じ（作成者が HomeBase の分だけを保存したと推測）。`WAN_WATCH/eufyhomebaseWANWATCH_2.pcap` だけ更新日が 2022-04-20（ほかは 2021-10-13） |
| 検査（中間者など） | 作成者による TLS の中間者の検査はない（README に記載なし、証明書は本物：`*.eufylife.com` は GoDaddy、S3 は DigiCert の `*.s3-us-west-2.amazonaws.com`）。POWER_1 で 192.168.137.2（MAC e8:1b:69:f8:d6:e6）から HomeBase の TCP 80 へ SYN が 8 回（2021-09-23T11:57:32〜11:57:54Z、応答なし。各フレームが 2 つの MAC で 2 重に記録） |

## 2. 機器

| 項目 | 内容（どこから分かったか） |
|---|---|
| 製造者 | Anker（ブランド eufy Security。プライバシーポリシーの名義は Anker Innovations、Shenzhen Oceanwing、Power Mobile Life LLC）。MAC の OUI は Wireshark で「SmartInnovat」 |
| 製品名・型番 | **HomeBase 2、T8010**：mDNS の HomeKit TXT `md=T8010`、mDNS 名 `eufy HomeBase2-1DEF`、UDP 8006 の平文のヘッダのシリアル `T8010P1320431DEF` |
| つながる機器 | **Video Doorbell 2K（Battery-Powered）と推定**。根拠：README が「doorbell」と書く。WAN の映像の枠に「2560×1920、H.265、15 fps」。米国の製品ページの仕様表で 2560×1920 はこのドアベル（と有線版）。有線版の保存先は「4GB, On Doorbell」で、HomeBase 2 のページの対応機器にあるドアベルは「Battery Video Doorbell 2K」だけ。ドアベルの型番・シリアル・ファームは通信に平文で出ない（CMD_CAMERA_INFO の返事は暗号化）→ **未確認** |
| ドアベルの通信は HomeBase を通るか | 通る。WAN の映像はすべて HomeBase の MAC と IP から出ている。LAN にドアベル自身の MAC は出てこない（データセットの機器の一覧にもドアベルは別にない） |
| ハードウェアの版 | **未確認** |
| MAC | 8c:85:80:6c:b6:47 |
| IP | 192.168.137.147（Power）、192.168.137.182（Interactions）、192.168.137.189（Idle・Active）。DHCP の vendor class は `udhcp 1.12.1` |
| ファームウェアの版 | **未確認**（版を示す文字列は平文にない。版を運びそうなものは TLS か暗号化された部分の中。収録の中で変わったかも未確認。2021-12-24T07:14:27Z に S3 から約 1.05 MB の取り込みがあるが中身は不明） |
| アプリの版 | **未確認** |

## 3. 公式文書

| ID | 文書 | 発行元 | 文書の中の日付 | Wayback の保存日時（UTC） | アーカイブの URL | 地域・言語 | 対象 | 収録との関係 |
|---|---|---|---|---|---|---|---|---|
| D1 | Privacy Commitment | eufy（ca.eufylife.com） | 記載なし | 2021-09-25 01:28:02 | https://web.archive.org/web/20210925012802/https://ca.eufylife.com/pages/privacy-commitment | カナダ・英語 | eufy Security 全般（HomeBase に言及） | 中（Interactions の前） |
| D2 | Privacy Commitment | eufy（us.eufylife.com） | 記載なし | 2021-06-19 01:34:02、2021-09-08 21:36:12、2021-12-08 01:30:43（本文は 3 つとも D1 と一字一句同じ） | https://web.archive.org/web/20210908213612/https://us.eufylife.com/pages/privacy-commitment | 米国・英語 | 同上 | 前・中 |
| D3 | Video Doorbell 2K (Battery-Powered) Add-on Unit（T8210）製品ページ | eufy（us.eufylife.com） | 記載なし | 2021-07-23 14:46:19（AES-256 の版）、2021-10-22 05:20:39（AES-128 の版） | https://web.archive.org/web/20210723144619/https://us.eufylife.com/products/t8210 、https://web.archive.org/web/20211022052039/https://us.eufylife.com/products/t8210 | 米国・英語 | このドアベル | 前と中（10-13 の 9 日後） |
| D4 | 同（T8210） | eufy（ca.eufylife.com） | 記載なし | 2021-12-04 01:32:36（カナダ版で最も早い保存） | https://web.archive.org/web/20211204013236/https://ca.eufylife.com/products/t8210 | カナダ・英語 | このドアベル | 中（WAN の操作より後、Idle の期間内） |
| D5 | Video Doorbell 2K (Battery-Powered) キット（E82101W3） | eufy（ca.eufylife.com） | 記載なし | 2021-09-24 23:22:03 | https://web.archive.org/web/20210924232203/https://ca.eufylife.com/products/e82101w3 | カナダ・英語 | ドアベル＋HomeBase 2 | 中 |
| D6 | HomeBase 2 (US/CA/AU) 製品ページ | eufy（us.eufylife.com） | 記載なし | 2021-10-05 07:43:37 | https://web.archive.org/web/20211005074337/https://us.eufylife.com/products/homebase-2 | 米国（US/CA/AU 用の製品） | HomeBase 2 | 中 |
| D7 | Privacy Policy（ウェブと App） | Anker Innovations ほか | Effective date: September 2, 2020 | 2021-09-08 21:36:15、2021-11-23 23:54:17 | https://web.archive.org/web/20211123235417/https://us.eufylife.com/policies/privacy-policy | 米国・英語（カナダ版は Wayback になし＝**未確認**） | 全製品 | 中（有効） |
| D8 | EufySecurity Privacy Policy（アプリ） | Power Mobile Life LLC | Effective date: 9, 15, 2018 | 2020-04-01 04:28:10（転送の先） | https://web.archive.org/web/20200401042810/https://security-app.eufylife.com/v1/overall/termsof?type=appleprivacypolicy | 米国 | アプリ | 前（2021 年に有効だったかは**未確認**。2021 年の保存なし） |
| D9 | Vulnerability Disclosure Policy | eufy（ca） | 記載なし | 2021-09-25 00:58:02 | https://web.archive.org/web/20210925005802/https://ca.eufylife.com/pages/vulnerability-disclosure-policy | カナダ | eufy Security | 中（手順だけ。通信と比べられる記載なし） |
| D10 | eufyCam 2 の製品ページ（2020-12-09、2021-12-04）、eufyCam 2 QSG（PDF、2021-07-16）、FAQ（ca、2021-12-04） | eufy | — | 各 URL は依頼のとおり | — | — | eufyCam 2（この機器ではない）／注文の FAQ | 範囲外または関係する記載なし |
| D11 | サポート記事（support.eufylife.com、2021 年の保存が多数） | eufy | — | 例：How-secure-is-the-eufyCam-system 2021-12-09 06:45:11 | — | — | — | 保存された HTML に本文がない（「Sorry to interrupt / CSS Error」）→ **未確認** |
| 参考（後の文書） | "Manual Video Recording in eufy App"、"How secure is the eufyCam system?" | eufy（service.eufy.com） | 日付の表示なし | 2026-11-27 に閲覧（Wayback ではない） | https://service.eufy.com/article-description/Manual-Video-Recording-in-eufy-App | — | — | 後。当時も同じとは推定しない |

該当する文（節の名前と原文）：

- D1/D2 冒頭：「your recorded footage will be kept private. Stored locally. With military-grade encryption. And transmitted to you, and only you.」
- D1/D2「Local Storage — For Your Eyes Only」：「With secure local storage, your private data never leaves the safety of your home, and is accessible by you alone.」
- D1/D2「End-to-End Encryption — Peeking Prohibited」：「All recorded footage is encrypted on-device and sent straight to your phone—and only you have the key to decrypt and watch the footage. Data during transmission is encrypted.」
- D1/D2「On-Device AI」：「It analyzes your recorded footage without the need to risk your privacy by sending it to the cloud.」
- D1/D2「Video Authorization」：「You have complete control over who has access to the live video stream and recordings.」
- D1/D2 FAQ 1：「eufy records and stores videos locally when motion is detected by your device.」
- D1/D2 FAQ 4：「Each clip will be encrypted with AES by your eufy device. … If you choose to store the clips in the cloud, we encrypt data between eufy devices and AWS using TLS and SRTP」
- D1/D2 FAQ 10：「No. eufy team members cannot activate and view live streams from your eufy devices.」
- D3（2021-07-23）・D4「Storage You Can Trust」：「Military-grade AES-256 data encryption ensures your footage is kept private on transmission and storage.」／D3（2021-10-22）：同じ文で「AES-128」
- D3 仕様表：「SONY Sensor, 2K Resolution (2560x1920)」「Video Storage Location: 16GB, On HomeBase」。D3 本文：「Every eufy Security product is engineered to ensure your data is kept private.」
- D5 説明：「All your data is stored locally meaning you will never have to pay for cloud storage.」
- D6：「Compatible with 2/2C/2Pro/2CPro/Battery Video Doorbell 2K/Alarm Kit.」
- D7「Images and biometric information」：「Except when you choose to store these information in the Cloud Storage Service, these information will be kept in the local Products only.」／「Product monitoring」：「… any unique identifiers associated with your Product.」

## 4. 観測（フェーズごと）

プロトコルの名前（PPPP の型、XZYH の命令の番号）は、公開の第三者の実装 bropat/eufy-security-client（`src/p2p/session.ts`、`types.ts`、2026-11-27 の master）に合わせた解釈。値そのものは tshark で確かめた。

**Power（2021-09-23）・Idle・Active**
- 平文：DHCP、DNS（`security-app.eufylife.com`、`p2p-vir-6/7.eufylife.com`、`mediaserver-usa3.eufylife.com`、`pushproxy-usa4.eufylife.com`、`zhixin-security-pr.s3.us-west-2.amazonaws.com`、`eufy-security-pr.s3-us-west-2.amazonaws.com`、`time.nist.gov`）、NTP、mDNS（HomeKit の `_hap._tcp`、`md=T8010`、`id=57:58:4A:5A:36:00`）。
- UDP 8006（eufy 独自、先頭 `XZ`）：HomeBase→サーバーの心拍（命令 0x0b）は**ヘッダにシリアル `T8010P1320431DEF` が平文**、本文なし。サーバー→HomeBase は平文の JSON `{"device_ip":"205.174.165.69"}`（4 つのサーバーから計 約 3 万回）と、ドメインの一覧の JSON（命令 0x0c）。128/256 バイトの本文（命令 0x0d、0x16、0x22）は読めない（暗号化と推測）。
- UDP 32100（PPPP、3 つの AWS のアドレス、DNS なし）：HELLO は平文、ログイン（f1 12）は中身が読めない（DID もシリアルも出ない）。Idle の 30 晩で f1 12 を約 7.5 万回ずつ。
- TCP は全部 443 の TLS 1.2（ECDHE-RSA-AES128-GCM-SHA256）：`security-app.eufylife.com` 255 回、S3 が 4 回。平文の HTTP はなし。
- Idle と Active に映像の送信（PPPP の DRW）はない。

**Interactions：LOCAL_RING（ボタンを押す、3 回、2021-10-13 14:31〜14:34）**
- 各回、`security-app.eufylife.com` へ TLS を 5〜6 本。
- 各回、始まりから 5〜6 秒後に S3 の `zhixin-security-pr` へ TLS で**上り 23,758〜24,306 バイト**（TLS の記録 475＋16,408＋6,875〜7,423）、下り 424 バイト。例：LCLRING_1、2021-10-13T14:31:49.656040Z、ClientHello（SNI `zhixin-security-pr.s3.us-west-2.amazonaws.com`）→ 52.92.147.210:443。中身は TLS で**観測不能**（大きさと時機から、呼び鈴の時の画像を上げたと**推測**）。
- 映像の送信はない。

**Interactions：LAN_WATCH・LAN_RECORDING**
- 心拍と TLS だけ。スマホとの映像は収録にない（スマホと HomeBase の間はスイッチの中で済み、収録の機械を通らないと推測）→ **観測不能**。

**Interactions：WAN_WATCH・WAN_RECORDING（2021-10-13 14:35〜14:42）**
- P2P の中継：P2P のサーバー（UDP 32100）が中継の住所（f1 82）を渡し、HomeBase は 174.119.221.52（Rogers）への穴あけ（f1 41）が返事なしのあと、AWS の中継へ送る。中継：WATCH_1 は 3.16.202.62:11197、WATCH_2 は 3.16.202.62:11463、REC_2 は 54.219.251.168:11392、REC_3 は 35.162.187.157:11159（どれも whois で Amazon。持ち主の会社は**未確認**）。穴あけと中継の登録（f1 41、f1 83）には P2P の機器 ID（DID）が平文で入る（値は secrets に。WOOT 2024 の論文ではこの ID とシリアルから P2P の鍵が作られるとされるので、報告には書かない）。
- スマホ→HomeBase の命令（チャネル 0）は暗号化（XZYH の signCode=2、中身は高エントロピー）。REC_2 では 14:40:09.886232Z に命令 1009、14:40:40.267588Z に 1010（実装の名前で START_RECORD／STOP_RECORD）。
- HomeBase→中継の映像（チャネル 1、DRW の番号で重複を除いて組み立て）：

| ファイル | 中継 | 時刻 | I フレーム | P フレーム | 音声 | 映像のバイト | うち暗号化 |
|---|---|---|---|---|---|---|---|
| WAN_RECORDING_2 | 54.219.251.168:11392 | 14:40:09.602183〜14:40:41.901858 | 16 | 459 | 505 | 1,587,594 | 3,840（0.24%） |
| WAN_RECORDING_3 | 35.162.187.157:11159 | 14:41:44.037024〜14:42:17.980627 | 16 | 483 | 531 | 1,613,434 | 4,096（0.25%） |
| WAN_WATCH_1 | 3.16.202.62:11197 | 14:35:44.801914〜14:35:58.105435 | 7 | 196 | 215 | 1,201,877 | 1,280（0.11%） |
| WAN_WATCH_2 | 3.16.202.62:11463 | 14:36:50.993129〜14:36:51.288904 | 1 | 1 | 1 | 267,979 | 384（0.14%） |

- **P フレーム（signCode=0）は暗号化なし**。例：WAN_WATCH_1、2021-10-13T14:35:45.093869Z、192.168.137.182:17469 → 3.16.202.62:11197、UDP 長 1040、先頭 `f1d0 0404 d101 04f5 | 585a5948 1405 … | 00fa0000 02 02 0100 0f00 000a 8007 … | 00000001 0201 d009 …`（DRW → XZYH の命令 1300 → 枠の情報 2560×1920・15 fps → H.265 の開始符号と NAL の頭）。確かめ方：P フレーム 1,139 枚すべてが H.265 の NAL 型 1、first_slice=1、PPS 0、slice_type=P。直前の I フレームからの枚数と、H.265 の頭の POC の下 8 ビットが 1,116 枚で一致（不一致 0、残り 23 枚は収録の最初の I フレームより前）。
- **I フレーム（signCode=1）**：128 バイトの鍵らしいブロック（1 つの流れで 1 種類。実装では RSA で包んだ AES 鍵）のあと、先頭 128 バイトだけが読めない。残り 2,662,655 バイトには `00 00 03`（H.265 の emulation prevention）が 40 回、`00 00 00/01/02` は 0 回（乱数なら各 0.16 回の見込み）→ 平文の H.265 と判断。
- **音声はすべて暗号化なし**：1,252 枚すべてが ADTS の AAC（`fff1 6040…`、AAC-LC、16 kHz、モノラル）。例：WAN_WATCH_1、14:35:45.473675Z。
- 取り出したもの（`V/out/work-eufy/media/`）：
  - 音声（`*.aac`、`*.wav`）は誤りなくデコードできた。WATCH_1 は 13.8 秒、REC_2 は 32.3 秒、REC_3 は 34.0 秒。どれもほとんど静かな背景の音（平均 −58〜−61 dBFS）。短い音が WATCH_1 の 0.5〜1 秒（−31 dBFS）と REC_2・REC_3 の初め（−43 dBFS）にあるだけ。人の声かどうかは確かめていない。
  - 映像（`*.h265`）は画像にできなかった。ffmpeg は「PPS id out of range」：パラメータの組（VPS/SPS/PPS）が I フレームの暗号化された先頭 128 バイトの中にあると推測。→ **見えたものはない**。

## 5. 比較

| ID | 通信フェーズ | 観測 | 公式文書の記載 | 判定 | PCAP 側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| K1 | WAN_RECORDING | 録画の操作の間、ドアベルの映像と音声が AWS の中継へ。P フレームと音声は暗号化なし。暗号化は映像のバイトの 0.25% | 「AES-256（10/22 の版は AES-128）data encryption ensures your footage is kept private on transmission and storage.」 | **条件付きの矛盾** | REC_2・REC_3（上の表）。P フレーム 942 枚、音声 1,036 枚、例 14:40:09.602183Z → 54.219.251.168:11392 | D3（2021-07-23、2021-10-22）、D4（2021-12-04）「Storage You Can Trust」 | 観測：高い。判定：中 | 条件は §8 の C-a。暗号化の方式と鍵の長さは観測不能 |
| K2 | WAN_RECORDING | 同上 | 「All recorded footage is encrypted on-device and sent straight to your phone … Data during transmission is encrypted.」 | **条件付きの矛盾** | 同上 | D1（2021-09-25）、D2（2021-06〜12） 「End-to-End Encryption」 | 観測：高い。判定：中 | 「only you have the key to … watch」は、映像が画像にできなかったので否定できない |
| K3 | WAN_WATCH | ライブ視聴で同じ形（P フレームと音声は暗号化なし） | K1・K2 の文 | **公式文書に記載なし** | WATCH_1・WATCH_2（上の表） | D1–D4 | 観測：高い | 最も限定的な読み方では「footage」は録画なのでライブは範囲外。ライブも含めて読むと**明確な矛盾**（eufy 自身が eufyCam 2 のページで「Live-stream and record footage」と書く） |
| K4 | WAN の両方 | 映像は直接ではなく AWS の中継を通る。中継の住所は P2P のサーバーが渡す | 「sent straight to your phone」「transmitted to you, and only you」 | **公式文書に記載なし** | WATCH_2 14:36:34.704401Z の f1 82（中継 3.16.202.62 など） | D1/D2 | 高い | 中継は届け先ではなく途中なので、限定的な読み方では矛盾しない。中継の持ち主は未確認 |
| K5 | — | 鍵の長さは見えない | 「Military-grade」「AES-256」／「AES-128」 | **判断不能**（military-grade）、**観測不能**（鍵の長さ） | I フレームの 128 バイト（中身は読めない） | D1–D4。米国の D3 は 7 月と 10 月で 256→128 に変わり、カナダの D4 は 256 | — | 文書どうしの食い違いで、通信との矛盾ではない |
| K6 | LOCAL_RING | 呼び鈴のたびに S3 の `zhixin-security-pr` へ約 24 KB を上げる（中身は TLS） | 「your private data never leaves the safety of your home」「All your data is stored locally」 | **公式文書に記載なし** | LCLRING_1〜3（§4）。例 14:31:49.656040Z → 52.92.147.210 | D1/D2「Local Storage」、D5 | 観測：高い。中身：観測不能 | 限定的な読み方では対象は録画（動画）で、24 KB は動画ではない。中身が画像で、広く読めば矛盾になりうる。上げ先の持ち主は未確認 |
| K7 | LOCAL_RING | 同上 | 顔の画像は「kept in the local Products only」（クラウド保存を選ばない限り） | **観測不能** | 同上 | D7「Images and biometric information」 | — | 中身、顔の機能の設定、クラウドの契約のどれも分からない |
| K8 | LOCAL_RING | 同上 | 「On-Device AI … without … sending it to the cloud」 | **観測不能** | 同上 | D1/D2 | — | 上げた物の用途が見えない |
| K9 | 全フェーズ | 心拍にシリアルが平文。サーバーが公開 IP を平文の JSON で返す。DNS・mDNS も平文 | 「Data during transmission is encrypted.」／「any unique identifiers associated with your Product」を集める | **公式文書に記載なし** | 例 POWER_1 2021-09-23T11:56:33.009662Z 192.168.137.147 → 18.224.66.194:8006（ヘッダに `T8010P1320431DEF`）、11:56:33.159431Z の `{"device_ip":…}` | D1/D2「End-to-End Encryption」、D7「Product monitoring」 | 高い | 限定的な読み方では「Data」は録画の映像。何でもと読むと矛盾。識別子を集めることは D7 が開示 |
| K10 | 全フェーズ | AWS への TCP はすべて TLS 1.2 | クラウドに保存するときは「TLS and SRTP」 | **観測不能** | TLS の ClientHello 259 回、すべて 0x0303 | D1/D2 FAQ 4 | — | クラウドへの録画の保存は見えない（契約も不明）。見えた TCP に矛盾はない |
| K11 | 全フェーズ | 録画の大きさの上りはない（ユーザーが求めた WAN の視聴だけ） | 「eufy records and stores videos locally」「Stored locally」 | **一致** | TLS の上りは Ring の S3 の 3 回（約 24 KB）のほかはどれも 1,024 バイト以下。UDP で映像を送ったのは WAN の操作の時だけ | D1/D2 FAQ 1、冒頭 | 中 | 呼び鈴で録画が作られたかは未確認 |
| K12 | — | 2560×1920 の H.265 を HomeBase が中継 | 2560×1920、HomeBase 2 が Battery Video Doorbell 2K に対応 | **一致** | 枠の情報 | D3 仕様表、D6 | 高い | 機種を決めるための材料 |
| K13 | — | — | 社員はライブを見られない、見る人を決められる、ISO 27001/27701、OTA の更新 | **観測不能** | — | D1/D2 FAQ 10・Video Authorization・Proof Of Privacy、D9 | — | — |
| K14 | LAN の両方 | 映像は収録にない | K1・K2 の文 | **観測不能** | LANWATCH 8〜11 パケット、LANRECORDING 68〜70 パケット（心拍と TLS だけ） | — | — | — |

## 6. 食い違いの詳しい内容（K1・K2）

**公式の主張（原文）**
- D3/D4「Storage You Can Trust」：「Military-grade AES-256 data encryption ensures your footage is kept private on transmission and storage.」（米国 2021-07-23・カナダ 2021-12-04。米国 2021-10-22 は AES-128）
- D1/D2「End-to-End Encryption」：「All recorded footage is encrypted on-device and sent straight to your phone—and only you have the key to decrypt and watch the footage. Data during transmission is encrypted.」

**観測した事実**
- README の操作「Record the video feed from the doorbell」（WAN＝別のネットワークのスマホ）の 2 回で、HomeBase は録画の命令（1009）から止める命令（1010）をはさむ間、ドアベルの映像と音声を UDP で AWS の中継（54.219.251.168、35.162.187.157）へ送った。
- 映像 3,201,028 バイトのうち暗号化された（読めない）のは I フレームの先頭 128 バイトずつ、計 7,936 バイト（0.25%）だけ。P フレーム 942 枚は全体が平文の H.265（NAL と POC で確認）。I フレームの残りも平文の H.265 の性質を示す。音声 1,036 枚（198,900 バイト）は全部平文の AAC で、そのままデコードできた。
- DTLS などの別の暗号化の層はない（UDP の中身の頭から PPPP、XZYH、H.265 が平文で読める）。

**どこが食い違うか**：文書は「footage は送るときに AES の暗号化で守られる」「Data during transmission is encrypted」と言う。通信では、録画の操作をした映像のほとんどと音声のすべてが、暗号化されずにインターネットの中継へ出ている。

**最も限定的な読み方と、それでも矛盾する理由**：「footage」＝録画した映像（ライブは含めない）、「on transmission」＝その映像を送るとき、と読む。WAN_RECORDING は録画の操作で、送られたフレームはその録画の中身そのもの。だから、**録画が eufy の機器（HomeBase）の上で行われたなら**、録画した映像が送られる時に暗号化されていない＝矛盾。D1/D2 の「encrypted on-device and sent … to your phone」も同じ。

**別の読み方と退けた理由**
- 「transmission」をドアベル→HomeBase の無線だけと読む：文に区間の限定がないので、足して読まない。その区間なら観測不能。
- 「先頭だけでも暗号化されているので encrypted と言える」：P フレームは暗号化の印（signCode）もなく全体が平文。音声も平文。「All recorded footage is encrypted」「Data during transmission is encrypted」とは合わない。
- 「見られないから private」（Anker の 2023 年の説明。The Verge の報道の二次資料による）：今回も映像は画像にできなかったので「only you … watch」は否定できない。ただし文が言うのは「暗号化」で、暗号化されていない事実は変わらない。音声は聞ける形で出ている。
- 録画がスマホの上なら（§8 C-a）、送った時点ではまだ「録画」ではない、と読める。この場合は限定的な読み方では範囲外になる。だから「明確」ではなく「条件付き」。

## 7. 反証の検討

| 探したもの | 見つけたもの | 判定への影響 |
|---|---|---|
| 同じ時期の公式文書が、中継・一部だけの暗号化・平文の音声を開示していないか（D1–D11、FAQ、VDP、QSG、プライバシーポリシー） | 開示なし。2021 年のサポート記事は保存に本文がなく読めない | 変わらない（サポート記事は未確認として残る） |
| 文の範囲（機種・地域） | D3/D4 はまさにこのドアベルのページ。カナダ版で 10-13 より前の保存はなく、カナダのキットのページ（D5、9 月）には暗号化の文がない。地域を問わない D1 は 9 月のカナダ版にある | K1 のカナダでの当時の有効性は、米国の D3（7 月と 10 月）と、後のカナダの D4（12 月）からの推測を含む。K2 はカナダの当時の文書で支えられる |
| 「footage」の範囲 | eufy 自身が「Live-stream and record footage」と書く（eufyCam 2、2020-12） | ライブも含めるなら K3 も矛盾。ただし限定的な読み方は変えない |
| データセットの事情 | README で操作の内容は分かる。中間者の検査なし（証明書は本物）。再送で同じ DRW が 1〜8 回出るので番号で重複を除いた。REC_2 で DRW の番号が 8 つ欠けるだけ | 変わらない |
| 本当に平文か | H.265 の文法（NAL 型、スライスの頭、POC が GOP の位置と 1,116/1,116 で一致）。I フレームの残りで `00 00 03` が 40 回・`00 00 0[0-2]` が 0 回。音声がデコードできる | 平文は確実 |
| 本当にこの機器か | 送り元は HomeBase の MAC と IP。枠の情報は 2560×1920 | 変わらない |
| 暗号化の印の読み違い | signCode の位置は第三者の実装による。ただし平文の判断は印に頼らず、中身の文法で確かめた | 変わらない |
| 後の文書 | 公式の記事（日付なし、現在）は「ライブ視聴中の手動録画はスマホのアルバムに保存」。WOOT 2024 の論文は、後のファームではスマホへのメディアの流れが P2P の AES で暗号化されると書く | 条件 C-a を「満たさない」方へ弱める。ファームの版によって振る舞いが違う可能性（今回の版は未確認） |

## 8. 条件

- **C-a（K1・K2）**：WAN_RECORDING の録画が eufy の機器（HomeBase／ドアベル）の上で行われたか。満たせば、送られたフレームは「録画した映像」で、限定的な読み方でも矛盾。
  - 調べたこと：README は「Record the video feed from the doorbell」とだけ書く。通信では録画の命令（1009/1010）がスマホから HomeBase へ送られている（中身は暗号化）。映像の流れは命令の前から始まり、止めた後も続く（ライブの流れの中で録画を入り切りした形）。後の公式の記事は「手動の録画はスマホのアルバムへ」（2021 年の版は Wayback に本文がなく未確認）。
  - 残ったこと：2021 年当時、録画がどこに保存されたかは決められない。後の記事は「スマホ」を示すので、条件はむしろ満たされない方に傾く。
- **C-b（K4・K6 の補足）**：中継の AWS のアドレスと S3 の `zhixin-security-pr` の持ち主（eufy か第三者か）、S3 に上げた物の中身。どちらも通信からは決められない。

## 9. 先行資料

検索語（先行資料の検索は 3 回）：「eufy camera live stream unencrypted P2P relay end-to-end encryption claim Paul Moore 2022 Verge」「eufy HomeBase P2P protocol video stream encryption analysis paper USENIX OR NDSS OR "IEEE S&P" OR CCS camera relay plaintext」「theverge.com Anker Eufy lied to us … Anker finally comes clean …」。

- **V. Goeman, D. de Ruck, T. Cordemans, J. Lapon, V. Naessens, "Reverse Engineering the Eufy Ecosystem: A Deep Dive into Security Vulnerabilities and Proprietary Protocols," USENIX WOOT 2024, pp. 133–147**（本文を読んだ）。同じ HomeBase 2＋Video Doorbell 2K。§2.1.2（p. 135）：スマホのアプリへのメディアは P2P で「encrypted with a symmetric P2P AES key」、WAN では「relayed through a custom cloud server」。§5.4.2（p. 140）：画像は頭の 256 バイトだけを暗号化し、残りは平文。§8（p. 144）：P. Moore が web の画面の映像の平文とクラウドへの画像の送信を示した。→ 「一部だけの暗号化」は画像について既に報告がある。**2021 年のファームで、スマホの WAN の視聴・録画の H.265 の P フレームと音声が P2P の層でも暗号化されずに中継へ出ていたこと**は、読んだ範囲では書かれていない（論文の版のファームでは P2P の層が暗号化されている）。WOOT は四大会議（S&P、USENIX Security、CCS、NDSS）ではない。四大会議で同じ問題を示す論文は見つけていない。
- 報道（2022-11〜2023-01、The Verge が元。今回読んだのは MacRumors、gHacks などの二次資料だけ、The Verge の原文は**未確認**）：web の画面の映像の流れが暗号化されていなかった。Anker は「natively end-to-end encrypted ではない」と認めた。アプリの流れは「傍受しても見られない」と説明した。Moore は通知の画像のクラウドへの送信も示した（K6 に近いが、今回のデータからは中身は見えない）。
- 公開の実装 bropat/eufy-security-client（`src/p2p/session.ts`、現在の版）：映像の枠で signCode>0 のとき「先頭 128 バイトだけ AES で復号し、残りはそのまま」、signCode=0 と音声は復号しない。→ この方式自体は公開のコードで知られている。
- 見つからなくても新しいとは言わない。

## 10. 断定できる／できない、未確認の一覧

**断定できる**
- 2021-10-13 の WAN の 4 本で、HomeBase は AWS の中継へドアベルの映像（2560×1920 の H.265）と音声（AAC）を UDP で送り、P フレーム 1,139 枚と音声 1,252 枚は暗号化されていなかった。暗号化されていたのは I フレームの先頭 128 バイトずつ（映像のバイトの 0.21%）だけ。
- その間、スマホから HomeBase への命令は暗号化されていた。
- HomeBase はいつも、シリアルを平文で含む心拍を 4 つの eufy のサーバーへ送り、公開 IP を平文の JSON で受け取っていた。
- TCP はすべて TLS 1.2。呼び鈴のたびに S3 の `zhixin-security-pr` へ約 24 KB を上げていた。
- 同じ時期の Privacy Commitment（カナダ・米国）と、ドアベルの製品ページ（米国の 7 月と 10 月、カナダの 12 月）は、送る時の暗号化を約束していた。中継や一部だけの暗号化の開示は見つからない。

**断定できない**
- 「録画した映像」を送る時の約束に反するか（条件 C-a）。
- ライブ視聴が約束の範囲に入るか（読み方による。限定的な読み方では入らない）。
- S3 に上げた物の中身と、それがプライバシーの約束に反するか。
- 暗号の方式・鍵の長さ（AES-128 か 256 か）。
- 映像そのものを第三者が見られるか（今回は画像にできなかった）。

**未確認**
- 論文の本文（IEEE Xplore が開けない）。データセットのライセンス。国と施設の明記（推測は UNB）。データセット全体の期間。
- ドアベルの型番・シリアル・ファーム。HomeBase のハードウェアの版・ファームの版。アプリの版。
- 2021 年のサポート記事（Wayback の保存に本文がない）。カナダのプライバシーポリシー（保存なし）。2021 年に有効だったアプリのプライバシーポリシー（D8 が後に D7 に置き換わったかどうか）。
- 中継と S3 のバケットの持ち主。スマホの WAN 側の住所（PUNCH_TO を読むと 131.202.221.52、穴あけの宛先は 174.119.221.52。住所の読み方は推測）。
- The Verge の原文。
- LAN の視聴・録画の通信（収録にない）。

## 11. まとめ

- 最も強い判定は**条件付きの矛盾**。WAN の録画の操作で、ドアベルの映像の 99.7% 以上（P フレームの全体と I フレームの残り）と音声のすべてが、暗号化されずに AWS の中継へ出ていた。一方、ドアベルの製品ページは「AES data encryption ensures your footage is kept private on transmission」、Privacy Commitment は「Data during transmission is encrypted」と書く。
- 論文の中心に使えるかは**条件つき**。平文の観測は確実（H.265 の文法と音声のデコードで確認）。ただし最も限定的な読み方（footage＝録画）で矛盾と言うには「録画が機器の上で行われた」という未確認の条件が要る。しかも後の公式の記事は、手動の録画の保存先をスマホと書いていて、条件を満たさない方に傾く。
- ライブ視聴（WAN_WATCH）も同じ形で平文だが、限定的な読み方では範囲外（公式文書に記載なし）。「footage」をライブまで含めて読む立場をはっきり書けば、より強い所見として示せる。
