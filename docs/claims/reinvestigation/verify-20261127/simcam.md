# SimCam 1S（Simshine）：公式の発表と CIC IoT Dataset 2022 の通信の照合

作成 2026-11-27。前の調査の結論（Quarant/docs、quarant-results、claims の解析結果）は読まずに、データと文書を一から確かめた。時刻はすべて UTC（`tshark -t ud`）。認証情報（AWS のアクセスキー ID と署名）は `simcam-secrets.md` にだけ書いた。

---

## 1. データセット

| 項目 | 内容 | 根拠 |
|---|---|---|
| 名前 | CIC IoT Dataset 2022 | https://www.unb.ca/cic/datasets/iotdataset-2022.html （2026-11-27 に本文を取得して読んだ） |
| 作成者・論文 | S. Dadkhah, H. Mahdikhani, P. K. Danso, A. Zohourian, K. A. Truong, A. A. Ghorbani, "Towards the Development of a Realistic Multidimensional IoT Profiling Dataset", 2022 19th Annual International Conference on Privacy, Security & Trust (PST), pp. 1–11, 2022-08-22, DOI 10.1109/PST55820.2022.9851966 | DOI・頁は Crossref で確認。論文の本文（機器表など）は IEEE の有料のため**読めていない（未確認）** |
| 配布元 | http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2022/（登録フォーム経由） | データセットのページの「Download the dataset」 |
| 利用条件 | データセットのページにもダウンロードのフォームにもライセンスの記載がない。**未確認**（探した所：データセットのページ、IoT Lab のページ https://www.unb.ca/cic/iot-lab/dataset.html 、ダウンロードのページ、データ内の Readme.txt 5 本） | |
| 収録の場所 | ページに明記なし。CIC（UNB、カナダ・ニューブランズウィック州フレデリクトン）の実験室と**推測**。根拠：PST 2022 がフレデリクトン開催、カメラが画像に焼き込んだ時刻「2021-11-02 16:11:33」が UTC 19:11:30 に対応し UTC−3（大西洋夏時間）と合う | 画像 1635880290（下の 4 節） |
| 収録の仕組み | 64 ビットの Windows 機に NIC 2 枚（ゲートウェイ側と、スイッチ側で Windows のインターネット接続共有）。Wireshark（手動の実験）と dumpcap（半自動）。無線の機器は同じスイッチにつないだ Vera Plus が作る無線環境に入る | 上の 2 ページ。データでも機器の相手は常にゲートウェイの MAC（3c:18:a0:45:da:85 / 3c:18:a0:41:c3:a0、192.168.137.1）で、192.168.137.0/24 は Windows の接続共有の既定と一致 |
| データセット全体の期間 | 手元で見える範囲：最初は 2021-09-22 15:32:43.203211Z（`1-Power/Cameras/ArloQ Camera/POWER/arloqcamPOWER_1.pcap` の先頭）、最後は Idle `2021_12_23_Idle.pcap` の終わり（SimCam 分の最後 2021-12-24 09:59:56.733203Z）。Active はページでは 30 日分だが手元にあるのは `2021_11_02_Active.pcap` の 1 日分だけ。6-Attacks は除外。**全体の正確な開始・終了は未確認** | Power・Interactions・Scenarios 1002 本の先頭パケットの時刻、Idle のファイル |
| この機器の最初と最後 | 最初 2021-09-22 16:17:25.110369Z（`1-Power/Cameras/SimCam/POWER/simcamPOWER_1.pcap`、LLC XID）／最後 2021-12-24 09:59:56.733203Z（`2-Idle/2021_12_23_Idle.pcap`） | tshark |
| 作成者の操作（ページと Readme.txt） | **Power**：全機器の電源を切りネットワークを再起動、1 台ずつ電源を入れて単独で収録、3 回。**Idle**：夜間（実験室は無人、操作なし）を 30 日。**Interactions**：カメラは Photo（撮影）・Recording（録画）・Watch（視聴）。LAN＝同じネットワークにつないだスマホのアプリ、WAN＝別ネットワークのアプリ。各 3 回。**Scenarios**：6 種の生活の筋書き。**Active**：日中、研究者が自由に出入りし機器を受動的・能動的に使う。**Attacks**：LOIC の洪水、Nmap/Hydra の RTSP 総当たり（攻撃側で収録） | 3-Interactions/Readme.txt ほか |
| SimCam の収録 | Power 3 本（2021-09-22 16:17–16:43Z）、Interactions は LAN_WATCH 3 本（2021-10-06 17:46–17:50Z）、LAN_PHOTO 3 本・LAN_RECORDING 3 本（2021-10-12 13:35–13:43Z）。**WAN_PHOTO / WAN_RECORDING / WAN_WATCH のフォルダは空**。Idle 30 本（各約 11 時間、22:00/23:00Z→09:00/10:00Z）、Active 1 本（2021-11-02 11:15:03–19:15:18Z）。Scenarios 18 本はこの MAC のパケットが 0 | 元のフォルダの一覧と tshark。Interactions の元ファイルは手元の切り出しとパケット数が同じ（作成者が既に MAC で絞っていた） |

注意：IoT Lab のページは Idle を「8 時間」とするが、実際は約 11 時間。Idle の Readme は「全 40 台のネットワーク全体」を収録したとし、IoT Lab のページは「機器ごとに MAC で絞った dumpcap」とする（どちらでも、この切り出しはカメラの MAC で行った）。ファイル名の日付と中身の日付がずれるもの（例 `2021_12_07_Idle.pcap` は 2021-12-06 23:00Z 開始）がある。

## 2. 機器

| 項目 | 内容 | 根拠 |
|---|---|---|
| 製造者 | Wuhan Simshine Intelligent Technology Co., Ltd.（武汉星巡智能科技有限公司） | プライバシーポリシー、App Store の販売元 |
| 製品名 | データセットの表記は「SimCam」だけ。**1S 系（SimCam 1S か Alloy 1S）と推定**。根拠：(1) S3 への PUT の User-Agent「Mozilla/4.0 (Compatible; s3; libs3 4.1; Linux aarch64)」＝64 ビット Arm で、1S と Alloy 1S の仕様の Ambarella CV25 と矛盾しない（初代 SimCam は Intel Movidius と記載）、(2) 更新サーバーが返す版名「1.20200720.tgz」が、Simshine のサポートの「Simcam 1S update.tgz V20200720 for SimHome」「Alloy 1S … V20200720」と一致（ただしその掲載の保存は 2022-05-16 で収録後）。1S か Alloy 1S かは通信から決められない。論文の機器表は**未確認** | Active の PUT、Power の HTTP 応答 |
| 型番・ハードウェアの版 | 通信に型番は出ない。**未確認** | |
| MAC | 10:2c:6b:1b:43:be（OUI は AMPAK Technology＝無線モジュールの会社） | Wireshark の manuf |
| 機器 ID | `0x972f85c7e3`（全期間で同じ。getZeroTime の本文、TCP 9999 の心拍、S3 のパス） | 下の 4 節 |
| IP（DHCP、Windows の接続共有） | .222（Power 09-22）、.23（LAN_WATCH 10-06）、.129（LAN_PHOTO/RECORDING 10-12）、.149（Active 11-02、Idle 11-02〜11-08）、.202（Idle 11-10〜12-02）、.218（Idle 12-03〜12-13）、.131（Idle 12-15〜12-23）、いずれも 192.168.137.x | 送信元 IP の集計 |
| DHCP | クライアント「udhcp 1.30.1」（BusyBox）。DHCP は DNS に 192.168.137.1 を渡すが、カメラは常に 114.114.114.114 に問い合わせる（固定と推測） | simcamPOWER_1.pcap 2021-09-22 16:17:25.757132Z ほか |
| ファームウェアの版 | **未確認**。カメラが送る版の情報は暗号化されている（getNewVersion の本文）。サーバーの応答は 7 回すべて `{"is_success":1,"data":"1.20200720.tgz"}`（Power 6 回、Active 2021-11-02 12:36:26Z の 1 回）。更新ファイルのダウンロードは収録中に一度もない（大きな受信は S3 への送信以外にない）。**収録の中で変わった形跡はない**（観測できた日だけ） | |
| アプリの版 | **未確認**（スマホの通信はこの切り出しに入っていない）。参考：SimHome の iOS 版は 2021-09-29 に 1.2.7（App Store、2021-10-09 保存）。1S は 2020 年の更新で SimCam アプリから SimHome アプリに移った（ストアの告知、2021-09-19 保存） | |

## 3. 公式文書

収録の期間：2021-09-22〜2021-12-24（中心の観測は Active 2021-11-02）。文書の中に日付があるものはほとんどない。Wayback の保存日時は UTC。

| ID | 文書 | 発行元 | 文書の中の日付 | Wayback 保存日時 | アーカイブ URL | 言語・地域 | 対象 | 収録との関係 |
|---|---|---|---|---|---|---|---|---|
| D1 | SimCam 1S FAQ（simshine.ai） | Simshine | なし | 2021-08-02 17:30:07／2021-10-24 05:07:25（両方で該当文は同じ。違いは商標表記だけ）。旧 URL 2020-07-13 にも同文 | https://web.archive.org/web/20211024050725/https://simshine.ai/simcam-1s/faq.html ／ https://web.archive.org/web/20210802173007/https://simshine.ai/simcam-1s/faq.html | 英語・全世界向け | 1S | 前・中（Active の 9 日前） |
| D2 | 1S の販売ページ（store.simcam.ai） | Simshine の直販 | なし（画像の更新 2020-12-28） | 2021-10-06 00:46:00／2022-01-25 10:28:24（該当段落は同じ） | https://web.archive.org/web/20211006004600/https://store.simcam.ai/products/home-security-camera-simcam-1s | 英語 | 1S の頁だが段落の主語は「SimCam Alloy 1S」 | 中 |
| D3 | 1S の製品ページ（simshine.ai） | Simshine | なし | 2021-01-24 12:57:08（次の保存は 2023-02-03 で別内容） | https://web.archive.org/web/20210124125708/https://www.simshine.ai/simcam-1s.html | 英語 | 同上（段落は D2 と同文） | 前（収録中も有効だったかは未確認。D2 に同文があるので文は収録中も公開） |
| D4 | SimHome Privacy Policy（英語） | Wuhan Simshine | なし | 2021-10-06 13:28:07（初保存。次 2022-06-25 は小さな追加のみ） | https://web.archive.org/web/20211006132807/https://www.simcam.ai/simhome-eprivacy | 英語 | SimHome アプリ・アカウント・Simshine の製品とサービス | 中 |
| D5 | SimHome 隐私政策（中国語） | 武汉星巡智能科技有限公司 | なし | 2020-11-27 05:46:03（次 2022-06-25） | https://web.archive.org/web/20201127054603/https://www.simcam.ai/simhome-privacy | 中国語 | 同上 | 前 |
| D6 | Privacy Statement（ストア） | store.simcam.ai | なし | 2021-10-25 06:16:12 | https://web.archive.org/web/20211025061612/https://store.simcam.ai/pages/privacy-policy | 英語 | ストアと「our products and services」 | 中 |
| D7 | SimHome の App Store の説明（米国） | 販売元 Simshine | 版 1.2.7（2021-09-29） | 2021-10-09 03:35:10 | https://web.archive.org/web/20211009033510/https://apps.apple.com/us/app/simhome/id1484916649 | 英語・米国 | SimHome アプリ | 中 |
| D8 | Upgrade your SimCam APP now | ストア | なし | 2021-09-19 13:56:46 | https://web.archive.org/web/20210919135646/https://store.simcam.ai/pages/upgrade-your-simcam-app-now | 英語 | 1S を含む全製品 | 前 |
| D9 | SimCam 1S User Manual 2020-05-28（PDF） | Simshine | 名前に 2020-05-28、PDF の作成 2020-07-06 | 2022-11-29 17:11:29（保存は先頭 1 MiB だけ。2026-11-27 に元の URL から全体 1,741,649 バイトを取得し、先頭 1 MiB が保存と一致することを確認） | https://web.archive.org/web/20221129171129/https://www.simshine.ai/images/SimCam%201S%20User%20Manual%202020-05-28.pdf | 英語 | 1S | 文書は前、保存は後 |
| D10 | 1S のサポート（ファーム V20200601、SimHome へ移行） | Simshine | V20200601 | 2020-07-12 18:03:06 | https://web.archive.org/web/20200712180306/http://www.simshine.ai:80/support-simcam-1s.html | 英語 | 1S | 前 |
| D11 | 1S/Alloy 1S のサポート（ファーム V20200720） | Simshine | V20200720 | 2022-05-16 12:57:19（初保存） | https://web.archive.org/web/20220516125719/https://simshine.ai/support/simcam-1s-and-alloy-1s.html | 英語 | 1S・Alloy 1S | 後（参考） |
| D12 | 1S の仕様・比較（ストア／simshine.ai） | Simshine | なし | 2021-09-19 14:26:44／2020-12-05 02:17:57 | https://web.archive.org/web/20210919142644/https://store.simcam.ai/pages/spec-of-simcam-1s ／ https://web.archive.org/web/20201205021757/https://simshine.ai/simcam-1s/compare.html | 英語 | 1S | 前 |
| R1 | 旧 1S 製品ページ（simcam.ai と simshine.ai） | Simshine | なし | simcam.ai 2020-08-08 13:57:42（その後 2022-12 まで保存なし）。simshine.ai 版は 2020-08-11 まで同文、2021-01-24 には D3 に差し替え | https://web.archive.org/web/20200808135742/https://www.simcam.ai/simcam-1s | 英語 | 1S | 前。**収録時に有効だったと確認できない**ので参考 |
| R2 | SimCam AI の App Store、2019 年の simcam.ai FAQ・サポート、Open Platform V1.2 | Simshine | — | 2021-10-09、2019-10-15、2021-04-13 | （本文は snapshots に保存済み） | 英語 | 初代 SimCam（Movidius）／SimCam アプリ | 機種・アプリが違うので参考 |
| — | ブログのプライバシー（blog.simcam.ai、2021-10-20）、ストアの利用規約（2021-11-30） | | | | | | ウェブサイトだけ | 対象外 |

セキュリティ専用のページ（ホワイトペーパー、脆弱性の窓口など）は見つからなかった。セキュリティの記述は D4・D5 の「Information security」節と製品ページの宣伝文だけ。探した所：snapshots の Simshine 関係 50 件、simshine.ai/support と simcam.ai の Wayback 一覧。

**該当する文（原文の引用）**

- D1「Privacy」Q1：*"Will you use my data to train the AI like Nest and Arlo? — No. Because the Simshine ® Simcam 1S uses entirely local AI processing, we never have access to your data."*
- D1「Privacy」Q2：*"The live videos are streamed directly into your phone on a secured P2P (peer-to-peer) network without going through a server. Only you can view the video through the paired APP."*
- D1「Event Alert & Recording」：*"Push notifications are usually sent within 1 to 2 seconds."*
- D2/D3「On-device privacy protection」：*"Simshine® SimCam Alloy 1S processes and stores video locally on the device. Both your account and the video stream are secured with bank-level encryption. Prevent hackers by locking access to the camera with Lan Mode. No one but you can access your data."* 下に「AES-128/256 Encryption」「P2P Network」「Lan Mode」。
- D2「Finally, an end to false alerts」：*"… sends alerts directly to your phone and immediately stores a video upon the detection of a person …"*
- D4「How we collect data」：*"When you synchronize Simshine products data, your image data will be transferred to your mobile device via the server."*（D5 は「您的数据将通过服务器传输到您的移动装置上」で「image」の語はない）
- D4「Information security」：*"We use SSL to encrypt many services."* ／ *"we will continue to work hard to protect your information and implement safeguards such as storage and transmission of full security encryption …"*（D5：「我们将不断努力保障您的信息安全，并实施储存和传输全程安全加密等保障手段」）
- D4「Sharing information」：*"To our third-party service providers who perform … website hosting, data analysis, … infrastructure provision, IT services …"*
- D7「Description」：*"… receive the push notifications, event pictures and videos anytime, anywhere …"*、*"Data security: encrypted storage, protect your data from leaking."*。「App Privacy」：*"Data Not Linked to You: … User Content …"*。In-App Purchases：*"One month cloud storage $4.99 …"*
- D9「Key features and benefits」：*"Local processing & storage - Never have to pay any subscription fee or concern your privacy."*
- R1：*"Unlike cloud-based cameras, SimCam 1S never collects user data or shares it with other parties. Everything is processed and stored locally on the device with a bank-level encryption."*

## 4. 観測（フェーズごと）

TLS・DTLS・QUIC は全 61 本で 0 フレーム。カメラが使った宛先ポートは TCP 80・9999、UDP 53・67・10001・10240 だけ。

**起動（Power、`1-Power/Cameras/SimCam/POWER/simcamPOWER_{1,2,3}.pcap`、2021-09-22）**
- 平文：DNS（114.114.114.114、例 16:17:32.000250Z `www.luuka.fun` A→44.229.24.254）。
- 平文 HTTP：`www.luuka.fun`（44.229.24.254:80、nginx/1.13.6、AWS us-west-2）への POST 4 種。16:17:32.183123Z `POST /bind/bind/getZeroTime` 本文 `data=0x972f85c7e3`（機器 ID が平文）→ 応答 `{"is_success":1,"data":1632327453}`（時刻）。16:17:32.999071Z `/ota/ota/getNewVersion` → 応答 `"1.20200720.tgz"`。ほかに `/ota/ota/saveOtaResult`、`/faceservice/deviceface/queryDeviceInTheFaceInfo`（応答 `"data":[]`＝登録顔なし）。URL と応答の JSON は平文。
- 平文：TCP 9999（54.202.68.76、AWS us-west-2）で 16:17:33.639618Z から「`0x972f85c7e3&`」を送り「`ok`」「`heart`」を受ける心拍（以後約 58 秒ごと）。
- 平文：公開 IP を調べる HTTP GET（ipinfo.io `/ip`、icanhazip.com `/`、myip.ipip.net `/ip`、ip.cip.cc `/`）、以後約 1 時間ごと（全体で各 340 回前後）。
- 読めない：16:17:48.645588Z `all-master.iotcplatform.com` を引き、UDP 10240 へ 54 バイト、続いて 3 台（139.162.61.175／62.210.208.47／198.255.24.202、Idle では 45.35.33.242 も）の UDP 10001 へ 288 バイトの登録と 4 バイトの保持（約 5 秒ごと）。中身に読める文字列はない。断片に「Char」が見え、ThroughTek（TUTK）の IOTC の難読化と**推測**（ホスト名と形からの推測で、目的は確かめていない）。標準の暗号プロトコルではない。
- 暗号化（根拠）：luuka.fun への POST の本文（getZeroTime 以外）は Base64 の Base64 で、中は 96／144／160／224 バイト（すべて 16 の倍数）、読める文字なし、同じ口では先頭 16 バイトが毎回同じ。16 バイト単位のブロック暗号と**推測**（AES かどうかは未確認）。

**夜間（Idle 30 本）**：UDP 10001 の保持、TCP 9999 の心拍、毎時の IP 調べ、DNS だけ。luuka.fun への HTTP も S3 への送信も 0 回（30 晩すべて）。上流から ICMP の時間超過・到達不能が少数。

**日中（Active `2021_11_02_Active.pcap`、11:15–19:15Z、カメラ 192.168.137.149）**：人の検出ごとに次の 3 つが続く。16 回。
1. `POST /event/event/saveEvents`（www.luuka.fun、本文は暗号化、405 バイト）
2. `PUT http://elasticbeanstalk-us-east-2-793503604989.s3.amazonaws.com/SimCam/0x972f85c7e3/PersonDetect/<UNIX 時刻>`（S3、TCP 80、**平文**）。ヘッダ `Content-Type: image/jpeg`、`x-amz-acl: public-read`（16 回すべて）、`x-amz-content-sha256: UNSIGNED-PAYLOAD`、AWS SigV4 の Authorization（値は secrets に）。本文は JPEG そのもの。
3. `POST /push/push/pushMessage`（www.luuka.fun、本文は暗号化）

PUT の一覧（先頭フレームの時刻、宛先、パスの末尾、バイト数、応答）：11:15:13.141971Z 52.219.96.164 1635851719 22549 200／11:39:47.863395Z 52.219.88.108 1635853194 23209 200／11:51:27.952930Z 52.219.80.188 1635853894 23311 200／11:55:52.525344Z 52.219.96.124 1635854159 23165 200／11:59:11.352317Z 52.219.101.195 1635854357 23158 200／**12:00:10.901106Z 52.219.84.10 1635854417 23211 途中で切断（100 Continue のみ）**／13:20:35.848881Z 52.219.84.124 1635859242 23287 200／13:21:10.744940Z 52.219.84.124 1635859277 23186 200／13:28:39.007637Z 52.219.104.236 1635859725 22471 200／13:31:34.937687Z 52.219.101.203 1635859900 22906 200／13:40:45.963361Z 52.219.98.132 1635860452 22944 200／17:13:54.197121Z 52.219.88.74 1635873241 23213 200／17:23:53.090490Z 52.219.102.220 1635873840 22416 200／19:06:44.707261Z 52.219.141.52 1635880012 23249 200／19:07:49.368844Z 52.219.141.52 1635880076 22250 200／19:11:22.806443Z 52.219.99.4 1635880290 24707 200。
- 取り出した 15 枚（`work-simcam/img/`、一覧 `contact.jpg`）：すべて 480×270 の白黒（赤外線の夜間モードの絵）の広角画像。左に扉、右の大半はカーテン。どの画像にも人が 1 人（扉の前や扉を通る姿、何人か別の人、顔が分かる程度の大きさのものもある）写る。最後の 1 枚だけ左上に「2021-11-02 16:11:33」、右下に「SimCam」の文字。15 枚はすべて別の画像（SHA-1 が重ならない）。
- 同日 12:36:26Z に更新確認（getNewVersion など 3 つ）。

**操作（Interactions、LAN）**：LAN_WATCH・LAN_PHOTO・LAN_RECORDING の 9 本とも、背景の通信（UDP 10001、TCP 9999、IP 調べ）だけ。カメラとスマホの間のパケットは 1 つもない（全フレームの相手はゲートウェイの MAC か同報）。収録の機械が無線の端末どうしの通信を通さない配置のためと**推測**。視聴・撮影・録画の中身は**観測できない**。WAN の収録はない。

## 5. 比較

| ID | フェーズ | 観測 | 公式文書の記載 | 判定 | PCAP 側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| S1 | Active（人の検出） | 人の写った JPEG を、検出ごとに AWS S3 のバケット（アカウント 793503604989）へ平文 HTTP で PUT（public-read）。前後に luuka.fun へ事象と通知 | 「we never have access to your data」 | **条件付きの矛盾** | `2021_11_02_Active.pcap` 11:15:13.141971Z ほか 16 回（15 回 200） | D1 Privacy Q1（2021-08-02、2021-10-24） | 中〜高 | 条件は 8 節。D4・D7 が画像のサーバー経由を別の所で開示（7 節） |
| S2 | Active・Idle | 動画は一度も送られない。送られたのは静止画だけ | 「processes and stores video locally on the device」、仕様の Storage「Local」 | 一致 | Idle 30 晩で送信 0、Active の送信は 1 回 22–25 KB の JPEG だけ | D2/D3、D12 | 中 | 主語は「Alloy 1S」。静止画は外に出る |
| S3 | Active | 同 S1 | 「No one but you can access your data.」 | 公式文書に記載なし（最も限定的な読み） | S1 と同じ | D2/D3 | 中 | 段落が動画とアカウントの話で、静止画を含まない読みをとった。「your data」に静止画を含めて広く読めば S1 と同じ条件で矛盾 |
| S4 | 全体 | アカウントと映像の流れの通信は観測なし | 「secured with bank-level encryption」 | 判断不能 | — | D2/D3 | — | 方法を言わない評価の言葉 |
| S5 | 起動・Active | luuka.fun の本文は 16 バイト単位の暗号文。JPEG と機器 ID は平文 | 「AES-128/256 Encryption」（何を暗号化するか書いてない） | 観測不能 | Power 16:17:32.999071Z ほか | D2/D3 | — | AES かは分からない。対象を書かないので静止画の平文とは比べられない |
| S6 | 視聴 | 視聴の通信が収録に入っていない。UDP 10001 には 400 バイト以上のパケットが一度もない | 「streamed directly into your phone … without going through a server」 | 観測不能 | LAN_WATCH 3 本、全ファイルの UDP の大きさ | D1 Privacy Q2 | — | WAN の視聴は収録なし |
| S7 | Active・Idle | 検出の種類（PersonDetect）はアップロードの前に決まっている。常時の映像送信なし | 「entirely local AI processing」「on-device AI」 | 一致 | S3 のパス、Idle の送信 0 | D1、D2、D3 | 中 | |
| S8 | Active | 画像がクラウドへ送られ、通知がサーバー経由 | 「your image data will be transferred to your mobile device via the server」、App Store「event pictures」 | 一致 | S1 と同じ | D4、D7 | 中 | S1 を弱める材料 |
| S9 | 全体 | カメラの通信に TLS は 0 | 「We use SSL to encrypt many services.」 | 観測不能 | 全 61 本で TLS 0 フレーム | D4/D5 Information security | — | 「many」はどのサービスか書いてない。アプリの通信は手元にない |
| S10 | Active | JPEG を平文 HTTP で送信 | 「implement safeguards such as storage and transmission of full security encryption」 | 公式文書に記載なし（最も限定的な読み） | S1 と同じ | D4/D5 | 低〜中 | 「will continue to work hard … implement … such as」を努力の表明と読んだ。「全ての送信を暗号化している」と広く読めば矛盾 |
| S11 | 全体 | AWS（S3、EC2）、Linode などの基盤を使用 | 第三者の基盤事業者に渡すことがある | 一致 | 宛先の逆引き（amazonaws.com、linodeusercontent.com） | D4 Sharing information | 中 | |
| S12 | 全体 | 中国の公開 DNS 114.114.114.114 と、公開 IP 調べ 4 社に毎時接続 | 記載なし | 公式文書に記載なし | DNS 2904 パケット、各サービス約 340 回 | — | 高 | 送るのは IP と簡単なヘッダだけ |
| S13 | Active | 通知は luuka.fun の `/push/push/pushMessage` 経由 | 「sends alerts directly to your phone」 | 公式文書に記載なし（最も限定的な読み） | Active 11:15:13.519620Z ほか 16 回 | D2 | 中 | 「directly」を経路ではなく「じかに知らせる」と読んだ。経路と読めば矛盾 |
| S14 | 全体 | Lan Mode の設定は通信から分からない | Lan Mode で映像の利用を LAN に限る | 観測不能 | — | D2/D3、R1 | — | |
| S15 | Active | S1 と同じ | 「never collects user data … Everything is processed and stored locally」 | 参考（収録時に有効か未確認） | S1 と同じ | R1 | — | 当時も有効なら矛盾。2021-01-24 までに D3 の文に差し替え |
| S16 | — | — | 「Never … concern your privacy」 | 判断不能 | — | D9 | — | 評価の言葉だけ |

## 6. 食い違いの詳しい内容（S1）

- **公式の主張**：D1（Simshine、SimCam 1S FAQ、Privacy の Q1、2021-08-02 と 2021-10-24 の保存で同文）"*Because the Simshine ® Simcam 1S uses entirely local AI processing, we never have access to your data.*"
- **観測した事実**：`2021_11_02_Active.pcap` で、カメラ（MAC 10:2c:6b:1b:43:be、IP 192.168.137.149、機器 ID 0x972f85c7e3）が、人を検出するたびに 480×270 の JPEG（人が写る）を `elasticbeanstalk-us-east-2-793503604989.s3.amazonaws.com` の `/SimCam/0x972f85c7e3/PersonDetect/<時刻>` に平文 HTTP で PUT し、S3 は 200 で受けた（15 回、最初は 11:15:13.141971Z、宛先 52.219.96.164:80、22,549 バイト）。各回の前後に `www.luuka.fun` へ `saveEvents` と `pushMessage`。PUT にはすべて `x-amz-acl: public-read`。夜間（Idle 30 晩）には 0 回。
- **どこが食い違うか**：カメラの AI が扱った画像そのものが、製造者側のクラウドの保存先に置かれている。保存先の持ち主（またはその委託先）はその画像を読める。さらに public-read の指定が効いていれば、URL を知る誰でも読める。「we never have access to your data」とは両立しない。
- **最も限定的な読み方**：「we」＝Simshine、「your data」＝この問いの文脈（AI の学習に使われうる利用者の画像・映像）に限る。それでも、人の検出で切り出した画像はまさに AI が処理した画像なので、この狭い範囲に入る。「have access」は「読める状態にある」と読むのが最も狭い（「実際に見た」とまで広げない）。保存先が Simshine か委託先のものなら、この狭い読みでも矛盾する。
- **別の読み方と退けた理由**：(a)「AI の学習に使わない」という意味だけ、という読み：文は「we never have access」と、使うかではなく手にするかを言い切っているので退けた。(b)「動画（録画）」だけを指す読み：問いは「my data」で、FAQ 自身が学習を「images」で説明しているので静止画を外せない。(c) 有料のクラウド保存を使う人は別、という読み：文に例外の記載がない。ただし論文で「既定の動作」と書くには 8 節の (ii) が要る。

## 7. 反証の検討

| 探したもの | 見つけたもの | 判定への影響 |
|---|---|---|
| 同じ時期の公式文書が画像の送信を開示していないか | D4（2021-10-06 保存）「your image data will be transferred to your mobile device via the server」。D7（2021-10-09）「receive … event pictures」、App Privacy に「User Content」を集めうる、クラウド保存の有料プラン。D5（2020 年、中国語）は「数据」をサーバー経由で送る | **開示はある**。S1 の矛盾（FAQ の文と通信）は消えないが、「隠していた」とは言えない。正しい言い方は「FAQ の言い切りが、通信とも、同じ会社のプライバシーポリシー・App Store の記載とも食い違う」。D4 は Simshine 自身がサーバー経由の画像の転送を認める材料でもある（8 節の (i) を強める） |
| 文の範囲（機種・機能・地域） | D1 は 1S を名指し。Alloy 1S とは「同じ機能」（D1 Model Comparison）。英語・全世界向け | 範囲の問題はない。D2/D3 の段落は主語が「Alloy 1S」なので、S3 は範囲の点でも弱い |
| データセットの事情 | Active は研究者が出入りする日中（ページ）。画像の人物はその研究者と推測。作成者の中間者の検査はない（攻撃は 6-Attacks だけで、ここでは除外。TLS もない）。Interactions は元ファイルとパケット数が同じ。Active は MAC での切り出し | 影響なし |
| 重複・再送 | PUT は 16 本の別々の TCP の流れ、15 枚の画像はすべて別のハッシュ。途中切断の 1 回は数に入れていない | 影響なし |
| 本当に平文か・本当にその機器か | JPEG を取り出して表示できた。MAC と機器 ID が Power（.222）と同じ。DHCP は機器の MAC で行われている | 影響なし |
| 利用者の設定 | クラウド保存の有料プランを買っていれば送信は利用者の選択の結果、という可能性。通信では動画の送信は 0 で、送られるのは検出ごとの 1 枚だけ。通知（pushMessage）の直前に送る。通知用の画像と**推測** | 8 節の (ii) として残す |
| D4 の「SSL」「full security encryption」 | 「many services」「will … implement … such as」 | 最も限定的な読みでは矛盾しない（S9、S10） |

## 8. 条件（S1）

**(i) 送り先の持ち主**：S3 のバケット（AWS アカウント 793503604989、us-east-2）と `www.luuka.fun` が、Simshine 自身か、その委託先のものか。
- 調べたこと：
  - カメラが使う AWS のアクセスキー ID を、公開されている方法（Be'ery 2023 の base32 復号。キーは使わず手元で計算）で復号すると、アカウント 793503604989 になり、バケット名の数字と一致した。つまり、カメラのファームウェアに入った長期の鍵の持ち主＝バケットの持ち主。
  - S3 のパスが「SimCam/<機器 ID>/PersonDetect/」。この機器 ID は luuka.fun（getZeroTime）と TCP 9999 の心拍でも使う。
  - luuka.fun の更新サーバーが返す版名「1.20200720」は、Simshine が配る 1S/Alloy 1S のファーム名「V20200720」と一致（D11、ただし収録後の保存）。
  - D4 は「image data … via the server」と、Simshine のサーバー経由を自ら書く。
  - `luuka.fun` の RDAP：2019-05-11 登録、登録業者は Alibaba Cloud（HiChina）、DNS は alidns.com、登録者は非公開。2026-11-27 時点でもまだ 44.229.24.254（AWS us-west-2）を指す。
  - Web 検索（"luuka.fun"、バケット名）では持ち主の情報は出てこない。
- 残ったこと：アカウント 793503604989 と luuka.fun の持ち主の名前は、公開の資料からは決められない。上の材料からは、Simshine か、その製品の裏側を運用する事業者のものと**推定**できる。
- (i) の代わりの条件：public-read の指定が実際に効いているか（バケットの公開設定）。バケットへのアクセスはしていないので**未確認**。

**(ii)（強さに関わる）利用者がクラウド保存の有料プランを契約していたか**：通信からは決められない。動画を送っていないことから、契約なしの通常の通知の動作と**推測**。契約ありでも「we never have access」とは両立しないが、論文で「既定の動作」と書くにはこれが要る。

## 9. 先行資料

検索語（5 回）：
1. `SimCam 1S camera security analysis unencrypted HTTP snapshot upload Amazon S3`
2. `"SimCam" Simshine vulnerability OR "security research" OR CVE camera`
3. `"CIC IoT Dataset 2022" OR "CICIoT2022" SimCam traffic privacy cloud upload`
4. `"elasticbeanstalk-us-east-2-793503604989" OR "SimCam/PersonDetect" OR "luuka.fun" camera`
5. `SimCam camera IoT network traffic measurement paper USENIX OR IMC OR NDSS OR "IEEE S&P" OR CCS`

結果：この主張（D1）とこの通信（S3 への画像の送信）の食い違いを指摘した資料は見つからなかった。通信そのもの（SimCam が画像を S3 に平文で送る、luuka.fun、TUTK 系の通信）を報告した資料も見つからなかった。IEEE S&P、USENIX Security、ACM CCS、NDSS で SimCam を扱う論文は見つからなかった。出てきたのは、宣伝の記事（Digital Trends「SimCam 1S uses strong encryption to prevent hacks」。製造者の文書ではないので比較には使っていない）と、ほかの会社のカメラの似た問題（Spotcam の S3 の画像、Guardzilla の共通の AWS 鍵など）だけ。見つからないことは「新しい」ことを意味しない。

## 10. 断定できる／できない

**断定できる（データで確かめた）**
- 2021-11-02 の日中に、このカメラが人の写った JPEG を 15 回、平文 HTTP で S3 のバケット `elasticbeanstalk-us-east-2-793503604989` に保存させた（200）。PUT は 16 回すべて `x-amz-acl: public-read`。
- その鍵とバケットは同じ AWS アカウント（公開の復号方法による）。
- 機器 ID は平文で luuka.fun と TCP 9999 に送られる。DNS はすべて 114.114.114.114 へ平文。TLS は一度も使われない。
- 夜間 30 晩は画像の送信 0。動画は一度も送られない。
- D1 の文は 2021-08-02 と 2021-10-24 の保存で同じで、Active の 9 日前にも公開されていた。

**断定できない**
- 送り先（バケット、luuka.fun）の持ち主の名前。public-read が実際に効いていたか。
- クラウド保存の契約、Lan Mode の設定。
- 機種が 1S か Alloy 1S か（データセットの表記は「SimCam」）。ファームとアプリの版。
- 視聴（P2P）が本当にサーバーを通らないか。
- luuka.fun の本文の暗号が AES か。UDP 10001/10240 の目的と中身。

**未確認の一覧**
論文の本文（機器表、期間、場所）／データセットのライセンス／データセット全体の正確な開始・終了／Active の残り 29 日（手元にない）／機器の型番・ハードウェアの版・現在のファームの版・アプリの版／luuka.fun と AWS アカウント 793503604989 の持ち主／バケットの公開設定／Lan Mode とクラウド保存の設定／スマホ側の通信／TUTK と見た通信の正体と中身／D3 の段落が 2021-09〜12 に simshine.ai に残っていたか（D2 で同文は確認）／収録中に有効だったセキュリティ専用のページ（見つからなかった）。

## 11. 3 行のまとめ

1. 最も強い判定：**条件付きの矛盾**（S1）。1S の FAQ（2021 年 8 月・10 月の保存で同文）は「we never have access to your data」と言うが、Active（2021-11-02）では人の写った JPEG を、検出ごとに AWS S3 へ平文 HTTP で、public-read の指定つきで 15 回保存させていた。条件は、保存先が Simshine かその委託先のものであること（またはそこが公開になっていること）。
2. 論文の中心に使えるか：**条件つき**。鍵とバケットは同じ AWS アカウントで、ファーム名も Simshine のものと一致し、Simshine 自身のポリシーも画像のサーバー経由を認めるので、持ち主はほぼ Simshine 側と推定できる。ただし名前は公開資料で確定できず、データは Active の 1 日分だけ。
3. 同じ時期のプライバシーポリシー（2021-10-06）と App Store（2021-10-09）が画像のサーバー経由・「User Content」の収集・クラウド保存を開示している。そのため、「隠していた」ではなく「FAQ の言い切りが、通信とも、同じ会社のほかの開示とも食い違う」という形でなら使える。
