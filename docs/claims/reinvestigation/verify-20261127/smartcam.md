# Samsung（Hanwha Techwin）SmartCam SNH-P6410BN：公式の発表と実際の通信の確かめ直し

2026-11-27 に作成。時刻はすべて UTC。前の調査の結論は読んでいない。認証情報の値は `smartcam-secrets.md` にだけ書いた。
作業ファイル：`V/out/work-smartcam/`（映像から取り出した画像と H.264 は `media/` にある）。

---

## 1. データセット

### 1-A UNSW 2018（IoT Benign and Attack Traces）
- **名前**：IoT Analytics「Attack Traces」。ページの見出しは「Data collected for our paper at ACM SOSR 2019」（https://iotanalytics.unsw.edu.au/attack-data.html 、2026-11-27 に取得）。
- **作成者と論文**：A. Hamza, H. Habibi Gharakheili, T. A. Benson, V. Sivaraman, "Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity", ACM SOSR 2019（2019-04-03〜04、San Jose）, pp. 36–48, DOI 10.1145/3314148.3314352。本文は https://cs.brown.edu/~tab/papers/SoSR19.pdf で読んだ。
- **配布元**：https://iotanalytics.unsw.edu.au/anomaly-data/pcap/benign/<日付>.pcap 。ページにある benign のファイルは 27 本（18-05-28〜18-05-31、18-06-09〜18-06-19、18-10-10〜18-10-19、18-10-28、18-10-29）。手元の 27 本と一致する。attack+benign のファイルは 17 本（18-06-01〜08、18-06-20、18-10-20〜27）。
- **利用条件**：ページに「SPDX-License-Identifier: MIT-0」「Copyright 2021 IoT Traffic Analytics Research Group, School of EE&T, UNSW Sydney」とある。
- **収録の場所**：オーストラリアの UNSW Sydney の研究室のテストベッド。ゲートウェイは OpenWrt 18.06 と OVS を入れた TP-Link Archer C7（論文 §5.1）。キャプチャの中のゲートウェイの MAC は 14:cc:20:51:33:ea、外側のアドレスは 149.171.37.10（NAT-PMP の応答による。UNSW のアドレス帯）。
- **データセット全体の期間**：ファイル名で 2018-05-28〜2018-10-29（benign と attack を合わせる）。論文は「16 days」の攻撃の収録と「one month」の公開と書いていて、ページのファイル数（44 本）と食い違う。正確な開始・終了の時刻は未確認。
- **この機器の通信の最初と最後**：最初は 2018-05-28 00:00:03.050276（`18-05-28.pcap`）、最後は 2018-10-29 12:59:37.765872（`18-10-29.pcap`）。27 本で 3,254,377 パケット、そのうち 2,876,834 はカメラが送ったもの。
- **作成者が行ったこと**（論文 §4）：Samsung Galaxy Tab に「touch replay tool」を入れ、「streaming video from camera」などの操作を記録して、一時間と一日の中にばらして再生した。ポート転送を有効にしたため、インターネットからの「wild attacks」が入った。攻撃（ARP spoof、TCP SYN、Ping of Death など）は attack+benign のファイルにだけある（今回は使っていない）。
  - データの中で確かめたこと：192.168.1.228 は MAC 08:21:ef:3b:fc:e3。UNSW の機器一覧（https://iotanalytics.unsw.edu.au/resources/List_Of_Devices.txt）では「Samsung Galaxy Tab」。UPnP の要求の User-Agent は「SEC_HHP_[Tablet]Galaxy Tab S2」。インターネットからポート 40000 への接続も入っている（例：46.148.19.59、2018-05-30 13:48:46.176523）。

### 1-B UNSW-IoTraffic（2016-17）
- **名前**：UNSW-IoTraffic。Dryad の題は「UNSW IoT traffic data with packets, flows, and protocols」、DOI 10.5061/dryad.w0vt4b94b、2025-08-29 公開（version 9）。
- **作成者と論文**：S. Wannigama, A. Sivanathan, H. Habibi Gharakheili, "Descriptor: UNSW IoT Traffic Data with Packets, Flows, and Protocols (UNSW-IoTraffic)", IEEE Data Descriptions, 2025, DOI 10.1109/IEEEDATA.2025.3602010（Dryad の記録による。論文の本文は未確認）。
- **利用条件**：CC0-1.0（Dryad API の `license`）。
- **収録の場所**：Dryad の説明は「lab testbed」で、「captured pre-NAT on the LAN side of a TP-Link Archer C7 v2 (OpenWrt) gateway using tcpdump」。ゲートウェイの MAC は 2018 年と同じ 14:cc:20:51:33:ea で、外側のアドレスは 149.171.37.162（2016-10）と 129.94.5.92（2017-04）。どちらも UNSW のアドレス帯なので、UNSW Sydney の同じ研究室と考えられる（推測）。
- **データセット全体の期間**：Dryad では「≈203 days」「27 devices」。開始と終了の日付は未確認（README と device_pcap_summary.csv は Dryad から 403/401 で取れなかった）。
- **このファイルの期間**：2016-09-30 14:00:07.766655〜2017-04-13 14:00:00.148052、5,880,402 パケット、pcapng。ファイルのコメントによると、`/Volumes/IoTData_Vijay/raw_testbed/16-10-01/...` などを mergecap でまとめたもの。時刻の順に並んでいない。抜けている期間：2016-11-29〜2017-01-31、2017-02-03〜02-09、2017-02-22〜03-02、2017-03-07〜03-10。
- **作成者が行ったこと**：Dryad には「setup, idle, and interactions」とだけある。データの中で見えたこと：
  - 研究室のタブレット（08:21:ef:3b:fc:e3。192.168.1.239/240）からのライブ映像。
  - Mac（192.168.1.243）がブラウザーでカメラの 80 番と 443 番を開いた（2016-11-15 05:22〜05:23）。
  - Mac（192.168.1.225）が RTSP 554 番に Digest 認証で試した（2017-03-23 04:47〜04:54。401 で失敗）。
  - 192.168.1.208（MAC 74:2f:68:81:69:42）から ONVIF の WS-Discovery の探索が多い。
  - 別の LAN 機器がポート 139 と 7 を探った（2017-02-03 01:39:06）。

## 2. 機器

| 項目 | 値 | どこから分かったか |
|---|---|---|
| 製造者 | Samsung Techwin／Hanwha Techwin | UPnP の `<manufacturer>SAMSUNG`、XMPP の証明書の O=Hanwha Techwin Co., Ltd.（2018） |
| 製品名・型番 | SNH-P6410BN | UPnP の rootDesc.xml（`18-05-28.pcap` 2018-05-28 00:01:01.216094、カメラ → 192.168.1.165）の `<modelName>SNH-P6410BN`。mDNS の `SAMSUNG-SNH-P6410BN-00166CAB6B88`（2016-10-03 06:54:27.332474〜）。ONVIF の Scopes `onvif://www.onvif.org/hardware/SNH-P6410BN`（両方のデータ）。RTCP の CNAME `SNH-P6410BN@192.168.1.248` |
| シリアル番号 | KHNL6V2H20003LX | rootDesc の `<serialNumber>`、mDNS の TXT `sn=`、event.stw の `serial=` |
| MAC | 00:16:6c:ab:6b:88 | Ethernet。UNSW の機器一覧の「Samsung SmartCam」と一致 |
| IP | 2016-17：192.168.1.249（2016-09-30〜10-16、2017-01-31〜02-22）と 192.168.1.248（2016-10-16〜11-29、2017-03-02〜04-13）。2018：192.168.1.248 | DHCP と送信元 |
| ハードウェアの版 | 未確認 | 通信の中に見当たらない |
| ファームウェアの版 | **未確認** | 下を参照 |
| アプリの版 | 未確認 | アプリと機器の制御は TLS の中。P2P の部分は STUN と RTP だけで、版の文字列はない |

**ファームウェアの版を探したところ**
- 通信：UPnP（SERVER `Ubuntu/precise UPnP/1.1 MiniUPnPd/1.7`。rootDesc に版はない）、mDNS の TXT（`sn`、`macaddress`、`path=profile2/media.smp` だけ）、ONVIF の Scopes、DHCP（vendor class `udhcp 1.19.4`）、ローカルの HTTP の Server（`SmartCamWebService`）、RTSP の応答（realm `iPOLiS`、版はない）、XMPP の STARTTLS の前の部分。どこにも版の文字列はなかった。版を伝えていそうな XMPP の本体は TLS の中で読めない。
- 更新の確認やダウンロード：両方のデータで、ファームの取得と見られる通信はなかった。外からの受信で多いのは XMPP の長い接続だけ。443 番の接続は 1 本あたり約 5 kB しかない。
- 2016-17 と 2018 の違い：
  - 変わらないもの：TLS の ClientHello（TLS 1.0、同じ 49 個の暗号スイート、拡張 11,10,35,15、deflate 圧縮）、`udhcp 1.19.4`、`MiniUPnPd/1.7`、mDNS のサービス（80、4520、554）。
  - 変わったもの：event.stw への HTTP の POST と smtp.gmail.com:465 への接続は、2016-11-29 04:52 が最後で、2017 と 2018 にはない。2017-01-31 までの抜けの間にファームが変わったのか、設定が変わったのかは決められない。
  - XMPP の暗号スイートは 2016-10-24 に 3DES（0xc012）から AES-256（0xc014）に変わった。ClientHello は同じなので、サーバー側の変化。
- 製造者の資料：
  - samsungsmartcam.com のお知らせ 2549「New firmware release ('16/07/01) – Fixed Email event notification error」（2016-07-01）には型番も版もない。
  - Hanwha の脆弱性の報告（2018-03-21）は「fixed in the firmware updates released from March」とだけ書き、版を書いていない。
  - wisenetlife.com に保存されているのは SNH-P6410BN のマニュアル、クイックガイド、トラブルシューティングだけで、ファームのページはなかった（Wayback の CDX で `wisenetlife.com/fileDownload.do` を 6410 で絞った）。
  - Web 検索「SNH-P6410BN firmware version release note download」でも見つからなかった。

## 3. 公式文書

収録との関係は、2016-17（A）と 2018（B）について書く。

| ID | 文書 | 発行元 | 文書の中の日付 | Wayback の保存日時 | URL | 地域・言語 | 対象 | 収録との関係 |
|---|---|---|---|---|---|---|---|---|
| D1 | SNH-P6410BN Datasheet | Samsung Techwin | 「REVISED 02-2014」 | 2016-06-23 23:56:57 | https://web.archive.org/web/20160623235657/https://www.samsung-security.com/SAMSUNG/upload/Product_Specifications/SNH-P6410BN_Datasheet.pdf | 英語（米・欧・中の連絡先つき） | SNH-P6410BN | A・B より前 |
| D2 | User Manual SNH-P6410BN（Web-1113） | Samsung Techwin | PDF の作成日 2015-11-13 | 2024-06-27 13:36:04（2019-09-17 22:44:17 の保存もある） | https://web.archive.org/web/20240627133604/https://www.wisenetlife.com/fileDownload.do?fileName=1491228809600.pdf&filePath=UPLOAD_MFGD_ATTRBT_PATH&downLoadName=User%20Manual-SNH-P6410BN-ENGLISH_Web-1113.pdf | 英語 | SNH-P6410BN（Web viewer） | 作成は A・B より前。収録のときに公開されていたかは未確認。ファイル名の数字 1491228809600 をミリ秒の時刻と読むと 2017-04-03 に wisenetlife に置かれた（推測） |
| D3 | SmartCam Android ガイド（Web-1120） | Samsung Techwin | PDF の作成日 2015-11-20 | 2024-06-27 13:25:46 | https://web.archive.org/web/20240627132546/https://www.wisenetlife.com/fileDownload.do?fileName=1491229101554.pdf&filePath=UPLOAD_MFGD_ATTRBT_PATH&downLoadName=SmartCam-Android-ENGLISH_Web-1120.pdf | 英語 | SmartCam の各機種 | D2 と同じ |
| D4 | SmartCam Android ガイド（android_en.pdf） | Hanwha Techwin（samsungsmartcam.com） | PDF の作成日 2016-10-11 | 2022-02-25 05:46:23（これより前の保存はない） | https://web.archive.org/web/20220225054623/https://www.samsungsmartcam.com/manual/android_en.pdf | 英語 | SmartCam の各機種 | 作成は A の途中。公開の時期は未確認 |
| D5 | samsungsmartcam.com Privacy Policy | Hanwha Techwin | 「last updated on July 11, 2005」 | 2016-05-27 18:10:56、2017-11-19 05:43:00（本文は同じ） | https://web.archive.org/web/20160527181056/http://www.samsungsmartcam.com:80/web/privacy_policy.do | 英語 | 「this web site (the "Site")」 | A では有効。B の時点の版は未確認（2018〜2019 年の保存がない） |
| D6 | samsungsmartcam.com Legal Notice | Hanwha Techwin | なし | 2016-05-27 18:12:13 | https://web.archive.org/web/20160527181213/http://www.samsungsmartcam.com:80/web/legal_notice.do | 英語 | Web サイト | A |
| D7 | samsungsmartcam.com「SmartCam is for Security」 | Hanwha Techwin | なし | 2016-01-21 00:22:19 | https://web.archive.org/web/20160121002219/http://www.samsungsmartcam.com:80/web/cmm/03_SF/Security.do | 英語 | 使い道の紹介 | A の前。セキュリティの約束はない |
| D8 | samsungsmartcam.com 製品一覧 | Hanwha Techwin | なし | 2016-08-05 10:25:41 | https://web.archive.org/web/20160805102541/http://www.samsungsmartcam.com:80/web/cmm/02_SP/Main.do | 英語 | 9 機種 | A。セキュリティの記載はない |
| D9 | samsungsmartcam.com 仕様（productId=6502） | Hanwha Techwin | なし | 2017-09-21 16:45:38 | https://web.archive.org/web/20170921164538/http://www.samsungsmartcam.com/web/cmm/02_SP/Specifications.do?productId=00000000000000006502 | 英語 | **別の機種**（画角 130°、2.4 GHz だけ、128 GB → SNH-C6417BN と見られる） | 参考。P6410BN（productId 1107）の仕様ページは保存がない |
| D10 | samsungsmartcam.com Support／FAQ | Hanwha Techwin | ガイドの日付 2016-07、2017-03 | 2016-11-11 23:02:20、2017-11-19 05:14:45 | https://web.archive.org/web/20161111230220/http://www.samsungsmartcam.com:80/web/cmm/05_ST/Main.do 、https://web.archive.org/web/20171119051445/http://www.samsungsmartcam.com:80/web/cmm/05_ST/Main.do | 英語 | 表示されているのは C6417BN／V6431BN の FAQ | A。LED の意味だけ |
| D11 | お知らせ 2549「New firmware release」 | Hanwha Techwin | 2016-07-01 | 2017-06-06 10:54:44 | https://web.archive.org/web/20170606105444/http://www.samsungsmartcam.com/web/cmm/board/view.do?idx=2549&currPage=1&lastPage=1 | 英語 | 型番なし | A の前 |
| D12 | Vulnerability Report (CVE-2018-6294 ~ 6303) | Hanwha Techwin | 2018-03-21 | PDF：2021-08-03 23:55:06。リンクのあるページ：2018-08-20 23:43:53 と 2018-10-21 18:22:59 | https://web.archive.org/web/20210803235506/https://www.hanwha-security.com/data/tutorial/attrbt/1521604298202.pdf （リンク元 https://web.archive.org/web/20180820234353/http://www.hanwha-security.com:80/en/technical-guides/cyber-security/） | 英語 | 「All Hanwha Techwin SmartCams」 | A より後。B の途中（2018-08-20 には公開されていた。5〜6 月は未確認） |
| D13 | Hanwha Cyber Security のページ | Hanwha Techwin | なし | 2018-10-21 18:22:59 | https://web.archive.org/web/20181021182259/http://www.hanwha-security.com:80/en/technical-guides/cyber-security/ | 英語 | WISENET 製品 | B。脆弱性の対応の方針だけ |
| D14 | Wisenet Life Terms of Use と Privacy Statement（SmartCam の製品ページに埋め込み） | Hanwha Techwin | 「Privacy Statement last updated May 23, 2018」 | 2018-10-10 06:08:16、2018-10-22 02:40:58 | https://web.archive.org/web/20181022024058/http://www.wisenetlife.com:80/en-us/product/SmartCam/SNH-C6417BN/feature/ | en-us | 「Hanwha's Products and Services」。samsungsmartcam.com のサービスと P6410BN に当てはまるかは未確認 | B の途中（05-23 は 05-28 より前） |
| D15 | wisenetlife 仕様・機能のページ | Hanwha Techwin | なし | 2018-10-10、2018-10-22 | https://web.archive.org/web/20181010060816/http://www.wisenetlife.com:80/en-us/product/SmartCam/SNH-V6414BN/specification | en-us | **別の機種**（V6414BN、C6417BN） | 参考 |
| D16 | SNH-P6410BN Network Troubleshooting Guide（Web-0806） | Samsung Techwin | なし | 2019-09-17 23:15:04 | https://web.archive.org/web/20190917231504/http://www.wisenetlife.com/fileDownload.do?fileName=1491228802876.pdf&filePath=UPLOAD_MFGD_ATTRBT_PATH&downLoadName=SNH-P6410BN-Troubleshooting%20Guide-ENGLISH_Web-0806.pdf | 英語 | SNH-P6410BN | 収録のときに公開されていたかは未確認（ファイル名から 2017-04-03 と推測） |

**該当する文（節の名前と原文）**
- D1「Network」の表：「Security: SSL ( AES 256bit )」。「Protocol: TCP/IP, DHCP, SMTP, DNS, RTSP, RTCP, RTP, HTTP, TCP, UDP, STUN, XMPP, uPNP, SNTP, IPv4, ICMP, Bonjour, TURN, SIP」。
- D2「Setup／Basic Info」：「Image encrypting — This encrypts the image transmitted.」「The image encryption function may affect the image transmission function.」
- D2「What is relay mode?」：「Relay mode is added feature where the video from the camera is transmitted to Samsung server then retransmitted to the user's computer.」
- D2「Specifications」：「Security SSL (AES 256bit)」。プロトコルの一覧は D1 と同じ。D2「Time」：「The time will synchronize with the NTP (Network Time Protocol) server automatically.」
- D3「General setting」：「Image encrypting : This encrypts the image transmitted. This function is only supported for SNH-P6410BN model.」「Events detected are saved on the server」。
- D4：「Image encrypting : This encrypts the image transmitted.」「Firmware Version : You can check the current version and the latest distributed version and even make updates.」
- D5「Protection of Information」：「Samsung will maintain the confidentiality of the information it collects. We maintain internal practices that help protect the security and confidentiality of this information by limiting employee access to and use of this information.」
- D5「Disclosure of Personal Information」：「We will not disclose, sell, trade, or rent Personal Information without your prior consent, except to the extent necessary to provide you with a requested Samsung Service.」
- D12：「Impacted Model: All Hanwha Techwin SmartCams」。「CVE-2018-6295 Unencrypted way of remote control and communications in Hanwha Techwin Smartcams — Resolved*1」。「CVE-2018-6294 Unsecured way of firmware update … — Resolved*1」。「*1 The resolved vulnerabilities are fixed in the firmware updates released from March.」
- D14「HOW WE USE…」：「We use industry-standard methods to keep this information safe and secure while it is transmitted from your devices, over your home network and through the Internet to our servers.」
- D14「Security of Your Personal Information」：「When we transmit highly confidential information (such as a credit card number or password) over the Internet, we protect it through the use of encryption, such as the Secure Socket Layer (SSL) protocol.」
- D16：中継モードになる原因として「"UPnP Port Forwarding" function is disabled in your router」。
- D15（別の機種）：「Security: HTTPS (SSL) Login Authentication, Digest Login Authentication」「SSL (AES 256bit)」。

## 4. 観測（フェーズごと）

| フェーズ | 平文で出たもの | 暗号化されていたもの（根拠） |
|---|---|---|
| 起動・LAN | DHCP（udhcp 1.19.4）。SSDP の NOTIFY（約 60 秒ごと。MiniUPnPd/1.7 で InternetGatewayDevice として告知）。UPnP の rootDesc（型番、シリアル）。mDNS（WN3.local、`sn=`、`macaddress=`、80/4520/554）。WS-Discovery の応答（ONVIF）。NAT-PMP（TCP 40000 → 外側 41000 の対応づけ） | — |
| 名前・時刻 | DNS：xmpp／media／www.samsungsmartcam.com、smtp.gmail.com（2016 年だけ）、pool.ntp.org など。NTP | — |
| クラウドの制御（XMPP 5222） | STARTTLS の前の stream の開始だけ | `<starttls><required/>` のあと TLS 1.0。2016-17 の ServerHello は 89 回（0xc014 AES-256-CBC が 84、0xc012 3DES が 5。3DES は 2016-10-03〜10-21）。2018 は 22 回すべて 0xc014。証明書は CN=xmpp.samsungsmartcam.com、O=Hanwha Techwin |
| media.samsungsmartcam.com:443 | — | TLS 1.0、ServerHello はすべて 0xc013 AES-128-CBC（2016-17 で 65、2018 で 22）。カメラは 0xc014 を先頭で出している |
| NAT 越え | STUN／TURN サーバー（AWS、SOFTWARE「NABLE COMMUNICATIONS TURN SERVER-V01」）への Binding。中身はアドレスだけ | — |
| **ライブ映像** | ICE 風の STUN（USERNAME。値は secrets に）のあと、**RTP の H.264（PT 97、1920×1080 High）と G.711 μ-law の音声（PT 0）、RTCP（SR と SDES CNAME）**。TCP では RFC 4571 の枠、UDP ではそのまま | なし。下の通り、SPS、PPS、IDR がそのまま見え、ffmpeg でエラーなしに画像に戻った |
| イベント（2016-09-30〜11-29 だけ） | **HTTP の POST `www.samsungsmartcam.com/web/event.stw`**。本文は `username=`（空）、`serial=KHNL6V2H20003LX`、`msg=`（空）、`time=`（現地時刻）、`type=m`、`youUrl=`、`picUrl=`（空）。応答は平文でアカウント名と見られる文字列 3 つ（値は secrets に） | — |
| メール（2016 年だけ） | smtp.gmail.com:465 への TCP 接続 9,591 回。カメラはデータを 1 バイトも送らず、TLS も始まらない（約 10 秒後にサーバーが閉じる） | （中身が出ていない） |
| ローカルの Web と RTSP（作成者の操作） | 80 番と **443 番の両方で平文の HTTP**（`HTTP/1.1 404`、Server `SmartCamWebService`。2016-11-15 05:23:32.147528 など）。RTSP 401（Digest、realm `iPOLiS`） | — |
| ファーム更新 | 観測なし | — |

**ライブ映像の詳しい内容（平文の根拠）**
- 2018（P2P、研究室の外）：`18-05-28.pcap`
  - 2018-05-28 04:17:11.387031 に 129.94.5.83:43320 → 192.168.1.248:40000 で SYN。
  - 04:17:12.113994 に RTCP の SR と SDES（CNAME `SNH-P6410BN@192.168.1.248`）。
  - 04:17:12.123835 に RTP PT97 の SPS（`67 64 00 28 …`）、04:17:12.123883 に PPS（`68 ee 01 9e 2c`）、04:17:12.123916 に IDR の FU-A（`7c 85 …`）。
  - 510 フレームに戻せて、デコードのエラーは 0。画像は研究室の机の上のケーブル、電源タップ、機器。
  - 129.94.5.83 からのセッションは 05-28 に 20 回（04:17〜23:50、多くは約 54 分おき）と 05-31 04:06:16.412043 に 1 回、合わせて 21 回。21 回とも画像に戻った（05-28 15:43:35 の 1 回だけ、欠けによるデコードの警告が 2 件）。カメラからこの相手へは 40,540 パケット、50.1 MB。
  - STUN の応答の MAPPED-ADDRESS は 149.171.37.10:41000 で、研究室の NAT の外側を通っている。
- 2018（LAN の中）：タブレット 192.168.1.228 とのセッション。05-28 に 4 回（04:23:01.512802、11:13:04.932681、14:33:42.196245、14:37:29.546951）、06-14 に 3 回（03:32:55.480051、04:59:47.303418、06:53:24.329343）。7 回とも画像に戻った。
- 2016（P2P、UDP、研究室の外）：`SamsungCamera_00166cab6b88.pcap`
  - フレーム 357328〜（2016-10-06 06:28:48.315396）が STUN。フレーム 357329 の応答で、カメラは 149.171.37.162:39034 として見えている。
  - フレーム 357337（06:28:48.607451）が SPS、357338 が PPS、357339 が IDR。相手は 129.94.5.88:38012。
  - 319 フレームに戻せて、エラーは 0。画像は研究室の室内（窓、棚、机、人物 2 人）。
- 2016（LAN の中）：タブレット 192.168.1.240 との 8 回。2016-11-28 00:42:43.377190（SYN フレーム 2881846）〜2016-11-29 04:51:53.629078（SYN フレーム 3016637）。8 回とも画像に戻った。
- 中継（relay）を通った映像：見つからない。

**event.stw の詳しい内容**：最初はフレーム 17830（2016-09-30 21:44:47.158181、192.168.1.249 → 104.98.5.24:80）で、応答はフレーム 17832。最後はフレーム 3023532（2016-11-29 04:52:37.644148）。POST は合わせて 13,311 回（形のこわれた 1 回を含む）、アカウント名を含む応答は 13,291 回。2017 年と 2018 年にはない。

## 5. 比較

| ID | フェーズ | 観測 | 公式文書の記載 | 判定 | PCAP 側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| R1 | ライブ映像 | RTP の H.264 と音声が平文。研究室の外の相手（P2P）とタブレット（LAN）。2016 と 2018 | 「Security: SSL (AES 256bit)」 | **公式文書に記載なし** | §4 の 2018 と 2016 のセッション（例：`18-05-28.pcap` 04:17:12.123835 の SPS、フレーム 357337） | D1・D2 の Network／Specifications の表 | 観測は高。判定は中 | 最も限定的な読みは「SSL（AES-256）の機能を持つ」で、映像を SSL で送るとは書いていない。同じ表のプロトコルに RTP、RTCP、RTSP があり、SRTP はない。広く読めば（すべての通信を SSL で守る）矛盾になる |
| R2 | ライブ映像 | 同上。暗号化されたセッションは 1 回もない（2016-10〜2018-06 の 37 回） | 「Image encrypting: This encrypts the image transmitted.」（D3 は「only supported for SNH-P6410BN」） | **公式文書に記載なし**（最も限定的な読み） | 同上 | D2 Setup／Basic Info、D3、D4 | 中 | 設定が on だったかは不明。既定の値も書いていない。「image」は文書の中で静止画（Picasa の event images、Capture）と映像（「video image」「high definition image」）の両方に使われているので、最も限定的には静止画だけと読める。映像を含むと読み、かつ設定が on なら矛盾（条件付き）。文書は作成日が収録より前だが、保存は後（§8） |
| R3 | クラウドの制御 | XMPP は STARTTLS 必須、TLS 1.0、AES-256（0xc014） | 「SSL (AES 256bit)」 | **一致** | 2018：`18-05-28.pcap` 05:59:58.680565 に 50.18.221.77:5222 が 0xc014。2016：フレーム 1288992（2016-10-24 03:41:36.589098）が 0xc014 | D1・D2 | 高 | 2016-10-03〜10-21 の 5 回は 3DES（例：フレーム 147222、2016-10-03 06:54:28.428832）。サーバーが選んだもので、カメラは AES-256 を先頭に出している |
| R4 | media サーバー | TLS 1.0、AES-128（0xc013）だけ | 「SSL (AES 256bit)」 | **一致**（最も限定的な読み） | 2018：`18-05-28.pcap` 06:00:00.099458、52.8.232.138:443。2016：フレーム 147282 | D1・D2 | 中 | 機器は AES-256 を出せる（ClientHello）。「すべての SSL で AES-256」と読めば食い違う |
| R5 | イベント（2016） | HTTP の平文の POST（シリアル、時刻、種類）と、平文の応答（アカウント名） | D5「maintain the confidentiality … internal practices … limiting employee access」 | **公式文書に記載なし** | フレーム 17830／17832〜3023532、13,311 回 | D5 Protection of Information | 高 | D5 の範囲は「this web site」で、守り方は社員のアクセスの制限。送り方には触れていない。D1 のプロトコルに HTTP がある。D3 に「Events detected are saved on the server」。広く読めば（集めた情報の秘密を通信でも守る）矛盾になる |
| R6 | イベント（2016） | 同上 | D1・D2「Security: SSL (AES 256bit)」 | **公式文書に記載なし** | 同上 | D1・D2 | 高 | R1 と同じ理由 |
| R7 | 送り先 | Hanwha のドメイン（AWS、Akamai）、smtp.gmail.com（データなし）、NTP pool、STUN/TURN | D5「not disclose … except to the extent necessary to provide … a requested Samsung Service」 | **一致** | DNS の一覧（§4）、465 番の SYN 9,591 回、ペイロード 0 | D5、D2（Gmail の通知、NTP） | 中 | サーバーの側で他社に渡しているかは観測不能 |
| R8 | プロトコル | HTTP、RTP、RTCP、RTSP、STUN、XMPP、UPnP、NTP、mDNS、SMTP（接続だけ）、DHCP、DNS、ICMP | D1 のプロトコル一覧 | **一致** | §4 | D1 | 高 | WS-Discovery（ONVIF）と NAT-PMP は一覧にない＝公式文書に記載なし（軽い） |
| R9 | P2P と中継 | NAT-PMP で 40000→41000。外から 40000 番に直接つながる。中継の映像はない | D2 の relay の説明、D16「UPnP Port Forwarding」 | **一致** | `18-05-28.pcap` 05:59:51.848957 の NAT-PMP の応答。§4 の P2P | D2、D16 | 中 | D16 は保存が後 |
| R10 | ファーム更新 | 観測なし | D12「CVE-2018-6294 … Resolved」、D4 の更新の説明 | **観測不能** | 両方のデータで更新の通信はない | D12、D4 | 高 | — |
| R11a | 2018 の遠隔の制御 | XMPP は TLS | D12「CVE-2018-6295 Unencrypted way of remote control and communications … Resolved」 | **一致** | R3 と同じ | D12 | 中 | 2016 年も TLS だった。機器のファームの版は不明 |
| R11b | 2018 のライブ映像 | 平文の RTP（05-28、05-31、06-14） | D12 同上 | **公式文書に記載なし**（最も限定的な読み） | §4 | D12、NVD（CWE-319） | 低〜中 | どの通信を直したかを D12 も NVD も書いていない。Kaspersky が挙げた平文は「HTTP API」と「firmware update」だけ。「communications」を映像まで含むと読み、かつこの機器が 3 月以降のファームだったなら矛盾（条件付き）。D12 が 5〜6 月に公開されていたかも未確認 |
| R12 | 2018 のクラウドへの送信 | Hanwha のサーバーへはすべて TLS。平文は LAN の中と相手との映像、DNS、NTP、STUN | D14「industry-standard methods to keep this information safe and secure while it is transmitted …」 | **判断不能** | §4 | D14 | — | 方法を書かない評価の言葉だけ。D14 が P6410BN と samsungsmartcam.com に当てはまるかも未確認 |
| R13 | 2018 | パスワードなどの平文はカメラから出ていない（`passw`、`pwd=`、`authorization:`、`token` などで検索して 0 件） | D14「highly confidential information (such as a credit card number or password) … encryption, such as … SSL」 | **一致**（観測の範囲） | 27 本の検索結果 0 件 | D14 | 中 | TLS の中は見えない |
| R14 | ローカルの Web（2016） | 443 番で平文の HTTP が返る | D15「HTTPS (SSL) Login Authentication」 | （参考） | 2016-11-15 05:23:32.147528、192.168.1.248:443 → 192.168.1.243 | D15 | — | D15 は別の機種で、収録より後。判定しない |

## 6. 食い違いの詳しい内容

最も限定的な読みで**矛盾と判定したものはない**。近いものを 3 つ書く。

**(a) R2「Image encrypting」とライブ映像の平文**
- 公式の主張：「Image encrypting: This encrypts the image transmitted.」「This function is only supported for SNH-P6410BN model.」（D3）
- 観測した事実：
  - 2016-10-06 から 2018-06-14 までのライブ映像 37 回（2016：UDP の P2P 1 回、LAN 8 回。2018：P2P 21 回、LAN 7 回）が、どれも平文の RTP の H.264 だった。
  - SPS、PPS、IDR のヘッダーがそのまま見え、ffmpeg でエラーなしに 1080p の画像に戻った。
  - 暗号化の形をとったセッションは一度もなかった。
- どこが食い違うか：この機能が on で、「image」がライブ映像を含むなら、文書の言う暗号化が起きていない。
- 最も限定的な読み：「設定を on にしたときに、送る image を暗号化する」。既定の値は書かれていない。「image」は同じ文書で静止画にも映像にも使われているので、静止画だけとも読める。この読みでは、平文の映像と矛盾しない。
- 退けた読み：
  - 「SNH-P6410BN の映像はいつも暗号化される」：設定の項目なので、広げた読みになる。
  - 「image は映像に限る」：文書は event images、Capture image にも使っていて、決められない。

**(b) R1・R4・R5「Security: SSL (AES 256bit)」と平文の映像・HTTP、AES-128 の TLS**
- 公式の主張：仕様の表の「Security: SSL ( AES 256bit )」（D1、D2）。
- 観測した事実：
  - SSL（TLS 1.0）と AES-256 は XMPP で使われている（R3）。
  - 一方で、映像（RTP）とイベント（HTTP。2016）は平文で、media サーバーの TLS は AES-128。
- 最も限定的な読み：機器がそなえるセキュリティの機能の表示で、どの通信に使うかは言っていない。この読みでは一致する。
- 退けた読み：「すべての通信を AES-256 の SSL で守る」は広げた読み。しかも同じ表が HTTP、RTP、RTSP をプロトコルとして並べている。

**(c) R11b Hanwha の報告（2018-03-21）と 2018 年の平文の映像**
- 公式の主張：CVE-2018-6295「Unencrypted way of remote control and communications」は「Resolved」、「fixed in the firmware updates released from March」。
- 観測した事実：2018-05-28〜06-14 に平文のライブ映像。
- 最も限定的な読み：登録された 1 つの脆弱性（中身を書いていない）がファームの更新で直った。
  - Kaspersky の公表（2018-03-12）が平文として挙げたのは「camera interaction via HTTP API」と「firmware update」。2018 年のデータには、どちらの通信も出ていない。
  - 遠隔の制御（XMPP）は TLS で、一致している。
- 矛盾にならない理由：映像が CVE の範囲に入るかが書かれていない。この機器が 3 月以降のファームだったかも分からない。

## 7. 反証の検討

**探したもの**
- 同じ時期の公式文書が平文の通信を開示していないか：
  - D1・D2 のプロトコル一覧（HTTP、RTP、RTCP、RTSP、uPNP、Bonjour がある。SRTP や HTTPS の書き分けはない）。
  - D2 の中継の説明、D16 の UPnP のポート転送、D3 の「Events detected are saved on the server」。
  - FAQ（D10）とお知らせ（D11、掲示板の一覧 2016-10-05、2017-11-19）。
  - samsungsmartcam.com の「Security」ページ（D7。使い道の紹介で、約束はない）。
  - D12 は収録の後に「Unencrypted … communications」を認めている。
- 文の範囲：
  - D5 は Web サイトの方針（2005 年）。
  - D9・D15 は別の機種。
  - D14 は wisenetlife（en-us）で、P6410BN が使う samsungsmartcam.com のサービスに当てはまるかが不明。
  - D3 は「Image encrypting」を P6410BN だけの機能と書いていて、この機種には当てはまる。
- データセットの事情：
  - 映像は作成者のタブレットの再生操作から出たもの（論文 §4「streaming video from camera」。タブレットの MAC は UNSW の一覧と一致）。
  - 129.94.5.83 と 129.94.5.88 が誰の端末かは不明（研究室のゲートウェイの外側のアドレスとは違う UNSW のアドレス）。
  - 中間者の検査の跡はない。映像はカメラ自身が出したもの（送信元 MAC と RTCP の CNAME）。
  - 2016-17 のファイルは機器ごとに切り出して mergecap でまとめたもの。2018 は MAC で切り出したもの。
- 観測の誤り：
  - 平文かどうかは、SPS、PPS、IDR の構造と、ffmpeg でエラーなしに戻ることで確かめた。圧縮や独自の暗号化ではない。
  - 回数は SYN と 4 組（アドレスとポート）で数え、再送は数えていない。
  - event.stw は HTTP の要求の数で数えた。
  - 465 番はペイロードが 0 で、メールの中身は出ていない。
  - TLS の暗号スイートはサーバーが選んだもので、カメラは AES-256 を先頭で出している。

**見つけたもの**：D1 のプロトコル一覧（HTTP、RTP）、D2 の Image encrypting が設定であること、D3 の「only supported for SNH-P6410BN」、D12 の CVE の範囲が書かれていないこと、D14 の範囲の不明さ。

**判定への影響**
- R1、R5、R6：「記載なし」にとどめた。
- R2：設定の状態と「image」の範囲のどちらも決められないので、条件付きにもせず「記載なし」にした（補足に、条件付きの矛盾になる読みを書いた）。
- R11b：「記載なし」。

## 8. 条件

| 条件 | 調べたこと | 残ったこと |
|---|---|---|
| 「Image encrypting」が on だったか（R2） | 設定はアプリから XMPP（TLS）で送られるので見えない。マニュアルに既定の値はない。論文と Dryad は操作の中身を書いていない | 未確認。データの中に暗号化された映像が 1 回もないので、off だった可能性が高い（推測） |
| 「image」に映像が入るか（R2） | 3 つのマニュアルの「image」の使い方を見た | 文書の中で決められない |
| 機器のファームウェアの版（R11b、R10） | §2 の通り | 未確認 |
| 文書が収録の時点に公開されていたか（D2、D3、D4、D16） | CDX で samsungsmartcam.com と wisenetlife.com を探した。samsungsmartcam.com にあったのは「User Manual-SNH-P6410BN-ENGLISH-Web-0124.pdf」（2019 年の保存で、中身は保存されていない） | 作成日は収録より前。公開の時期は未確認 |
| D14 が P6410BN と samsungsmartcam.com のサービスに当てはまるか | D14 は「Hanwha's Products and Services」。P6410BN の wisenetlife のページは保存がない | 未確認 |
| 映像の相手 129.94.5.83 と 129.94.5.88 | NAT-PMP と STUN で研究室の外側のアドレスと照らした（別のアドレス） | 誰の端末かは未確認 |

## 9. 先行資料

検索語（5 回）：
1. `Kaspersky "Somebody's watching" Hanwha SmartCam SNH-V6410PN vulnerabilities HTTP XMPP unencrypted CVE-2018-6295`
2. `Loi Sivanathan Sivaraman "Systematically Evaluating Security and Privacy for Consumer IoT Devices" Samsung smart camera unencrypted`
3. `"Systematically Evaluating Security and Privacy for Consumer IoT Devices" pdf 2017 IoT S&P Samsung camera`
4. `Samsung SmartCam unencrypted video stream RTP H.264 P2P plaintext network traffic analysis`
5. `"samsungsmartcam.com" "event.stw" OR "xmpp.samsungsmartcam.com" plaintext HTTP SmartCam security research`

見つけたもの：
- **Kaspersky ICS CERT**（A. Muravitsky, V. Dashchenko, "Somebody's watching! When cameras are more than just 'smart'", Securelist, 2018-03-12）。対象は SNH-V6410PN/PNW。平文として挙げたのは「Use of insecure HTTP protocol during firmware update」と「… during camera interaction via HTTP API」。映像の暗号化については書いていない（本文は WebFetch で要約を読んだ）。CVE-2018-6294〜6303 がこれから出た。NVD の CVE-2018-6295 は「Unencrypted way of remote control and communications in Hanwha Techwin Smartcams」、CWE-319、2018-03-13 公開（NVD API で確かめた）。会議の論文ではない。
- Loi ほか「Systematically Evaluating Security and Privacy for Consumer IoT Devices」（ACM IoT S&P 2017。同じ UNSW の研究室で 20 機種）。本文を取れず、SmartCam を扱っているかは未確認。
- Alrawi ほか「SoK: Security Evaluation of Home-Based IoT Deployments」（IEEE S&P 2019）。PDF を読んだが、Samsung SmartCam は入っていない。

IEEE S&P、USENIX Security、ACM CCS、NDSS の論文で、この機器（または SmartCam の系列）について「公式文書のこの主張とこの通信が食い違う」と示したものは見つからなかった。通信そのもの（平文の HTTP）は Kaspersky が SNH-V6410PN で報告している。P2P のライブ映像が平文の RTP であることと、event.stw の平文の POST を書いた資料は見つからなかった。見つからないことは、新しいことを意味しない。

## 10. 断定できる／できない

**断定できる（データで確かめた）**
- このカメラは SNH-P6410BN、シリアルは KHNL6V2H20003LX。
- 2016 年と 2018 年のライブ映像（37 回）は平文の RTP の H.264 と G.711 で、画像に戻せる。そのうち 22 回（2016 年の 1 回と 2018 年の 21 回）は研究室の NAT の外の相手へ出ている。
- 2016-09-30〜11-29 に、平文の HTTP で event.stw への POST が 13,311 回あった（シリアル、時刻、種類）。応答には平文のアカウント名が入っていた。
- XMPP の制御は TLS で、AES-256 を使う。
- 公式の仕様（D1、D2）に「SSL (AES 256bit)」と、HTTP と RTP を含むプロトコル一覧がある。
- 最も限定的な読みでは、どの公式の文とも矛盾しない。

**断定できない**
- 「Image encrypting」の設定の状態と、その範囲。
- 機器のファームウェアの版と、2016 年と 2018 年で版が変わったか。
- D2、D3、D4、D16 が収録のときに公開されていたか。
- D12 の CVE-2018-6295 が指す通信。
- D14 が P6410BN に当てはまるか。

**未確認の一覧**
- ハードウェアの版、ファームウェアの版、アプリの版。
- UNSW 2018 データセット全体の正確な期間と、ファイル数の食い違い（論文 30、ページ 44）。
- UNSW-IoTraffic の正確な開始と終了、README の中身（Dryad で 403）、論文の本文。
- 2018 年の samsungsmartcam.com のプライバシーポリシーの版。
- samsungsmartcam.com の P6410BN の仕様ページ、Support ページ、マニュアル（Web-0124）の中身。
- D12 が 2018-05〜06 に公開されていたか。
- 129.94.5.83 と 129.94.5.88 が誰の端末か。
- Loi ほか（2017）の本文。
- Talos の報告（TALOS-2018-0582）は読んでいない。

## 11. まとめ（3 行）

1. 最も強い判定は「一致／公式文書に記載なし」で、明確な矛盾も条件付きの矛盾もない。ライブ映像は 2016 年も 2018 年も平文の RTP で（研究室の外の相手 22 回を含む 37 回）、2016 年はイベントを平文の HTTP で送っていたが、公式の「Security: SSL (AES 256bit)」は最も限定的に読むと機能の表示で、同じ表に HTTP と RTP が並んでいる。
2. いちばん近いのは「Image encrypting: This encrypts the image transmitted.」（P6410BN だけの設定）と平文の映像の組み合わせ。ただし、設定が on だったかも、「image」が映像を含むかも決められないので、矛盾とは言えない。
3. 論文の中心の所見には**使えない**。条件（設定の状態、ファームの版、文書の公開の時期）がデータと公開資料から決められず、平文の通信の一部は製造者が後に（2018-03 の報告で）認めている。
