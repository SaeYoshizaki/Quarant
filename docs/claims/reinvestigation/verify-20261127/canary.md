# Canary（家庭用防犯カメラ）：公式の発表と実際の通信の照合

作成：2026-11-27。前の調査の結論は読まずに、データと文書からやり直した。時刻はすべて UTC。
略号：**D1** = UNSW-IoTraffic（2016-11〜2017-03）、**D2** = UNSW IoT Benign and Attack Traces の正常日（2018-05〜10）。
作業ファイル：`/private/tmp/claude-501/-Users-yoshizakisae-Desktop-research/2b3961f0-bc4b-4312-b98c-5ea32672fea3/scratchpad/verify5/out/work-canary/`

---

## 1. データセット

| 項目 | D2：UNSW IoT Benign and Attack Traces | D1：UNSW-IoTraffic |
|---|---|---|
| 書誌 | A. Hamza, H. Habibi Gharakheili, T. A. Benson, V. Sivaraman, "Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity", Proc. ACM SOSR 2019, San Jose, doi:10.1145/3314148.3314352（配布ページの bib `19sosrIoT` による。bib の題は "LoT" と誤記）。SOSR 論文の本文は**未読**。同じグループの拡張版 arXiv:2304.04987（Hamza, Habibi Gharakheili, Benson, Batista, Sivaraman, 2023）を読んだ | データ：S. Wannigama, A. Sivanathan, H. Habibi Gharakheili, "UNSW IoT traffic data with packets, flows, and protocols", Dryad, doi:10.5061/dryad.w0vt4b94b（公開 2025-08-29、version 9）。論文：同じ著者の "Descriptor: … (UNSW-IoTraffic)", IEEE Data Descriptions, 2025-08, doi:10.1109/IEEEDATA.2025.3602010（本文は**未読**。IEEE のページが取れなかった） |
| 配布元 | https://iotanalytics.unsw.edu.au/attack-data.html （ファイル：`https://iotanalytics.unsw.edu.au/anomaly-data/pcap/benign/<日付>.pcap`） | https://datadryad.org/dataset/doi:10.5061/dryad.w0vt4b94b 、https://iotanalytics.unsw.edu.au/unsw-iotraffic.html |
| 利用条件 | ページ上は MIT-0（"SPDX-License-Identifier: MIT-0 / Copyright 2021 IoT Traffic Analytics Research Group, School of EE&T, UNSW Sydney"） | CC0-1.0（Dryad API の license 欄。UNSW ページにも CC0 と記載） |
| 場所 | UNSW Sydney の実験室（オーストラリア）。arXiv 版：TP-Link の OpenWrt ゲートウェイに外付けディスクをつなぎ tcpdump で全通信を保存 | Dryad："captured from a lab testbed"、"pre-NAT on the LAN side of a TP-Link Archer C7 v2 (OpenWrt) gateway using tcpdump"。国と施設は本文に書かれていない（著者の所属は UNSW Sydney。オーストラリアと**推測**） |
| 全体の期間 | ファイル名で 2018-05-28〜2018-10-29（正常 27 日分、攻撃を含む 17 日分：18-06-01〜08、18-06-20、18-10-20〜27）。arXiv 版は「16 日間」「1 か月」と書き、ファイル数と合わない | 「≈203 日」、27 機器、95,543,405 パケット。開始日と終了日は**未確認**（`device_pcap_summary.csv` は Dryad が 403 を返し取れなかった）。ファイルのコメントに `/Volumes/IoTData_Vijay/raw_testbed/16-10-01/…` がある |
| この機器の最初と最後 | 最初：`18-05-28.pcap` 2018-05-28T00:00:11.444761Z。最後：`18-10-29.pcap` 2018-10-29T12:59:58.499562Z（正常日のファイルだけを見た。攻撃日のファイルは見ていない） | 最初：フレーム 1、2016-11-22T01:46:56.448910Z。最後：フレーム 6,131,096、2017-03-05T03:59:18.149493Z。**実際にパケットがあるのは 6 日だけ**：2016-11-22T01:46:56〜2016-11-23T00:03:09.630256Z（フレーム 973,537）と 2017-03-02T03:52:05.492993Z（フレーム 973,538）〜2017-03-05 |
| 作成者の操作 | arXiv 版：攻撃を受けたのは 10 機器（WeMo ×2、Samsung カメラ、TP-Link プラグ、Netatmo カメラ、Chromecast、Echo、Hue、LiFX、iHome）。Canary は「研究対象外の 17 機器」の側で、正常データだけ含まれる。注釈ファイル（`annotations.zip`）に Canary の MAC と IP はない。利用者の操作は Galaxy Tab のタッチ再生ツールで再現（"streaming video from camera" を含む。Canary が対象だったかは未確認） | Dryad："setup, idle, and interactions"。"No ground-truth annotations of events or interactions are provided."。機器ごとのファイルは 164 個の `7c70bc5d5edc_N.pcap` を mergecap で結合したもの（ファイルのコメント） |
| 手元のファイル | `V/data/canary/unsw2018/18-MM-DD.pcap` 27 本。元の日ファイルから `ether host 7c:70:bc:5d:5e:dc` で切り出したもの。元ファイルとのハッシュ照合は未確認。キャプチャ漏れ（"Previous segment not captured"）がある | `CanaryCamera_7c70bc5d5edc.pcap`（pcapng、6,058,160,128 バイト）。**パケットの途中で切れている**（capinfos）。27 本の合計 26.88 GiB は公開値「≈26.9 GB」と合うので、公開ファイルと同じ大きさだと考えられるが、Canary 単体のパケット数は照合できていない |

---

## 2. 機器

| 項目 | 値と根拠 |
|---|---|
| 製造者 | Canary Connect, Inc.（MAC の OUI 7c:70:bc は "CanaryConnec"。TLS の証明書の O="Canary Connect, Inc."） |
| 製品・型番 | **初代 Canary（All-in-One、Model CAN100）と推測**。根拠：DHCP の Host Name "C100F1615229"（D1・D2 とも。シリアル番号と推測）の頭の "C100" が、Canary の Compliance ページ（Wayback 2017-03-31）の "FCC ID: 2ACDL-C100 / Model No. CAN100" と合う。同じページの別機種は "2ACDL-C600 / CAN600"。UNSW は "Canary Camera" と呼ぶ。HTTP などに型番の文字列はない |
| ハードウェアの版 | 未確認（DHCP、HTTP、証明書を見たが出ていない） |
| SoC | Ambarella と推測（更新後の再起動で DHCP Host Name が "Ambarella" になる：D1 2017-03-04T03:33:55.512487Z〜、D2 2018-05-30T02:06:57.192356Z〜） |
| MAC / IP | 7c:70:bc:5d:5e:dc / 192.168.1.230（D1・D2 とも）。ゲートウェイ 192.168.1.1（14:cc:20:51:33:ea、TP-Link） |
| 機器の証明書 | D1：CN=7aedff2ddaff485986991654f92b7c0c（有効 2016-08-09〜2018-08-16）。D2：CN=5e178ebbd8694cc69127063e648a5923（有効 2017-12-08〜2019-12-15）。どちらも O=Canary Connect, Inc., OU=Development, OU=Device、発行者 "Device CA 2"。MAC と Host Name が同じなので同じ個体で、証明書が入れ替わったと考えられる |
| ファームウェアの版 | **版の番号は未確認**。探した所：DHCP（Host Name だけで、Vendor Class なし）、HTTP の User-Agent、DNS 名、証明書。暗号化されていない所に版の番号はなかった。分かるのは部品の版だけ：D1＝curl/7.49.0、ConnMan/1.29、htpdate/1.1.2。D2＝2018-05-28 は curl/7.56.1、ConnMan/1.35。**2018-05-30T02:07:00.399650Z からは curl/7.58.0** |
| 収録の中の更新 | D1：2017-03-04T03:29:51.796375Z に o.canaryis.com（CNAME device-ota.prod.canaryis.com、52.6.61.83）から TLS で 26,597,336 バイトを受信。03:33:55Z に再起動（curl と ConnMan の版は変わらない）。D2：2018-05-30T02:01:26.666356Z に o.canaryis.com（34.196.229.0）から TLS で 35,566,658 バイトを受信。02:06:57Z に再起動し、その後 curl が 7.56.1 から 7.58.0 に変わった。**どちらも更新と推測**（中身は暗号化されている） |
| アプリの版 | 未確認（スマートフォンの通信はこのファイルにない） |

---

## 3. 公式文書

収録との関係：D1 = 2016-11-22〜2017-03-05、D2 = 2018-05-28〜2018-10-29。「中」は保存日が収録期間の中、「前」と「後」は外。

| # | 文書 | 発行元 | 文書の中の日付 | Wayback 保存日時 | URL | 地域・言語 | 対象 | D1 | D2 |
|---|---|---|---|---|---|---|---|---|---|
| A1 | Security（Data protection ほか） | Canary Connect | なし（© 2014-2016） | 2016-12-19 07:19:25 | https://web.archive.org/web/20161219071925/https://canary.is/security/ | 米・英語 | Canary の仕組み全体 | 中 | 前 |
| A2 | 同上 | 同上 | なし | 2017-05-13 16:54:24 | https://web.archive.org/web/20170513165424/https://canary.is/security/ | 米・英語 | 同上 | 後 | 前 |
| A3 | Security（英国版） | 同上 | なし（© 2014-2017） | 2018-02-27 16:01:18 | https://web.archive.org/web/20180227160118/https://canary.is/uk/security/ | 英国・英語 | 同上 | — | 前（約 3 か月） |
| A4 | Security（参考） | 同上 | なし | 2019-02-07 23:36:14 | https://web.archive.org/web/20190207233614/https://canary.is/security/ | 米・英語 | 同上 | — | 後 |
| B1 | Privacy Policy | Canary Connect / Canary Technology Europe | Last Updated: May 19, 2016 | 2016-12-19 09:20:39（同じ本文が 2017-04-09、2017-05-13 にも） | https://web.archive.org/web/20161219092039/https://canary.is/legal/privacy-policy/ | 米・英語 | 機器、アプリ、ウェブ | 中 | 前 |
| B2 | Privacy Policy（英国版） | 同上 | Last Updated: August 14, 2017 | 2018-02-27 16:01:12 | https://web.archive.org/web/20180227160112/https://canary.is/uk/legal/privacy-policy/ | 英国・英語 | 同上 | — | 前 |
| B3 | Privacy Policy | 同上 | Effective Date: May 25, 2018 | 2019-02-08 03:00:49 | https://web.archive.org/web/20190208030049/https://canary.is/legal/privacy-policy/ | 米・英語 | 同上 | — | 日付は前、保存は後（2018-02〜2019-02 にどの地域の版も保存なし） |
| C1 | Original Canary FAQ（help 記事 206619098） | Canary（help.canary.is） | なし | 2018-08-18 02:14:10 | https://web.archive.org/web/20180818021410/https://help.canary.is/hc/en-us/articles/206619098-Original-Canary-FAQ | 米・英語 | 初代 Canary | — | **中** |
| C2 | 同記事（独語版） | 同上 | なし | 2018-10-09 05:50:43 | https://web.archive.org/web/20181009055043/https://help.canary.is/hc/de/articles/206619098-H%C3%A4ufig-gestellte-Fragen-zu-Canary | ドイツ語 | Canary | — | **中** |
| C3 | Pre-purchase FAQ（同じ記事の旧名） | 同上 | なし | 2016-08-22 09:15:19 | https://web.archive.org/web/20160822091519/http://help.canary.is:80/hc/en-us/articles/206619098-Pre-purchase-FAQ | 米・英語 | Canary | 前（2016-08-22〜2018-08-18 は保存なし） | 前 |
| D1doc | How do I connect through a firewall?（help 記事 211590367） | 同上 | なし | 2016-10-10 10:05:50（2016-05、2016-08 も同じ内容） | https://web.archive.org/web/20161010100550/http://help.canary.is/hc/en-us/articles/211590367-How-do-I-connect-through-a-firewall- | 米・英語 | Canary | 前 | 前 |
| D2doc | 同上 | 同上 | なし | 2019-07-20 22:06:22 | https://web.archive.org/web/20190720220622/https://help.canary.is/hc/en-us/articles/211590367-How-do-I-connect-through-a-firewall- | 米・英語 | Canary | — | 後（2016-09〜2019-07 は保存なし） |
| E1 | 製品ページ（Tech Specs の "Security & Data Protection"） | Canary Connect | なし | 2016-12-19 08:24:00 | https://web.archive.org/web/20161219082400/https://canary.is/canary/ | 米・英語 | 初代 Canary（Wired Ethernet を記載） | 中 | 前 |
| E2 | 同上 | 同上 | なし | 2018-10-04 05:51:08 | https://web.archive.org/web/20181004055108/https://canary.is/canary/ | 米・英語 | 同上 | — | 中 |
| E3 | How it works | 同上 | なし | 2016-12-19 06:14:16 / 2018-10-16 08:52:52 | https://web.archive.org/web/20161219061416/https://canary.is/how-it-works/ 、https://web.archive.org/web/20181016085252/https://canary.is/how-it-works/ | 米・英語 | Canary | 中（暗号化の記述なし） | 中 |
| E4 | Specs ページ | 同上 | なし | 2016-04-17 16:59:21 | https://web.archive.org/web/20160417165921/https://canary.is/specs/ | 米・英語 | Canary | 前 | 前 |
| E5 | 仕様書 PDF | 同上 | なし | 2017-03-31 08:37:05 | https://web.archive.org/web/20170331083705/http://website-assets.canary.is/resources/press/specs/canary_specs.pdf | 英語 | Canary | 後 | 前 |
| E6 | User Guide PDF | 同上 | なし | 2016-06-15 / 2017-08-09 | https://web.archive.org/web/20160615144808/http://website-assets.canary.is:80/resources/Canary_UserGuide_EN.pdf 、https://web.archive.org/web/20170809173457/http://website-assets.canary.is:80/resources/Canary_UserGuide_EN.pdf | 英語 | Canary | 前 | 前（通信や暗号化の記述なし） |
| F1 | ブログ "Security You Can Trust" | Canary Team | 01.26.17 | 2017-11-03 04:55:13 / 2018-08-25 19:02:18 | https://web.archive.org/web/20180825190218/http://blog.canary.is:80/security-you-can-trust/ | 英語 | Canary | 投稿日は中 | 中 |
| G1 | Firmware Open Source Disclosures v1.0（PDF） | Canary Connect | なし | 2016-02-07 08:34:12（2017-03-31 の Open Source ページもこの v1.0 にリンク） | https://web.archive.org/web/20160207083412/http://website-assets.canary.is:80/resources/legal/Firmware-Open-Source-Disclosures-v1.0.pdf | 英語 | ファームウェア | 前 | 前 |
| G2 | Compliance Notices | Canary Connect | なし | 2017-03-31 14:25:01 | https://web.archive.org/web/20170331142501/https://canary.is/legal/compliance/ | 米・英語 | CAN100、CAN600 | 後 | 前 |
| G3 | Feature and Service Updates FAQ | Canary | なし | 2017-10-06 | https://web.archive.org/web/20171006120342/https://help.canary.is/hc/en-us/articles/115012435047-Feature-and-Service-Updates-FAQ | 英語 | All-in-One、Flex | — | 前 |
| H1 | How do I know my Canary's connection is secure?（参考） | Canary | なし | 2019-07-16 20:27:59（それ以前の保存なし） | https://web.archive.org/web/20190716202759/https://help.canary.is/hc/en-us/articles/115005468648-How-do-I-know-my-Canary-s-connection-is-secure- | 英語 | Canary | — | 後 |

オーストラリア版（`canary.is/au/…`）の Security とプライバシーは Wayback に見つからなかった。

**該当する文（原文の短い引用）**

- C1（"How secure is it?" の節）："We use bank-level security, and any data that Canary generates is immediately encrypted. **All communication between your Canary device, the Canary Cloud, and your smartphone is encrypted over TLS/SSL (HTTPS).** Video and audio are stored and encrypted using AES-256 bit encryption …"。C3（2016-08-22）も同じ文（文字列で一致を確認）。C2（独語）："Sämtliche Kommunikation zwischen deinem Canary-Gerät, der Canary-Cloud und deinem Smartphone wird über TLS/SSL (HTTPS) verschlüsselt."
- C1（"Where is the video stored?"）："Video recordings captured by your Canary are encrypted and sent to the Canary Cloud …"。（モードの節）："When set to private, Canary's camera, microphone, and motion detection capabilities are fully disabled. Only temperature, humidity, and air quality information are uploaded to the Canary Cloud."
- A1〜A4（"Data protection."）："… employ extensive security measures to protect private data, such as AES 256-bit symmetric-key encryption, Virtual Private Cloud (VPC), secure HTTP access (HTTPS) using TLS/SSL, and more."。（"Encryption and secure streaming."）："When a customer streams video through the Canary app, all video and data is securely encrypted between the device, the cloud, and the smartphone. … their video and data connection to the Canary Cloud is securely encrypted."。（"Storage in the Canary Cloud."）："The Canary Cloud is strengthened by the power and security of Amazon Web Services (AWS)."。（"Transparency and user accounts."）："Users can also easily customize settings to disable the camera and microphone."。A1、A2、A3、A4 でこれらの文は同じ。
- D1doc・D2doc（"Unblock Ports"）："Canary communicates with our servers through specific ports on your network, so you'll want to make sure the following ports are unblocked: TCP port 443 / UDP port 123"。2016 年版と 2019 年版で同じ。
- E1・E2（"Security & Data Protection"）："Encrypted cloud storage / Secure web transfer (SSL/TLS) / AES 256-bit data encryption"。E2・E3（2018）："videos securely stored with AES 256-bit symmetric-key encryption"。E4・E5："Instant data encryption / Bank-level security / AES 256-bit … / Secure data transfer (TLS/SSL) / Secure firewalls"。
- B1・B2（"International Users"）："the computer servers that handle data collected from the app and the device are hosted in the United States"。B3："the technical infrastructure that processes collected data … hosted in the United States"。B1〜B3（"Security"）："We follow generally accepted industry standards to protect the information transmitted to us …"。B1〜B3（"Video & Audio"）："In privacy mode … the camera and microphone are turned off."
- F1："we automatically encrypt all audio and video from your device"、"a privacy setting in Canary that completely disables the camera and microphone"、"a mandatory firmware upgrades right after setup"。
- G1：ソフトウェアの一覧に "Htpdate 1.1.2"、"libcurl"、"Connman"、"RabbitMQ"、"OpenSSL" がある（使用許諾の表示だけで、通信の仕方は書いていない）。
- H1（参考・後）："Canary devices have no listening ports"、"Canary connects directly to Canary Services through authenticated and encrypted channels."、"We perform signed firmware updates"。

---

## 4. 観測（フェーズごと）

数は D2（27 日）/ D1（6 日）。

| フェーズ | 平文で出たもの | 暗号化されたもの（根拠） |
|---|---|---|
| Wi-Fi の接続 | EAPOL 4-way（32 / 553 フレーム）、LLC XID、ARP | — |
| アドレス取得 | DHCP：Host Name "C100F1615229"（D2 136 / D1 28）、"Ambarella"（7 / 9）。要求オプションに 252（WPAD）と 42（NTP） | — |
| 名前解決 | DNS（192.168.1.1 へ）。D2：b.canaryis.com 25,299、h 12,561（A）+290（AAAA）、i 9,242、m 430+418、v 13、o 7、09-wl2-d-prod 5、wpad.lan 44（NXDOMAIN）、ipv4.connman.net 22。D1：b 5,648、i 695、h 86、m 6、v 3、o 3、wpad.lan 6、connman 3。CNAME：b→b.prod、i→ingress.prod / lvs-ingress.prod、h→htpdate.prod / lvs-htpdate.prod、m→rabbitmq-multi-external.prod、v→viks-device.prod、o→device-ota.prod（いずれも .canaryis.com） | — |
| 時刻・接続確認（TCP 80） | **h.canaryis.com への `HEAD / HTTP/1.1`**：D2 299 回（UA htpdate/1.1.2 が 286、curl/7.56.1 が 7、curl/7.58.0 が 6）、D1 53 回（htpdate 50、curl/7.49.0 3）。応答は "HTTP/1.1 301 Moved Permanently"、"Server: nginx"、Date、"Location: https://ip-10-10-…/"。**ipv4.connman.net への `GET /online/status.html`**（UA "ConnMan/1.35 wispr" / "ConnMan/1.29 wispr"）：D2 11 回（212.227.81.55）、D1 3 回（82.165.8.211）。応答 200、"X-ConnMan-Status: online"。D1 だけ NTP（UDP 123）を 192.168.1.1 へ送り、ICMP port unreachable が返る（144 パケット）。D2 に NTP はない | — |
| クラウドとの通信（TCP 443） | TLS の握手の中身：SNI（b、i、o、v。m は SNI なし）、**機器のクライアント証明書（CN＝機器 ID）**、サーバー証明書（*.canaryis.com、発行者 Canary Connect, Inc. の Server CA 1 / Root CA 1） | **TLS 1.2**。全 443 の TCP ストリームで、最初のペイロードが TLS レコードの頭（D2：機器側 0x16 41,515、0x15 28、0x17 55／サーバー側 0x16 42,210、0x15 8、0x17 61。D1：機器側 0x16 5,882、0x15 18、0x17 3／サーバー側 0x16 5,896、0x17 3）。ServerHello：D2 は 0xc030（ECDHE-RSA-AES256-GCM-SHA384）41,099、0xc02f（AES128-GCM）23、0xc028 17。D1 は 0xc030 5,850、0xc02f 9、0xc028 3。SNI 別：b・i は 0xc030、o・v は 0xc02f、SNI なし（m）は 0xc028 と 0xc030。サーバーは CertificateRequest を送り、相互認証の TLS になっている |
| ファーム更新 | — | o.canaryis.com へ TLS（0xc02f）。上の 2 回の大きな受信 |
| 外からの接続 | なし（機器あての SYN は D1・D2 とも 0） | — |

量：D2 の送信は 1 日 約 6〜11 MB（2018-06-14 は 32.6 MB、2018-10-13〜19 は 約 1.9 MB で、b.canaryis.com への接続が 0）。D1 の送信は 2016-11-22 が 868.8 MB、2017-03-03 が 1,299.0 MB、2017-03-04 が 2,164.5 MB で、すべて TLS。

---

## 5. 比較

| ID | フェーズ | 観測 | 公式文書の記載 | 判定 | PCAP 側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| K1 | 時刻・接続確認（D2） | Canary のサーバー h.canaryis.com と TCP 80 の平文 HTTP で 299 回やり取り | 機器とクラウドの「すべての通信」は TLS/SSL（HTTPS）で暗号化 | **明確な矛盾** | `18-05-28.pcap` 2018-05-28T00:20:36.847168Z 192.168.1.230→34.230.191.96:80 HEAD / UA htpdate/1.1.2、応答 00:20:37.054779Z 301 nginx。最後は `18-10-29.pcap` 2018-10-29T12:15:15.397860Z。27 ファイルすべてにある（1〜54 回／日）。310 の HTTP 要求はすべて別の TCP 接続で、再送 0 | C1（2018-08-18 保存、収録の中）"How secure is it?"、C2（2018-10-09、独語） | データ：高。解釈：中〜高 | 中身は `HEAD /` と UA、応答の Date だけで、利用者のデータはない。6 章 |
| K2 | 時刻・接続確認（D1） | 同じ平文 HEAD が 53 回 | 同じ文 | **条件付きの矛盾** | フレーム 23（2016-11-22T01:46:59.955581Z、curl/7.49.0）、フレーム 48（01:47:01.519632Z、htpdate）→54.165.61.246:80、応答フレーム 50。最後はフレーム 5,856,706（2017-03-05T03:04:14.330330Z） | C3（2016-08-22）と C1（2018-08-18）で同じ文 | データ：高。文書：中 | 条件：D1 の期間に FAQ がこの文のまま公開されていたか（8 章） |
| K3 | クラウド通信（D1・D2） | 443 はすべて TLS。平文の大量送信はない | 動画を見るときは "all video and data is securely encrypted between the device, the cloud, and the smartphone" | **一致**（暗号化の有無に限る） | 4 章の TLS の根拠 | A1（D1 の中）、A3（D2 の前、英国版） | 中 | どの TLS が視聴中の動画かは見分けられない。HEAD は視聴の通信ではないので、最も限定的な読み方では範囲外。広く読めば K1 と同じく矛盾。"securely" は評価語 |
| K4 | 時刻・接続確認 | HEAD の接続は動画も利用者データも運ばない | "their video and data connection to the Canary Cloud is securely encrypted" | **公式文書に記載なし** | K1・K2 と同じ | A1、A3 | 中 | 「動画とデータの接続」に限って読む。h へ平文の接続があることを、どの文書も書いていない。広く読めば矛盾 |
| K5 | クラウド通信 | b・i は AES-256-GCM、o・v は AES-128-GCM | "such as AES 256-bit symmetric-key encryption"、"AES 256-bit data encryption" | **一致** | D2：0xc030 41,099 回、o 10 回・v 13 回は 0xc02f。D1：0xc030 5,850、o 6・v 3 は 0xc02f | A1〜A3、E1、E2、E4、E5 | 高 | 文は「AES-256 を使う」で「すべての通信が AES-256」ではない。広く読めば o・v で食い違う。保存時の AES-256（C1、E2）は観測不能 |
| K6 | 全体のポート | TCP 80 を使う（D2 310 接続、D1 56 接続）。UDP 123 は D1 で同じ LAN のルーターにだけ、D2 では使わない | 開けるべきポートは "TCP port 443 / UDP port 123" | **公式文書に記載なし** | K1、K7 と同じ | D1doc（2016-10-10、D1 の前）、D2doc（2019-07-20、D2 の後） | 中 | 文は「次のポートを開けて」で、「これだけを使う」とは言っていない。全部の一覧と読めば矛盾。記事は両方の収録期間の中で保存されていない |
| K7 | 接続確認（第三者） | ipv4.connman.net（Canary 以外、IONOS、現在の whois でドイツ）へ平文 GET。D2 11 回、D1 3 回 | サーバーは米国にある。第三者への共有は限られた場合だけ | **公式文書に記載なし** | D2：`18-05-28.pcap` 2018-05-28T05:59:20.364430Z →212.227.81.55:80（最後 `18-10-28.pcap` 2018-10-28T04:44:47.747402Z）。D1：フレーム 39、973,563、3,739,241 →82.165.8.211 | B1（D1 の中）、B2（D2 の前）、B3（D2 の後、日付は前） | 中 | 文は「Canary が集めたデータを扱う Canary のサーバー」の話。接続確認はそこに入らない。広く読めば矛盾。G1 に "Connman" とあるが、この通信のことは書いていない。サーバーの持ち主と当時の場所は未確認 |
| K8 | クラウド通信 | 大量の送信はすべて TLS | "Video recordings … are encrypted and sent to the Canary Cloud"、"we automatically encrypt all audio and video"、"Secure web transfer (SSL/TLS)" | **一致** | 4 章の TLS の根拠。D1 で 1 日 0.87〜2.16 GB の送信がすべて TLS | C1、C3、F1、E1、E2 | 中 | 動画かどうかは中身が見えないので推測 |
| K9 | ファーム更新 | 更新とみられる受信が 2 回、どちらも TLS | 更新はクラウド経由で行われる。F1：更新は必須 | **一致** | D1：2017-03-04T03:29:51.796375Z、26,597,336 バイト。D2：2018-05-30T02:01:26.666356Z、35,566,658 バイト | A1〜A3 "embedded Canary firmware will be updated regularly"、F1 | 中 | 署名の有無（H1、後）は観測不能 |
| K10 | 全体 | モードは分からない。中身は暗号化 | プライバシーモードではカメラとマイクが止まり、環境のデータだけ送る | **観測不能** | D2 の 2018-10-13〜19 は送信 約 1.9 MB／日で b への接続 0。理由は分からない | B1〜B3、C1、F1、A1〜A3 | — | 操作の記録がない |
| K11 | — | — | "bank-level security"、"generally accepted industry standards"、"Secure firewalls"、"Instant data encryption" | **判断不能** | — | C1、B1〜B3、E4、E5 | — | 方法を書かない評価の言葉 |
| K12 | 握手と名前 | SNI、機器の証明書（CN＝機器 ID、OU=Development）、DNS 名、DHCP Host Name（シリアルとみられる）が平文 | なし（C1 "any data that Canary generates is immediately encrypted" はある） | **公式文書に記載なし** | D2：機器の Certificate を含む握手 1 日 25〜1,940 回。例 `18-05-28.pcap` 最初の機器 Certificate | C1 | 中 | TLS 1.2 の仕組みで出るもの。「機器が作るデータ」を中身（映像・音声・センサー）に限って読むと範囲外。広く読めば矛盾 |
| K13 | 外からの接続 | 機器あての SYN は 0 | "Canary devices have no listening ports"（2019 年） | **観測不能** | D1・D2 とも機器あての SYN なし | H1（後、参考） | — | 文書が収録の後。待ち受けを試す通信もない |

---

## 6. 食い違いの詳しい内容

### K1（明確な矛盾）と K2（条件付きの矛盾）

**公式の主張（原文）**
"All communication between your Canary device, the Canary Cloud, and your smartphone is encrypted over TLS/SSL (HTTPS)."
出典：Original Canary FAQ、節 "How secure is it?"、help.canary.is 記事 206619098、Wayback 2018-08-18 02:14:10（D2 の中）。同じ文が 2016-08-22（"Pre-purchase FAQ"）と独語版 2018-10-09（D2 の中）にもある。

**観測した事実**
- 機器（MAC 7c:70:bc:5d:5e:dc、192.168.1.230）が h.canaryis.com に TCP 80 で接続し、暗号化しない HTTP を送る。
  要求："HEAD / HTTP/1.1 / Host: h.canaryis.com / User-Agent: htpdate/1.1.2 / Pragma: no-cache / Cache-Control: no-cache / Connection: close"。
  応答："HTTP/1.1 301 Moved Permanently / Server: nginx / Date: … / Location: https://ip-10-10-22-130/"。
  （例：`18-05-28.pcap` 2018-05-28T00:20:36.847168Z と 00:20:37.054779Z）
- D2 の 27 日すべてで、計 299 回ある。間隔は 30 分〜16 時間で、htpdate らしく変わる。ネットワークにつないだ直後には curl の HEAD もある。D1 でも 53 回ある。
- **この相手が Canary のクラウドであることの根拠**：
  - DNS は h.canaryis.com → htpdate.prod.canaryis.com → lvs-htpdate.prod.canaryis.com。
  - 同じ 3 つの IP（34.230.191.96、34.230.213.152、52.200.251.249）は、TCP 443 では i.canaryis.com（ingress.prod）として相互認証の TLS を受ける。サーバー証明書は *.canaryis.com で、発行者は "Canary Connect, Inc." の私設 CA（Server CA 1 / Root CA 1）。サーバーはクライアント証明書を要求し（CertificateRequest）、機器は Canary の "Device CA 2" が発行した証明書を出す。例：`18-05-28.pcap` 2018-05-28T00:00:42.293915Z の ClientHello（SNI i.canaryis.com）と、00:00:42.503710Z の CertificateRequest。D1 でも h の IP 28 個のうちの IP に、i.canaryis.com の握手が 352 回ある。
  - 301 の行き先 `ip-10-10-…` は AWS の VPC 内部の名前の形。A1〜A3 は Canary Cloud が AWS と VPC の上にあると書いている。
  - 現在の whois では、これらの IP は Amazon（米国）。

**どこが食い違うか**
文は機器と Canary Cloud の間の「すべての通信」が TLS/SSL（HTTPS）だと言う。実際には、機器と Canary のサーバーの間に、TLS を使わない HTTP のやり取りが定期的にある。

**最も限定的な読み方と、それでも矛盾する理由**
- 「Canary Cloud」は、Canary が運用する、機器がつなぐサーバー群に限って読む（A1〜A3 の "Canary Cloud … AWS"、"VPC" と合う）。
- 「smartphone」との通信は除き、機器とクラウドの間だけを見る。
- それでも、平文の HTTP の相手は、機器のデータの入口（i.canaryis.com）と同じ IP、同じ社内 CA、同じ VPC の Canary のサーバーである。
- 文は "All communication" と言い切り、用途や中身で範囲を絞っていない。

**別の読み方と、退けた理由**
1. 「通信」を利用者のデータ（映像、音声、センサー）の通信に限る：この文には限定の言葉がない。前の文 "any data that Canary generates is immediately encrypted" がデータの話をしており、この文はそれとは別に「通信」全体を言っている。だから退けた。ただし、この読み方を取る人がいることは補足として書く。
2. 時刻サーバーは「Canary Cloud」ではない：データの入口と同じ IP と同じ社内の仕組みの上にあり、区別する根拠が文書にない。だから退けた。
3. サーバーが HTTPS へ 301 で転送しているので、HTTPS を使う設計だ：機器は転送先へ進まず、平文の要求と応答（Date を含む）が実際にやり取りされている。

**K2 の条件**：D1 の期間（2016-11-22〜2017-03-05）に、この FAQ が保存された記録がない。前（2016-08-22）と後（2018-08-18）は同じ文。

---

## 7. 反証の検討

| 探したもの | 見つけたもの | 判定への影響 |
|---|---|---|
| 同じ時期の公式文書が HTTP（80 番）や平文の時刻合わせを開示していないか（Security、製品、How it works、Specs、仕様書 PDF、User Guide、FAQ、ファイアウォール記事、プライバシー、ブログ、Compliance、Open Source） | 平文の通信や TCP 80 を書いた文書はない。ファイアウォール記事は 443/TCP と 123/UDP だけ。**G1（Open Source 一覧、2016-02 保存）に "Htpdate 1.1.2"、"libcurl"、"Connman" の名前がある**。htpdate は HTTP の Date で時刻を合わせる道具なので、詳しい人なら HTTP の時刻合わせを推測できる | 弱める材料。ただし G1 は使用許諾の表示だけで、通信の仕方も暗号化の有無も書いていない。C1 の "All communication … TLS/SSL" を打ち消す記述ではない。K1 は変えない |
| 文の範囲（機種、地域） | C1 の題は「Original Canary」。機器は "C100…" から CAN100（初代）と推測。独語版は題に機種の限定がない。オーストラリア版の文書は見つからない | 機種の推測が外れても、C2 と C3 は機種を限らないので K1 は変わらない。地域版の違いは未確認 |
| データセットの事情（攻撃、中間者、走査、操作） | Canary は攻撃対象ではない（arXiv 版の表、注釈に MAC と IP なし）。HEAD は機器の MAC から出て、毎日、決まった UA で、D1 と D2 の両方にある。作成者の操作ではない | 影響なし |
| 観測の誤り（再送、重複、本当に平文か、本当にその機器か） | D2 の HTTP 要求 310 回はすべて別の TCP 接続で、再送 0。中身は ASCII の HTTP で、圧縮も符号化もない。MAC、IP、DHCP の Host Name、機器の証明書が一致する | 影響なし |
| 送り先の持ち主 | 6 章の根拠（CNAME、i と同じ IP で社内 CA の相互 TLS、VPC の内部名） | 条件にしなくてよいと判断した |
| 中身の重さ | 利用者のデータはない（要求は `HEAD /` と UA、応答は 301 と Date） | 判定は変えない（中身の重さは評価しない）。論文ではこの点を必ず書く |
| 先行研究の評価 | Alrawi ほか（IEEE S&P 2019）は、Canary の機器とクラウドの通信を「完全に暗号化（●）」、HTTP を "✓+ (TLS/SSL)" としている | 反対の見方の資料。データは否定しないが、ファームの違いか、評価の基準の違いの説明が要る |

---

## 8. 条件

- **K2**：D1 の期間に C3（FAQ）がこの文のまま公開されていたか。CDX で記事 206619098 のすべての名前（Pre-purchase-FAQs、Pre-purchase-FAQ、Original-Canary-FAQ）、en-gb、de を見た。2016-08-22 と 2018-08-18 の間に保存はない。前と後で文は同じ。決められないので「条件付き」のままにする。D1 については、A1（2016-12-19、D1 の中）の Security ページが範囲の狭い文（K3、K4）しか持たない。
- **K1 の参考**：プライバシーポリシーは 2018-02-27（英国版）と 2019-02-08（米国版、Effective Date May 25, 2018）の間に保存がない。K1 はプライバシーポリシーではなく FAQ（収録の中の保存）に基づくので、影響しない。
- **K7**：ipv4.connman.net の持ち主と、当時のサーバーの場所。現在の whois は IONOS SE（DE）。当時の割り当てと運用者（ConnMan の開発者側か）は未確認。

---

## 9. 先行資料（検索 5 回）

1. `"canaryis.com" htpdate OR "port 80" OR plaintext Canary camera traffic` → Canary に特有のものはなかった。
2. `Alrawi "SoK: Security Evaluation of Home-Based IoT Deployments" Canary camera` → O. Alrawi, C. Lever, M. Antonakakis, F. Monrose, "SoK: Security Evaluation of Home-Based IoT Deployments", IEEE S&P 2019。Canary を評価している。Table II（PDF p.10）は Running Services 0、MITM なし、Encryption ●（fully encrypted）。Table VII（p.18）は DNS ✓、HTTP "✓+ (TLS/SSL)"、NTP なし、D-C の MITM ✗、D-C の Encryption ●。**平文の HTTP は報告していない**（この報告と逆の結論）。
3. `UNSW MUD profile "canary" camera "h.canaryis.com" OR "canaryis.com" MUD` → 検索では出なかった。UNSW の MUD 一覧（https://iotanalytics.unsw.edu.au/mudprofiles.html 、IEEE TDSC 2020 "Verifying and Monitoring IoTs Network Behavior Using MUD Profiles", Hamza ほか, doi:10.1109/TDSC.2020.2997898 のデータ）を直接開いた。`canaryCameraMud.json` に **h.canaryis.com の TCP 80（from-device）と ipv4.connman.net の TCP 80** がある。**通信そのものは許可リストとして公開済み**。ただし、平文であることや公式の発表との食い違いは論じていない。
4. `Network World review IP cameras "Canary" passed security test no open ports encrypted 2017` → CSO Online（2017-01-23、Network World のテスト）は「待ち受けポートなし」「自動更新」と書き、平文の通信には触れない。Canary のブログ（F1）がこの記事を引用している。
5. `"ipv4.connman.net" IoT device connectivity check privacy third party traffic study` → Canary に特有のものはなかった。

この文書のこの主張とこの通信の食い違いを示した資料は見つからなかった。IEEE S&P、USENIX Security、ACM CCS、NDSS で同じ問題を詳しく示した論文も見つからなかった（S&P 2019 の SoK は逆の評価）。新しいとは言わない。

---

## 10. 断定できる／できない

**断定できる**
- D1 と D2 で、同じ個体（MAC、DHCP の Host Name C100F1615229）が、h.canaryis.com と TCP 80 で暗号化しない HTTP（HEAD）をやり取りした。回数は D2 299、D1 53。
- その相手の IP は、Canary の社内 CA で相互認証の TLS を受ける i.canaryis.com と同じ。
- FAQ（収録 D2 の中に保存、英語版と独語版）は、機器と Canary Cloud の「すべての通信」が TLS/SSL（HTTPS）だと書いている。
- 機器は ipv4.connman.net（Canary 以外）へ平文の HTTP GET を送った。
- 443 の通信はすべて TLS 1.2 で始まり、大量の送信もファーム更新も TLS だった。

**断定できない**
- HEAD の目的（時刻合わせと推測）。
- 型番（CAN100 と推測）とファームの版の番号。
- D1 の期間の FAQ の掲載状態。
- プライバシーモードの動作。
- connman.net の運用者と当時の場所。
- TLS の中身（映像かどうか）。

**未確認の一覧**
- SOSR 2019 の論文本文と IEEE Data Descriptions の本文。
- UNSW-IoTraffic 全体の開始日と終了日。Canary の公開パケット数（`device_pcap_summary.csv` が 403）。
- 公開ファイルそのものが途中で切れているか。
- D2 の切り出し元と公開ファイルのハッシュの一致。
- 攻撃日のファイルの Canary の通信。
- ハードウェアの版、ファームの版の番号、アプリの版。
- オーストラリア向けの文書。
- 2018-02〜2019-02 の米国版プライバシーポリシーの実際の掲載内容。
- 2016-09〜2019-07 のファイアウォール記事。

---

## 11. 3 行のまとめ

- 最も強い判定：**明確な矛盾（K1）**。Original Canary FAQ（2018-08-18 保存、収録の中）の "All communication between your Canary device, the Canary Cloud … is encrypted over TLS/SSL (HTTPS)" に対し、2018 年の 27 日すべてで、機器が Canary のサーバー h.canaryis.com と TCP 80 の平文 HTTP（HEAD、299 回）をやり取りした。2016-17 年（53 回）は FAQ の掲載が確認できないので条件付き。
- 論文の中心に使えるか：**条件つき**。
- 理由：事実と送り先の持ち主は固い。しかし、中身は時刻合わせとみられる `HEAD /` と Date だけで利用者のデータがない。IEEE S&P 2019 の SoK は Canary を「完全に暗号化」と評価している。通信そのものは UNSW の MUD 一覧で既に公開されている。この 3 点を本文で説明できる場合に限る。
