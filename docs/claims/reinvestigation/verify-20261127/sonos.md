# Sonos（PLAY:1 2018／Sonos One 2021）：公式の発表と実際の通信の食い違い

確かめ直しの日：2026-11-27。前の調査の結論は読んでいない。数と時刻はすべて tshark で確かめた。時刻は `tshark -t ud` の UTC（マイクロ秒）。認証情報やトークンの値は `V/out/sonos-secrets.md` にだけ書いた（この報告では「値は secrets に」と書く）。

引用について：原文は短い 1 か所だけ引く。ほかの文は日本語で要約し、本文の場所（ファイルと行）を書く。主な文書は Wayback から取り直して `V/out/work-sonos/web/`（以下 `Wweb/`）に置いた（生の HTML と、それを文字にした `.txt`。行番号は `.txt` のもの）。外付けディスクの `~/datasets/claims/snapshots/`（以下 `S/`）の本文も作業の途中までは読んだが、ディスクが外されたため、`S/` にしかないもの（表の D6・D9〜D12、E3・E4、2022 年の記事）はいま手元で読み直せない（本文は読んである。再確認は未確認（ディスクなし））。

---

## 1. データセット

### 1-A. YourThings（2018 年、PLAY:1）

| 項目 | 内容 |
|---|---|
| 名前 | YourThings（配布ページ https://yourthings.info/data/ ） |
| 作成者と論文 | Omar Alrawi, Chaz Lever, Manos Antonakakis, Fabian Monrose, "SoK: Security Evaluation of Home-Based IoT Deployments", 2019 IEEE Symposium on Security and Privacy, pp. 1362–1380, DOI 10.1109/SP.2019.00013（Crossref で確認）。本文 PDF：https://coeus.ece.gatech.edu/articles/sok_sp19.pdf |
| 利用条件 | データのページには「使うなら論文を引用してほしい」という依頼だけがある。ライセンスの明記はなし（未確認。yourthings.info の data・method・トップを見た） |
| 収録の場所 | 米国。Georgia Institute of Technology（論文の所属）。研究室の網（IoT 用のサブネット、Debian のゲートウェイ、評価用の機械）。ゲートウェイが IoT サブネットから出る IP の通信をすべて記録した（論文 §IV-A）。Cloudflare の応答の CF-RAY が `-ATL`（アトランタ）で、場所と合う |
| 全体の収録の期間 | 2018-03-20、03-21、03-28（機器の評価）と 2018-04-10〜04-19（ネットワークの評価）の計 13 日。配布ページの本文には「March 20, 21, 25」とあり、見出しとファイル名（iot_traffic20180328.tgz）は 28 日で、ページの中で食い違っている |
| この機器の最初と最後 | 2018-03-20 00:00:00.160322Z（`eth1-20180320.0000.1521522000`）〜 2018-04-19 23:59:59.847611Z（`eth1-20180419.2355.1524200100`）。ただし pcap の時刻そのもの。下の「時刻の注意」を参照 |
| 作成者が行った操作・検査 | Nessus による走査、sslsplit による中間者の検査（論文 §IV-D、§IV-G）。「自動更新は評価を乱すので、設定できる機器では止めた」（§IV-C）。Sonos の更新は「利用者の同意が要る」と分類（Table VI の Upgrade＝C）。データでは：(1) 192.168.0.200 からの走査（03-20 02:46–03:03 と 15:43–16:45、03-21 17:17–20:41、03-28 20:28–20:30。Sonos は 1400・1410・1443 番で応答）。(2) 偽の証明書（発行者 thing-catcher.gtisc.gatech.edu）による中間者の検査：Sonos の接続では 04-11 19:38 に 2 回、04-13 03:03–03:09 に 7 回見えた。(3) 作成者のアプリからの更新の指示（下の 2、4 を参照） |

データの事情（自分で確かめたこと）：

- 重複：ユニキャストは「VLAN タグなし」と「VLAN 1 のタグつき」の 2 回、Sonos から出るマルチキャストは 3 回（タグなし 2＋タグつき 1）入っている。Ethernet（と 802.1Q）の後ろのバイト列と MAC が同じで、5 ms 以内のものを 1 つと数えた。13 日で 8,033,812 → 3,433,992 パケット。以下の回数は重複を除いた数。
- 時刻の注意：(a) 元のファイル名の末尾の数（例 1521522000＝05:00Z）は、中のパケットの時刻（00:00Z から）と 5 時間ずれている。(b) サーバの HTTP の Date と比べると、収録の機械の時計は 3 月は約 17〜18 分進み、4 月は 3〜56 秒進んでいた。報告の時刻は pcap の値そのまま。結論には影響しない。
- 機器の確かめ：MAC 5c:aa:fd:6c:e0:d4、DHCP のホスト名 `SonosZP`、配布の device_mapping.csv で `Sonos,192.168.0.7`、device_description.xml の serialNum も同じ MAC。

### 1-B. CIC IoT Dataset 2022（2021 年、Sonos One）

| 項目 | 内容 |
|---|---|
| 名前 | CIC IoT Dataset 2022（配布ページ https://www.unb.ca/cic/datasets/iotdataset-2022.html 、一覧では "CIC IoT Profiling Dataset 2022"） |
| 作成者と論文 | Sajjad Dadkhah, Hassan Mahdikhani, Priscilla Kyei Danso, Alireza Zohourian, Kevin Anh Truong, Ali A. Ghorbani, "Towards the Development of a Realistic Multidimensional IoT Profiling Dataset", 2022 19th Annual International Conference on Privacy, Security & Trust (PST), pp. 1–11, DOI 10.1109/PST55820.2022.9851966（Crossref で確認）。論文の本文は読んでいない（未確認） |
| 利用条件 | CIC のデータセット一覧の FAQ：再配布・再公開してよいが、使うときはデータセットと論文の引用が必要 |
| 収録の場所 | カナダ。UNB の Canadian Institute for Cybersecurity（会議の開催地 Fredericton と同じ。ページ自体に住所の記載はない）。Windows の機械に NIC 2 枚、Wireshark/dumpcap で記録（配布ページ）。データでは Sonos の DNS の相手が 192.168.137.1（Windows のインターネット接続共有の既定の網と推測）、Cloudflare の CF-RAY が `-YUL`（モントリオール） |
| 全体の収録の期間 | 配布ページに日付はない（未確認）。Idle と Active はそれぞれ 30 日分とある。Idle は「夕方遅くから朝早く」、人は入らない |
| この機器の最初と最後 | 2021-09-28 13:05:59.113892Z（3-Interactions の `sonosonePOWER_1.pcap`）〜 2021-12-24 09:59:57.845699Z（`2-Idle/2021_12_23_Idle.pcap`） |
| 作成者の操作 | Power（電源投入）、Interactions（`sonosoneLANPLAY`、`LANSTOP`、`ALEXAPLAY`、`ALEXASTOP`、`POWER`、各 3 回）、Scenarios（ComingHome、LeavingHome、IoTNonIoT など。HomeIntrusion・OwnerError の 12 本にはこの機器のパケットがない）、Active（`2021_11_02_Active.pcap`）、Idle（30 本）。Attacks は渡されていない |

データの事情：重複はほとんどない（5 ms 以内の同じパケットは 1 本あたり数個で、本物の再送）。数え直しはしていない。IP は 192.168.137.120（09-28）、192.168.137.13（10-13）、192.168.137.2（11 月〜12 月）と変わる。サーバの Date との差は 1〜2 秒。

---

## 2. 機器

| 項目 | YourThings（2018） | CIC（2021） |
|---|---|---|
| 製造者 | Sonos, Inc. | Sonos, Inc. |
| 製品名・型番 | Sonos PLAY:1、modelNumber `S1`、SSDP・User-Agent の型コード `ZPS1`（device_description.xml、port 1400 の応答） | Sonos One、modelNumber `S18`、型コード `ZPS18`、アイコン `/img/icon-S18.png`（同） |
| ハードウェアの版 | `1.8.3.7-1`（hardwareVersion） | `1.26.1.7-1.2`（同）、swGen `2`（S2） |
| MAC／製造番号 | 5c:aa:fd:6c:e0:d4／serialNum `5C-AA-FD-6C-E0-D4:F`（更新要求では `5CAAFD6CE0D4F`） | 48:a6:b8:f9:1b:88／`48-A6-B8-F9-1B-88:1`（更新要求では `48A6B8F91B881`） |
| IP | 192.168.0.7（固定） | 192.168.137.120 → .13 → .2 |
| ほかの識別子 | sonosid `114318238`、household `Sonos_P8cV8f1KTV2o3UsRygDDfluIEc`、部屋名 Office | sonosid `132068149`、household `Sonos_fDHIljBe20CoWQ8ms7hPxIpuEs`、部屋名 Living Room |
| ファームウェア（どこから） | SSDP の SERVER と HTTP の User-Agent、device_description.xml の softwareVersion/displayVersion、更新要求の cmaj/cmin/cbld、更新の URL の経路 | 同じく SSDP・User-Agent・`X-Sonos-Firmware` ヘッダ・device_description.xml・更新の URL |
| ファームウェアの変化 | `33.15-33210`（表示 6.4.2）→ 2018-03-20 21:42:47 に `34.16-37101`（経路名 v7.1）→ 21:43:51 に `41.3-50131`（経路名 v8.4）→ 2018-04-13 16:34:05 に `42.2-51240`（表示 8.5）。3 回とも作成者のアプリが UPnP の `BeginSoftwareUpdate` を送った直後 | `64.3-19080`（表示 13.2、09-28）→ `65.1-21040`（10-13〜11-18。表示の版は未確認、経路名から 13.3 系と推測）→ 2021-11-18 07:14 に `66.4-23090`（表示 13.4）→ 2021-12-10 07:48 に `66.4-23300`（経路名 v13.4.1）。後の 2 回は Idle（人がいない）中で、LAN からの指示は見えない（自動更新と推測） |
| アプリの版 | 作成者のアプリ：192.168.0.151 の User-Agent は `Sonos/41.3-50131 (ACR_:samsung:gts3lwifixx:SM-T820)`（Android タブレット。配布の対応表では .151 は "iPhone" で、食い違う）、192.168.0.159 は `Sonos/42.2-52112 (ICRU_iPad5,1)`。論文 Table IV は Android 版 8.3.1 | 未確認（LAN のアプリの通信が切り出しにない） |
| つなぎ方 | 論文 Table VI で「Wired」 | 未確認 |

---

## 3. 公式文書

### 3-1. 表

| ID | 文書名 | 発行元 | 文書の中の日付 | Wayback の保存日時 | アーカイブの URL | 地域・言語 | 対象 | 収録との関係 |
|---|---|---|---|---|---|---|---|---|
| D1 | Sonos, Inc. Privacy Statement | Sonos, Inc. | Last Updated: August 2017 | 2018-02-02 08:51:45 | https://web.archive.org/web/20180202085145/https://www.sonos.com/en-us/legal/privacy | 米国・英語 | すべての Sonos 製品とアプリ | 前（3 月の収録時に有効。4 月は D2 と並ぶ候補） |
| D2 | 同上 | Sonos, Inc. | Last Updated: April 2018 | 2018-04-24 22:31:12 | https://web.archive.org/web/20180424223112/https://www.sonos.com/en-us/legal/privacy | 米国・英語 | 同上 | 4 月中のいつ公開されたかは未確認（2018-02-02 と 04-24 の間に保存がない）。中または後 |
| D3 | Privacy Statement Archive | Sonos, Inc. | 版の一覧：Current（Nov 2020）, April 2020, March 2019, April 2018, August 2017, November 10, 2014 | 2021-10-25 22:27:37 | https://web.archive.org/web/20211025222737/https://www.sonos.com/en-us/legal/privacy-archive | 米国 | — | 版の順の確認用（`Wweb/privarch-20211025.txt` 43–49 行） |

| D4 | Configuring your firewall to work with Sonos（a_id 692） | Sonos（custhelp のサポート） | Updated 03/08/2017 | 2017-08-22 23:15:07 | https://web.archive.org/web/20170822231507/https://sonos.custhelp.com/app/answers/detail/a_id/692 | 英語 | パソコンのファイアウォールの設定 | 前（2018 年 3〜4 月にまだ載っていたかは未確認。次の保存は 2019 年の別のサイト） |
| D5 | Information about SonosNet（a_id 126） | Sonos サポート | Updated 11/25/2015 | 2016-01-17 04:46:45 | https://web.archive.org/web/20160117044645/https://sonos.custhelp.com/app/answers/detail/a_id/126/~/information-about-sonosnet | 英語 | SonosNet | 前 |
| D6 | PLAY:1 Product Guide（PDF） | Sonos | ©2004-2016 | 2016-11-30 15:23:59 | https://web.archive.org/web/20161130152359/http://www.sonos.com:80/documents/productguides/en/Play1Guide_EN.pdf | 英語 | PLAY:1 | 前 |
| D7 | Sonos Setup Guide（PDF） | Sonos | ©2004-2016 | 2017-10-13 15:40:32 | https://web.archive.org/web/20171013154032/http://www.sonos.com:80/documents/productguides/en/SetupGuide_EN.pdf | 英語 | Sonos 全般 | 前 |
| D8 | Release notes 8.4 | Sonos | Current software version 8.4 | 2018-04-09 20:03:24 | https://web.archive.org/web/20180409200324/https://www.sonos.com/en-us/software/release/8-4 | 米国 | ソフトウェア | 中 |
| D9 | PLAY:1 製品ページ | Sonos | なし | 2018-04-09 08:28:54 | https://web.archive.org/web/20180409082854/https://www.sonos.com/en-us/shop/play1.html | 米国 | PLAY:1 | 中（暗号・データの記載なし） |
| D10 | EULA（PDF） | Sonos | なし | 2016-08-05 09:45:18 | https://web.archive.org/web/20160805094518/http://www.sonos.com/documents/eula/EN/EULA_EN.pdf | 英語 | ソフトウェア | 前（製品の利用は Privacy Policy に従うとだけ書く） |
| D11 | Support policies | Sonos | なし | 2017-10-23 06:57:36 | https://web.archive.org/web/20171023065736/http://www.sonos.com/en-us/support/policies.html | 米国 | 適合宣言の一覧だけ | 前（関係なし） |
| D12 | Updating Sonos（サポートの索引） | Sonos | なし | 2017-12-06 12:00:20 | https://web.archive.org/web/20171206120020/https://www.sonos.com/en-us/support/troubleshooting/updating-sonos | 米国 | 索引だけ | 前（関係なし） |
| E1 | Sonos, Inc. Privacy Statement | Sonos, Inc. | Last updated: November 2020 | 2021-11-03 21:04:34／2021-12-21 20:47:11（本文同じ） | https://web.archive.org/web/20211103210434/https://www.sonos.com/en-us/legal/privacy | 米国・英語 | すべての Sonos 製品 | 中 |
| E2 | 同上（カナダ英語版） | Sonos, Inc. | Last updated: November 2020 | 2021-10-22 06:25:20 | https://web.archive.org/web/20211022062520/https://www.sonos.com/en-ca/legal/privacy | カナダ・英語 | 同上 | 中（収録地の版。暗号の文は米国版と同じ趣旨、`Wweb/privca-20211022.txt` 187 行） |
| E3 | Security Researcher Recognition（/en-us/security） | Sonos | なし | 2021-11-21 06:07:04 | https://web.archive.org/web/20211121060704/https://www.sonos.com/en-us/security | 米国 | 脆弱性の届け出 | 中（通信の約束はない） |
| E4 | Sonos One 製品ページ | Sonos | なし | 2021-11-04 03:24:15 | 保存日時は `S/sonos_one-20211104032415.txt` の名前から。元の URL は読み直せず未確認（ディスクなし） | 米国 | Sonos One | 中（暗号の記載なし） |
| E5 | ファイアウォールの記事（support.sonos.com/s/article/688） | Sonos | — | 2021-06-16、09-25、10-25 | https://web.archive.org/web/20210925000831/https://support.sonos.com/s/article/688?language=en_US | 英語 | — | 中。本文は JavaScript で読み込まれ、アーカイブに本文がない（未確認） |
| 参考 | Configure your firewall to work with Sonos（新しいサイト） | Sonos | — | 2022-12-06 | https://web.archive.org/web/20221206092811/https://support.sonos.com/en-us/article/configure-your-firewall-to-work-with-sonos | 米国 | — | 後（当時も同じとは推定しない。TCP 80・443 を「音楽サービス、ラジオ、Sonos アカウント」に、4444 を「システムの更新」に使うと書く） |

本文の置き場所：D1＝`Wweb/priv20180202.txt`、D2＝`Wweb/priv20180424.txt`、D4＝`Wweb/kb692-20170822.txt`、D5＝`Wweb/kb126-20160117.txt`、D7＝`Wweb/setupguide-20171013.txt`（PDF も同じ場所）、D8＝`Wweb/release84-20180409.txt`、E1＝`Wweb/priv-us-20211103.txt`、E2＝`Wweb/privca-20211022.txt`。

2021 年の「セキュリティ」の内容のあるページは見つからなかった（`/en-us/legal/security` は 2021 年に 410）。Release 13.x のノート（support.sonos.com/s/article/3521）も本文が JavaScript で、未確認。

### 3-2. 該当する文（要約と場所。行番号は `Wweb/` の `.txt`）

- D1「Security」節（`priv20180202.txt` 295–296 行）：インターネットで送るデータは暗号で守る、とする。2 文目で「あなたのデータは、TLS などの暗号で、インターネットを通る間守られる」とする。同じ文書の FAQ「How is information stored and secured on Sonos' servers?」（350–351 行）も「インターネットで送るデータはすべて暗号で守る」とする。
- D2「Security, Storage and Retention」節（`priv20180424.txt` 259 行）と FAQ（380 行）：D1 と同じ趣旨。
- E1「Security, Storage and Retention of Personal Information We Collect」節（`priv-us-20211103.txt` 188 行）：原文 "your data is protected with encryption ... during transmission over the Internet"。E2（`privca-20211022.txt` 187 行）も同じ（"during transition"）。
- 同じ文書の中で、何を「集めるデータ」と呼んでいるか：
  - D1「Using Sonos Products」の Functional Data（174–175 行）：Registration data に Product serial number と IP address、System data に software version information と Product type を含む。Additional Usage Data の Performance Information（180 行）に製品の温度、Wi-Fi の信号の強さなどを含む。D2 は 180・181・186 行。
  - D1「Registering your Sonos System」（164 行）：登録のときに Sonos システムの英数字の識別番号を作り、メール・製造番号・IP と結び付ける。
  - D1 の冒頭（141 行）：自動で集めるものも含めて「your data」と呼んでいる。
  - E1（64 行）：personal information を「あなたを特定できる、またはあなたに結び付けられる情報」と定める。Registration data に Product serial number（96 行）、System data に software version と温度・Wi-Fi 信号などの性能の値（97 行）。E2 は 95・96 行。
- 第三者について：D1（229 行、236 行）、E1（169 行）。許可した音楽サービスと Activity Information を共有することがある。第三者の製品に渡したデータはその第三者の方針に従う。
- D4（`kb692-20170822.txt` 212–242 行、生の HTML でもコメントではなく表示される本文と確認）：Sonos が使う TCP のポートとして、80 番を「インターネットラジオ、更新、登録」用、443 番を Rhapsody・Napster・SiriusXM、4444 番を Sonos の更新の処理に使うと書く。パソコンのソフトのファイアウォールの設定の記事。
- D5（`kb126-20160117.txt` 18–19 行）：SonosNet は AES で暗号化した、安全なメッシュ網だとする。
- D6・D7：無料のオンライン更新があり、受けるには登録が要る。D7（`setupguide-20171013.txt` 590–592 行）：使用データ（Usage Data）は第三者に渡さない。
- D8（`release84-20180409.txt` 138–139 行）：2018-04-09 時点の現行版は 8.4。

---

## 4. 観測（フェーズごと）

### 4-A. YourThings（重複を除いた数）

| フェーズ | 平文で出たもの | 暗号化されたもの（根拠） |
|---|---|---|
| 更新の確認（毎日と、アプリの指示） | `GET http://update.sonos.com/firmware/latest/default-1-1.ups?cmaj=…&cmin=…&cbld=…&subm=3&rev=7&reg=1&serial=5CAAFD6CE0D4F&sonosid=114318238&householdid=Sonos_P8cV…`、User-Agent `Sonos`。13 日で 28 回（相手は Akamai の 184.27.26.43、23.198.220.216、23.218.197.58）。15 回は機器から（直前 3 秒に LAN の指示なし。毎日 21:48〜22:05 または 17:29〜17:30）、13 回は作成者のアプリの UPnP `CheckForUpdate` の直後 | — |
| ファームのダウンロード | `GET http://update-firmware.sonos.com/firmware/Gold/<版>/<版>.upd?` に上と同じ serial・sonosid・householdid・現在の版。User-Agent `Wget`。3 回（03-20 21:42:47、21:43:51、04-13 16:34:05）。応答は `application/octet-stream`（34.16 は 8,306,684 バイト）。中身の暗号・署名は調べていない（未確認） | — |
| 時刻帯の表 | `GET http://update-timezone.sonos.com/timezone/timezones.xml`、User-Agent `Sonos`、識別子なし。15 回 | — |
| 使用データ（テレメトリ） | 1 回だけ：2018-03-20 12:38:08.524403Z、`POST http://msmetrics.ws.sonos.com:80/HRMetrics/submit.aspx`、User-Agent `Linux UPnP/1.0 Sonos/33.15-33210 (ZPS1)`、本文は XML `<UsageMetrics>`：`<cu>114318238</cu>`、`<hh>Sonos_P8cV…</hh>`、`<sn>5C-AA-FD-6C-E0-D4:F</sn>`、`<md>ZPS1</md>`、`<uptime>`、`<wifi>`（送信の待ち行列など）、`<links … freq="2437" …>` と雑音の値 `nf0`〜`nf2`、`<temperatures><CPUTempHist>…`。応答は 200 と JSON の messageId。もう 1 回：2018-03-20 14:03:07.720764Z `GET http://msmetrics.ws.sonos.com/HRMetrics/pollInterval.htm?hhid=Sonos_P8cV…`。どちらも古いファーム 33.15 のときだけ。41.3 と 42.2 では 80 番の msmetrics は 0 回 | msmetrics.ws.sonos.com への 443 番は毎時あり、TLS 1.2（証明書 `*.ws.sonos.com`、Sonos Inc.） |
| クラウドの設定など | — | config.ws、service-catalog.ws、registration.ws、oauth.ws、system-api.sonos.com。Sonos から外への 443 番の接続は 13 日で 433 本、すべて TLS 1.2 の ClientHello で始まる。HTTP として読めるものは 0 |
| ラジオ・音楽サービス（第三者） | TuneIn（legato.radiotime.com）への SOAP `POST /Radio.asmx` 61 回：ヘッダ `<credentials><deviceId>5C-AA-FD-6C-E0-D4:F</deviceId><deviceProvider>Sonos</deviceProvider>`、本文は `getMediaMetadata`、`getMediaURI`、`reportPlaySeconds`、`setPlayedSeconds`（局の ID と再生の秒数）。`GET /Tune.ashx?…&partnerId=Sonos&serial=5C-AA-FD-6C-E0-D4:F&version=42.2` 20 回。streamtheworld の放送（80 番と 3690 番）、cdn-profiles.tunein.com | — |
| Spotify の SDK（第三者） | `GET http://esdk-ffl.spotify.com/esdk-fire-and-forget/?key_id=1&value=<Base64>` 3 回（再起動の直後）。value は復号すると約 306 バイト、7.2〜7.4 bit/byte で読めない（独自の暗号化と推測。中身は判断できない） | （同左。中身は読めない） |
| 時刻合わせ | NTP（UDP 123、*.sonostime.pool.ntp.org） | — |
| LAN | UPnP/SOAP（TCP 1400）、SSDP（ヘッダ `X-RINCON-HOUSEHOLD` に household ID）、device_description.xml（製造番号、部屋名）、Bose・Google 機器への SSDP の応答 | 1443 番の LAN 用 HTTPS（Sonos 自身の CA の証明書） |
| 検査への反応（普段のふるまいから外す） | 走査に 1400・1410・1443 番が応答。偽の証明書（thing-catcher.gtisc.gatech.edu）には 9 回とも TLS の警告 Unknown CA を返して切った（例：04-11 19:38:03.012339Z） | — |

### 4-B. CIC（Sonos One）

| フェーズ | 平文で出たもの | 暗号化されたもの |
|---|---|---|
| 毎日の更新の確認（Idle の各日 1 回） | `GET http://update-firmware.sonos.com/firmware/Prod/<目標の版>/update.upm`（30 回）、`GET http://update-timezone.sonos.com/timezone/timezones.xml`（32 回）。どちらもヘッダ `USER-AGENT: Linux UPnP/1.0 Sonos/<版> (ZPS18)`、`X-Sonos-SWGen: 2`、`X-Sonos-Firmware: <版>`、`X-Sonos-Muse-Api`、`X-Sonos-Id-Hash`（いつも同じ値。値は secrets に）。URL に製造番号はない | update.sonos.com は TLS（SNI で確認） |
| ファームのダウンロード（自動と推測） | 2 回：2021-11-18 07:14:22.325677Z と 2021-12-10 07:48:02.640768Z、`GET http://update-firmware.sonos.com/firmware/Prod/<版>/<版>-1-26.upd?cmaj=…&cmin=…&cbld=…&subm=1&rev=7&reg=1&serial=48A6B8F91B881&sonosid=132068149&householdid=Sonos_fDHIljBe20CoWQ8ms7hPxIpuEs`、User-Agent `Wget`。応答 200、約 47 MB | — |
| テレメトリ・クラウド | — | msmetrics.ws、ab-us.ws、lechmere、feature-config.sslauth、service-catalog、product-settings、sslvalidator など。外への 443 番の接続 2,950 本のうち 2,856 本は TLS 1.2 の ClientHello（TLS 1.3 の申し出なし）。残り 94 本は収録の前から続く接続で、TLS のレコードだけ |
| Alexa（第三者の SDK） | `GET http://spectrum.s3.amazonaws.com/kindle-wifi/wifistub.html`、User-Agent `AvsDeviceSdk/1.24.0`、約 5 分ごとに 4,052 回（接続の確認と推測。利用者の値はなし） | AVS（*.avs.na.gateway.devices.a2z.com、api.amazon.com）は TLS |
| ラジオ（第三者） | `GET http://opml.radiotime.com/Tune.ashx?…&partnerId=…&serial=…`（2 回、値は secrets に）、放送の URL にトークン `partnertok`（JWT、値は secrets に）。opml.radiotime.com と 190.3.169.87:9322 には `X-Sonos-Id-Hash` も付く | sali.sonos.radio は TLS |
| 時刻合わせ | NTP | — |
| LAN | SSDP、mDNS、UPnP（Windows の機械の DLNA の問い合わせ） | — |

---

## 5. 比較

判定は 6 区分。D1/D2 は 2018 年、E1/E2 は 2021 年の文書。

| ID | フェーズ | 観測 | 公式文書の記載 | 判定 | PCAP 側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| Y1 | テレメトリ | 使用データ（製造番号、household ID、Sonos ID、Wi-Fi の値、温度）を平文の HTTP で msmetrics.ws.sonos.com へ POST | 送るデータは TLS などで暗号化。温度・Wi-Fi は同じ文書で「集めるデータ」 | **明確な矛盾** | `eth1-20180320.1235.1521567300` 元フレーム 61241（VLAN の写し 61242）、2018-03-20 12:38:08.524403Z、192.168.0.7:40691 → 34.199.54.23:80、HTTP POST、本文 `<UsageMetrics>`、1 回。応答 61249 | D1 Security 節 295–296 行、FAQ 351 行、Performance Information 180 行、Registration data 174 行 | 高（データ）／中（代表性） | 古いファーム 33.15（表示 6.4.2）で 1 回だけ。更新後は 0 回。走査の時間帯の外、LAN からの指示もなし |
| Y2 | 更新の確認 | 製造番号・Sonos ID・household ID・現在の版を URL に入れて平文の HTTP で update.sonos.com へ | 同上。製造番号・ソフトの版は「集めるデータ」 | **明確な矛盾** | 28 回。例：`eth1-20180320.1400.1521572400` 元 60977、2018-03-20 14:03:08.725631Z（ファーム 33.15、機器から）；`eth1-20180416.1730.1523917800` 元 3580、2018-04-16 17:30:07.286826Z、→ 23.198.220.216:80（ファーム 42.2、機器から、操作のない日） | D1 295–296・351・174–175 行、D2 259・380・180–181 行 | 高 | 当時の現行版 8.4・8.5 でも毎日。D4 が「80 番を更新と登録に使う」と書いていた（7 章） |
| Y3 | ファームのダウンロード | 同じ識別子つきの URL で平文の HTTP | 同上 | **明確な矛盾**（Y2 と同じ食い違い） | 3 回。`eth1-20180320.2140.1521600000` 元 133992（21:42:47.719047Z）・元 178481（21:43:51.055748Z）、`eth1-20180413.1630.1523655000` 元 141952（16:34:05.284653Z） | 同上 | 高 | 3 回とも作成者のアプリの `BeginSoftwareUpdate`（元 133219、21:42:45.619911Z、192.168.0.151 から；元 139872、16:34:01.211571Z、192.168.0.159 から）の直後。要求の中身は機器のもの |
| Y4 | テレメトリの設定 | household ID だけを URL に入れて HTTP で GET | 同上 | **条件付きの矛盾** | `eth1-20180320.1400.1521572400` 元 60493、2018-03-20 14:03:07.720764Z、→ 52.55.66.68:80、1 回 | D1 164 行（登録で作る英数字の識別番号） | 中 | 条件：household ID が D1 の言う「メールなどと結び付ける識別番号」であること（8 章）。Y2 では製造番号と一緒に出るので Y2 の判定は変わらない |
| Y5 | 時刻帯の表 | 識別子のない GET（User-Agent `Sonos`） | 該当なし | 公式文書に記載なし | 15 回、例 `eth1-20180320.1400.1521572400` 元 60135（14:03:06.892251Z） | — | 高 | 利用者のデータを含まない |
| Y6 | ラジオ（TuneIn） | 製造番号（deviceId）、局の ID、再生の秒数を平文の SOAP で TuneIn へ | 音楽サービスと Activity Information を共有しうる。第三者の扱いはその方針 | 公式文書に記載なし | 81 回。例 `eth1-20180410.0840.1523367600` 元 131693、2018-04-10 08:44:26.060879Z、→ 104.17.106.184:80、`getMediaMetadata` | D1 229・236 行 | 高 | 最も限定的な読みでは暗号の文は Sonos が集めるデータの話。広く読めば（製品が送るデータすべて）矛盾になる |
| Y7 | Spotify の SDK | 読めない Base64 を HTTP の URL で | 該当なし | 公式文書に記載なし（中身は判断不能） | 3 回。`eth1-20180320.2140.1521600000` 元 171819・216643、`eth1-20180413.1635.1523655300` 元 549 | D1 236 行 | 中 | 第三者の SDK。中身が利用者のデータか判断できない |
| Y8 | 放送・NTP | 放送の音声、NTP | 該当なし | 公式文書に記載なし | streamtheworld 各接続、NTP 各日 2 パケット前後 | — | 高 | — |
| Y9 | LAN | UPnP/SOAP、SSDP に household ID、製造番号 | 暗号の文は「インターネット」の話 | 公式文書に記載なし | 例 SSDP の `X-RINCON-HOUSEHOLD`（04-16 は 2,976 パケット、03-20 は 3,862 パケット） | D1 296 行 | 高 | LAN は文の範囲の外 |
| Y10 | クラウドの TLS | 443 番は 433 本すべて TLS 1.2 | 暗号化する | 一致 | 各日 28〜48 本、すべて ClientHello から | D1 296 行 | 高 | — |
| Y11 | ポート | 80 番を更新・ラジオ・（登録）に使用 | D4：80 番は「インターネットラジオ、更新、登録」用 | 一致（ただし msmetrics の 80 番は D4 にない＝記載なし） | Y2・Y3・Y6 | D4 212–213 行 | 中 | D4 が収録時に有効だったかは未確認 |
| Y12 | SonosNet | 無線のメッシュは見えない（有線の出口で記録） | AES で暗号化 | 観測不能 | — | D5 19 行 | — | 論文 Table VI で Sonos は Wired |
| Y13 | 使用データの第三者提供 | TuneIn への再生の報告、Spotify の SDK | D7：使用データは第三者に渡さない | 公式文書に記載なし | Y6・Y7 | D7 590–592 行 | 低 | 最も限定的な読みでは「この情報」は Sonos が Usage Data として集めるもの。TuneIn の報告が同じ情報かは決められない。D7 は 2016 年の版で、D1 は音楽サービスとの共有を開示 |
| C1 | ファームのダウンロード | 製造番号・Sonos ID・household ID・現在の版を URL に入れて平文の HTTP | E1/E2：TLS などで暗号化。製造番号・ソフトの版は「集めるデータ」 | **明確な矛盾** | 2 回。`2-Idle/2021_11_17_Idle.pcap` 元フレーム 592023（切り出し 6910）、2021-11-18 07:14:22.325677Z、192.168.137.2 → 23.9.105.98:80；`2-Idle/2021_12_09_Idle.pcap` 元 813200（切り出し 7305）、2021-12-10 07:48:02.640768Z、→ 104.105.42.62:80 | E1 188・96・97・64 行、E2 187・95・96 行 | 高 | 人のいない Idle 中で、LAN の指示なし（自動更新と推測） |
| C2 | 毎日の更新の確認 | ソフトの版・型（User-Agent、`X-Sonos-Firmware`）と `X-Sonos-Id-Hash` を平文のヘッダで | 同上。ソフトの版・型は System data | **条件付きの矛盾** | 62 回。例 `2-Idle/2021_11_17_Idle.pcap` 元 591688（07:14:16.394638Z、timezones.xml）・元 591813（07:14:17.117116Z、update.upm） | E1 97・64・188 行 | 中 | 条件：ヘッダの値が「あなたに結び付けられる情報」であること（Id-Hash が何のハッシュか不明） |
| C3 | ラジオ（TuneIn など） | TuneIn 用の serial、パートナーの値、トークン、`X-Sonos-Id-Hash` を平文で第三者へ | 第三者の扱いはその方針 | 公式文書に記載なし | `4-Scenarios/…/IoTNonIoT_1.pcap` 元 39444（2021-11-03 16:50:34.211773Z）、`3-Interactions/…/sonosoneLANPLAY_1.pcap` 4 番目 | E1 169 行 | 高 | Y6 と同じ考え方 |
| C4 | Alexa SDK | 接続確認の GET（利用者の値なし） | 該当なし | 公式文書に記載なし | 4,052 回 | — | 高 | — |
| C5 | クラウドの TLS | 443 番はすべて TLS 1.2 | 暗号化する | 一致 | 2,950 本 | E1 188 行 | 高 | — |
| C6 | 音声 | AVS は TLS で、何を送ったかは読めない | 呼びかけの言葉の前は何も送らない | 観測不能 | Idle 中も AVS への TLS の接続が続く | E1 114 行 | — | 量だけでは決められない |
| C7 | LAN・NTP | SSDP・mDNS・UPnP、NTP | 「インターネット」の話 | 公式文書に記載なし | — | — | 高 | — |

---

## 6. 食い違いの詳しい内容

### Y1：使用データの平文の送信（2018-03-20、PLAY:1、ファーム 33.15-33210）

- 公式の主張：D1（Last Updated August 2017、2018-02-02 の保存。3 月 20 日に有効だった版）の Security 節 295–296 行と FAQ 351 行。インターネットで送るデータは暗号で守り、あなたのデータは TLS などでインターネットを通る間守られる、とする。同じ文書が、製品の温度と Wi-Fi の信号の強さを「集めるデータ」（Additional Usage Data の Performance Information、180 行）、製造番号を Registration data（174 行）と書く。
- 観測：`eth1-20180320.1235.1521567300` の元フレーム 61241、2018-03-20 12:38:08.524403Z、192.168.0.7 → 34.199.54.23 TCP 80 番、`POST /HRMetrics/submit.aspx`、`Host: msmetrics.ws.sonos.com:80`。本文は平文の XML で、Sonos ID・household ID・製造番号・型・稼働時間・Wi-Fi の統計・温度の分布が読める。同じ IP の 443 番は `*.ws.sonos.com`（Sonos Inc.）の証明書を出しており、送り先は Sonos のサービス。
- 食い違い：文書が「集める」と書くデータそのもの（温度、Wi-Fi、製造番号）が、暗号なしでインターネットを通った。
- 最も限定的な読み方：「your data」を「この文書が Sonos が集めると書いている、利用者についてのデータ」と読む。これでも温度・Wi-Fi・製造番号は入る。送り先は Sonos 自身で、第三者の例外も使えない。「such as TLS」は方法を限らないが、HTTP の本文はどの層でも暗号化されていない。
- 別の読み方と退けた理由：(a)「your data」を「利用者が自分で入力したデータ（メール、パスワード）」に限る読み。Security 節の暗号の文はその限定の言葉を使っていない。また文書は冒頭から自動で集めるものも「your data」と呼んでいる（141 行）。(b) 1 文目の「we transmit」を「Sonos の会社が送る」と読み、製品から Sonos への送信を外す読み。2 文目は主語がなく、通る間のデータすべてを指すので、2 文目だけで矛盾は残る。
- 限り：古いファームで 1 回だけ。作成者が 21:42 に更新した後は 0 回。この点は論文で明記が要る。

### Y2・Y3：更新の確認とダウンロードで識別子を平文で送る（2018 年、13 日）

- 公式の主張：D1・D2 の暗号の文（上と同じ）。同じ文書が製造番号を Registration data、ソフトの版を System data と書く（D1 174–175 行、D2 180–181 行）。D1・D2 のどちらが 4 月に有効でも、文は同じ。
- 観測：`update.sonos.com` への GET 28 回、URL に `serial=5CAAFD6CE0D4F`、`sonosid=114318238`、`householdid=Sonos_P8cV8f1KTV2o3UsRygDDfluIEc`、現在の版（`cmaj`・`cmin`・`cbld`）。15 回は機器が自分で毎日送り、操作のない日（04-16〜04-19）にもある。当時の現行版 41.3（8.4）・42.2（8.5）でも同じ。ダウンロードの 3 回も同じ値が URL にある。
- 食い違い：文書が「集めるデータ」とする製造番号・ソフトの版、と識別子が、暗号なしで毎日インターネットを通った。
- 最も限定的な読み方とそれでも矛盾する理由：Y1 と同じ。送り先は sonos.com の名前の更新サーバ（Akamai の CDN の上。応答に `Sonos-updateID` ヘッダがある）。
- 別の読み方：「製造番号は個人のデータではない」という読み。文書自身が製造番号を利用者から集める Registration data に入れ、メールと結び付けると書くので退けた。

### C1：自動更新のダウンロードで識別子を平文で送る（2021 年、Sonos One）

- 公式の主張：E1（米国、Last updated November 2020、2021-11-03 と 12-21 の保存で本文同じ、`Wweb/priv-us-20211103.txt`）188 行と E2（カナダ版、収録地）187 行の暗号の文。E1 は personal information を「あなたを特定できる、または結び付けられる情報」と定め（64 行）、製造番号を Registration data（96 行）、ソフトの版を System data（97 行）とする。
- 観測：2 回。2021-11-18 07:14:22.325677Z と 2021-12-10 07:48:02.640768Z、`update-firmware.sonos.com` への GET の URL に `serial=48A6B8F91B881`、`sonosid=132068149`、`householdid=Sonos_fDHIljBe20CoWQ8ms7hPxIpuEs`、現在の版。人のいない Idle の中で、LAN からの指示はない。
- 最も限定的な読み方とそれでも矛盾する理由：E1 の定義で製造番号は personal information に入り、送り先も Sonos。2018 年と同じく例外はない。
- 2018 年との違い：2021 年は更新の確認（update.sonos.com）が TLS になった。製造番号つきの平文は、更新があった 2 回のダウンロードだけ。毎日の平文の要求（C2）は製造番号を含まない。

### C2（条件付き）：毎日の平文のヘッダ

- 観測：Idle の毎日、版・型と `X-Sonos-Id-Hash` を平文の HTTP ヘッダで送る（62 回、Id-Hash は 65 回とも同じ値）。
- 最も限定的な読みでは、ソフトの版と型だけでは「あなたに結び付けられる情報」と言えない。Id-Hash が Sonos の側で利用者に結び付く値なら矛盾になる。そこは決められない（8 章）。

---

## 7. 反証の検討

| 探したもの | 見つけたもの | 判定への影響 |
|---|---|---|
| 同じ時期の公式文書が平文の更新・80 番を開示していないか | D4（ファイアウォールの記事、Updated 03/08/2017、2017-08-22 の保存）は、TCP 80 番を「インターネットラジオ、更新、登録」に使うと書いていた。暗号なしとは書いていない。パソコンのファイアウォールの記事で、プライバシーの文を狭める文もない。2018 年 3〜4 月にまだ載っていたかは未確認（次の保存は 2019 年の別のサイト）。2021 年版（E5）は本文がアーカイブになく未確認。2022 年版は 80 番を「音楽サービス、ラジオ、Sonos アカウント」とし、更新は 4444 番とする（後の文書。参考） | Y2・Y3 は判定を変えない（ポートの開示で、暗号の約束は残る）。ただし「Sonos は一切開示していなかった」とは書けない。Y1（msmetrics の 80 番）は D4 にも載っていない |
| 文の範囲（誰が、どの機能、どの機種、どの地域） | 暗号の文は Security 節にあり、製品・機能・地域の限定がない。冒頭で文書はすべての Sonos 製品とアプリに当てはまるとする。カナダ版も同じ文。第三者への送信は「その第三者の方針」とする文がある | 第三者の流れ（Y6・Y7・C3・C4）は記載なしに下げた |
| 文書の版と日付 | D3 で版の順（2017 年 8 月 → 2018 年 4 月）を確認。2018 年 4 月版の公開日は不明（求人の通知 PDF の名前が 2018-04-23 だが、別の文書）。3 月の収録は 2017 年 8 月版、4 月は 2 つの版のどちらか。どちらも同じ暗号の文 | 影響なし |
| データセットの検査 | 走査の時間帯（03-20 02:46–03:03、15:43–16:45）の外で Y1（12:38）と Y4（14:03）が起きた。LAN からの指示もない。中間者の検査は TLS だけで、HTTP の要求の中身は機器が作ったもの。作成者がアプリで更新を指示したのは 03-20、04-11、04-13、04-15。指示のない毎日の確認だけで Y2 は成り立つ | 影響なし。Y3 は作成者の操作のときだが、更新は普通の利用者の操作でもある |
| 重複・再送 | 重複を除いた数で数えた（VLAN の写し、マルチキャストの 3 重）。Y1 の元フレーム 61241 と写し 61242 を 1 回と数えた | 影響なし |
| 本当に平文か | HTTP の要求の行・ヘッダ・本文を ASCII で直接読んだ。圧縮・Base64 ではない（Spotify の value だけが読めない） | 影響なし |
| 本当にその機器か | MAC、DHCP のホスト名、配布の対応表（192.168.0.7）、device_description.xml の製造番号が一致。CIC も MAC・製造番号・mDNS 名が一致 | 影響なし |
| 送り先の持ち主 | update*.sonos.com、msmetrics.ws.sonos.com はどちらも Sonos のドメイン。同じ IP が 443 番で Sonos の証明書を出す。IP の持ち主は whois で Akamai（184.27.26.43、23.198.220.216、23.218.197.58、23.9.105.98、104.105.42.62）と Amazon（34.199.54.23、52.55.66.68）で、Sonos のサービスが CDN・クラウドの上にあると読める | 送り先が Sonos でないという余地は小さい。条件にしなかった |
| ファームの版 | 通信から確定（2 章）。Y1 だけが古いファーム | Y1 の代表性を下げる（判定は変えない） |
| 先に書かれた資料 | 9 章 | 影響なし |

---

## 8. 条件

- Y4（household ID だけの平文）：household ID が、D1 の言う「登録で作り、メール・製造番号・IP と結び付ける英数字の識別番号」と同じものか。名前（household）と形から推測はできるが、文書にも通信にも決め手はない。
- C2（毎日のヘッダ）：`X-Sonos-Id-Hash` が何のハッシュで、Sonos が利用者に結び付けられるか。値は 2021 年 11〜12 月の 65 回すべて同じで、TuneIn などの第三者にも送られる。決め手は見つからなかった。

---

## 9. 先行資料

検索（5 回）：
1. `Sonos speaker unencrypted HTTP update.sonos.com serial householdid plaintext traffic analysis`
2. `IoT privacy policy claims vs network traffic encryption inconsistency study Sonos "privacy policy" plaintext`
3. `"msmetrics.ws.sonos.com" OR "HRMetrics" Sonos`
4. `Sonos smart speaker network traffic plaintext firmware update HTTP USENIX Security OR NDSS OR CCS OR "IEEE S&P" measurement`
5. `"Sonos" telemetry "port 80" OR "unencrypted" OR "cleartext" "serial number" household ID update check 2018`

見つけたもの：
- 同じデータの論文（IEEE S&P 2019、Alrawi ほか）：Table II で Sonos の通信を「一部だけ暗号化」とし、Table VII で HTTP・TLS の両方を使うと記録している（§IV-G、PDF の 9〜12 ページと付録）。平文の中身（製造番号、使用データ）や、プライバシーの文との食い違いは書いていない。通信そのもの（平文の HTTP があること）は既に報告されていると言える。
- Trend Micro, "The Sound of a Targeted Attack"（2017、PLAY:1）と HITB 2018 の発表：LAN の 1400 番の状態ページと SOAP が認証も暗号もない、という内容。LAN の話で、インターネットへの平文の送信ではない。
- Sonos のコミュニティの投稿：msmetrics.ws.sonos.com を DNS で止める話。平文かどうかの話ではない。
- Bradley ほか（FPS 2022、Carleton）：IoT の更新が HTTP で配られることを示すが、Sonos は出てこない（本文で "Sonos" は 0 回）。

同じ食い違い（このプライバシーの文と、この平文の通信）を指摘した資料は見つからなかった。見つからなかっただけで、新しいとは言わない。

---

## 10. 断定できる／できない、未確認

断定できる：
- 2018 年（PLAY:1）：製造番号・Sonos ID・household ID・ソフトの版が、平文の HTTP で update.sonos.com・update-firmware.sonos.com に送られた（28＋3 回、毎日、当時の現行のファームでも）。同じ時期の米国のプライバシーの文書は、インターネットを通るデータは TLS などで暗号化すると無条件に書き、同じ文書が製造番号とソフトの版を集めるデータに入れていた。
- 2018-03-20：古いファーム 33.15 の PLAY:1 が、温度・Wi-Fi の値・製造番号を含む使用データを平文の HTTP で msmetrics.ws.sonos.com に 1 回送った。
- 2021 年（Sonos One、カナダ）：自動更新の 2 回、製造番号・Sonos ID・household ID が平文の HTTP の URL で送られた。米国版・カナダ版の 2020 年 11 月の文書は同じ暗号の文を持っていた。
- Sonos のクラウドへの 443 番はすべて TLS 1.2。偽の証明書は受け入れなかった（検査への反応）。

断定できない：
- 2018 年 4 月版の公開日（4 月の収録日にどちらの版だったか）。結論には影響しない。
- D4（80 番を更新に使うという記事）が 2018 年 3〜4 月にまだ載っていたか。2021 年の同じ記事の本文。
- household ID と `X-Sonos-Id-Hash` が利用者に結び付く値か（Y4・C2 の条件）。
- 2021 年の更新が自動か、クラウドからの指示か（LAN の指示がないことからの推測）。
- Spotify の SDK が送った値の中身。AVS への音声の中身。
- ファームの本体が暗号化・署名されているか（調べていない）。

未確認の一覧：
- YourThings のライセンス（yourthings.info のトップ・data・method を見た。引用の依頼だけ）。
- CIC の論文の本文（機器の一覧、日付）。配布ページだけを読んだ。全体の収録の期間も未確認。
- 2018 年の米国版プライバシーの文書の、2018-02-02 と 04-24 の間の保存（Wayback にない）。カナダ版 2018 年（2017-11-12 の後は 2018-05-14 まで保存なし。読んでいない）。
- 2021 年のファイアウォールの記事（support.sonos.com/s/article/688）とリリースノートの本文（JavaScript で読み込み、アーカイブに本文なし。Chrome で開こうとしたが拡張がつながらなかった）。
- 表示の版 13.3（65.1-21040）は推測。
- D6（PLAY:1 の手引き）、D9〜D12、E3、E4、2022 年のファイアウォールの記事は、作業の途中で `S/` の本文を読んだが、ディスクが外されたので読み直していない（未確認（ディスクなし））。判定に使った D1・D2・D4・D5・D7・D8・E1・E2 は Wayback から取り直して `Wweb/` で行を確かめた。
- 192.168.0.130（03-20 に 30 秒ごとに device_description.xml を取りに来た機械）の正体。192.168.0.151 が対応表では iPhone なのに User-Agent は Android のタブレット。

---

## 11. 3 行のまとめ

1. 最も強い判定は**明確な矛盾**：Sonos のプライバシーの文書（2017 年 8 月版・2018 年 4 月版・2020 年 11 月版、米国とカナダ）は「インターネットを通るデータは TLS などで暗号化する」と書いたが、PLAY:1（2018）は製造番号・household ID・ソフトの版を平文の HTTP で更新サーバへ送り（13 日で 28 回、うち 15 回は機器が毎日自分で）、古いファームでは温度・Wi-Fi の使用データも平文で送った（1 回）。Sonos One（2021）も自動更新の 2 回で製造番号などを平文で送った。
2. 論文の中心に**使える**：データ（平文の要求の行と本文）と文書（無条件の暗号の文と、同じ文書が製造番号・ソフトの版を「集めるデータ」と書くこと）の両方があり、最も限定的な読みでも矛盾し、二つの時点・機種・国で同じ形が出るため。
3. ただし書き方に限りがある：Sonos は別のサポート記事（2017 年）で 80 番を「更新と登録」に使うと書いており、「全く開示していなかった」とは言えない。使用データの平文は古いファームの 1 回だけで、household ID と Id-Hash だけの流れは条件付き、第三者（TuneIn、Spotify、Alexa）への平文は最も限定的な読みでは対象外。
