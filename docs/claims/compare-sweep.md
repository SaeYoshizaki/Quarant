# 公式文書と通信の食い違い（5 つのデータセット、2026-11-11）

製造者の公式文書に書いてあることと、データセットの実際の通信を比べた結果（[D42](../DECISIONS.md)、[sweep-handoff.md](sweep-handoff.md)）。YourThings 2018 の 44 製品は以前の作業（[results-yourthings.md](results-yourthings.md)）、ほかの 4 つのデータセットは今回集めた文書による。主張の 1 行ずつは [claims.tsv](claims.tsv)、探した文書は [coverage.tsv](coverage.tsv)。

## やったこと

- **文書**：UNSW 2016、UNSW-IoTraffic、CIC IoT 2022、Deakin 2023 の製品について、収録の時期の公式文書（製品ページ、セキュリティ、プライバシー、サポート、マニュアル、リリースノート）を Wayback から集めた（[method.md](method.md) の D1〜D6）。引用はすべて保存した本文と照合した（`check_quotes.py`）。
- **主張の型**：暗号化（T1）、暗号の性質（T2）、認証情報（T3）、映像・音声（T4）、更新（T5）、送るデータ（T6）、機器の中での処理（T7）、送り先（T8）。開示（「MAC を集める」）も記録した。
- **比べ方**：主張ごとに、洗い出し（[sweep-results.md](sweep-results.md)）の観測と、パケットでの確認（`verify.py`）を当てた。判定は「食い違いの候補」「一致（見えた範囲で）」「見えない」「判定できない」。
- **先行研究**：同じ食い違いを指摘した資料と、通信の問題そのものの報告を分けて探した（[sweep/prior-claims.tsv](sweep/prior-claims.tsv)）。

## 数（主張の行）

| データ | 製品 | 食い違いの候補 | 文言の上で | 一致 | 見えない | 判定できない |
|---|---|---|---|---|---|---|
| YourThings 2018 | 44 | 10 | 0 | 50 | 16 | 749 |
| UNSW 2016 | 3 | 0 | 0 | 6 | 20 | 31 |
| UNSW-IoTraffic | 25 | 4 | 1 | 50 | 184 | 255 |
| CIC IoT 2022 | 26 | 9 | 2 | 45 | 187 | 205 |
| Deakin 2023 | 14 | 2 | 0 | 39 | 130 | 117 |
| 製品 | 主張（文書、版の日付） | 観測 | 先行研究 |
|---|---|---|---|
| SimCam 1S（CIC） | 「Everything is processed and stored locally on the device」（製品ページ、2020-08-08）。「Because the Simshine ® Simcam 1S uses entirely local AI processing, we never have access to your data.」（FAQ、2021-10-24） | 人物検知の JPEG（22〜25 KB）を平文の HTTP で S3 のバケットに 15 回 PUT（`2021_11_02_Active.pcap` フレーム 1234〜631073、パス `/SimCam/<id>/PersonDetect/<id>`）。カメラは TLS を一度も使っていない | 食い違い：見つからず。画像の送信：見つからず |
| Awair（IoTraffic） | 「Awair encrypts and stores all information over TLS (Transport Layer Security) and AES 256 bit encryption」（サポート記事、2016-07-31） | 826 回の握手のうち 744 回が `TLS_RSA_WITH_AES_128_CBC_SHA256`（`AwairAirQuality_70886b100fc6.pcap` フレーム 22〜24） | 食い違い：見つからず。TLS：論文で一部（Wannigama ほか、WoWMoM 2024） |
| Samsung SmartCam（IoTraffic） | 「Security SSL (AES 256bit)」（仕様、2017-09-21、収録の 5 か月後） | 65 回の握手はすべて AES-128。イベントの通知 `POST www.samsungsmartcam.com/web/event.stw` が平文で、シリアル番号 `KHNL6V2H20003LX` つき（13,310 回） | 食い違い：見つからず。TLS：論文で一部（同上） |
| Samsung Pan/Tilt（Deakin） | 「we make sure that Personal Information can be safely transmitted over the network through encrypted communication」（wisenetlife、2024-01-01 施行）。「industry-standard methods to keep this information safe and secure while it is transmitted from your devices」（2021-04-19） | 同じ平文のイベントの POST、シリアル番号 `ZDZ56V2K100594B`（mDNS の sn と一致）つき、68 回 | 食い違い：見つからず。平文：ブログ等（CVE-2018-6295、Kaspersky 2018） |
| D-Link DCH-S161（CIC、弱い） | 「The SSL protocol is also implemented for ... better securing all logs of settings and Services of your devices」（US のプライバシー、2021-11-28） | `GET mp-us-fwd.auto.mydlink.com/fw-upgrade?device_id=F0B4D2F96095`（機器の MAC）が平文、32 回 | 食い違い：見つからず。更新の確認：論文で一部（Bradley & Barrera, FPS 2022） |
| iRobot Roomba（CIC） | 「Currently, we use AES 256-bit encryption and Transport Layer Security (TLS v1.2).」（データセキュリティのページ、2021-12-06、すべての製品が対象） | 34 回の握手はすべて AES-128-GCM（TLS 1.3 の `TLS_AES_128_GCM_SHA256` が 20、TLS 1.2 の `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` が 14）。AES-256 は一度も選ばれていない | 食い違い：見つからず。暗号の選択：見つからず |
| Philips Hue Bridge（CIC） | 「Hue only connects to the internet securely via a dedicated cloud so your devices cannot be seen from the open internet.」（FAQ、2021-12-22） | ブリッジの通信の 27% が平文の HTTP：`diagnostics.meethue.com/v2/diagnostics/report?...&sso=<トークン>`（4,760 回、本文は 16 進の暗号文）、`dcp.dc1.philips.com:80` への POST の `Authorization: CBAuth` にブリッジ ID と SSO トークン（1,017 回） | 食い違い：見つからず。平文の HTTP：論文で一部（Mandalari ほか, PoPETs 2021, §5.5 p.379）。トークンとブリッジ ID の平文：見つからず |
| Philips Hue Bridge（IoTraffic、2016-17） | 「Philips Lighting, transfers data securely (using SSL) and will encrypt some data, such as your MAC address when it is stored.」（プライバシー、2016-10-17 と 2017-03-01 の版、収録の期間に有効） | ブリッジの通信の 70%（36.5 MB）が平文の HTTP：`dcp.cpp.philips.com:80` などへの POST に `Authorization: CBAuth`（4,810 回）、`bridge.meethue.com:80/queue/getmessage` に `auth`（8,370 回）（`PhilipsHue_0017882b9a25.pcap` フレーム 1586〜3925289） | 食い違い：見つからず（この文を名指しした検索はしていない）。平文の HTTP：論文で一部（PoPETs 2021）、ブログ（AV-TEST 2017） |
| Invoxia Triby（IoTraffic、弱い） | 「we will not disclose the personal information you provide via the Site or Products to parties unaffiliated with invoxia」（プライバシー、2017-02-11） | 機器の MAC を `8937406324.airable.io/authentication?device=<MAC>` に平文で送る | 食い違い：見つからず。Basic 認証：論文で一部（WoWMoM 2024） |

- **SimCam**：同じ会社のアプリ（SimHome）のプライバシーポリシー（2021-10-06）は「your image data will be transferred to your mobile device via the server」と開示している。製品ページと FAQ の説明が、同じ会社の別の文書と合っていない。S3 のバケットと `www.luuka.fun` の持ち主は未確認。
- **Hue**：送り先が Philips/Signify のホストだけという点（dedicated cloud）は一致。食い違いは「securely」の部分で、AV-TEST（2017）は本文が別に AES で暗号化されているとして「十分に安全」と評価している。食い違いの根拠は、平文で見えるブリッジ ID と SSO トークン。YourThings の Hue は、文書の時期と範囲の理由で利用者が除いた（D40）。今回は 2021 年の文書と CIC の通信で別に比べた。
- **Roomba**：TLS 1.3 は書かれた TLS 1.2 より新しく、弱くはない。食い違いは AES-256 の部分だけ。機種は未確認。
- **Nest Mini（文言の上で食い違い）**：NCC Group の ioXt 評価報告（2021-06、Google が公開）の「all BLE and WLAN communication was secured using ... up-to-date TLS」に対し、平文は中身のない HEAD の接続確認（`connectivitycheck.gstatic.com`）だけ。報告を製造者の文書として数えるかは判断待ち。
- **Canary（UNSW-IoTraffic、文言の上で食い違い）**：ヘルプ（2016-08-22）の「All communication between your Canary device, the Canary Cloud, and your smartphone is encrypted over TLS/SSL (HTTPS)」に対し、平文は中身のない接続確認（`h.canaryis.com:80` への HEAD 53 回、`ipv4.connman.net` への GET 3 回）だけ。「AES 256-bit」は 5,843 回のうち 5,834 回の握手で一致（AES-128 は 9 回）。
- **Ring Alarm Base Station（文言の上で食い違い）**：Ring のポートの記事（2021-10-24）は「HTTP (port 80) ( Note : Not applicable to Ring Alarm Base Station)」とするが、Base Station は `st.rings.solutions:80/online/check.html` に中身のない GET を送っていた（`ringbasestationPOWER_1.pcap` フレーム 50、64）。
- **弱い候補**：D-Link は、ファームウェアの確認が「設定のログとサービス」に入るかの読み方による。Triby は、airable が「unaffiliated」に当たるかと、MAC が「personal information you provide」に当たるかによる。どちらも判断待ち（[sweep-handoff.md](sweep-handoff.md) の 4）。
- YourThings の候補（Sonos、Withings Home、August、HomePod、TP-Link HS105・LB130、Wink Hub 2）は [results-yourthings.md](results-yourthings.md) と [known-reports.md](known-reports.md)。

## 文書に主張がないが、通信に問題があるもの

食い違いではないが、パッシブに見えた重い問題。

| 製品 | 観測 | 文書 |
|---|---|---|
| TP-Link NC220（UNSW 2016） | 遠隔での視聴のとき、映像（H.264）と音声（AAC）を平文の HTTP で TP-Link の中継（`aps1-relay.tplinkcloud.com:80/relayservice`）に送る（`16-09-28.pcap` フレーム 567700、567706、`16-09-30.pcap` フレーム 493448、493482） | FAQ は、ライブ映像が TP-Link のクラウドを通ると開示している。当時の文書に暗号化の主張はない（「encryption and SSL」の文は 2018-01 の版から） |
| Withings Aura、Baby Monitor、Smart Scale（UNSW） | MAC を認証の値として、セッション ID とともに平文の HTTP で送る | 当時の Withings の文書に暗号化の主張は見つからなかった |
| Amazon Echo 第 1 世代（UNSW） | 更新のパッケージ（`doppler-4172.ipk`、56,637,742 バイト）を HTTP で取得 | 更新の転送の保護についての記述なし |
| Belkin WeMo 4 製品、Lutron Caseta（YourThings）、Withings Smart Scale（UNSW） | ファームウェアを HTTP で取得（WeMo は `.bin.gpg`） | 更新の転送の保護についての記述なし |
| Nest Cam（CIC、2021） | 48 回の握手すべてで TLS 1.0 までしか提示しない（38 回で TLS 1.0 が選ばれた） | 「128-bit AES encryption with TLS/SSL」などの主張とは一致する。版についての主張はない |
| Samsung Smart Monitor M80B（Deakin） | Netflix のアプリが `nrdp52-appboot.netflix.com:80` に `NetflixId`、`nfvdid` のクッキーを平文の HTTP で送る（27 回）。サーバー証明書が SHA-1（Samsung Hubsite CA） | Samsung の文書に送信の具体的な主張はない。クッキーの値は quarant-results |
| Amazon Video のサーバー（YourThings の Samsung TV、CIC の Echo Spot、Deakin の Echo Show 8） | `api.amazonvideo.com` などのサーバーが、2018・2021・2023 年のどれでも、一部の握手で TLS 1.0 を選んだ | Amazon の「interactions are encrypted in transit」とは一致する（TLS 1.0 も暗号化）。版についての主張はない |
| Amcrest カメラ（CIC） | 公開のアドレスへの通信の 99% が、UDP の上の HTTP の形の P2P の制御（mDNS の名前を含む） | 暗号化の具体的な主張なし |

## 見えないもの

- 保存時の暗号化、クラウドの中での扱い、エンドツーエンドかどうか（Netatmo Welcome の「videos stay on the SD card」「end-to-end encrypted」など）。暗号化された通信の中身。
- 遠隔での映像の視聴が収録されていない製品（SimCam の「ライブ映像はサーバーを通さない」など）。

## 限界

- 機種が分からない製品（Amcrest、Globe、Gosund、Atomi、HeimVision、Insteon Camera、HP ENVY、iHome、SmartCam）は、共通の文書（プライバシーなど）だけで判定した。
- 文書の多くは米国版で、収録した国（カナダ、オーストラリア）の版は確かめていない。
- Deakin は、洗い出しのやり直し（2026-11-11、[sweep-results.md](sweep-results.md) の「Deakin のやり直し」）までサーバーからの応答が見えていなかった。判定はやり直したあとの観測による。
- 先行研究の区分は人がまだ確かめていない。
