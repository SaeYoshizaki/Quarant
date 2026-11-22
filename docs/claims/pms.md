# Passive-Mode-Study（PerCom 2025）：公式文書と通信（2026-11-22）

8 つ目のデータセットとして、Passive-Mode-Study の PCAP を洗い出し、強い観測について製造者の文書と比べた。機器は「受け身のモード」（使っていない状態）に置かれ、操作は一度もない。そのため、映像の視聴や音声操作のときの通信はない。

## データ

- **出典**：C. Badolato, K. Kullman, N. Papadakis, M. Bhatt, G. Bouloukakis, D. Engel, R. Yus, "Your Smart Home Exchanged 3M Messages: Defining and Analyzing Smart Device Passive Mode", IEEE PerCom 2025, pp.47-56, doi:10.1109/PerCom64205.2025.00024（[PDF](https://damslabumbc.github.io/uploads/PassiveModeNTAPerCom2025.pdf)）。コードと集計：https://github.com/DAMSlabUMBC/Passive-Mode-Study（コミット c542e8a、2026-11-14）。PCAP は同じリポジトリの `datasets.csv` にある Google Drive。
- **取得**：2026-11-22。`Percom116Dataset.zip`（13.1 GB、展開して 18.5 GB）、`ExtendedPaperDataset.zip`（144 MB）、`PrivacyPolicyDataset.zip`（267 MB。著者が集めた 26 機器の文書）。置き場所は `~/datasets/raw/passive-mode-2025/`。
- **収録**：OpenWrt 23.05 のルーターで tcpdump（論文 §IV-B）。パケットの長さの上限なし（中身まで入っている）。

| 収録 | 期間（UTC） | 機器 |
|---|---|---|
| US2-Capture-Headsets | 2023-10-19 21:00〜10-27 09:59 | Magic Leap 1、HoloLens 2、Meta Quest 1・2 |
| US1-Capture1 | 2023-11-01 23:00〜11-08 22:59 | Hue Bridge、TP-Link HS110、Echo Dot 5、Govee のケトル、Litokam、Netvue、Amazon の電球 |
| US2-Capture-RoboRock | 2023-11-02 16:00〜11-16 14:59 | Roborock S7 |
| FR-Capture1 | 2023-11-24 15:00〜11-27 13:59 | フランスの 11 台 |
| US1-Capture2 | 2024-05-01 20:00〜05-09 22:59 | US1 の 10 台（Meta Quest Pro、DreamGlass Air、Nest Mini を足す） |
| FR-Capture2 | 2024-05-03 17:00〜05-07 12:59 | フランスの 12 台（Hue Bridge を足す） |
| US1-CaptureHome（補助） | 2024-09-11 07:00〜09-16 02:59 | US1 の 10 台 |
| Extended：Idle / Aligned Passive | 2024-01-30〜02-01 / 2024-05-06〜05-09 | US1 の 7 台（機能を有効にした待機と、それにそろえた受け身） |

- **機器と MAC**：各収録の `devices.txt`。[devices.tsv](devices.tsv) に `pms` として 29 行を足した。機種は、著者の文書集の README（D01〜D26）と、機器が LAN で名乗った値（`lan_models.py`、`~/datasets/claims/sweep-v2/lan-models-pms.tsv`）で確かめた：DHCP のホスト名 HS110（TP-Link 3 台）、LB120、DCS-8300LH、Google-Home、Google-Nest-Mini、UPnP の BSB002（Hue Bridge 2 台）と SONY KD-43XH8096、mDNS の model=HoloLens 2。ほかに、DreamGlass Air の DHCP のホスト名は `android-37c8fc544d09111c`（SDK に送っていた Android ID と同じ）、Nest Thermostat のホスト名はシリアル番号の形（`09AA01AC4519022J`）。
- **利用条件**：リポジトリの GPL v3 はコードのもの。データのライセンスは書いていない（未確認）。CITATION.cff で引用を求めている。

## 洗い出し

STARTTLS に対応した `expose.py` で読み（`~/datasets/claims/sweep-v2/pms/`）、`report.py` で製品ごとにまとめた（`~/datasets/claims/sweep-v2/report-pms/`）。下の観測は、どれも tshark で根拠のフレームを開いて確かめた。認証情報の値は quarant-results の `claims/sweep-credentials.md`。

## 観測と判定

| 製品 | 観測（根拠） | 文書 | 判定 | 先に報告した資料 |
|---|---|---|---|---|
| GoveeLife Smart Electric Kettle H7171 | 平文の HTTP で `app.govee.com` に、MAC を含む機器 ID `19:BE:60:74:F4:1B:24:16`、型番 H7171、版、タイムゾーン（America/New_York）を送る（`US1-Capture1.pcap` フレーム 43616 `/device/rest/devices/v1/wifiCheckVersion`、43627 `/bff-device/v1/config/gateway/group`。各 43 回）。**ファームウェアを平文の HTTP で取得**（フレーム 1520664、2023-11-07 06:43:21 UTC、`http://s3.amazonaws.com/govee-public/upgrade-pack/…-H7171_WIFI_BLE_HW1.02.00_SW1.00.10_OTA.bin`、852,100 バイト）。その 4 分後から版が 1.00.07 から 1.00.10 に変わった（フレーム 1522818） | Govee Home のプライバシーポリシー（[Wayback 2023-12-07](https://web.archive.org/web/20231207113053/https://app-h5.govee.com/common/privacy)、収録の期間中）：「We will use state-of-the-art data security tools to secure your data security and protect Govee Home products from unauthorized access.」。MAC などは「encrypted and saved to the server」（保存の話） | 文言の上で食い違い（弱い）。方法を書かない約束で、比べられるのは「最新のセキュリティの道具」という言葉だけ。HTTPS で暗号化するという文は 2026 年の EU の文書（収録の後）にしかない | ブログ等のみ（同じメーカーの別の機種）。Include Security のブログ（krisinclude, "Replacing a Space Heater Firmware Over WiFi", 2025-02-04, https://blog.includesecurity.com/2025/02/replacing-a-space-heater-firmware-over-wifi/ ）が、電気ヒーター H7135 で同じ `wifiCheckVersion` と `govee-public/upgrade-pack` の平文の取得を示し、改造したファームウェアを書き込めたとする。ケトルと文書との比較はない |
| DreamGlass Air（Dreamworldvision） | 画面ミラーリングの SDK（hpplay）に、平文の HTTP で MAC `C0847D2E9C86`、シリアル番号 `DW0045202800256`、Android ID `37c8fc544d09111c`、CPU ID `15fb9f55baf3bc34`、機種 `rk3399-dreamworld_glass_air` を送る（`US1-CaptureHome.pcap` フレーム 157021、2024-09-11 16:11:15 UTC、`sdkauth.hpplay.cn`、1.14.243.73。合わせて 10 回）。ほかに `rp.hpplay.cn/scandev`（116 回）、`imdns.hpplay.cn`、Tencent のクラッシュ報告 `android.bugly.qq.com`（セッション ID つき）。US2（2023-10）では `dw.xiongning.online` に `mac` と `sn` のヘッダー（フレーム 7596865）。送信の 46% が平文 | 製造者のサイトのポリシー（[Wayback 2023-03-30](https://web.archive.org/web/20230330151718/https://www.dreamworldvision.com/pages/privacy-policy)）は Shopify の通販だけが対象。著者の文書集の 2024 年版も同じ（OCR で確認） | 文書なし（機器の文書が見つからない）。重い問題として残す | 見つからず（検索語：hpplay.cn Lebo SDK MAC serial plaintext） |
| Netvue Orb Mini | **ルーターに UPnP でポート転送を作らせた**：外の TCP 38232 をカメラの TCP 5555 へ、期限なし、説明 `nvc_7236532252900787_tcp_5555`（`US1-Capture2.pcap` フレーム 3125211、2024-05-05 22:47:36 UTC、ルーターの応答 200 OK はフレーム 3125213）。収録中に外から 5555 への接続はなかった。ほかに、ルーターのポート転送の一覧を 23,387 回問い合わせ（GetGenericPortMappingEntry）、US1-Capture1 では Hue Bridge（192.168.1.106）の UPnP の説明を 57,570 回取得、US1-Home では外側のアドレスを 13,243 回問い合わせ。インターネットへの平文は `checkip.amazonaws.com` の GET、DNS、UDP 9700 のサーバー割り当て（32 桁の値と `GLOBAL`、例 フレーム 3532279、54.223.118.211） | 利用規約（[Wayback 2023-04-06](https://web.archive.org/web/20230406151940/https://resource.netvue.com/legacy/en/agreement.html)）：「Only the data you need to use will be transmitted and all data are encrypted during the transmission.」。[2024-02-21](https://web.archive.org/web/20240221092609/https://resource.netvue.com/legacy/en/agreement.html) の版ではこの文が消えた | 暗号化：一致（見えた範囲で。2023-11 の収録の時点の版は未確認）。ポート転送：文書に主張なし。重い問題として残す | 見つからず（検索語：Netvue camera UPnP port forwarding） |
| Roborock S7 | 操作と状態の MQTT（`mqtt-us.roborock.com`）の 8 回の接続で、掃除機が **TLS 1.0 までしか出さず**、RC4、DES、3DES、MD5 も出す（`US2-Capture-RoboRock.pcap` フレーム 34166）。サーバーは TLS 1.0、TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA を選んだ（フレーム 34168）。`api-us.roborock.com` と Xiaomi の保存先は TLS 1.2 | プライバシーポリシー（[US 2023-11-02](https://web.archive.org/web/20231102104621/https://us.roborock.com/pages/privacy-policy)、[global 2023-11-24](https://web.archive.org/web/20231124040955/https://global.roborock.com/pages/privacy-policy)）に通信の暗号化の文はない。「the use of the Internet is not entirely secure」 | 文書に主張なし。重い問題として残す | 見つからず（Giese の修士論文は古い機種で、本文は読んでいない。未確認） |
| Philips Hue Bridge（US1・FR） | `diagnostics.meethue.com:80` に `sso`、`auth`、`i` を平文で送る（US1 `US1-Capture2.pcap` フレーム 192109、FR `FR-Capture2.pcap` フレーム 574436）。**`sso` は US1 とフランスの別の個体で同じ値**。TLS は 1.2・1.3 で、TLS 1.0 が 1 回（US1-Capture2 フレーム 745789） | CIC で候補にした FAQ の文（「Hue only connects to the internet securely via a dedicated cloud …」、2021-12-22）は、同じページの [2023-11-27 の版](https://web.archive.org/web/20231127215728/https://www.philips-hue.com/en-us/support/faq/hardware-and-connectivity) にない。保存された本文はナビゲーションだけで、FAQ の中身が読み込まれていない可能性がある（未確認） | 未（収録の時期の文書が読めない） | 論文で一部（Mandalari ほか、PoPETs 2021。CIC と同じ） |
| Sony BRAVIA KD-43XH8096 | Netflix のアプリが `nrdp70-appboot.netflix.com:80` に `NetflixId` と `nfvdid` のクッキーを平文で送る（`FR-Capture1.pcap` フレーム 458346 ほか 8 回）。Deakin の Samsung M80B と同じ形 | 著者の文書集の Sony の 2022 年の文書に、通信の暗号化の文はない（収録の時期の版は未） | 文書に主張なし（未確認） | Deakin の M80B と同じ（見つからず） |
| D-Link DCS-8300LH | CA の証明書の束を平文の HTTP で確認（`HEAD http://ca-mgr.auto.mydlink.com/default/ca-bundle.crt`、`FR-Capture1.pcap` フレーム 42843）。取得（GET）はなかった。`mp-eu-sas-1.auto.mydlink.com/relay` への GET が 3 回（フレーム 3204027） | 著者の文書集の 2024 年のプライバシーポリシーに「The SSL protocol is also implemented for (i) guarding your account …」（CIC の DCH-S161 と同じ文。収録の時期の版は未） | 弱い候補（CIC と同じ読み方の問題） | 未 |
| Google Nest Cam（第 1 世代） | 122 回の握手で、カメラは TLS 1.0 までしか出さない（`FR-Capture1.pcap` フレーム 45606） | CIC と同じ文書（版の主張なし） | 一致（CIC と同じ判定） | — |
| Maxcio Smart Power Strip、Litokam | Maxcio は Tuya の TLS-PSK（前方秘匿性なし）、Litokam は TLS だけ | Tuya の共通の文面（「transmission encryption protocols」） | 一致 | — |
| Amazon Echo Dot 5（US1）、Echo Dot 3・Echo Show 5（FR） | TLS が 98.5〜99.7%（TLS 1.2・1.3）。平文は接続確認（`HTTPConnTest.txt`、`generate_204`）、証明書の失効の情報、Echo Dot 3 の `web.diagnostic.networking.aws.dev` への POST（本文 284 バイトはランダムに見えるバイナリで読めない、`FR-Capture1.pcap` フレーム 4103）。3DES を出す握手がある（選ばれてはいない） | プライバシー：米国「We work to protect the security of your personal information during transmission by using encryption protocols and software.」（[2023-08-01](https://web.archive.org/web/20230801190640/https://www.amazon.com/gp/help/customer/display.html?nodeId=468496&ref_=footer_privacy)）、フランス「Nous protégeons la sécurité de vos informations personnelles lors de leur transmission en utilisant des protocoles de cryptage et des logiciels.」（[2023-11-28](https://web.archive.org/web/20231128070120/https://www.amazon.fr/gp/help/customer/display.html?nodeId=201909010)） | 一致（見えた範囲で） | — |
| TP-Link HS110（US1・FR）、LB120（FR） | 公開のアドレスへは TLS 1.2 だけ（ECDHE、AES-128-GCM）。HS110 は export、DES、3DES、MD5 の暗号も出す。LAN では tplink-smarthome（9999） | プライバシー：「We have implemented measures, including encryption and TLS technology, designed to secure your personal data …」（米国 [2023-10-13](https://web.archive.org/web/20231013154156/https://www.tp-link.com/us/about-us/privacy/)、フランス語 [2024-05-16](https://web.archive.org/web/20240516092352/https://www.tp-link.com/fr/about-us/privacy/)） | 一致（見えた範囲で）。LAN の 9999 の通信（論文は位置情報が入ると書く）は、ここでは確かめていない | — |
| Google Nest Mini（US1・FR）、Nest Learning Thermostat、Nest Cam（第 1 世代）、Google Home（FR） | 平文は接続確認（`generate_204`。US1 の Nest Mini は 1 週間で 35,713 回）と、フランスの Nest Mini の `clientservices.googleapis.com/uma/v2` への POST 29 回（本文は読めない、フレーム 42707）だけ。Nest Cam は TLS 1.0 だけ | Nest のヘルプ「We don’t transmit unencrypted personal data from your Nest products over the Internet.」「… fully encrypted using the state-of-the-art security tools.」（[2023-12-06](https://web.archive.org/web/20231206175846/https://support.google.com/product-documentation/answer/9293126?hl=en&ref_topic=9361783&visit_id=638374823259407367-425612080&rd=1)、[2024-05-29](https://web.archive.org/web/20240529181046/https://support.google.com/product-documentation/answer/9293126?hl=en&ref_topic=10123615)）。Google Home はプライバシーポリシー（フランス語 [2023-11-01](https://web.archive.org/web/20231101021146/https://policies.google.com/privacy?hl=fr)） | 一致（見えた範囲で）。Nest Cam の TLS 1.0 と「state-of-the-art」は、CIC と同じ読み方の判断待ち | — |
| Microsoft HoloLens 2 | Windows Update の配信（`*.dl.delivery.mp.microsoft.com`）を平文の HTTP で取得（送信の 31.6%） | 未（Microsoft は配信の中身をハッシュで確かめると説明している。未確認） | 未 | — |

## 先行研究との関係

- 元の論文は、通信の量、プロトコルの種類、TLS を使った割合（WAN 90%、LAN 3.9%）、送り先の種類を扱う。TLS の版と暗号、平文の中身、製造者のセキュリティの主張との比較はない。ポリシーについては「no policy for any tested device contained information regarding periods during which devices captured data」（§VI）とだけ書く。
- 論文が書く平文の例（TP-Link のプラグの LAN の位置情報、Google Home の YouTube への平文）は、こちらでは扱っていない。
- 著者の文書集（2026-11-13 公開）は、データの集め方と「Privacy Mode」「Sleep Mode」についての説明を集めたもの（README）。これを使う拡張版の論文は見つからなかった（未確認）。

## 未と限界

- 文書を集めたのは Govee、Dreamworldvision、Netvue、Roborock、Amazon、TP-Link、Google（2026-11-22）。Meta、Microsoft、Magic Leap、Sony、D-Link、Philips の 2023〜24 年の版は未。
- 年ごとの表（[longitudinal.md](longitudinal.md)）に、Hue Bridge、Echo Dot 3、Nest Mini、Google Home、Nest Cam、サーモスタット、TP-Link のプラグと電球の 13 行を加えた。
- 受け身のモードだけなので、映像・音声を送る主張（エンドツーエンドなど）は見えない。
- 「プライバシーモードでは送らない」といったモードの主張は、まだ比べていない。拡張版の idle と aligned passive の量の比べ合わせが材料になる。
