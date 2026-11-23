# 4. Samsung（Hanwha）SmartCam SNH-V6410PN（Deakin、2023-07〜2024-05）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- ファームウェアの版：通信に平文で出ていない。**未確認**。CVE-2018-6295 の修正（2018 年 3 月以降の版）が入っているかは分からない。
- アプリの版、利用者の操作：Deakin の記録（`activeInteractions.csv`）では、2023-07-11 14:14〜14:25（現地時刻）に操作がある。中身は**未確認**。
- 取り直したのは 4 日（設定の日 2023-07-11、2023-07-26、07-31、2024-05-19）。Deakin の 1 日のファイルは UTC の 14:00 から翌 14:00。2023-07-11 のファイル（`IoT_` で始まる）は機器から出たパケットしか入っておらず、各パケットが 2 回ずつ入っている。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Samsung（Hanwha Techwin／Hanwha Vision）SmartCam SNH-V6410PN。mDNS の名乗り `SNH-V6410PN-SAMSUNG-SNH-V6410PN-00166CD7D5F9`、SSDP の `MiniUPnPd/1.7` |
| MAC・IP | 00:16:6c:d7:d5:f9、192.168.1.111 |
| シリアル番号 | ZDZ56V2K100594B（平文の要求の `serial`。前回の確認で mDNS の sn と同じ） |
| ファームウェア／アプリ | 未確認 |
| 収録日時（UTC） | 2023-07-11 04:13（設定の直後）〜 2024-05-19 13:59 のうち 7 日分のデータ |
| データセット | Deakin IoT Traffic Dataset（figshare 28013234）。オーストラリアの大学の実験室。Linux cooked の形式 |
| 観測できた通信フェーズ | 設定の直後、操作（視聴とみられる）、待機中の XMPP、12 時間おきの平文の通知、時刻合わせ、SSDP |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | プライバシーポリシー（2024-01-01 施行）第 9 条 | Hanwha Vision（wisenetlife.com/en-us/privacy） | [2024-02-21](https://web.archive.org/web/20240221104807/https://www.wisenetlife.com/en-us/privacy/) | 2024-05 の分に有効。2023 年の分には前の版（未確認） |
| B | SmartCam のプライバシーステートメント | Hanwha Techwin（samsungsmartcam.com） | [2021-04-19](https://web.archive.org/web/20210419195333/https://www.samsungsmartcam.com/web/cmm/privacy_policy.do) | 収録の約 2 年前。2023 年に有効だったかは未確認 |
| C | SNH-V6410PN の製品ページ（Specs のタブ） | Hanwha Vision（wisenetlife.com） | [2023-12-01](https://web.archive.org/web/20231201065137/https://www.wisenetlife.com/en-us/product/SmartCam/SNH-V6410PN_W/feature) | 収録中 |
| D | 同、仕様のページ（欧州） | Hanwha Vision | [2024-04-25](https://web.archive.org/web/20240425072937/https://www.wisenetlife.com/eu/product/SmartCam/SNH-V6410PN_W/specification/) | 収録中 |
| E | Cybersecurity のページ | Hanwha Vision（hanwhavision.com） | [2023-03-08](https://web.archive.org/web/20230308232401/https://www.hanwhavision.com/en/technology/cybersecurity/) | 収録前。業務用のカメラの会社の説明で、SmartCam に当てはまるかは未確認 |

- 文書 A：「In addition, we make sure that Personal Information can be safely transmitted over the network through encrypted communication.」第 1 条：「"Personal information" means information relating to a living individual, that identifies a particular individual …」。集める項目に「Service usage record, access IP address, access log, MAC address …」。
- 文書 B：「Technical information about your Products, including your Product’s model, serial number and software version …」「We use industry-standard methods to keep this information safe and secure while it is transmitted from your devices, over your home network and through the Internet to our servers.」
- 文書 C：「Security SSL (AES 256bit)」。文書 D：「HTTPS (SSL) Login Authentication, Digest Login Authentication」。
- 文書 E：「Video footage captured by all cameras is encrypted during the entire process of data transfer, storage and backup.」

**最も限定的な読み方**：A は「Personal Information」（個人を特定する情報）だけが対象。C は「SSL と AES-256 を使う」で、すべての通信とは書いていない。B の「industry-standard methods」は方法を書いていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| K1 | 12 時間おきの通知 | `POST http://www.samsungsmartcam.com/web/event.stw` を平文で（取り直した 7 日で 8 回）。本文は `&username=&serial=ZDZ56V2K100594B&msg=&time=May-18-2024 13:14:09&type=l` | 「Personal Information can be safely transmitted … through encrypted communication」 | 公式文書に記載なし | `2024-05-19.pcap` 2024-05-18 18:14:10.550308、`IoT_2023-07-11.pcap` 2023-07-11 04:13:54.637904、`2023-07-26.pcap`（前回、元のフレーム 278764） | 文書 A | 高 | シリアル番号と時刻は、個人を特定する情報とは言い切れない（最も限定的な読み方）。同じポリシーが集める項目に「access log」を挙げているので、これに当たると広く読めば矛盾 |
| K2 | 同上 | 同上 | 「We use industry-standard methods to keep this information safe and secure while it is transmitted」（「this information」はシリアル番号を含む） | 判断不能 | 同上 | 文書 B | — | 方法を書かない約束。文書が 2023 年に有効だったかも未確認 |
| K3 | 待機中・操作中の XMPP | `xmpp.samsungsmartcam.com` などの 5222 番へ、STARTTLS のあと TLS 1.2。サーバーが選んだのは `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`（握手が見えた分）。証明書は `xmpp.samsungsmartcam.com`（DigiCert、2023-02-10〜2024-03-12、名前は一致）。設定の日は 11.9 MB をこの TLS で送った（映像とみられる、推測） | 「Security SSL (AES 256bit)」 | 一致 | `2023-07-31.pcap` 2023-07-30 15:59:05.065586（ClientHello）、`IoT_2023-07-11.pcap` 2023-07-11 04:13:34.402896（STARTTLS のあとの記録） | 文書 C | 高 | |
| K4 | HTTPS | `media.samsungsmartcam.com:443` は TLS 1.2、`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`（Amazon RSA 2048 M02、名前は一致） | 「Security SSL (AES 256bit)」 | 公式文書に記載なし | `2023-07-31.pcap` 2023-07-30 15:59:07.069315 | 文書 C | 高 | すべての通信を AES-256 にするとは書いていない。詳しくは [15](15-samsung-https-aes.md) |
| K5 | 映像 | 設定の日の操作の時間帯（04:14〜04:25 UTC）に、XMPP の TLS で 11.9 MB の上り。平文の映像は見えない | 「Video footage captured by all cameras is encrypted during the entire process of data transfer」 | 一致（参考） | `IoT_2023-07-11.pcap` 2023-07-11 04:13:33〜04:25 | 文書 E | 低 | 文書 E が SmartCam に当てはまるかは未確認 |
| K6 | P2P の試み | 139.132.188.38（Deakin のアドレス）の多数のポートへ STUN | 記載なし | 公式文書に記載なし | `IoT_2023-07-11.pcap` 2023-07-11 04:14:20.297037 ほか | — | 中 | スマートフォンとの直接接続の試みとみられる（推測） |
| K7 | 暗号の提示 | HTTPS の ClientHello で 65〜78 種を出し、RC4、3DES を含む | 記載なし | 公式文書に記載なし | `IoT_2023-07-11.pcap` 2023-07-11 04:13:36.550492 | — | 高 | 選ばれたのは AES-GCM |
| K8 | LAN | SSDP の NOTIFY を大量に（2 日で約 5 万回）、mDNS | 記載なし | 公式文書に記載なし | 全期間 | — | 高 | |
| K9 | ログイン | — | 「HTTPS (SSL) Login Authentication, Digest Login Authentication」 | 観測不能 | アプリや機器のウェブの画面へのログインは収録にない | 文書 D | — | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- K1：シリアル番号とイベントの時刻を、12 時間おきに平文の HTTP で送っている。2018 年に「Unencrypted way of remote control and communications」（CVE-2018-6295）が「Resolved」とされた後も続いている（[report-2026-11-15.md](../report-2026-11-15.md) の D）。
- K4、K6〜K8。

## 4. 公式文書と一致した事項

- K3（XMPP は AES-256）、K5（参考）。

## 5. 観測不能・判断不能な事項

- K2（評価の言葉）、K9。

## 6. 追加調査に必要なデータ

- ファームウェアの版（アプリの表示）。
- 2023 年に有効だった Hanwha のプライバシーポリシー（文書 A の前の版）。
- ほかの日（Deakin は約 240 日ある）。

## 断定できる範囲／できない範囲

- **断定できる**：シリアル番号つきの通知が平文の HTTP だったこと。XMPP は TLS 1.2 で AES-256 だったこと。
- **断定できない**：シリアル番号とイベントの時刻が、ポリシーの言う個人情報に当たるか。

## 前回との違い

- 前回は「食い違いの候補（T1a、T2）」。新しい決まり（最も限定的な読み方）で、K1 は「公式文書に記載なし」、AES-256 は XMPP で使われているので K3 は「一致」にした。
