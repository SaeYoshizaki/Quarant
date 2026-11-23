# 24. Google Nest Cam（第 1 世代、Nest Cam Indoor）

[一覧に戻る](README.md)

Passive-Mode-Study（フランス、2023-24）は今回パケットを取り直して調べた。CIC IoT 2022（カナダ、2021）は取り直していない（利用者の判断、前回の記録だけ）。

## 不足している情報（分析の前に）

- ファームウェアの版：通信に平文で出ていない（TLS 1.0 の ClientHello に SNI もない）。**未確認**。
- ハードウェアの版：Passive-Mode-Study の著者の文書集では「Nest Cam (1st gen)」。機器自身が名乗った型番は見えない（DHCP の vendor class は `udhcp 1.19.3` だけ）。
- Nest Aware の契約の有無、利用者の操作：**未確認**。

## 調査対象と前提条件

| 項目 | Passive-Mode-Study（今回取り直し） | CIC IoT 2022（前回の記録） |
|---|---|---|
| 製品名・型番 | Nest Cam（第 1 世代）。著者の機器一覧の名前。型番は通信からは未確認 | Nest Cam（CIC の機器一覧の名前） |
| MAC・IP | 64:16:66:4a:65:71、192.168.231.120 | 44:bb:3b:00:39:07 |
| ファームウェア／アプリ | 未確認 | 未確認 |
| 収録日時（UTC） | FR-Capture1：2023-11-24〜11-27、FR-Capture2：2024-05-03〜05-07（機器の通信は 9 日） | 2021-10〜12 |
| 観測できた通信フェーズ | 待機中のクラウド接続、時刻合わせ、名前解決、ルーターへの HTTP の確認、DHCP。視聴・録画の操作は不明 | 待機と操作 |

**使用した公式文書**

| # | 文書 | 発行元 | 公開・更新 | 保存 | 収録との関係 |
|---|---|---|---|---|---|
| A | Technical specs for Google Nest cameras and doorbells（「Nest Cam Indoor」の Security の行） | Google（support.google.com/googlenest/answer/9259110） | 不明 | [2023-09-23](https://web.archive.org/web/20230923191613/https://support.google.com/googlenest/answer/9259110?hl=en) | FR-Capture1 の 2 か月前 |
| B | Google Nest のヘルプ（product-documentation 9293126） | Google | 不明 | [2023-12-06](https://web.archive.org/web/20231206175846/https://support.google.com/product-documentation/answer/9293126?hl=en&ref_topic=9361783&visit_id=638374823259407367-425612080&rd=1) | FR-Capture1 の 9 日後、FR-Capture2 の前 |
| C | Google Nest Security & Privacy（safety.google/nest） | Google | 不明 | [2023-11-23](https://web.archive.org/web/20231123055447/https://safety.google/nest/) | FR-Capture1 の前日 |
| D | CIC の分：Google Store の仕様（カナダ）「128-bit AES encryption with TLS/SSL」 | Google | 不明 | [2021-10-20](https://web.archive.org/web/20211020173952/https://store.google.com/ca/product/nest_cam_indoor_specs?hl=en-CA&GoogleNest) | CIC の収録中 |

- 文書 A：「Security: 128-bit AES with TLS/SSL」（Nest Cam Indoor の節）
- 文書 B：「Data sent from Nest products, including personal data, is fully encrypted using the state-of-the-art security tools.」「We don’t transmit unencrypted personal data from your Nest products over the Internet.」
- 文書 C：通信の暗号化について具体的な文はない（アカウントの保護、脆弱性の報奨金など）。

**最も限定的な読み方**：A は「TLS/SSL を使い、暗号は 128 ビットの AES」。TLS の版は書いていない。B の「state-of-the-art」は評価の言葉で、具体的な版や方式を約束していない。B の「Data … including personal data」は利用者のデータを指し、時刻合わせや名前解決の問い合わせまで含むとは読まない。

## 比較結果（Passive-Mode-Study）

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| N1 | 待機中のクラウド接続 | `nexus.dropcam.com`、`nexus-eu1.dropcam.com`、`oculus395-eu1.dropcam.com` の 443 番へ TLS（121 接続）。カメラは TLS 1.0 までしか出さず、提示する暗号は 3 種。選ばれたのは `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`（121 回すべて） | 「128-bit AES with TLS/SSL」 | 一致 | `FR-Capture1.pcap` 2023-11-24 15:43:14.303170（最初の ClientHello） | 文書 A | 高 | 128 ビットの AES、TLS とも一致。前方秘匿性（ECDHE）もある |
| N2 | 同上 | TLS の版は 1.0 だけ（RFC 8996、2021 年に廃止） | 「fully encrypted using the state-of-the-art security tools」 | 一致 | 同上 | 文書 B | 中 | 暗号化はされている。「state-of-the-art」を TLS 1.2 以上と読むのは拡大解釈になるので、とらない |
| N3 | 証明書 | サーバー証明書は `oculusNNNN-us1.dropcam.com` など（発行者 `Dropcam Certificate Authority`、自社の認証局、2001-01-01〜2050-01-01、RSA 2048、SHA-256）。カメラも自分の証明書（主体は 32 桁の 16 進、発行者は同じ認証局、SHA-1 署名）を出す相互認証。ClientHello に SNI はない | 記載なし | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-24 15:43:14 以降 | 該当なし | 高 | 自社の認証局なので、証明書の検証のふるまいはパッシブには分からない |
| N4 | 時刻合わせ | `pool.ntp.org` へ平文の NTP（35 回以上、9 日） | 記載なし（限定的な読み方で「データ」に入れない） | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-24 15:43:14.221389 | 文書 B | 高 | |
| N5 | 名前解決 | DNS は平文。ルーターのほか、Google の 8.8.8.8、8.8.4.4 にも問い合わせる（46 回） | 記載なし | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-24 15:43:14.125457 ほか | 該当なし | 高 | ルーターを使わない名前解決（フォールバックとみられる、推測） |
| N6 | LAN の確認 | ルーター（192.168.231.1）の 80 番へ `GET /` を 119 回（6 日） | 記載なし | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-24 15:43:14.839554 | 該当なし | 高 | 目的は未確認 |
| N7 | 平文の個人のデータ | インターネットへの平文は NTP と DNS だけ | 「We don’t transmit unencrypted personal data … over the Internet.」 | 一致 | 上の全期間 | 文書 B | 高 | |
| N8 | 映像の送信 | 4.1 MB 上り（`oculus395-eu1`）など。中身は暗号化されていて見えない | 文書 C の「video footage」の扱い | 観測不能 | | 文書 C | — | |
| N9 | 切断 | サーバーからの TCP のリセット 116 接続、サーバーからの TLS の警告（user_canceled）2 回 | 記載なし | 公式文書に記載なし | `FR-Capture1.pcap`、`FR-Capture2.pcap` | 該当なし | 中 | |

## CIC IoT 2022 の分（前回の記録、今回は取り直していない）

| ID | 観測（前回） | 文書 | 判定 | 確信度 |
|---|---|---|---|---|
| C1 | 48 回の握手すべてでカメラは TLS 1.0 まで。38 回で TLS 1.0 と `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` | 文書 D「128-bit AES encryption with TLS/SSL」（2021-10-20、収録中） | 一致 | 中（取り直していない） |
| C2 | 同上 | 「Data sent from Nest products … fully encrypted using the state-of-the-art security tools.」（[2022-01-31](https://web.archive.org/web/20220131070838/https://support.google.com/product-documentation/answer/9293126?hl=en&ref_topic=10123615)、収録後） | 判断不能（文書が収録後。限定的な読み方なら一致） | 低 |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- N3（自社の認証局、相互認証、SNI なし）、N4（平文の NTP）、N5（Google の DNS への問い合わせ）、N6（ルーターへの HTTP）、N9。

## 4. 公式文書と一致した事項

- N1（128 ビットの AES と TLS）、N2（暗号化はされている）、N7（インターネットへの平文に個人のデータは見えない）。

## 5. 観測不能・判断不能な事項

- N8（映像の扱い）、C2（収録後の文書）。

## 6. 追加調査に必要なデータ

- ファームウェアの版（アプリの表示）。
- 収録の時点の、TLS の版を書いた Google の文書（見つからなかった）。

## 断定できる範囲／できない範囲

- **断定できる**：カメラは TLS 1.0 だけを使い、選ばれる暗号は ECDHE と AES-128-CBC だった。インターネットへの平文は NTP と DNS だけだった。
- **断定できない**：TLS 1.0 が文書の「state-of-the-art」に反するか（評価の言葉で、具体的な約束がない）。

## 前回との違い

- 前回（判断待ち B1）は「文言の上での食い違い（T1b）に変える」をおすすめにしていた。今回の決まり（最も限定的な読み方、評価だけでは食い違いにしない）では「一致」になる。
- 収録前の仕様ページ（文書 A、2023-09-23）を新しく見つけた。
