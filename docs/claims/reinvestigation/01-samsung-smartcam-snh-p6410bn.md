# 1. Samsung（Hanwha）SmartCam SNH-P6410BN（UNSW 2018）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- **ファームウェアの版**：通信に平文で出ていない（UPnP の説明にも版の欄がない）。**未確認**。Hanwha が「2018 年 3 月以降の更新で修正」とした問題（下の文書 C）に当てはまるかを決める条件になる。
- **「Image encrypting」の設定**（映像を暗号化する任意の設定）がオンかオフか：**未確認**（説明書の画面の写真ではオフ）。
- 視聴者（129.94.5.83）が誰か、大学の外の通信だったか：**未確認**。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Samsung SmartCam SNH-P6410BN（UPnP の `modelName`・`modelNumber`、mDNS `SAMSUNG-SNH-P6410BN-00166CAB6B88`） |
| MAC・IP・シリアル | 00:16:6c:ab:6b:88、192.168.1.248、`KHNL6V2H20003LX`（UPnP） |
| ファームウェア／アプリ | 未確認 |
| 収録日時（UTC） | 2018-05-28〜2018-10-29（UNSW 2018 の正常な日の 27 のファイル、通信は 29 の日付） |
| データセット | UNSW IoT Benign and Attack Traces の正常な日（Hamza ほか、ACM SOSR 2019） |
| 観測できた通信フェーズ | クラウドとの常時接続（XMPP）、通知の HTTPS、外の視聴者へのライブ映像、STUN、時刻合わせ、SSDP |

**使用した公式文書**

| # | 文書 | 発行元 | 公開・作成 | 保存 | 収録との関係 |
|---|---|---|---|---|---|
| A | SNH-P6410BN のデータシート（仕様の表、Security の行） | Samsung Techwin | PDF の作成 2014-02-28 | [2016-06-23](https://web.archive.org/web/20160623235657/https://www.samsung-security.com/SAMSUNG/upload/Product_Specifications/SNH-P6410BN_Datasheet.pdf) | 収録前 |
| B | ユーザーマニュアル Web-1113（p.22 Image encrypting、p.33 仕様） | Samsung Techwin | PDF の作成 2015-11-13 | [2024-06-27](https://web.archive.org/web/20240627133604/https://www.wisenetlife.com/fileDownload.do?fileName=1491228809600.pdf&filePath=UPLOAD_MFGD_ATTRBT_PATH&downLoadName=User%20Manual-SNH-P6410BN-ENGLISH_Web-1113.pdf) | 作成は収録前、保存は後（2016〜17 年のサポートページが同じファイル名にリンク） |
| C | 脆弱性の報告（CVE-2018-6295 など） | Hanwha Techwin | 2018-03-21（ファイル名の時刻） | [2021-08-03](https://web.archive.org/web/20210803235506/https://www.hanwha-security.com/data/tutorial/attrbt/1521604298202.pdf) | 公開は収録前、保存は後 |

- 文書 A：「Security SSL ( AES 256bit )」
- 文書 B p.22：「Image encrypting … This encrypts the image transmitted. … The image encryption function may affect the image transmission」
- 文書 C p.1：「Unencrypted way of remote control and communications … in Hanwha Techwin Smartcams」を「Resolved」とし、注に「fixed in the firmware updates released from March」。対象は「All Hanwha Techwin SmartCams」。

**最も限定的な読み方**：文書 A は「SSL と AES-256 を使う」で、映像を暗号化するとは書いていない。文書 B の映像の暗号化は、利用者が入れる任意の設定。文書 C は、2018 年 3 月以降のファームウェアで暗号化されない遠隔の通信を直したと言っている。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| C1 | 外の視聴者へのライブ映像 | 外のアドレス 129.94.5.83 からカメラの tcp/40000 への接続 21 回（2018-05-28 に 20 回、05-31 に 1 回）。どれも STUN のあと RTP（RFC 4571 の枠）で、H.264 の映像（PT 97。SPS・PPS が読め、禁止ビットはすべて 0）と G.711 μ-law の音声（PT 0）が暗号化されていない | 「Unencrypted way of remote control and communications … Resolved … fixed in the firmware updates released from March」 | 条件付きの矛盾 | `18-05-28.pcap` 2018-05-28 15:43:35.481961（129.94.5.83:48041、映像のフレーム 3,787、前回は絵と音を再生できた）ほか 20 回、`18-05-31.pcap` 2018-05-31 04:06:16.412043 | 文書 C | 高（観測）／中（条件） | 条件：カメラが 2018 年 3 月以降のファームウェアだったこと（版は未確認）。そうなら「解決した」とする遠隔の暗号化されない通信が 5 月にも続いていたことになる |
| C2 | 同上 | 同上 | 「Image encrypting … This encrypts the image transmitted.」 | 条件付きの矛盾 | 同上 | 文書 B p.22 | 中 | 条件：利用者が Image encrypting をオンにしていたこと（説明書の写真の初期値はオフで、オフなら矛盾しない） |
| C3 | 同上 | 同上 | 「Security SSL ( AES 256bit )」 | 公式文書に記載なし | 同上 | 文書 A | 高 | 仕様の行は映像の暗号化を約束していない（最も限定的な読み方） |
| C4 | クラウドとの常時接続 | `xmpp.samsungsmartcam.com` の 5222 番へ STARTTLS のあと TLS（43 接続）。サーバーが選んだのは `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`（TLS 1.0、握手が見えた 22 回）。証明書は `xmpp.samsungsmartcam.com`（Symantec Class 3 Secure Server CA - G4、2017-11-07〜2020-01-06、名前は一致） | 「Security SSL ( AES 256bit )」 | 一致 | `18-05-28.pcap` 2018-05-28 05:59:57.988401 | 文書 A | 高 | |
| C5 | HTTPS | `media.samsungsmartcam.com:443` へ TLS 1.0、`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`（22 回） | 「Security SSL ( AES 256bit )」 | 公式文書に記載なし | `18-05-28.pcap` 2018-05-28 05:59:59.718393 | 文書 A | 高 | [15](15-samsung-https-aes.md) を参照 |
| C6 | XMPP の再接続 | 2018-05-30 に、STARTTLS の前の `<stream:stream to="xmpp.samsungsmartcam.com" …>` だけを約 32 秒おきに送る接続が 32 回（認証などは送っていない） | 記載なし | 公式文書に記載なし | `18-05-30.pcap` 2018-05-30 08:59:47.036697 ほか | — | 高 | サーバーが応答しなかった時間帯の再試行とみられる（推測） |
| C7 | 外からの接続 | 見知らぬ外のアドレス（46.148.19.59、77.72.83.235、185.153.197.202 など）から tcp/40000 への接続が 9 回（中身なし） | 記載なし | 公式文書に記載なし | `18-05-30.pcap` 2018-05-30 13:48:46.176523 ほか | — | 中 | カメラの 40000 番がインターネットから届いていた。どう公開されていたか（ルーターの設定）は未確認 |
| C8 | そのほか | STUN（13.56.104.1 などの 3478 番）、`pool.ntp.org` への平文の NTP、SSDP の大量の告知（約 240 万回） | 記載なし | 公式文書に記載なし | 全期間 | — | 高 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

- C1：カメラが 2018 年 3 月以降のファームウェアだったなら、Hanwha が「解決した」とした暗号化されない遠隔の通信（CVE-2018-6295）が、5 月にもライブ映像と音声で続いていた。
- C2：利用者が Image encrypting をオンにしていたなら、映像が暗号化されていないことと両立しない（初期値はオフとみられ、可能性は低い）。

## 3. 公式文書に記載のない観測事項

- C3（仕様の行に対して、平文の映像と音声）、C5（AES-128）、C6、C7、C8。

## 4. 公式文書と一致した事項

- C4（XMPP の TLS は AES-256）。

## 5. 観測不能・判断不能な事項

- ファームウェアの版、Image encrypting の設定。

## 6. 追加調査に必要なデータ

- カメラのファームウェアの版（アプリの表示、収録の記録）。データセットの作成者への問い合わせ。
- 視聴者 129.94.5.83 の操作の記録。

## 断定できる範囲／できない範囲

- **断定できる**：外の視聴者へのライブ映像と音声が 21 回、暗号化されずに送られたこと（2018-05-28、05-31）。クラウドとの XMPP は AES-256 の TLS だったこと。
- **断定できない**：そのときのファームウェアが修正済みの版だったか。Image encrypting の設定。

## 前回との違い

- 前回は「食い違いの候補（T2）」で、仕様の「SSL (AES 256bit)」と比べていた。新しい決まり（最も限定的な読み方）では仕様の行は映像を約束していないので「公式文書に記載なし」。代わりに、Hanwha 自身の脆弱性の報告（文書 C）と比べて「条件付きの矛盾」にした。
- 27 日すべてで数え直し、平文の視聴は 21 回（05-28 に 20 回、05-31 に 1 回）、外から 40000 番への見知らぬ接続も新しく確かめた。

## 確かめ直し（2026-11-27）

前の報告を見ずに組み立て直した結果（[verify-20261127/smartcam.md](verify-20261127/smartcam.md)）、判定を**公式文書に記載なし**に下げた。C1 で比べた文書 C の CVE-2018-6295 は、どの通信を直したかを書いておらず（元の Kaspersky の公表が平文として挙げたのは HTTP API と更新だけ）、2018-05〜06 に公開されていたかも確かめられない。C2 の「Image encrypting」も、設定の状態と「image」が映像を含むかの両方が決められない。平文のライブ映像そのものは同じ結果（2018 年は 28 回、うち 129.94.5.83 が 21 回）。
