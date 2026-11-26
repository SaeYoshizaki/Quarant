# 13. Awair（UNSW 2018、UNSW-IoTraffic 2016-17）

[一覧に戻る](README.md)

UNSW 2018 は 2026-11-23 に取り直して調べた（27 日のうち、機器の通信があったのは 2018-05-28〜06-19 の 15 日）。UNSW-IoTraffic は 2026-11-26 に外付けディスクで確かめ直した（下）。

## 不足している情報（分析の前に）

- ファームウェアの版：通信に平文で出ていない。**未確認**。
- 主な文書「How secure is Awair?」は 2016-07-31 の保存のあと、2019-08-23 まで保存がない。2019 年の版にも同じ文がある（参考）が、2018 年に出ていたことは**未確認**。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Awair（UNSW の機器一覧の名前。機種の細かい区別は未確認） |
| MAC・IP | 70:88:6b:10:0f:c6、192.168.1.152 |
| 収録日時（UTC） | UNSW 2018：2018-05-28〜06-19 の 15 日（10 月の分には通信なし） |
| データセット | UNSW IoT Benign and Attack Traces の正常な日（Hamza ほか、ACM SOSR 2019）。オーストラリアの大学の実験室 |
| 観測できた通信フェーズ | クラウドとの常時接続（8883 番）、時刻のサーバー、OTA のサーバー、名前解決 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | How secure is Awair? | Awair（support.getawair.com） | [2016-07-31](https://web.archive.org/web/20160731193440/http://support.getawair.com:80/hc/en-us/articles/206241477-How-secure-is-Awair-) | 収録の約 2 年前 |
| A' | 同じ記事（改題） | Awair | [2019-08-23](https://web.archive.org/web/20190823101922/https://support.getawair.com/hc/en-us/articles/206241477-How-secure-is-my-data-Will-Awair-ever-sell-my-data-) | 収録の後（参考。同じ文がある） |
| B | Connecting Awair to an Enterprise Network | Awair | [2017-09-26](https://web.archive.org/web/20170926093145/https://support.getawair.com/hc/en-us/articles/115004833588-Connecting-Awair-to-an-Enterprise-Network) | 収録前 |
| C | Legal（プライバシー） | Awair | [2018-08-25](https://web.archive.org/web/20180825153536/https://getawair.com/pages/legal) | 収録の後（5〜6 月の分に対して） |

- 文書 A：「Awair encrypts and stores all information over TLS (Transport Layer Security) and AES 256 bit encryption to ensure security.」
- 文書 B：「Awair and Glow require outgoing TCP+TLS connections on ports 8883 and 443.」「After connecting to your wireless network, the Awair will open an outgoing TCP connection on port 8883 to the Awair server, and the connection will be secured with standard TLS …」「Once per day, the Awair unit will check if any firmware updates are available. This check is done again via a TCP connection using TLS security and the HTTPS protocol …」

**最も限定的な読み方**：文書 A の「AES 256 bit encryption」は、TLS の中の暗号だとは言っていない（「stores」と並べている）。文書 B の「Once per day … will check」は、1 日 1 回は確認すると言っており、ほかの接続がないとは言っていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| W1 | クラウドとの接続 | `messaging.awair.is` の 8883 番へ TLS 1.2（15 日で 73 接続、上り 63 MB）、`ota.awair.is`・`timeserver.awair.is` の 443 番へ TLS 1.2。インターネットへの平文は DNS だけ | 「encrypts … all information over TLS」「require outgoing TCP+TLS connections on ports 8883 and 443」「port 8883 … secured with standard TLS」 | 一致 | `18-05-28.pcap` 2018-05-28 00:00:05.963203（messaging）、05:53:55.805777（ClientHello） | 文書 A・B | 高 | |
| W2 | 同上 | 選ばれた暗号：`messaging`・`ota` は `TLS_RSA_WITH_AES_256_CBC_SHA*`、`timeserver` は `TLS_RSA_WITH_AES_128_CBC_SHA256`（353 回、全体の約 32%）。すべて RSA の鍵交換（前方秘匿性なし）。機器が出す暗号は 17 種 | 「AES 256 bit encryption」 | 公式文書に記載なし | `18-05-28.pcap` 2018-05-28 00:21:23.254345（timeserver の ClientHello） | 文書 A | 高 | AES-256 を通信の暗号と広く読めば、AES-128 の接続は矛盾。限定的な読み方ではとらない |
| W3 | OTA のサーバー | `ota.awair.is`（35.203.134.251）へ、毎時 2 回の TLS の接続（1 日 48 回） | 「Once per day, the Awair unit will check if any firmware updates are available … TLS security and the HTTPS protocol」 | 判断不能 | `18-05-29.pcap` の毎時 17〜18 分（例 2018-05-29 00:17:57.695672） | 文書 B | — | TLS で HTTPS の点は一致。毎時の接続が更新の確認かは、中身が見えないので分からない（名前だけで目的を決めない） |
| W4 | 名前解決 | ルーターのほか、Google の 8.8.8.8 へ平文の DNS（1,082 回） | 記載なし | 公式文書に記載なし | `18-05-28.pcap` 2018-05-28 00:21:23.085451 | — | 高 | |
| W5 | 証明書 | サーバー証明書は `*.awair.is`（DigiCert SHA2 Secure Server CA、2015-10-19〜2018-10-22、名前は一致） | 記載なし | 公式文書に記載なし | 同上 | — | 高 | |

## UNSW-IoTraffic の分（2026-11-26 に確かめ直した）

- 2016-11-10〜2017-03-07 の 28 日。握手は 826 回：`timeserver.awair.is`（563）、`messaging.awair.is`（8883 番、179）、`api.awair.is`（2）が `TLS_RSA_WITH_AES_128_CBC_SHA256`（合わせて 744 回）、`ota.awair.is`（82）が `TLS_RSA_WITH_AES_256_CBC_SHA256`。平文は 8.8.8.8 への DNS と `pool.ntp.org` への NTP だけ。最初の ClientHello は `AwairAirQuality_70886b100fc6.pcap` 2016-11-10 11:28:41.723249。前回の記録と同じ。文書 A（2016-07-31、収録前）と比べて、判定は W2 と同じ（公式文書に記載なし）。

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- W2（AES-128、前方秘匿性なし）、W4（8.8.8.8 への平文の DNS）、W5。

## 4. 公式文書と一致した事項

- W1（TLS、ポート 8883 と 443）。

## 5. 観測不能・判断不能な事項

- W3（毎時の接続の目的）。保存時の暗号化。

## 6. 追加調査に必要なデータ

- 2018 年に有効だった「How secure is Awair?」の版。
- ファームウェアの版、更新の確認の中身（Awair の技術文書）。

## 断定できる範囲／できない範囲

- **断定できる**：インターネットとの通信は DNS を除いてすべて TLS で、AES-128 の接続が約 3 割あったこと。
- **断定できない**：文書の「AES 256」が通信のことか。毎時の `ota.awair.is` への接続が更新の確認か。

## 前回との違い

- 前回は「食い違いの候補（T2）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。
