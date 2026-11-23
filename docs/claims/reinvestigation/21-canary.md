# 21. Canary（UNSW 2018、UNSW-IoTraffic 2016-17）

[一覧に戻る](README.md)

UNSW 2018 は今回取り直して調べた（27 日のうち、通信があったのは 29 の UTC の日付）。UNSW-IoTraffic は取り直していない（利用者の判断、前回の記録）。

## 不足している情報（分析の前に）

- ファームウェアの版：**未確認**（DHCP のホスト名 `C100F1615229`、User-Agent `htpdate/1.1.2`、`ConnMan/1.35 wispr`、`curl/7.56.1`→`7.58.0` から、機器の中の部品の版は分かる）。
- 利用者の操作（視聴、プライバシーモード）：記録がない。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Canary（初代。DHCP のホスト名 `C100F1615229`、一時的に `Ambarella`） |
| MAC・IP | 7c:70:bc:5d:5e:dc、192.168.1.230 |
| 収録日時（UTC） | 2018-05-28〜2018-10-29（UNSW 2018 の正常な日の 27 のファイル） |
| データセット | UNSW IoT Benign and Attack Traces の正常な日（Hamza ほか、ACM SOSR 2019） |
| 観測できた通信フェーズ | クラウドとの常時接続、映像とみられる上り、時刻合わせ（HTTP）、接続確認 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Original Canary FAQ（「How secure is it?」） | Canary（help.canary.is） | [2018-08-18](https://web.archive.org/web/20180818021410/https://help.canary.is/hc/en-us/articles/206619098-Original-Canary-FAQ) | 収録中 |
| B | Security のページ（英国） | Canary | [2018-02-27](https://web.archive.org/web/20180227160118/https://canary.is/uk/security/) | 収録前 |
| C | 製品ページ | Canary | [2018-10-04](https://web.archive.org/web/20181004055108/https://canary.is/canary/) | 収録中 |

- 文書 A：「We use bank-level security, and any data that Canary generates is immediately encrypted. **All communication between your Canary device, the Canary Cloud, and your smartphone is encrypted over TLS/SSL (HTTPS).** Video and audio are stored and encrypted using AES-256 bit encryption …」
- 文書 B：「When a customer streams video through the Canary app, all video and data is securely encrypted between the device, the cloud, and the smartphone.」
- 文書 C：「Secure web transfer (SSL/TLS)」「AES 256-bit data encryption」

**最も限定的な読み方**：文書 A の文は「機器、Canary Cloud、スマートフォンの間のすべての通信」と範囲を言い切っている。Canary Cloud は Canary 自身のサーバー（`*.canaryis.com`）と読む。文書 B は「映像を見るとき」に限った文。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| C1 | 時刻合わせ | `HEAD http://h.canaryis.com/`（User-Agent `htpdate/1.1.2`）を平文の HTTP で 299 回（28 日）。サーバー（`nginx`）は 301 で `https://ip-10-10-22-130/` などに転送し、`Date` の見出しを返す | 「All communication between your Canary device, the Canary Cloud, and your smartphone is encrypted over TLS/SSL (HTTPS).」 | 明確な矛盾 | `18-05-28.pcap` 2018-05-28 00:20:36.847168（要求）、同じ時刻の応答 301 | 文書 A | 高 | `htpdate` は HTTP の `Date` で時刻を合わせる道具。送っているのは見出しだけで、利用者のデータはない。影響は小さいが、「すべての通信」と言い切る文と直接両立しない |
| C2 | クラウドとの常時接続 | `b.canaryis.com`（27,736 接続、約 60 秒おき）、`i.canaryis.com`（13,509 接続、約 30 秒おき）へ TLS 1.2、`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`。`m`、`o`、`v`、`09-wl2-d-prod.canaryis.com` も TLS 1.2（AES-256-CBC、AES-128-GCM） | 「encrypted over TLS/SSL (HTTPS)」「Secure web transfer (SSL/TLS)」「AES 256-bit data encryption」 | 一致 | `18-05-28.pcap` 2018-05-28 00:00:12.159274（i）、00:00:12.325661（b） | 文書 A・C | 高 | 映像とみられる大きな上り（`09-wl2-d-prod` へ 22.8 MB など）も TLS |
| C3 | 接続確認 | `GET http://ipv4.connman.net/online/status.html`（User-Agent `ConnMan/1.35 wispr`）を平文で 11 回 | 同上 | 公式文書に記載なし | `18-05-28.pcap` 2018-05-28 05:59:20.364430 | 文書 A | 高 | 相手は Canary Cloud ではなく ConnMan の公開のサーバー |
| C4 | 名前解決の失敗 | `h.canaryis.com` の DNS が REFUSED（rcode 5）で 10,086 回、`m.canaryis.com` が 184 回 | 記載なし | 公式文書に記載なし | 全期間 | — | 高 | 失敗が続いても繰り返し問い合わせる |
| C5 | 応答のない接続 | `h`／`i.canaryis.com` の 443 番への SYN だけの接続が 158 回 | 記載なし | 公式文書に記載なし | 全期間 | — | 中 | |
| C6 | 映像を見るとき | 利用者の視聴の記録がなく、どの通信が視聴かは分からない | 「When a customer streams video … all video and data is securely encrypted」 | 観測不能 | — | 文書 B | — | 視聴らしい平文の通信は見えない |
| C7 | 保存 | — | 「Video and audio are stored and encrypted using AES-256」 | 観測不能 | | 文書 A | — | |

## UNSW-IoTraffic の分（前回の記録、取り直していない）

- 2016-17：5.4 GB のうち HTTP は 17.6 KB だけで、`h.canaryis.com:80` への HEAD が 53 回、`ipv4.connman.net` への GET が 3 回。文書（2016-08-22 の FAQ、同じ文）と比べて、C1 と同じく「明確な矛盾」（中身は時刻合わせだけ）。

## 1. 明確な矛盾

- C1：文書は「機器、Canary Cloud、スマートフォンの間のすべての通信は TLS/SSL（HTTPS）で暗号化」と言い切っているが、機器は Canary 自身のサーバー `h.canaryis.com` と平文の HTTP でやり取りしていた（時刻合わせ、2018 年に 299 回、2016-17 年に 53 回）。送っているのは見出しだけで、利用者のデータは含まない。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- C3、C4、C5。

## 4. 公式文書と一致した事項

- C2（クラウドとの主な通信は TLS 1.2、AES-256-GCM が中心）。

## 5. 観測不能・判断不能な事項

- C6、C7。

## 6. 追加調査に必要なデータ

- ファームウェアの版。
- 利用者の操作の記録（視聴の時間帯）。

## 断定できる範囲／できない範囲

- **断定できる**：Canary のサーバーへの平文の HTTP の要求（時刻合わせ）が、2016-17 年にも 2018 年にもあったこと。ほかのクラウドとの通信は TLS だったこと。
- **断定できない**：平文の要求に利用者のデータが含まれないこと以外の影響（時刻を書き換えられた場合の影響は、パッシブには分からない）。

## 前回との違い

- 前回は「文言の上での食い違い（T1b）」。新しい決まり（文書が「すべての通信」と言い切り、平文の通信が観測された場合は明確な矛盾の候補）で「明確な矛盾」にした。平文の要求が `htpdate` による時刻合わせであることを新しく確かめた。
