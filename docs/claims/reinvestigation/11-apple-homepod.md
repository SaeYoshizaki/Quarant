# 11. Apple HomePod（YourThings、2018-03〜04）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- 比べる文書は iOS と Siri の説明で、HomePod の名前は出てこない。HomePod に当てはまるかは**推定**（下の条件）。
- 利用者の操作（どの曲を再生したか、Siri に何を頼んだか）：記録がない。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Apple HomePod（`AudioAccessory1,1`） |
| MAC・IP | d4:90:9c:cc:62:42、192.168.0.47 |
| ソフトウェア | 11.2.5（ビルド 15D59）。機器の HTTP の User-Agent（`server-bag [iPhone OS,11.2.5,15D59,AudioAccessory1,1]`、`AppleCoreMedia/1.0.0.15D59 (HomePod; U; CPU OS 11_2_5 like Mac OS X; en_us)`）による |
| 収録日時（UTC） | 2018-03-20、03-21、04-11、04-12、04-13（機器の通信は 03-20 17:48 から） |
| データセット | YourThings。重複を除き、日ごとにつないで調べた（根拠のファイル名は元の 5 分のファイルの名前） |
| 観測できた通信フェーズ | 起動と設定（iCloud、証明書の失効の確認）、Siri、音楽の再生、プッシュ通知、時刻合わせ |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Apple のプライバシーのページ「Our Approach to Privacy」（Siri の節、HomeKit の節） | Apple | [2018-04-12](https://web.archive.org/web/20180412230006/https://www.apple.com/privacy/approach-to-privacy/) | 収録中 |
| B | iOS Security Guide（2018 年 1 月、iOS 11） | Apple | [2018-04-11](https://web.archive.org/web/20180411110236/https://www.apple.com/business/docs/iOS_Security_Guide.pdf) | 収録中 |

- 文書 A（Siri）：「certain information such as your name, contacts, music you listen to, and searches is sent to Apple servers using encrypted protocols.」
- 文書 A（iCloud）：「All your iCloud content — like photos, contacts, and reminders — is encrypted when it’s transferred …」
- 文書 B（Siri）：「All communication with the server is over HTTPS.」

**最も限定的な読み方**：A の最初の文は Siri の説明の中にあり、Siri に関わる情報を Apple のサーバーに送るときの話。音楽の配信のデータを取りに行く要求まで含むとは書いていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| P1 | Siri | `guzzoni.apple.com:443` へ TLS 1.2（5 日で 26 接続）。選ばれた暗号は `TLS_RSA_WITH_AES_256_CBC_SHA`。証明書は `guzzoni.apple.com`（Symantec Class 3 EV SSL CA - G3、名前は一致） | 「All communication with the server is over HTTPS.」 | 一致 | `eth1-20180320.1745.1521585900` 2018-03-20 17:48:59.018197（ClientHello） | 文書 B | 中 | guzzoni が Siri のサーバーであることは、通信からは推定 |
| P2 | 音楽の再生 | `streamingaudio.itunes.apple.com` から平文の HTTP で音声のファイルを 3 回取得（下り 23.7 MB）。パスは `…/Music/…/mzm.<id>.aac.a.m4p`、問い合わせに `accessKey`、ヘッダーに `x-playback-session-id`。User-Agent は `AppleCoreMedia … (HomePod; …)` | 「music you listen to … is sent to Apple servers using encrypted protocols」 | 公式文書に記載なし | `eth1-20180321.2015.1521681300` 2018-03-21 20:16:23.682176、20:16:26.860252 | 文書 A（Siri の節） | 中 | 文は Siri の説明で、音楽の配信の要求は対象外（最も限定的な読み方）。再生の要求も含むと広く読めば矛盾。ファイルは `.m4p`（保護された形式）で、音そのものは暗号化されているとみられる（推測）。平文なのは、どのファイルを取りに行ったかと `accessKey` |
| P3 | iCloud | `setup.icloud.com`、`gateway.icloud.com`、`p38-keyvalueservice.icloud.com` などはすべて TLS | 「All your iCloud content … is encrypted when it’s transferred」 | 一致 | `eth1-20180321.2015.1521681300` 2018-03-21 20:15:32.435752 ほか | 文書 A | 中 | |
| P4 | 証明書の確認 | `ocsp.digicert.com`、`sr.symcd.com`、`ocsp.apple.com` などへ平文の OCSP（User-Agent `trustd`） | 記載なし | 公式文書に記載なし | `eth1-20180320.1745.1521585900` 2018-03-20 17:48:32.872711 ほか | — | 高 | OCSP は普通は平文 |
| P5 | 設定の取得 | `init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag`、`init-p01md.apple.com/bag` などを平文の HTTP で | 記載なし | 公式文書に記載なし | `eth1-20180320.1750.1521586200` 2018-03-20 17:51:28.836951 | — | 高 | |
| P6 | 接続確認 | `captive.apple.com` へ平文の GET（7 回） | 記載なし | 公式文書に記載なし | `eth1-20180320.1745.1521585900` 2018-03-20 17:48:26.407625 | — | 高 | |
| P7 | 時刻合わせ | 平文の NTP | 記載なし | 公式文書に記載なし | — | — | 高 | |
| P8 | AirPlay、HomeKit | LAN での AirPlay・HomeKit の通信は、この 2 日には見えない | 「AirPlay audio … encrypts communication … using AES-128」ほか | 観測不能 | — | 文書 A・B | — | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- P2（どの曲のファイルを取りに行ったかと `accessKey` が平文）、P4〜P7。

## 4. 公式文書と一致した事項

- P1（Siri のサーバーは TLS）、P3（iCloud は TLS）。

## 5. 観測不能・判断不能な事項

- P8。`.m4p` のファイルの中身（保護の有無）。

## 6. 追加調査に必要なデータ

- HomePod を対象にした、収録の時点の Apple の文書（HomePod のプライバシーの説明。今回は見つからなかった）。
- 再生した曲の記録（`.m4p` のパスと曲の対応）。

## 断定できる範囲／できない範囲

- **断定できる**：音楽のファイルを平文の HTTP で取得し、要求に `accessKey` があったこと。Siri と iCloud は TLS だったこと。
- **断定できない**：音そのものが暗号化されていたか。文書の Siri の文が再生に当てはまるか。

## 前回との違い

- 前回は「食い違いの候補（T1a）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。ソフトウェアの版（11.2.5）を新しく特定した。
