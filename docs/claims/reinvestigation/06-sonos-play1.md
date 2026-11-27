# 6. Sonos PLAY:1（YourThings、2018-03〜04）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- アプリの版：アプリの通信は収録にない。**未確認**。
- 利用状況の共有（Additional Usage Data）を利用者が止めていたか：**未確認**。
- 取り直したのは 5 日（03-20、03-21、04-11、04-12、04-13）。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Sonos PLAY:1（`ZPS1`。SSDP の `SERVER` による） |
| MAC・IP | 5c:aa:fd:6c:e0:d4、192.168.0.7 |
| シリアル番号など | `serial=5CAAFD6CE0D4F`、`sonosid=114318238`、`householdid=Sonos_P8cV8f1KTV…`（更新の確認の URL） |
| ファームウェア | 収録の中で 4 つの版：33.15-33210 → 34.16-37101 → 41.3-50131（2018-03-20 21:42〜21:44 UTC）→ 42.2-51240（2018-04-13 16:34 UTC）。SSDP の `SERVER`、更新の要求の値による |
| 収録日時（UTC） | 2018-03-20、03-21、04-11、04-12、04-13 |
| データセット | YourThings。重複を除き、日ごとにつないで調べた。作成者の検査用の機器（192.168.0.200）は除いた |
| 観測できた通信フェーズ | 更新の確認と更新、利用状況の送信、ラジオの再生（TuneIn、streamtheworld）、LAN の音楽サーバーからの再生、時刻合わせ |

**使用した公式文書**

| # | 文書 | 発行元 | 更新 | 保存 | 収録との関係 |
|---|---|---|---|---|---|
| A | Sonos Privacy Statement（米国） | Sonos | 「Last Updated: August 2017」 | [2018-02-02](https://web.archive.org/web/20180202085145/https://www.sonos.com/en-us/legal/privacy) | 収録前。収録の時点で有効 |

文書 A の該当部分：
- Security の節：「Sonos is committed to protecting the security of your personal data. … When we transmit data over the Internet, we protect it through the use of encryption.」
- FAQ の「How is information stored and secured on Sonos’ servers?」：「Any data we transmit over the internet is protected using encryption.」
- 同じく：「In addition, your data is protected with encryption, such as Transport Layer Security (TLS), during transition over the Internet.」
- 集めるデータ：「Registration data. This data includes your email address, location, language preference, Product serial number, IP address, and Sonos account login information」（Functional Data）。「Activity Information. This includes … information about track, playlist, or station container data …」（Additional Usage Data）。

**最も限定的な読み方**：
- 「we transmit」は Sonos（会社と、その製品・サーバー）が送るデータ。
- Security の節の「data」は個人データの段落の中にある。限定的に読んでも、同じ文書が集めるデータとして挙げる製品のシリアル番号や利用状況のデータは対象に入る。FAQ の文は「Any data」と言い切っている。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| S1 | 更新の確認 | `GET http://update.sonos.com/firmware/latest/default-1-1.ups?…&serial=5CAAFD6CE0D4F&sonosid=114318238&householdid=Sonos_…` を平文で 18 回（5 日）。シリアル番号（MAC に `F`）、Sonos ID、household ID | 「Any data we transmit over the internet is protected using encryption.」「When we transmit data over the Internet, we protect it through the use of encryption.」 | 明確な矛盾 | `eth1-20180320.1400.1521572400` 2018-03-20 14:03:08.725631 ほか | 文書 A（Security の節、FAQ） | 高 | シリアル番号は文書が集めるデータ（Registration data）に挙げている |
| S2 | ファームウェアの更新 | `update-firmware.sonos.com` から平文の HTTP で 3 回取得：34.16（8,306,684 バイト）、41.3（8,805,698 バイト）、42.2。取得の後に版が上がった（42.2 は 8,826,617 バイト） | 同上 | 明確な矛盾 | `eth1-20180320.2140.1521600000` 2018-03-20 21:42:47.719047（34.16）、21:43:51.055748（41.3）、`eth1-20180413.1630.1523655000` 2018-04-13 16:34:05.284653（42.2） | 文書 A | 高 | Sonos のサーバーが送るデータ（ファームウェア）そのものが平文。要求の URL にもシリアル番号など |
| S3 | 利用状況の送信 | `POST http://msmetrics.ws.sonos.com:80/HRMetrics/submit.aspx` を平文で 1 回。本文は `<UsageMetrics>`（`cu` に Sonos ID、`hh` に household ID ほか）。同じ時期に `GET /HRMetrics/pollInterval.htm?hhid=…` も平文。版 41.3 以降は同じ送り先に TLS（5 日で 150 接続以上） | 同上 | 明確な矛盾 | `eth1-20180320.1235.1521567300` 2018-03-20 12:38:08.524403（版 33.15 のとき） | 文書 A | 高 | 利用状況は文書が集めるデータ（Additional Usage Data）。平文だったのは古い版（33.15）のときだけ |
| S4 | ラジオの再生 | TuneIn（`legato.radiotime.com`）へ平文の HTTP で、SOAP の見出しに `deviceId`（`5C-AA-FD-6C-E0-D4:F`）、`GET /Tune.ashx?id=s225441&…&serial=5C-AA-FD-6C-E0-D4:F&version=42.2` など。streamtheworld から平文の HTTP で音声 | 同上 | 公式文書に記載なし | `eth1-20180411.0840.1523454000` 2018-04-11 08:44:33.441045、`eth1-20180413.1730.1523658600` 2018-04-13 17:33:05.995285 | 文書 A | 中 | 送り先は第三者（TuneIn）で、送り手は Sonos の製品。「we transmit … over the internet」に当たると読めば矛盾だが、相手が第三者のサービスなので、Sonos の送信とまでは限定的に読まない |
| S5 | Sonos のサービス | `msmetrics`、`service-catalog`、`config`、`system-api`、`oauth`、`registration` の各 `*.sonos.com` は TLS 1.2。版 33.15 では `TLS_RSA_WITH_AES_*`（前方秘匿性なし、提示 7 種）、41.3 以降は `TLS_ECDHE_RSA_WITH_AES_*`（提示 9 種） | 「your data is protected with encryption, such as Transport Layer Security (TLS)」 | 一致 | `eth1-20180320.0030.1521523800` 2018-03-20 00:31:55.870152 ほか | 文書 A | 高 | |
| S6 | 時刻と時刻帯 | `update-timezone.sonos.com/timezone/timezones.xml` を平文で取得、`*.sonostime.pool.ntp.org` へ平文の NTP | 同上 | 公式文書に記載なし | `eth1-20180320.1400.1521572400` 2018-03-20 14:03:06.892251 | 文書 A | 中 | 公開の時刻帯の表で、個人のデータではない |
| S7 | Spotify | `esdk-ffl.spotify.com` へ平文の HTTP（3 回） | 記載なし | 公式文書に記載なし | `eth1-20180320.2140.1521600000` 2018-03-20 21:43:40.555437 | — | 中 | 第三者の部品の送信 |
| S8 | LAN | LAN の音楽サーバー（192.168.0.151:3500、192.168.0.159:9000）から平文の HTTP で再生、SSDP | 記載なし | 公式文書に記載なし | `eth1-20180411.1935.1523493300` 2018-04-11 19:37:47.775998 | — | 高 | |

## 1. 明確な矛盾

- S1・S2・S3：文書は「インターネットで送るデータはすべて暗号化する」と言い切っているが、シリアル番号と household ID を含む更新の確認、ファームウェアそのもの、利用状況のデータ（古い版のとき）が平文の HTTP で送られた。どれも Sonos のサーバーとの通信で、送ったデータは文書自身が集めるデータとして挙げているもの（S1・S3）、または Sonos が送るデータ（S2）。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- S4（第三者のラジオのサービスに、Sonos の製品が機器の ID を平文で送る）、S6〜S8。

## 4. 公式文書と一致した事項

- S5（Sonos のほかのサービスは TLS）。

## 5. 観測不能・判断不能な事項

- ファームウェアのファイルに署名があるか（中身は今回確かめていない）。

## 6. 追加調査に必要なデータ

- 利用状況の共有の設定（アプリ）。
- Sonos のファームウェアの署名についての文書。

## 断定できる範囲／できない範囲

- **断定できる**：シリアル番号と household ID を含む要求、ファームウェア、利用状況のデータが、平文の HTTP で Sonos のサーバーとやり取りされたこと。版が上がってから、利用状況の送信は TLS になったこと。
- **断定できない**：ファームウェアの改ざんが防がれていたか。

## 前回との違い

- 前回も「食い違いの候補（T1a）」。今回は利用状況のデータの平文の送信（S3）と、04-13 の 3 回目の更新（42.2）を新しく確かめた。新しい決まりでも、文書が「Any data」と言い切っているので「明確な矛盾」のまま。

## 確かめ直し（2026-11-27）

前の報告を見ずに組み立て直した結果（[verify-20261127/sonos.md](verify-20261127/sonos.md)）、判定は**明確な矛盾**のまま。13 日で数え直し、更新の確認 28 回のうち 15 回は機器が自分で送っていた（残りは作成者のアプリの操作の直後）。CIC 2021 の Sonos One も、カナダ版の文書と比べて明確な矛盾（自動更新の 2 回）。
