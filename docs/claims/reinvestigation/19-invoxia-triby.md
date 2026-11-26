# 19. Invoxia Triby（UNSW 2016、UNSW-IoTraffic 2016-17）

[一覧に戻る](README.md)

UNSW 2016（2016-09-22〜10-11、20 日）を 2026-11-23 に取り直して調べた。UNSW-IoTraffic は 2026-11-26 に外付けディスクで確かめ直した（下）。

## 不足している情報（分析の前に）

- 利用者の操作（通話、ラジオの再生）の記録：ない。2016-09-28 の通話、2016-10-06 のラジオの再生は通信から分かったこと。
- アプリの通信：収録にない。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Invoxia Triby（DHCP の vendor class `invoxia/triby`、SIP の User-Agent `invoxia KTP1 10.48.1 [18:B7:9E:02:20:44]`） |
| MAC・IP | 18:b7:9e:02:20:44、192.168.1.120 |
| ハードウェア／ファームウェア | 基板 `TRIBY_V0`、revision 5、sub_revision 4271。ファームウェア `triby-10.48.1`（ビルド `52.3a.e0`）。更新の確認の URL の値による |
| 収録日時（UTC） | 2016-09-22 14:00 〜 2016-10-11 12:59（UNSW 2016 の 20 日） |
| データセット | UNSW IoT Traffic Traces（Sivanathan ほか、IEEE TMC）。オーストラリアの大学の実験室 |
| 観測できた通信フェーズ | SIP の登録（常時）、通話（2016-09-28）、ラジオの再生（2016-09-28、10-06）、更新の確認（毎日）、管理の接続（TLS）、時刻合わせ |

**使用した公式文書**

| # | 文書 | 発行元 | 更新 | 保存 | 収録との関係 |
|---|---|---|---|---|---|
| A | Privacy policy（en-INT） | invoxia | 2016-04-27（「last updated April 27, 2016」） | [2016-09-28](https://web.archive.org/web/20160928091057/http://www.invoxia.com:80/en-INT/privacy/) | 収録中 |
| B | 同上 | invoxia | — | [2017-02-11](https://web.archive.org/web/20170211125150/http://www.invoxia.com/en-INT/privacy/) | UNSW-IoTraffic の収録中（前回の比較） |

文書 A：
- 「We may also collect data that identify you indirectly such as (but not limited to) your IP address, your zipcode or the settings of your phone.」
- 「The protection of your data is at the heart of our confidentiality policy and we undertake to preserve them by applying the optimum level of security.」
- 「Additionally, we will not disclose the personal information you provide via the Site or Products to parties unaffiliated with invoxia, unless you specifically authorize it.」
- 「Invoxia uses a variety of third party contractors to perform services such as website management and hosting, online product purchases and shipping, credit card processing and email marketing.」

**最も限定的な読み方**：第三者に渡さないとしているのは「you provide」の個人情報（利用者が入力したもの）。機器の MAC や機器の名前は含めない。「optimum level of security」は方法を書かない約束。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| T1 | SIP の登録 | `sip.invoxia.com`（46.105.38.79）の tcp/5228 へ、平文の SIP の REGISTER を 5 分おき。ユーザー名はアカウントのメールアドレス（`smarthomeunsw` で始まる Gmail。`@` を `.` にしたもの）に `triby_<MAC>` を付けたもの。User-Agent に版と MAC | 「applying the optimum level of security」 | 判断不能 | `16-09-28.pcap` 2016-09-27 14:03:01.139179 ほか | 文書 A | — | 方法を書かない約束 |
| T2 | 同上 | 送り先は invoxia のサーバー | 「will not disclose … to parties unaffiliated with invoxia」 | 一致 | 同上 | 文書 A | 中 | 第三者ではない |
| T3 | 通話 | 2016-09-28 02:10〜02:11 に平文の SIP の INVITE と BYE、`sip.invoxia.com` の udp/48360 と RTP（PT 9、G.722）で音声を双方向に約 1,600 パケットずつ。SRTP ではない | 記載なし（通話の暗号化の文はない） | 公式文書に記載なし | `16-09-28.pcap` 2016-09-28 02:10:29.807541（INVITE）、02:10:45.457952（RTP） | 文書 A に該当なし | 高 | 中身は無音に近い（`fa` の繰り返しが多い）。聞いて確かめてはいない |
| T4 | ラジオの再生 | `8937406324.airable.io`（airable、ラジオ配信の会社）へ平文の HTTP で、`/authentication?device=18B79E022044&name=KTP1&version=triby-10.48.1&locale=en-AU&salt=…&signature=…`、その後 Basic 認証つきで番組を取得（値は quarant-results） | 「will not disclose the personal information you provide … to parties unaffiliated with invoxia」 | 公式文書に記載なし | `16-10-06.pcap` 2016-10-06 06:48:26.657421 | 文書 A | 高 | MAC と機器の名前は「you provide」の個人情報ではない（最も限定的な読み方）。airable は invoxia の取引先 |
| T5 | 更新の確認 | `GET http://developer.invoxia.com/update/triby/update.pup?mac=18:B7:9E:02:20:44&machine=triby&board_name=TRIBY_V0&…&version=triby-10.48.1…` を毎日 1 回（19 日）。版は 20 日間変わらない | 記載なし | 公式文書に記載なし | `16-09-23.pcap` 2016-09-23 07:19:15.992548 | — | 高 | |
| T6 | 管理の接続 | `ws.invoxia.io:443` へ TLS 1.2（73 回）、`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`。サーバー証明書は自社の `invoxia CA`（RSA 1024、SHA-1、2015-03-02〜2045-02-22）。機器も自分の証明書（主体は MAC、同じ認証局、RSA 1024、SHA-1）を出す相互認証。ほかに `ws.invoxia.io:8090` へ中身の読めない TCP（21 接続） | 記載なし | 公式文書に記載なし | `16-09-23.pcap` 2016-09-23 07:19:15.673608 | — | 高 | 8090 番の中身は未分類 |
| T7 | ラジオの配信 | `icecast.icecast.sbs.com.au` から平文の HTTP で音声（10 接続） | 記載なし | 公式文書に記載なし | `16-09-28.pcap` 2016-09-28 02:11:53.798600 | — | 高 | |
| T8 | そのほか | `esdk-ffl.spotify.com` へ平文の HTTP、`*.invoxia.pool.ntp.org` へ平文の NTP | 記載なし | 公式文書に記載なし | `16-10-06.pcap` 2016-10-06 06:48:36.614103 ほか | — | 高 | |
| T9 | 間接的な識別子 | IP アドレス、機器の設定（版、ロケール `en-AU`）を送る | 「We may also collect data that identify you indirectly such as … your IP address …」 | 一致 | T4、T5 | 文書 A | 中 | |

## UNSW-IoTraffic の分（2026-11-26 に確かめ直した）

- 2016-09-30〜2017-04-07（92 日、UNSW 2016 と一部重なる）。airable への平文の `/authentication?device=<MAC>…` が 7 回（6 日）、Basic 認証つきの番組の要求が 21 回。`sip.invoxia.com` の 5228 番への平文の SIP（48 日）、`developer.invoxia.com` の更新の確認（MAC つき）、`ws.invoxia.io` への TLS 1.2（3,667 回、AES-256-GCM）。最初の airable の要求は `TribySpeaker_18B79E022044.pcap` 2016-10-06 06:48:26.657421。前回の記録と同じ。文書 B（2017-02-11）の同じ文と比べて、判定は T4 と同じ（公式文書に記載なし）。

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- T3：通話の音声が暗号化されない RTP。
- T4：機器の MAC と名前を、取引先の airable に平文で送る。
- T5〜T8。T1 で、アカウントのメールアドレスをもとにした SIP のユーザー名が平文。

## 4. 公式文書と一致した事項

- T2、T9。

## 5. 観測不能・判断不能な事項

- T1（評価の言葉）。TLS の中身と 8090 番の中身。

## 6. 追加調査に必要なデータ

- 通話とラジオの操作の記録。
- invoxia と airable の関係を書いた invoxia の文書（今回は見つからなかった）。

## 断定できる範囲／できない範囲

- **断定できる**：SIP の登録と通話の音声が平文だったこと。airable に MAC と機器の名前を平文で送ったこと。
- **断定できない**：MAC がポリシーの言う個人情報に当たるか。airable が「unaffiliated」に当たるか。

## 前回との違い

- 前回は「弱い候補（T8）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。
- 収録中（2016-09-28）に保存された版の文書を使った。UNSW 2016 で、平文の通話（SIP と RTP）を新しく確かめた。
