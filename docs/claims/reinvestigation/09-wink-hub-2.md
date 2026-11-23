# 9. Wink Hub 2（YourThings、2018-03〜04）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- ファームウェア、アプリの版：**未確認**（2018-03-21 19:40 に `hub-updates.winkapp.com` から TLS で 134 MB を取得。更新とみられる、推測）。
- 下の H3 は、データセットの作成者が行った**能動的な**中間者の検査（偽の証明書）の最中の通信。こちらはその記録を読んだだけ。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Wink Hub 2（SSDP の `SERVER: node.js/6.1.0 UPnP/1.1 node-ssdp/2.9.1`、`LOCATION: https://192.168.0.52:8888`） |
| MAC・IP | 00:21:cc:4d:59:35、192.168.0.52 |
| 収録日時（UTC） | 03-20、03-21、04-11、04-12、04-13（取り直した 5 日） |
| データセット | YourThings |
| 観測できた通信フェーズ | クラウドとの常時接続、更新とみられる取得、LAN のアプリとの TLS（8888 番）、SSDP、中間者の検査（04-12） |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | ヘルプの FAQ | Wink（wink.com/help/faq） | [2017-07-08](https://web.archive.org/web/20170708204125/https://www.wink.com/help/faq/) | 収録前 |
| B | Security のページ | Wink | [2017-04-23](https://web.archive.org/web/20170423174149/https://www.wink.com/security/) | 収録前 |

- 文書 A：「We adopt security measures that include certificate pinning, encryption, two-factor authentication for all system administrators, and regular security audits.」
- 文書 B：「We use certification encryption for all personalized data transmitted by the app」「We even built our platform to stay safe if someone manages to get access to your home network.」

**最も限定的な読み方**：文書 A は、会社の対策の中に certificate pinning が含まれると言っている。どの部分（アプリ、ハブ、サーバー）で使うかは書いていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| H1 | クラウドとの接続 | インターネットへの通信はすべて TLS 1.2。`hub-api.wink.com`（普段は `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`、44 回）、名前のない AWS のアドレスへの常時接続（`TLS_RSA_WITH_AES_256_CBC_SHA256`）。平文の HTTP はない | 「encryption」 | 一致 | `eth1-20180321.1940.1521679200` 2018-03-21 19:43:29.714070 ほか | 文書 A | 高 | |
| H2 | 更新とみられる取得 | `hub-updates.winkapp.com` から TLS で 134 MB（16 接続） | 記載なし | 公式文書に記載なし | `eth1-20180321.1940.1521679200` 2018-03-21 19:40:36.453244 | — | 中 | |
| H3 | 中間者の検査（04-12） | 2018-04-12 02:57:51〜02:59:37 に、`hub-api.wink.com` への 42 の接続で作成者の偽の証明書（発行者 `thing-catcher.gtisc.gatech.edu`）。21 回はハブが警告（unknown_ca）を返して切り、**21 回はハブが握手のあとにデータを送った** | 「certificate pinning」 | 公式文書に記載なし | `eth1-20180412.0255.1523519700` 2018-04-12 02:57:51.221340（最初）〜02:59:37.928264 | 文書 A | 高（観測） | 文書は pinning をどこで使うかを書いていない（最も限定的な読み方）。ハブの接続に pinning があると広く読めば矛盾。拒んだ接続と受け入れた接続が半分ずつで、ハブの中に検証するものとしないものがあるとみられる（推測） |
| H4 | 同上 | 同上 | 「We even built our platform to stay safe if someone manages to get access to your home network.」 | 判断不能 | 同上 | 文書 B | — | 方法を書かない約束 |
| H5 | LAN のアプリ | アプリ（192.168.0.151）とハブの 8888 番で TLS（34 回）。アプリが警告（certificate_unknown）を返す接続がある（10 回） | 「We use certification encryption for all personalized data transmitted by the app」 | 一致（見えた範囲で） | `eth1-20180321.1835.1521675300` 2018-03-21 18:38:57.616854 | 文書 B | 中 | 中身は見えない |
| H6 | 探索 | SSDP で `https://192.168.0.52:8888` を告知（約 12 万回） | 記載なし | 公式文書に記載なし | 全期間 | — | 高 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- H3：偽の証明書の接続の半分で、ハブがデータを送った（作成者の能動的な検査）。
- H2、H6。

## 4. 公式文書と一致した事項

- H1（インターネットへの通信はすべて TLS）、H5（見えた範囲で）。

## 5. 観測不能・判断不能な事項

- H4（評価の言葉）。偽の証明書の接続でハブが送ったデータの中身。

## 6. 追加調査に必要なデータ

- Wink の pinning がどこで使われているかを書いた文書（見つからなかった）。
- 作成者の中間者の検査の手順。

## 断定できる範囲／できない範囲

- **断定できる**：偽の証明書の 42 の接続のうち 21 でハブがデータを送ったこと。ふだんのインターネットへの通信はすべて TLS だったこと。
- **断定できない**：文書の「certificate pinning」がハブのこの接続に当てはまるか。

## 前回との違い

- 前回は「食い違いの候補（T2、証明書の検証）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。数（42 のうち 21）は今回の取り直しでも同じ。
