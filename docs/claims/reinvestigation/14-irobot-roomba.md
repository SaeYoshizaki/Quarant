# 14. iRobot Roomba（CIC IoT 2022）

[一覧に戻る](README.md)

**今回はパケットを取り直していない**（CIC IoT 2022 は利用者の判断で外した）。観測は前回の記録（[compare-sweep.md](../compare-sweep.md)、claims.tsv 1465〜1482 行）による。

## 不足している情報（分析の前に）

- 機種：**未確認**（機器の名乗りは DHCP のホスト名 `iRobot-<BLID>` だけ）。ファームウェア、アプリの版も**未確認**。
- TLS 1.3 の接続では証明書が暗号化されていて、機器の証明書（「identities … validated」）は見えない。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | iRobot Roomba（機種未確認） |
| MAC | 50:14:79:37:80:18 |
| 収録 | CIC IoT 2022（カナダ、2021-10〜12） |
| 観測できた通信フェーズ | クラウドとの接続（TLS）、時刻合わせ |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Data Security（すべての製品が対象） | iRobot（irobot.com/legal/data-security） | [2021-12-06](https://web.archive.org/web/20211206234053/https://www.irobot.com/legal/data-security) | 収録中 |
| B | プライバシーの FAQ | iRobot | 2021-03-11（claims.tsv 1479〜1482 行） | 収録前 |

文書 A：「All iRobot connected products communicate with the iRobot cloud service using robust encryption.」「Currently, we use AES 256-bit encryption and Transport Layer Security (TLS v1.2).」「The data is encrypted both in transit and at rest.」「All iRobot connected products have identities when they come out of the factory and those identities are validated upon each new cloud connection.」

**最も限定的な読み方**：「we use AES 256-bit encryption and Transport Layer Security (TLS v1.2)」は、AES-256 と TLS 1.2 を使っていると言っているが、AES-256 が TLS の中の暗号だとは書いていない（同じページは保存時の暗号化にも触れている）。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実（前回） | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| R1 | クラウド接続 | 2.8 MB の 95% が TLS、残りは NTP | 「communicate with the iRobot cloud service using robust encryption」「encrypted … in transit」 | 一致 | CIC の Roomba の全ファイル（前回） | 文書 A | 中 | |
| R2 | 同上 | 34 回の握手すべてで AES-128-GCM（TLS 1.3 の `TLS_AES_128_GCM_SHA256` が 20 回、TLS 1.2 の `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` が 14 回）。AES-256 は一度も選ばれていない | 「Currently, we use AES 256-bit encryption and Transport Layer Security (TLS v1.2).」 | 公式文書に記載なし | 同上 | 文書 A | 中 | 文は AES-256 が TLS の中の暗号だとは言っていない（最も限定的な読み方）。通信の暗号と広く読めば矛盾 |
| R3 | 同上 | TLS 1.2 は 14 回、TLS 1.3 は 20 回 | 「Transport Layer Security (TLS v1.2)」 | 一致 | 同上 | 文書 A | 中 | TLS 1.3 も使っているが、TLS 1.2 を使っていることとは両立する |
| R4 | 機器の認証 | TLS 1.3 では証明書が見えない。TLS 1.2 の接続での機器の証明書は前回の記録にない | 「identities … validated upon each new cloud connection」 | 観測不能 | — | 文書 A | — | |
| R5 | 地図・画像 | 中身が暗号化されていて見えない | 「Images used for navigation are NOT sent to the Cloud.」 | 観測不能 | — | 文書 B | — | |
| R6 | 時刻合わせ | 平文の NTP | 記載なし | 公式文書に記載なし | 同上 | — | 中 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- R2：選ばれた暗号はすべて AES-128（文書の AES-256 が通信のことなら矛盾になるが、その読み方はとらない）。
- R6。

## 4. 公式文書と一致した事項

- R1、R3。

## 5. 観測不能・判断不能な事項

- R4、R5、保存時の暗号化。

## 6. 追加調査に必要なデータ

- CIC の取り直し（TLS 1.2 の接続の証明書、機種の手がかり）。
- iRobot の技術文書で、AES-256 が何を指すか。

## 断定できる範囲／できない範囲

- **断定できる**（前回の確認による）：選ばれた暗号がすべて AES-128 だったこと。
- **断定できない**：文書の AES-256 が通信のことか。
