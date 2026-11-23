# 22. Google Nest Mini（CIC IoT 2022）

[一覧に戻る](README.md)

**今回はパケットを取り直していない**（CIC IoT 2022 は利用者の判断で外した）。観測は前回の記録（[compare-sweep.md](../compare-sweep.md)、claims.tsv 1439〜1461 行）による。Passive-Mode-Study にも Nest Mini がいる（[pms.md](../pms.md)。今回の 24 件には入っていない）。

## 不足している情報（分析の前に）

- ファームウェアの版：**未確認**。
- 比べる文書の中心（NCC Group の ioXt の報告）は、保存が収録の後（2022-01-31）。収録の時点で公開されていたかは**未確認**。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Google Nest Mini |
| MAC | cc:f4:11:9c:d0:00 |
| 収録 | CIC IoT 2022（カナダ、2021-10〜12） |
| 観測できた通信フェーズ | 待機、音声アシスタントの操作 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | ioXt の評価報告（Nest Mini） | NCC Group が作成、Google が掲載 | [2022-01-31](https://web.archive.org/web/20220131005844/https://storage.googleapis.com/support-kms-prod/aUdYcY7JigJgD1vsMuMZujo4QqahlGthh6xi) | 収録の後 |
| B | Google のプライバシーポリシー（カナダ） | Google | [2021-11-27](https://web.archive.org/web/20211127004737/https://policies.google.com/privacy?hl=en-CA) | 収録中 |
| C | Nest のヘルプ（フランス語） | Google | 2021-02-26（claims.tsv 1454 行） | 収録前 |
| D | Nest のヘルプ（英語） | Google | [2022-01-31](https://web.archive.org/web/20220131070838/https://support.google.com/product-documentation/answer/9293126?hl=en&ref_topic=10123615) | 収録の後 |

- 文書 A：「all BLE and WLAN communication was secured using best-practices, namely up-to-date TLS」「Establish that wherever TLS is used, it is version 1.2 or greater.」
- 文書 B：「We use encryption to keep your data private while in transit」
- 文書 C：「Les produits Nest ne transmettent jamais de données personnelles non chiffrées via Internet.」

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実（前回） | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| M1 | 待機・操作 | 送信の 71% が TLS（1,168 回の握手、すべて TLS 1.3、`TLS_AES_128_GCM_SHA256`）、23% が QUIC | 「wherever TLS is used, it is version 1.2 or greater」 | 判断不能（文書が収録の後）。参考として一致 | CIC の Nest Mini の全ファイル（前回） | 文書 A | 中 | |
| M2 | 接続確認 | 平文は中身のない `HEAD connectivitycheck.gstatic.com` だけ（1 日約 0.5 MB） | 「all BLE and WLAN communication was secured … up-to-date TLS」 | 判断不能（文書が収録の後） | 同上 | 文書 A | 低 | 文書が収録の時点のものなら、「all … communication」と平文の接続確認は両立しない（参考） |
| M3 | 全体 | 個人のデータを含む平文は見えない | 「ne transmettent jamais de données personnelles non chiffrées」 | 一致 | 同上 | 文書 C | 中 | |
| M4 | 全体 | 同上 | 「We use encryption to keep your data private while in transit」 | 一致 | 同上 | 文書 B | 中 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし（M2 は文書の時点が条件。収録の時点の文書ではないので「判断不能」にした）。

## 3. 公式文書に記載のない観測事項

- QUIC の利用（文書 A は TLS だけを書く）。

## 4. 公式文書と一致した事項

- M3、M4。

## 5. 観測不能・判断不能な事項

- M1、M2（収録後の文書）。音声の扱い。

## 6. 追加調査に必要なデータ

- ioXt の報告が収録の時点（2021-10〜12）で公開されていたことを示す資料（報告の日付は 2021-06）。
- CIC の取り直し。

## 断定できる範囲／できない範囲

- **断定できる**（前回の確認による）：平文は中身のない接続確認だけだったこと。
- **断定できない**：収録の時点で文書 A が有効だったか。

## 前回との違い

- 前回は「文言の上での食い違い（T1b）」。新しい決まり（収録後の文書は参考に分ける）で「判断不能」にした。
