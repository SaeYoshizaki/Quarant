# 12. August Doorbell Cam（YourThings、2018-03〜04）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- ファームウェア、アプリの版：**未確認**（機器の証明書の名前は「August Doorbell Cam 2.0」）。
- データセットの作成者の中間者の検査（2018-04-10〜13）の手順の詳細：**未確認**。下の A3 はその最中の通信。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | August Doorbell Cam（DHCP のホスト名 `August-Doorbell-Cam-D2GTH00390`、機器の証明書の名前 `August Doorbell Cam 2.0`） |
| MAC・IP | cc:b8:a8:ad:4d:04、192.168.0.36 |
| 収録日時（UTC） | 03-20、03-21、04-11、04-12、04-13（取り直した 5 日） |
| データセット | YourThings |
| 観測できた通信フェーズ | クラウドとの常時接続、PubNub のメッセージ、映像のサーバー、録画の保存（S3）、中間者の検査の最中の通信 |

**使用した公式文書**

| # | 文書 | 発行元 | 更新 | 保存 | 収録との関係 |
|---|---|---|---|---|---|
| A | Privacy Policy | August Home | 2017-09-20 | [2018-04-07](https://web.archive.org/web/20180407050015/http://august.com/legal/privacy-policy/) | 収録中 |

- 文書 A：「We follow generally-accepted industry standards to protect the PII submitted to us, both during transmission and once we receive it.」「However, no method of transmission over the Internet, or method of electronic storage, is 100% secure.」
- 製品ページ・サポートの文書には、通信の暗号化の記載が見つからなかった（claims.tsv 210〜317 行、「no security claim」）。

**最も限定的な読み方**：対象は利用者が送った PII。「generally-accepted industry standards」は方法を書いていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| A1 | クラウドとの常時接続 | `doorbells.august.com:443` へ TLS 1.2（5 日で 8,276 接続、約 56 秒おき）。`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`。サーバーも機器も August 自身の認証局の証明書を出す相互認証 | 「generally-accepted industry standards to protect the PII … during transmission」 | 判断不能 | `eth1-20180320.0000.1521522000` 2018-03-20 00:00:21.718468 | 文書 A | — | 方法を書かない約束。TLS で守られている、という観測にとどまる |
| A2 | 映像と録画 | `*.video-cloud.net`、`s3-us-west-2.amazonaws.com`、rackcdn などへ TLS。映像のサーバー（`rpsv*.video-cloud.net`）は TLS 1.0（`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`）、ほかは TLS 1.2 | 同上 | 判断不能 | `eth1-20180320.0025.1521523500` 2018-03-20 00:25:42.753310 ほか | 文書 A | — | |
| A3 | 中間者の検査の最中 | 2018-04-11 20:28:36 から、作成者の偽の証明書（発行者 `thing-catcher.gtisc.gatech.edu`）の接続が始まり、機器の接続がいっせいに切れた。その約 2 秒後から、普段は TLS の `august.pubnub.com` へ、**平文の HTTP** で `GET /publish/pub-c-…/sub-c-…?uuid=…&auth=…&pnsdk=PubNub-C-core/2.2` を 3 回（`auth` は PubNub の秘密の鍵の形、値は quarant-results） | 同上 | 公式文書に記載なし | `eth1-20180411.2025.1523496300` 2018-04-11 20:28:36.893086（最初の偽の証明書）、20:28:38.662553・20:28:38.857232（平文の publish）、`eth1-20180411.2030.1523496600` 20:32:42.167797 | 文書 A | 高 | TLS が使えないときに平文に切り替えたとみられる（推測）。送った値は鍵と ID で、利用者の PII ではない（最も限定的な読み方） |
| A4 | 中間者の検査への反応 | 映像のサーバーへの偽の証明書には、機器が警告（unknown_ca）を返して切った。前回の記録では、偽の証明書の接続 10 回のうち 5 回で機器がデータを送った | 記載なし（証明書の検証の文はない） | 公式文書に記載なし | `eth1-20180411.2025.1523496300` ほか | — | 中 | 作成者の能動的な検査の結果を読んだもの |
| A5 | 普段の PubNub | `august.pubnub.com:443` へ TLS 1.2（3,573 接続） | — | 一致（参考） | `eth1-20180320.0000.1521522000` 2018-03-20 00:03:09.965008 | — | 高 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- A3：TLS の接続が妨げられた直後に、PubNub への送信を平文の HTTP に切り替え、鍵の形の値を平文で送った（フォールバックとみられる）。
- A4、A2 の TLS 1.0。

## 4. 公式文書と一致した事項

- A5（参考）。

## 5. 観測不能・判断不能な事項

- A1、A2（評価の言葉の約束）。TLS の中身。

## 6. 追加調査に必要なデータ

- 中間者の検査の手順（データセットの作成者の説明）。

## 断定できる範囲／できない範囲

- **断定できる**：偽の証明書の接続が始まった約 2 秒後に、PubNub への平文の HTTP の送信が 3 回あったこと。普段は TLS だったこと。
- **断定できない**：平文への切り替えが、TLS の失敗によるものか（時間が重なることだけが根拠）。

## 前回との違い

- 前回は「食い違いの候補（T1a）」。新しい決まり（評価の言葉、PII に限る読み方）で「判断不能」「公式文書に記載なし」にした。
- 平文の送信が、中間者の検査が始まった直後に起きていたことを新しく確かめた。
