# 16. Somfy のスマートロックのゲートウェイ（IoT-23）

[一覧に戻る](README.md)

**2026-11-26 に外付けディスクの IoT-23（7-1、Somfy-01〜06）で確かめ直した**（下の「確かめ直し」の節）。表の観測は前回の記録と同じ結果だった。

## 不足している情報（分析の前に）

- ロックとゲートウェイの機種、ファームウェア：**未確認**（ゲートウェイの名乗りは `ESP_1E7654` だけ。Espressif の OUI）。
- 比べる文書が収録（2019-07）の約 27 か月前（2017-04）のもの。収録の時点の製品ページは、セットのページについては見つからなかった（ロック単体のページは 2019-07-22 の保存があり、収録の後）。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Somfy Connected Doorlock（Serrure connectée）と Internet gateway（Passerelle）。機種は未確認 |
| MAC | 5c:cf:7f:1e:76:54（ゲートウェイ） |
| 収録 | IoT-23 CTU-Honeypot-Capture-7-1（2019-07-03〜08、6 本。最初のファイル名は `first_start_somfy_gateway`） |
| 観測できた通信フェーズ | ゲートウェイの初回の起動、クラウドとの常時接続 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | 直営店の「ロックとゲートウェイのセット」のページ | Somfy（boutique.somfy.fr） | [2017-04-03](https://web.archive.org/web/20170403111106/http://boutique.somfy.fr:80/serrure-connectee-passerelle-connectee.html) | 収録の約 27 か月前 |
| B | ロックの製品ページ | Somfy（somfy.fr） | [2017-01-26](https://web.archive.org/web/20170126155738/https://www.somfy.fr/produits/acces/serrure-connectee) | 収録前 |
| C | 直営店のロックのページ | Somfy | [2019-07-22](https://web.archive.org/web/20190722012908/https://boutique.somfy.fr/serrure-connectee.html) | 収録の直後（参考） |
| D | ゲートウェイの説明書（英語） | Somfy | [2024-02-16](https://web.archive.org/web/20240216160601/https://service.somfy.com/downloads/ac_v5/somfypasserelle-pourserrureconnectee_notice_eng.pdf) | 収録の後（参考） |

- 文書 A：「• Connexion sécurisée par cryptage normé AES 256」
- 文書 B：「Connexion Smartphone/Serrure cryptée AES 256 similaire au cryptage des cartes bancaires」「la communication entre la serrure connectée et l’application mobile est dotée du cryptage sécurisé AES256」

**最も限定的な読み方**：A の「Connexion sécurisée」は、どの接続か書いていない。同じ会社の B は、AES 256 をスマートフォンとロックの間（Bluetooth）としている。限定的に読むと、A も B と同じスマートフォンとロックの接続を指す。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実（前回） | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| G1 | ゲートウェイとクラウド | `somfykeys.opendoors.net` と TLS。4 回の握手すべてで `TLS_RSA_WITH_AES_128_CBC_SHA256`（前方秘匿性なし）。ゲートウェイは RSA 鍵交換の暗号だけを 8 種類提示し、1 番目は AES-256。証明書は `*.opendoors.net`（GoDaddy）。SNI なし | 「Connexion sécurisée par cryptage normé AES 256」 | 公式文書に記載なし | `Somfy-01/…first_start_somfy_gateway.pcap` フレーム 440〜447（前回確認） | 文書 A | 中 | A をゲートウェイの接続と読むのは拡大解釈なので、とらない。とれば条件付きの矛盾 |
| G2 | スマートフォンとロック | Bluetooth は収録にない | 「Connexion Smartphone/Serrure cryptée AES 256」 | 観測不能 | — | 文書 B | — | |
| G3 | ゲートウェイの常時接続 | 通信の大半は、1 日続く 1 本の TLS 接続（18.195.134.106:443） | 「With the gateway, your doorlock will be automatically synchronised with the server …」 | 一致（参考） | 同上 | 文書 D（収録の後） | 低 | 文書が収録の後 |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- G1：ゲートウェイとクラウドの TLS は AES-128、前方秘匿性なし。

## 4. 公式文書と一致した事項

- G3（参考。文書が収録の後）。

## 5. 観測不能・判断不能な事項

- G2（Bluetooth）。

## 6. 追加調査に必要なデータ

- IoT-23 の取り直し（配布元が戻ったとき）。
- 収録の時点（2019 年）の、ゲートウェイの暗号化を説明した Somfy の文書。

## 断定できる範囲／できない範囲

- **断定できる**（前回の確認による）：ゲートウェイの TLS で選ばれた暗号は AES-128 だったこと。
- **断定できない**：Somfy の「AES 256」がゲートウェイの接続を指すか。

## 前回との違い

- 前回は「弱い候補（T2）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。

## 確かめ直し（2026-11-26）

- **確認**：6 日で `somfykeys.opendoors.net`（18.195.134.106、35.157.240.102）の 443 番へ TLS の接続が 9 本（上り 44.8 MB、下り 95.4 MB）。握手が見えた 4 回は TLS 1.2 の `TLS_RSA_WITH_AES_128_CBC_SHA256`。機器の提示は 8 種の RSA の暗号（1 番目は `TLS_RSA_WITH_AES_256_CBC_SHA256`）と再交渉の印（SCSV）。証明書は `*.opendoors.net`（Go Daddy G2、2018-05-16〜2019-09-05、名前は一致）。平文は `0.europe.pool.ntp.org` への NTP だけ。最初の ClientHello は `Somfy-01/2019-07-03-15-15-47-first_start_somfy_gateway.pcap` 2019-07-03 13:25:04.800862。判定は変わらない。
