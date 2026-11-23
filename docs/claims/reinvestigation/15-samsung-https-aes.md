# 15. Samsung（Hanwha）SmartCam の HTTPS の暗号（UNSW 2018、Deakin、UNSW-IoTraffic）

[一覧に戻る](README.md)

項目 1（SNH-P6410BN）と項目 4（SNH-V6410PN）のうち、「Security SSL (AES 256bit)」と、HTTPS で選ばれた暗号の比較だけをまとめた。UNSW 2018 と Deakin は今回取り直して調べた。UNSW-IoTraffic は取り直していない（前回の記録）。

## 不足している情報（分析の前に）

- 「SSL (AES 256bit)」が、カメラのどの通信を指すか（文書に書いていない）。
- ファームウェアの版（どちらの機種も未確認）。

## 調査対象と前提条件

| 項目 | SNH-P6410BN | SNH-V6410PN |
|---|---|---|
| データ | UNSW 2018（2018-05〜10、今回）、UNSW-IoTraffic（2016-17、前回） | Deakin（2023-07〜2024-05、今回） |
| MAC | 00:16:6c:ab:6b:88 | 00:16:6c:d7:d5:f9 |
| 詳しい報告 | [1](01-samsung-smartcam-snh-p6410bn.md) | [4](04-samsung-snh-v6410pn.md) |

**使用した公式文書**

| # | 文書 | 保存 | 収録との関係 |
|---|---|---|---|
| A | SNH-P6410BN のデータシート「Security SSL ( AES 256bit )」 | [2016-06-23](https://web.archive.org/web/20160623235657/https://www.samsung-security.com/SAMSUNG/upload/Product_Specifications/SNH-P6410BN_Datasheet.pdf) | UNSW 2018 の前 |
| B | SNH-V6410PN の製品ページ「Security SSL (AES 256bit)」 | [2023-12-01](https://web.archive.org/web/20231201065137/https://www.wisenetlife.com/en-us/product/SmartCam/SNH-V6410PN_W/feature) | Deakin の収録中 |
| C | SmartCam の仕様（別の機種、productId 6502）「Security SSL (AES 256bit)」 | [2017-09-21](https://web.archive.org/web/20170921164538/http://www.samsungsmartcam.com/web/cmm/02_SP/Specifications.do?productId=00000000000000006502) | IoTraffic の収録の後（参考） |

**最も限定的な読み方**：「SSL と AES-256 を使う」。すべての SSL の接続で AES-256 になるとは書いていない。

## 比較結果

| ID | データ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| E1 | UNSW 2018 | XMPP（5222 番、STARTTLS のあと）は `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`（TLS 1.0） | 「Security SSL ( AES 256bit )」 | 一致 | `18-05-28.pcap` 2018-05-28 05:59:57.988401 | 文書 A | 高 | |
| E2 | UNSW 2018 | HTTPS（`media.samsungsmartcam.com:443`）は `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`（TLS 1.0、22 回）。カメラは AES-256 の暗号も出していた | 同上 | 公式文書に記載なし | `18-05-28.pcap` 2018-05-28 05:59:59.718393 | 文書 A | 高 | AES-256 はサーバーの選択で使われなかった。「すべての接続で AES-256」と広く読めば矛盾 |
| E3 | Deakin | XMPP は `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`（TLS 1.2） | 「Security SSL (AES 256bit)」 | 一致 | `2023-07-31.pcap` 2023-07-30 15:59:05.065586 | 文書 B | 高 | |
| E4 | Deakin | HTTPS（`media.samsungsmartcam.com:443`）は `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`（TLS 1.2） | 同上 | 公式文書に記載なし | `2023-07-31.pcap` 2023-07-30 15:59:07.069315 | 文書 B | 高 | E2 と同じ |
| E5 | IoTraffic（前回） | HTTPS の 65 回の握手はすべて AES-128（TLS 1.0、`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`） | 同上 | 公式文書に記載なし | `BelkinCamera_b4750eece5a9.pcap` など（前回） | 文書 A | 中 | 取り直していない |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- E2、E4、E5：HTTPS の接続はどの年も AES-128（サーバーの選択）。

## 4. 公式文書と一致した事項

- E1、E3：XMPP の接続は AES-256。

## 5. 観測不能・判断不能な事項

- 「SSL (AES 256bit)」がどの通信を指すか。

## 6. 追加調査に必要なデータ

- 仕様の「Security」の行が何を指すかを説明した Hanwha の文書（見つからなかった）。

## 断定できる範囲／できない範囲

- **断定できる**：XMPP は AES-256、HTTPS は AES-128 だったこと（2016〜2024 年）。
- **断定できない**：仕様の行が HTTPS まで含むか。

## 前回との違い

- 前回は「弱い候補（T2）」。新しい決まり（最も限定的な読み方）で、AES-256 を使う接続（XMPP）があるので「一致」、HTTPS の AES-128 は「公式文書に記載なし」にした。
