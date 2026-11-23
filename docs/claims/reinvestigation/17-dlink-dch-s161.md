# 17. D-Link DCH-S161 水漏れセンサー（CIC IoT 2022）

[一覧に戻る](README.md)

**今回はパケットを取り直していない**（CIC IoT 2022 は利用者の判断で外した）。観測は前回の記録（[compare-sweep.md](../compare-sweep.md)、claims.tsv 1074〜1079 行）による。

## 不足している情報（分析の前に）

- ハードウェア・ファームウェアの版：**未確認**（更新の確認の応答の中身は前回の記録にない）。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | D-Link DCH-S161（mydlink Wi-Fi Water Sensor） |
| MAC | f0:b4:d2:f9:60:95 |
| 収録 | CIC IoT 2022（カナダ、2021-10〜12）、待機の日 |
| 観測できた通信フェーズ | 待機中のクラウド接続、ファームウェアの更新の確認 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Privacy Policy（米国） | D-Link（us.dlink.com/en/privacy-policy） | [2021-11-28](https://web.archive.org/web/20211128062831/https://us.dlink.com/en/privacy-policy) | 収録中 |
| B | mydlink のプライバシー（アプリ内の文書） | D-Link | [2019-05-20](https://web.archive.org/web/20190520235623/https://d1rvtd08ngd4ef.cloudfront.net/new+mydlink/privacy_and_tos/js/lang/privacy_lang.js) | 収録前 |

- 文書 A：「When you are ordering Services via our site, we use the Internet encryption protocol Secure Sockets Layer (SSL) to help protect the security of your personal information. The SSL protocol is also implemented for (i) guarding your account information, and (ii) better securing all logs of settings and Services of your devices.」
- 文書 A：「Technical information from the Product: … By collecting technical information we are better able to troubleshoot …」

**最も限定的な読み方**：SSL の対象は「注文」「アカウントの情報」「機器の設定とサービスのログ」。ファームウェアの更新の確認はログではない（[18. D-Link DCS-8300LH](18-dlink-dcs8300lh.md) と同じ読み方）。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実（前回） | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| W1 | 待機中のクラウド接続 | 送信の 95.2% が TLS（45 回の握手、`TLS_RSA_WITH_AES_128_CBC_SHA`、前方秘匿性なし） | SSL を設定とサービスのログに使う | 一致 | CIC の DCH-S161 の待機の日（前回） | 文書 A・B | 中 | 中身がログかは見えない |
| W2 | 更新の確認 | `GET http://mp-us-fwd.auto.mydlink.com/fw-upgrade?device_id=F0B4D2F96095`（機器の MAC）を平文で 32 回 | 記載なし | 公式文書に記載なし | `2-Idle/2021_12_16_Idle.pcap` フレーム 462331〜466813 ほか（前回確認） | 文書 A に該当なし | 中 | 「Services of your devices」を広く読めば食い違いだが、その読み方はとらない |
| W3 | 同上 | 平文の要求に機器の MAC | 「Technical information from the Product」を集める | 一致（集めること） | 同上 | 文書 A | 中 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- W2：ファームウェアの更新の確認が平文で、MAC を含む。

## 4. 公式文書と一致した事項

- W1、W3。

## 5. 観測不能・判断不能な事項

- TLS の中身。

## 6. 追加調査に必要なデータ

- CIC の取り直し（更新の確認の応答の中身、ファームウェアの版）。

## 断定できる範囲／できない範囲

- **断定できる**（前回の確認による）：更新の確認が平文で MAC を含んでいたこと。
- **断定できない**：それが文書の「ログ」に当たるか。

## 前回との違い

- 前回は「弱い候補（T1a）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。
