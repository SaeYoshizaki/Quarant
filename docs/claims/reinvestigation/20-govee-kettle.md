# 20. GoveeLife Smart Electric Kettle H7171（Passive-Mode-Study、米国 US1）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- アプリ（Govee Home）の版：アプリの通信は収録にない。**未確認**。
- 利用者の操作（湯沸かし、通知の設定）：記録がない。2024-02-01 の通知（G5）が何のきっかけかは**未確認**。
- ファームウェアの更新を利用者が許可したか（自動か）：**未確認**。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | GoveeLife Smart Electric Kettle、型番 H7171（機器が平文の要求の `sku` で名乗る） |
| MAC・IP | 60:74:f4:1b:24:16、192.168.1.112 |
| ハードウェア／ファームウェア | ハードウェア 1.02.00、ファームウェア 1.00.07 → 1.00.10（2023-11-07 に更新、下の G3）。どちらも機器が平文の要求で名乗った値（`wifiVersionHard`、`wifiVersionSoft`） |
| アプリ | 未確認 |
| 収録日時（UTC） | US1-Capture1：2023-11-01 23:00〜11-08 22:59。US1-Capture2：2024-05-01〜05-09。拡張版の Idle：2024-01-30〜02-01、Aligned Passive：2024-05-06〜05-09（機器の通信は 19 日） |
| データセット | Passive-Mode-Study（`Percom116Dataset/US1`、`ExtendedPaperDataset`）。米国の家庭 |
| 観測できた通信フェーズ | 待機中の版の確認と設定の取得（約 143 秒の中央値の間隔）、MQTT（TLS）、ファームウェアの更新、時刻合わせ、通知 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Govee Home のプライバシーポリシー（アプリ内のページ） | Shenzhen Intellirocks Tech（Govee） | [2023-04-06](https://web.archive.org/web/20230406151939/https://app-h5.govee.com/common/privacy) | 収録前 |
| B | 同上 | 同上 | [2023-12-07](https://web.archive.org/web/20231207113053/https://app-h5.govee.com/common/privacy) | US1-Capture1 の 1 か月後、ほかの収録の前。A と同じ文 |

文書 A の該当部分：
- 冒頭の約束の III：「We will use state-of-the-art data security tools to secure your data security and protect Govee Home products from unauthorized access.」
- 1 節：「… we need to collect the following information about you: device name, model, version, device identifier, MAC address, device running status, … The above information will be encrypted and saved to the server …」
- 4 節：「Govee Home … adopts physical, administrative, and technical protections to help maintain the integrity and security of all the information we collect …」

**最も限定的な読み方**：「encrypted and saved to the server」は保存の話として読み、送るときの暗号化までは約束していないとする。約束の III と 4 節は方法を書いていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| G1 | 待機中の版の確認 | `POST http://app.govee.com/device/rest/devices/v1/wifiCheckVersion` を平文で 125 回（19 日）。本文に `sku`（H7171）、`wifiVersionHard`、`wifiVersionSoft`、`device`（`19:BE:60:74:F4:1B:24:16`、末尾 6 バイトが MAC）、`timezoneID` | 機器の名前、型番、版、識別子、MAC を集め、「encrypted and saved to the server」 | 一致（集めることは書いてある）。送るときの暗号化は公式文書に記載なし | `US1-Capture1.pcap` 2023-11-02 02:28:44.331958（元のフレーム 43616） | 文書 A 1 節 | 高 | 「encrypted and saved」を送信の暗号化と読むのは拡大解釈なので、とらない |
| G2 | 待機中の設定の取得 | `POST http://app.govee.com/bff-device/v1/config/gateway/group` を平文で 125 回。本文に `device`、`timeStamp`、`saltVersion`、`sign`（署名、値は quarant-results） | 同上 | 一致（集めること）／送信は公式文書に記載なし | `US1-Capture1.pcap` 2023-11-02 02:28:44.396507（元のフレーム 43627） | 文書 A 1 節 | 高 | 要求には署名がある（改ざんの防止とみられる、推測） |
| G3 | ファームウェアの更新 | `GET http://s3.amazonaws.com/govee-public/upgrade-pack/3c047f599c0220275ab63e2de2d35bf7-H7171_WIFI_BLE_HW1.02.00_SW1.00.10_OTA.bin` を平文の HTTP で取得（応答 206、`application/octet-stream`、852,100 バイト）。その後の版の確認で `wifiVersionSoft` が 1.00.07 から 1.00.10 に変わった | 記載なし（更新の配り方の文はない） | 公式文書に記載なし | `US1-Capture1.pcap` 2023-11-07 06:43:21.387382（要求、元のフレーム 1520664）、06:47:55.483658（1.00.10 の最初の確認） | 文書 A に該当なし | 高 | 署名や暗号化の有無は見えない（ファイルの中身は今回確かめていない） |
| G4 | 操作と状態（MQTT） | AWS IoT（`aqm3wd1qlc3dy-ats.iot.us-east-1.amazonaws.com:8883`）へ TLS 1.2。選ばれた暗号は `TLS_RSA_WITH_AES_128_CBC_SHA256`（前方秘匿性なし）、機器が出す暗号は 5 種。サーバー証明書 `*.iot.us-east-1.amazonaws.com`（Amazon RSA 2048 M01、名前は一致）。機器も「AWS IoT Certificate」を出す相互認証 | 「technical protections」 | 一致 | `US1-Capture1.pcap` 2023-11-07 06:44:33.864915（ClientHello） | 文書 A 4 節 | 中 | 方法が書かれていないので、一致は「保護がある」の範囲 |
| G5 | 通知 | `POST http://app.govee.com/device/v1/push/alert` を平文で 1 回。本文に `device`、`sku`、`type`（[11]）、`timeStamp`、`signature` | 「device running status … business events」を集める | 一致（集めること）／送信は公式文書に記載なし | `US1-idle-Govee.pcap` 2024-02-01 17:15:58.116562 | 文書 A 1 節 | 高 | `type` の意味は未確認 |
| G6 | 時刻合わせ | `ntp.aliyun.com`、`time.google.com`、`pool.ntp.org` へ平文の NTP | 記載なし | 公式文書に記載なし | `US1-Capture1.pcap` 2023-11-01 23:24:52.644049 ほか | 該当なし | 高 | |
| G7 | 全体 | インターネットへの送信のうち平文の HTTP は約 18%（前回の集計） | 「state-of-the-art data security tools to secure your data security and protect Govee Home products from unauthorized access」 | 判断不能 | 上の全期間 | 文書 A 約束の III | — | 方法を書かない評価の言葉で、観測と直接比べられない |
| G8 | アカウントのログイン | — | 「the Govee Home account username and login password … will be encrypted and transmitted」 | 観測不能 | アプリの通信は収録にない | 文書 A 1 節 | — | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。（G1・G2・G5 は、「encrypted and saved to the server」を送信の暗号化も含むと広く読む場合だけ食い違いになる。その読み方はとらない。）

## 3. 公式文書に記載のない観測事項

- G1・G2・G5：機器の識別子（MAC を含む）、型番、版、タイムゾーン、通知を平文の HTTP で送る。
- G3：ファームウェアを平文の HTTP で取得し、直後に版が上がった。
- G6。

## 4. 公式文書と一致した事項

- 集める情報の種類（G1・G2・G5）は文書に書いてある。
- MQTT は TLS（G4）。

## 5. 観測不能・判断不能な事項

- G7（評価の言葉）、G8（アプリ）。保存時の暗号化。

## 6. 追加調査に必要なデータ

- ファームウェアのファイルに署名があるか（取得したファイルの中身の確認。PCAP から取り出せる）。
- アプリの通信。
- Govee の更新の仕組みについての技術文書（見つからなかった）。

## 断定できる範囲／できない範囲

- **断定できる**：機器の識別子と版を平文の HTTP で送っていたこと。ファームウェアを平文の HTTP で取得し、その後に版が上がったこと。
- **断定できない**：更新のファイルが改ざんから守られているか。文書の「state-of-the-art」に反するか。

## 前回との違い

- 前回は「文言の上での食い違い（T1b）」。新しい決まり（評価の言葉だけでは食い違いにしない）で「判断不能」にした。
- 収録前の版（2023-04-06）を新しく確かめた。同じ文がある。
- 2024-02-01 の平文の通知（G5）を新しく見つけた。
