# 2. SimCam 1S（CIC IoT 2022）

[一覧に戻る](README.md)

**2026-11-26 に外付けディスクの CIC IoT 2022 で確かめ直した**（対象の 8 台の通信を切り出して `profile.py` で調べた。下の「確かめ直し」の節）。表の観測は前回（2026-11-02〜16）の記録と同じ結果だった。

## 不足している情報（分析の前に）

- ファームウェアとアプリの版：**未確認**。
- 画像の送り先（S3 のバケット `elasticbeanstalk-us-east-2-793503604989`）の持ち主：**未確認**。Simshine のものか、利用者が設定した送り先か（SimCam には利用者が自分のサーバーを設定できる「open platform」がある、文書 F）。
- 送った画像がクラウドに残るか（保存か、中継だけか）：**未確認**。
- ライブ映像の経路：前回の記録にない（**未確認**）。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | SimCam 1S（Simshine、SimCam Alloy 1S とも）。CIC の機器一覧の名前 |
| MAC | 10:2c:6b:1b:43:be |
| ハードウェア／ファームウェア／アプリ | 未確認 |
| 収録日時 | 2021-11-02（CIC の Active の日、`2021_11_02_Active.pcap`） |
| データセット | CIC IoT Dataset 2022（カナダ、ニューブランズウィック大学） |
| 観測できた通信フェーズ | 人物検知のときの画像の送信。カメラは TLS を一度も使っていない |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | SimCam 1S の製品ページ | Simshine（simcam.ai） | [2020-08-08](https://web.archive.org/web/20200808135742/https://www.simcam.ai/simcam-1s) | 収録の約 15 か月前 |
| B | SimCam 1S の FAQ | Simshine（simshine.ai） | [2021-10-24](https://web.archive.org/web/20211024050725/https://simshine.ai/simcam-1s/faq.html) | 収録中 |
| C | SimHome アプリのプライバシーポリシー | Simshine（simcam.ai） | [2021-10-06](https://web.archive.org/web/20211006132807/https://www.simcam.ai/simhome-eprivacy) | 収録中 |
| D | SimCam Alloy 1S の製品ページ | Simshine | 2021-10-06（claims.tsv 828〜833 行） | 収録中 |
| E | 同上（以前の版） | Simshine | 2021-01-24（claims.tsv 836、837 行） | 収録前 |
| F | SimCam open platform の説明 | Simshine | 2021-04-13（claims.tsv 873 行） | 収録前 |

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| S1 | 人物検知 | 人が写った JPEG（22〜25 KB）を、平文の HTTP の PUT で Amazon S3 のバケット（パス `/SimCam/<id>/PersonDetect/<id>`）に 15 回送った。署名つき（AWS4-HMAC-SHA256、アクセスキー ID は quarant-results） | 「Unlike cloud-based cameras, SimCam 1S never collects user data or shares it with other parties.」 | 条件付きの矛盾 | `2021_11_02_Active.pcap` フレーム 1234〜631073（前回確認） | 文書 A | 中 | 条件：送り先が利用者の設定した場所でないこと。送り先が Simshine なら「collects」に、ほかの会社なら「shares」に当たる |
| S2 | 同上 | 同上 | 「No. Because the Simshine ® Simcam 1S uses entirely local AI processing, we never have access to your data.」 | 条件付きの矛盾 | 同上 | 文書 B | 中 | 条件：送り先のバケットを Simshine が使えること（持ち主は未確認） |
| S3 | 同上 | 同上 | 「Everything is processed and stored locally on the device with a bank-level encryption.」 | 条件付きの矛盾 | 同上 | 文書 A | 中 | 条件：送った画像がバケットに残ること（PUT は保存の操作だが、残る期間は見えない）。「処理」はカメラの中とみられ、矛盾しない |
| S4 | 同上 | 同上 | 「When you synchronize Simshine products data, your image data will be transferred to your mobile device via the server.」 | 一致 | 同上 | 文書 C | 中 | 画像がサーバーを通ることは開示されている |
| S5 | 同上 | 画像は平文で送られた | 「implement safeguards such as storage and transmission of full security encryption」 | 公式文書に記載なし | 同上 | 文書 C | 中 | 「such as」の例示で、すべての送信を暗号化するとは言い切っていない（最も限定的な読み方）。画像の送信も対象と広く読めば矛盾 |
| S6 | 同上 | 同上 | 「Both your account and the video stream are secured with bank-level encryption.」 | 公式文書に記載なし | 同上 | 文書 D | 中 | 対象は「video stream」。静止画の送信は書いていない（限定的な読み方） |
| S7 | ライブ映像 | 前回の記録にない | 「The live videos are streamed directly into your phone on a secured P2P (peer-to-peer) network without going through a server.」 | 判断不能 | — | 文書 B | — | |
| S8 | すべて | カメラは TLS を一度も使っていない（前回の記録） | 記載なし | 公式文書に記載なし | `2021_11_02_Active.pcap` 全体（前回） | — | 中 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

- S1〜S3。どれも「画像の送り先が誰のものか」「残るか」が分からないことが条件になる。送り先が Simshine の設備で、画像が残るなら、明確な矛盾になる。

## 3. 公式文書に記載のない観測事項

- S5・S6（静止画の平文の送信。文書の約束は例示や動画に限られる）、S8。

## 4. 公式文書と一致した事項

- S4（画像がサーバーを通ることは、アプリのポリシーに書いてある）。

## 5. 観測不能・判断不能な事項

- S7（ライブ映像）。保存時の暗号化（「bank-level encryption」）。

## 6. 追加調査に必要なデータ

- CIC IoT 2022 の取り直し（ライブ映像のファイル、ファームウェアの手がかり）。
- バケットの持ち主（Simshine の技術文書、アプリの通信）。
- 利用者の設定（open platform を使っていたか）。

## 断定できる範囲／できない範囲

- **断定できる**（前回の確認による）：人が写った画像が平文の HTTP でクラウドの保存先に送られたこと。
- **断定できない**：送り先が Simshine のものか、画像が残るか。今回はパケットを取り直していない。

## 確かめ直し（2026-11-26）

- **確認**：`2021_11_02_Active.pcap` の 2021-11-02 11:15:13.284857 から、人物検知の JPEG の平文の `PUT` が 15 回（`elasticbeanstalk-us-east-2-793503604989.s3.amazonaws.com/SimCam/0x972f85c7e3/PersonDetect/…`、User-Agent `Mozilla/4.0 (Compatible; s3; libs3 4.1; Linux aarch64)`）。カメラは 47 日のどの日も TLS を使っていない。
- **新しく見えたこと**（どれも「公式文書に記載なし」）：
  - `www.luuka.fun` へ平文の `POST`：`/event/event/saveEvents`（16 回）、`/push/push/pushMessage`（16 回）、`/ota/ota/getNewVersion`（7 回）。本文は `data=` のあとの Base64 で、中身は読めない（暗号化されているかは未確認）。最初は `2021_11_02_Active.pcap` 2021-11-02 11:15:12.886044。
  - 毎時、外部のサービスで自分のグローバルの IP を調べる：`ipinfo.io/ip`、`icanhazip.com`、`myip.ipip.net/ip`、`ip.cip.cc`（各 347 回、47 日）。最初は `1-Power/…/simcamPOWER_1.pcap` 2021-09-22 16:17:48.642169。
  - 4 つの外のサーバー（62.210.208.47、139.162.61.175、45.35.33.242、198.255.24.202）の UDP 10001 番へ、12 バイトと 296 バイトの小さなパケットを途切れなく送る（中身は読めない）。映像の大きさではなく、P2P のつなぎ役のサーバーとの定期の通信とみられる（推測）。`54.202.68.76` の tcp/9999 にも定期の接続（79 回、中身は読めない）。
- ライブ映像（S7）は、この収録には見えなかった（判断不能のまま）。判定は変わらない。
