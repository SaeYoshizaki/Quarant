# 3. Eufy HomeBase 2 とドアベル（CIC IoT 2022）

[一覧に戻る](README.md)

**2026-11-26 に外付けディスクの CIC IoT 2022 で確かめ直した**（対象の 8 台の通信を切り出して `profile.py` で調べた。下の「確かめ直し」の節）。表の観測は前回（2026-11-02〜16）の記録と同じ結果だった。

## 不足している情報（分析の前に）

- HomeBase のファームウェア、ドアベルの機種とファームウェア：**未確認**（HomeBase の型番 T8010 は mDNS の TXT による。ドアベルは映像の解像度から Video Doorbell 2K と推測）。
- クラウド保存の契約の有無：**未確認**。
- 「WAN_RECORDING」の操作が、文書の言う「recorded footage」の送信に当たるか：**未確認**（CIC の説明は「ドアベルの映像を録画する」だけ）。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | eufy HomeBase 2（T8010）とドアベル（機種未確認） |
| MAC・IP | 8c:85:80:6c:b6:47、192.168.137.182 |
| 収録日時（UTC） | 2021-10-13 14:35〜14:42（WAN_WATCH、WAN_RECORDING の 4 本、各 25〜43 秒）、LOCAL_RING の 3 本、待機の 30 日分 |
| データセット | CIC IoT Dataset 2022 `3-Interactions/Home Automation/Eufy Homebase/` |
| 観測できた通信フェーズ | 別のネットワークのスマートフォンからの視聴と録画、ドアベルを押したとき、待機 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Privacy Commitment（カナダのストア） | eufy（Anker、ca.eufylife.com） | [2021-09-25](https://web.archive.org/web/20210925012802/https://ca.eufylife.com/pages/privacy-commitment) | 収録の 18 日前（同じ文は 2021-12-08 の米国の版にもある） |

文書 A の該当部分：
- 「**End-to-End Encryption** / Peeking Prohibited — All recorded footage is encrypted on-device and sent straight to your phone—and only you have the key to decrypt and watch the footage. Data during transmission is encrypted.」
- 「**Local Storage** — Home is where your data belongs. With secure local storage, your private data never leaves the safety of your home, and is accessible by you alone.」
- 「If you choose to store the clips in the cloud, we encrypt data between eufy devices and AWS using TLS and SRTP (Secure Real Time Protocol).」

**最も限定的な読み方**：「Data during transmission is encrypted.」は「End-to-End Encryption」の見出しの下で、録画した映像（recorded footage）をスマートフォンに送る話の中にある。限定的に読むと、対象は録画した映像の送信。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実（前回） | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| E1 | 外からの視聴（ライブ） | UDP の PPPP（`XZYH` のメッセージ）で、Amazon のアドレスの中継（3.16.202.62:11197 ほか）を通して音声と映像を送る。音声（AAC）は全部平文（4 本で 1,252 フレーム、80 秒をそのまま復号できた）。映像（H.265）で暗号化されているのは、鍵つきのフレームの先頭 128 バイトだけ（最大 0.21%） | 「Data during transmission is encrypted.」 | 公式文書に記載なし | `WAN_WATCH/eufyhomebaseWANWATCH_1.pcap` フレーム 275（ADTS の見出し `ff f1 60 40`）、213（平文の H.265 の開始コード） | 文書 A | 高（観測） | 文は録画した映像の見出しの下にあり、ライブの視聴は対象外（最も限定的な読み方）。ライブも含むと広く読めば矛盾 |
| E2 | 外からの録画の操作 | 同上（`WAN_RECORDING` の 2 本。音声・映像とも同じ形） | 「All recorded footage is encrypted on-device and sent straight to your phone」「Data during transmission is encrypted.」 | 条件付きの矛盾 | `WAN_RECORDING/eufyhomebaseWANRECORDING_2.pcap`、`_3.pcap` | 文書 A | 中 | 条件：CIC の「録画」の操作で送られたのが録画した映像であること（データセットの説明は「ドアベルの映像を録画する」だけ）。そうなら、ほぼ平文で、中継を通っている（「straight」ではない） |
| E3 | 同上 | 中継は Amazon のアドレス、平文 | 「If you choose to store the clips in the cloud, we encrypt data between eufy devices and AWS using TLS and SRTP」 | 判断不能 | 同上 | 文書 A | — | クラウド保存の契約が分からない。中継は保存の通信ではないかもしれない |
| E4 | ドアベルを押したとき | `zhixin-security-pr.s3.us-west-2.amazonaws.com` へ TLS で約 24 KB（毎回） | 「your private data never leaves the safety of your home」 | 観測不能 | `LOCAL_RING/eufyhomebaseLCLRING_1.pcap` フレーム 88 ほか | 文書 A | — | 中身が見えない。待機の 30 日にはこの送り先はない |
| E5 | 待機 | 送信の 12% が TLS 1.2（ECDHE、AES-128-GCM） | 記載なし | 公式文書に記載なし | 2-Idle（前回） | — | 中 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

- E2：CIC の「録画」の操作で送られたのが録画した映像なら、「暗号化して送る」という文と、平文の音声とほぼ平文の映像は直接両立しない。

## 3. 公式文書に記載のない観測事項

- E1（ライブの視聴の音声と映像がほぼ平文）、E5。中継が Amazon のアドレス（eufy が使うものかは未確認）。

## 4. 公式文書と一致した事項

なし。

## 5. 観測不能・判断不能な事項

- E3（契約が分からない）、E4（中身が見えない）。

## 6. 追加調査に必要なデータ

- CIC の取り直し（ドアベルのファームウェアの手がかり）。
- 収録の操作の詳しい説明（WAN_RECORDING で何をしたか）。データセットの作成者への問い合わせ。
- クラウド保存の契約の有無。

## 断定できる範囲／できない範囲

- **断定できる**（前回の確認による）：外から見た音声は平文、映像は大部分が平文だったこと。
- **断定できない**：文書の「Data during transmission」がこの送信を指すか。

## 前回との違い

- 前回は「食い違いの候補（T1a）」。新しい決まりで、文の置かれた見出し（録画した映像）に限って読み、ライブの視聴は「公式文書に記載なし」、録画の操作は「条件付きの矛盾」にした。報道（The Verge 2022）と論文（WOOT 2024）との関係は [blog-level.md](../blog-level.md)。

## 確かめ直し（2026-11-26）

- **確認**：`scripts/claims/sweep/eufy_p2p.py` で 4 本をもう一度読み、前回と同じ結果。音声（AAC）はすべて平文（WANWATCH_1 で 215 フレーム、WANRECORDING_2 で 505、_3 で 531）、映像で暗号化されうるのは最大 0.11〜0.25%。送り先も同じ（3.16.202.62:11197、54.219.251.168:11392、35.162.187.157:11159）。
- **新しく見えたこと**（「公式文書に記載なし」）：待機中も、Amazon の 3 つのアドレスの UDP 32100 番へ約 63 秒おきの通信（46 日、各約 1.9 万回）と、`p2p-vir-*`、`pushproxy-usa4`、`mediaserver-usa3.eufylife.com` の UDP 8006 番への通信。中身は読めない。アプリのサーバー `security-app.eufylife.com` は TLS 1.2（AES-128-GCM、255 回）。
- 判定は変わらない。
