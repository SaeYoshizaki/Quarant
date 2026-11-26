# 23. Ring Alarm Base Station（CIC IoT 2022）

[一覧に戻る](README.md)

**2026-11-26 に外付けディスクの CIC IoT 2022 で確かめ直した**（対象の 8 台の通信を切り出して `profile.py` で調べた。下の「確かめ直し」の節）。表の観測は前回（2026-11-02〜16）の記録と同じ結果だった。

## 不足している情報（分析の前に）

- ファームウェアの版：**未確認**。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Ring Alarm Base Station |
| 収録 | CIC IoT 2022（カナダ、2021-10〜12）。電源を入れたとき（1-Power）と待機 |
| 観測できた通信フェーズ | 起動時の接続確認、待機中のクラウド接続 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | What Ports Do I Need to Open in My Firewall for Ring Doorbells and Chimes? | Ring（support.ring.com） | [2021-10-24](https://web.archive.org/web/20211024095422/https://support.ring.com/hc/en-us/articles/205385394-What-Ports-Do-I-Need-to-Open-in-My-Firewall-for-Ring-Doorbells-and-Chimes-) | 収録中 |
| B | Ring のセキュリティとプライバシーの説明 | Ring | 2021-12-16（claims.tsv 1685〜1688 行） | 収録中 |

- 文書 A：「HTTP (port 80) ( Note : Not applicable to Ring Alarm Base Station)」（ファイアウォールで開けるポートの一覧）
- 文書 B：「We use a combination of AES encryption (Advanced Encryption Standard) and TLS (Transport Layer Security) to secure data between Ring devices and AWS …」

**最も限定的な読み方**：文書 A は、ファイアウォールで開ける必要のあるポートの一覧。「Not applicable」は「Base Station のためにポート 80 を開ける必要はない」と読み、「Base Station はポート 80 を使わない」とまでは読まない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実（前回） | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| A1 | 起動時の接続確認 | `GET http://st.rings.solutions:80/online/check.html`（中身なし） | 「HTTP (port 80) ( Note : Not applicable to Ring Alarm Base Station)」 | 公式文書に記載なし | `1-Power/…/ringbasestationPOWER_1.pcap` フレーム 50、64（前回確認） | 文書 A | 中 | 「Base Station はポート 80 を使わない」と広く読めば食い違いだが、その読み方はとらない |
| A2 | 待機中のクラウド接続 | 送信の 98.2% が TLS（825 回の握手、TLS 1.2 と 1.3、主に AES-128-GCM） | 「AES encryption … and TLS … to secure data between Ring devices and AWS」 | 一致 | CIC の Ring Alarm の全ファイル（前回） | 文書 B | 中 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- A1：ポート 80 での中身のない接続確認。

## 4. 公式文書と一致した事項

- A2。

## 5. 観測不能・判断不能な事項

- 録画の保存時の暗号化（文書 B）。

## 6. 追加調査に必要なデータ

- CIC の取り直し。

## 断定できる範囲／できない範囲

- **断定できる**（前回の確認による）：ポート 80 で中身のない接続確認をしていたこと。
- **断定できない**：文書 A の「Not applicable」が、使わないという意味か。

## 前回との違い

- 前回は「文言の上での食い違い（T1b）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。

## 確かめ直し（2026-11-26）

- **確認**：ポート 80 で `GET http://st.rings.solutions/online/check.html`（9 回、7 日、User-Agent は Go の HTTP クライアント）と、`/status/check.html`（3 回、User-Agent は curl）。最初は `1-Power/…/ringbasestationPOWER_1.pcap` 2021-09-29 12:36:16.828096。ほかはすべて TLS（主な送り先 `prdw-hub-us`、`prd-hapi-us.prd.rings.solutions` は TLS 1.2 の AES-128-GCM）。判定は変わらない。
