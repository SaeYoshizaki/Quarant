# 5. Philips Hue Bridge（UNSW-IoTraffic 2016-17、CIC IoT 2022、Passive-Mode-Study 2023-24）

[一覧に戻る](README.md)

- UNSW-IoTraffic と CIC IoT 2022 は**取り直していない**（利用者の判断）。観測は前回の記録（[compare-sweep.md](../compare-sweep.md)、[report-2026-11-15.md](../report-2026-11-15.md) の E）による。
- Passive-Mode-Study（2023-24）は今回取り直して調べた（ただし比べる主張がない）。

## 不足している情報（分析の前に）

- UNSW-IoTraffic と CIC のファームウェアの版：**未確認**（前回の記録にない）。
- 平文の POST の本文は 16 進の文字列で、別に暗号化されているとみられる（AV-TEST 2017 の報告、推測）。中身は読めない。

## 調査対象と前提条件

| 項目 | UNSW-IoTraffic（前回） | CIC IoT 2022（前回） | Passive-Mode-Study（今回） |
|---|---|---|---|
| 型番 | BSB002（UPnP） | BSB002 | BSB002（UPnP） |
| MAC | 00:17:88:2b:9a:25 | 00:17:88:60:d6:4f | US1 ec:b5:fa:99:ac:15、FR ec:b5:fa:80:80:f4 |
| ファームウェア | 未確認 | 未確認 | US1：1.60.0 → 1.63.0 → 1.64.0、FR：1.64.0（SSDP の `SERVER: Hue/1.0 UPnP/1.0 IpBridge/…`） |
| 収録 | 2016-10〜2017-04 | 2021-10〜12 | US1：2023-11、2024-05。FR：2024-05 |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Privacy Policy（オーストラリア） | Philips Lighting（www2.meethue.com/en-au） | [2017-03-30](https://web.archive.org/web/20170330130814/http://www2.meethue.com:80/en-au/privacy-policy/)（2016-10-17 の版にも同じ文） | UNSW-IoTraffic の収録中。この文は 2017-11 の改訂で消えた |
| B | FAQ「Hardware and connectivity」 | Signify（philips-hue.com） | [2021-12-22](https://web.archive.org/web/20211222052747/https://www.philips-hue.com/en-us/support/faq/hardware-and-connectivity) | CIC の収録中 |
| C | 同じ FAQ | Signify | [2023-11-27](https://web.archive.org/web/20231127215728/https://www.philips-hue.com/en-us/support/faq/hardware-and-connectivity) | Passive-Mode-Study の収録中。B の文はない（保存されたのはナビゲーションだけで、本文は未確認） |

- 文書 A：「Philips Lighting, transfers data securely (using SSL) and will encrypt some data, such as your MAC address when it is stored.」
- 文書 B：「Hue only connects to the internet securely via a dedicated cloud so your devices cannot be seen from the open internet.」

**最も限定的な読み方**：
- A は「データを SSL で安全に送る」。すべての通信を SSL にするとは書いていない。
- B の要点は「専用のクラウドだけにつなぐので、機器がインターネットから見えない」。「securely」は説明の言葉で、方式を約束していない。

## 比較結果

| ID | データ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| H1 | IoTraffic | ブリッジの通信の 70%（36.5 MB）が平文の HTTP。`dcp.cpp.philips.com:80` への POST の `Authorization: CBAuth`（ブリッジ ID と SSO トークン、4,810 回）、`bridge.meethue.com:80/queue/getmessage` の `auth`（8,370 回）。TLS は 4.7% | 「transfers data securely (using SSL)」 | 公式文書に記載なし | `PhilipsHue_0017882b9a25.pcap` フレーム 1586〜3925289（前回） | 文書 A | 中 | 文はすべての送信を SSL にするとは言っていない（最も限定的な読み方。TLS の通信も 4.7% ある）。ブリッジの通信全体と広く読めば矛盾。平文の本文は別に暗号化されているとみられ（推測）、見出しのトークンと ID が平文 |
| H2 | IoTraffic | 同上 | 「will encrypt some data, such as your MAC address when it is stored」 | 観測不能 | — | 文書 A | — | 保存時の話 |
| H3 | CIC | 送り先は Philips／Signify のホストだけ | 「connects to the internet … via a dedicated cloud」 | 一致 | CIC の Hue の全ファイル（前回） | 文書 B | 中 | |
| H4 | CIC | 通信の 27% が平文の HTTP：`diagnostics.meethue.com/v2/diagnostics/report?…&sso=<トークン>`（4,760 回）、`dcp.dc1.philips.com:80` の CBAuth（1,017 回） | 「Hue only connects to the internet securely」 | 公式文書に記載なし | `1-Power/…/philipshuePOWER_1.pcap` フレーム 133〜207 ほか（前回） | 文書 B | 中 | 「securely」を「すべて暗号化」と読むのは拡大解釈なので、とらない |
| H5 | Passive-Mode-Study | `POST http://diagnostics.meethue.com/v2/diagnostics/report` を平文で（US1 15 回、FR 4 回）。問い合わせに `sso`、`auth`、`i`、`report_type`、本文は 16 進。User-Agent は `ureq/2.6.2`。`sso` は米国とフランスの別の個体で同じ値（前回の確認） | 記載なし（文書 C に該当する文がない） | 公式文書に記載なし | `US1-Capture1.pcap` 2023-11-02 01:40:42.455373、`FR-Capture2.pcap` 2024-05-03 23:30:01.467811（元のフレーム 574436） | 文書 C | 高 | 値は quarant-results |
| H6 | Passive-Mode-Study | ほかは TLS：`diag.meethue.com`・`data.meethue.com`（TLS 1.2、ECDHE、AES-128-GCM）、`ws.meethue.com`・`mqtt-us-01.iot.meethue.com`・`mqtt.2030.ltsapis.goog`（TLS 1.3、ChaCha20）、`otau.meethue.com`（更新、TLS 1.2） | 記載なし | 公式文書に記載なし | `US1-Capture1.pcap` 2023-11-01 23:20:34.481744 ほか | — | 高 | |
| H7 | Passive-Mode-Study | ファームウェアが 1.60.0 から 1.64.0 に上がった（SSDP の名乗り）。更新の取得は `otau.meethue.com` への TLS（中身は見えない） | 記載なし | 公式文書に記載なし | `US1-Capture2.pcap` 2024-05-02 16:07:58.431355（otau の ClientHello） | — | 中 | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- H1（2016-17 年、通信の 70% が平文の HTTP でトークンと ID が平文。文書の「using SSL」をブリッジの通信全体と広く読めば矛盾）、H4、H5（平文の診断の報告とトークン。2016 年から 2024 年まで続く）、H6、H7。

## 4. 公式文書と一致した事項

- H3（専用のクラウドだけ）。

## 5. 観測不能・判断不能な事項

- H2（保存時の暗号化）。平文の本文の中身。

## 6. 追加調査に必要なデータ

- UNSW-IoTraffic と CIC の取り直し（ファームウェアの版、本文の暗号化の確認）。
- 2023-24 年の Signify のセキュリティの文書（今回は見つからなかった）。

## 断定できる範囲／できない範囲

- **断定できる**：2023-24 年も、診断の報告を平文の HTTP で送り、トークンが平文だったこと（今回確認）。
- **断定できない**：2016-17 年の文書の「using SSL」がブリッジの通信を指すか。平文の本文が暗号化されているか。

## 前回との違い

- CIC の分（H4）は、前回「食い違いの候補（T1a）」。新しい決まりで「公式文書に記載なし」にした。
- Passive-Mode-Study でファームウェアの版（1.60.0〜1.64.0）を新しく特定した。
