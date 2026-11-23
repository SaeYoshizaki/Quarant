# 8. Withings Home（当時は Nokia Home。YourThings、2018-03〜04）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- ファームウェアの版：通信に平文で出ていない。**未確認**（2018-03-20 14:05 に `cdnfw.withings.net` から 61.9 MB を TLS で取得しており、更新とみられる。推測）。
- アプリの版、Withings の契約（映像の保存）：**未確認**。
- データセットの作成者の中間者の検査（04-10〜13）の最中の通信がある（下の W6）。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | Withings Home（DHCP のホスト名 `WBP02-A534`、HTTP の User-Agent `Withings UserAgent`） |
| MAC・IP | 00:24:e4:2b:a5:34、192.168.0.32 |
| 収録日時（UTC） | 03-20、03-21、04-11、04-12、04-13（取り直した 5 日） |
| データセット | YourThings |
| 観測できた通信フェーズ | 映像の保存（S3）、XMPP（STARTTLS のあと TLS）、API（scalews）、更新とみられる取得、証明書の取得（平文）、アプリとの LAN の映像（DTLS）、STUN |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Nokia Home の製品ページ（Security の表） | Nokia（health.nokia.com） | [2018-04-04](https://web.archive.org/web/20180404154334/https://health.nokia.com/us/en/home) | 収録中 |
| B | プライバシーポリシー | Nokia Technologies | 2018-04-10（claims.tsv 255〜258 行） | 収録中 |

- 文書 A：「Our engineers take security seriously.」「Nokia Home uses bank level technologies such as AES-256 and secure HTTP (HTTPS) to protect your data at the device, cloud and app level so that all your data is stored safely.」「Communication via Secure Socket Layer (SSL)」「h5LS end-to-end encryption.」
- 文書 B：通信の暗号化の具体的な文はない（「appropriate steps to address online security」など）。

**最も限定的な読み方**：「Communication via Secure Socket Layer (SSL)」は SSL で通信すると言うが、すべての通信とは書いていない。AES-256 の文は「stored safely」で終わり、保存のことと読める。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| W1 | API・映像の保存 | `scalews.withings.net:443`（約 10 分おき）、`prod-oregon-timeline-2-days.s3.amazonaws.com:443`（映像の保存とみられる、4 日で 134 MB の上り）へ TLS 1.2。選ばれた暗号はほぼ `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`。証明書は `*.withings.net`（Gandi）、`*.s3.amazonaws.com`（DigiCert）で、名前は一致 | 「Communication via Secure Socket Layer (SSL)」 | 一致 | `eth1-20180320.0005.1521522300` 2018-03-20 00:06:18.959226（S3）、00:06:19.750044（scalews） | 文書 A | 高 | |
| W2 | 同上 | AES-128 が大半。`scalews` で AES-256 は 2 回だけ | 「bank level technologies such as AES-256 and secure HTTP (HTTPS) … so that all your data is stored safely」 | 公式文書に記載なし | 同上 | 文書 A | 高 | AES-256 は保存のことと読める（最も限定的な読み方）。通信の暗号と広く読めば矛盾 |
| W3 | 証明書の取得 | `POST http://scalews.withings.net/cgi-bin/v2/certificate?action=get` を平文の HTTP で（2 日で 3 回）。本文は `mac_address=00:24:e4:2b:a5:34&service=LINUX_ROOT_CA&challenge=…&key_type=rsa2048&method=sha256`。応答は JSON で、PEM の証明書 4 つ（1 つ目は Withings 自身の認証局） | 「Communication via Secure Socket Layer (SSL)」 | 公式文書に記載なし | `eth1-20180320.2235.1521603300` 2018-03-20 22:36:27.165900 | 文書 A | 高 | 機器が信頼する認証局の一覧を平文で受け取っているとみられる（推測）。文書はすべての通信とは言っていない |
| W4 | XMPP | `xmpp.withings.net`（89.30.121.24、.26）の 5222 番へ STARTTLS のあと TLS 1.2（`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` など）。認証は TLS の中（前回の確認） | 同上 | 一致 | `eth1-20180320.0000.1521522000` 2018-03-20 00:00:18.234110 | 文書 A | 高 | |
| W5 | LAN の映像 | アプリ（192.168.0.159）と DTLS 1.0（`TLS_RSA_WITH_AES_256_CBC_SHA`）。外の Withings の中継（`us-ovh-fwd-02`、`us-aws-fwd-03.withings.net`）と STUN | 「h5LS end-to-end encryption.」 | 一致（見えた範囲で） | `eth1-20180413.1640.1523655600` 2018-04-13 16:44:18.775962 | 文書 A | 中 | 中身が端から端まで暗号化かは見えない。DTLS であることだけ |
| W6 | 中間者の検査の最中 | `scalews.withings.net`（2 回）と `xmpp.withings.net`（1 回）で、作成者の偽の証明書（発行者 `thing-catcher.gtisc.gatech.edu`）の握手 | 記載なし（証明書の検証の文はない） | 公式文書に記載なし | `eth1-20180411.2025.1523496300` 2018-04-11 20:26:20.397512 ほか | — | 中 | 機器がその後データを送ったかは今回数えていない（前回の記録では YourThings の評価に記載） |
| W7 | 更新とみられる取得 | `cdnfw.withings.net` から TLS で 61.9 MB | 記載なし | 公式文書に記載なし | `eth1-20180320.1405.1521572700` 2018-03-20 14:05:08.196087 | — | 中 | |
| W8 | 保存 | — | 「all your data is stored safely」 | 観測不能 | | 文書 A | — | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- W3：機器の MAC を送り、認証局の証明書の一覧を平文の HTTP で受け取る。
- W2（AES-128）、W6、W7。

## 4. 公式文書と一致した事項

- W1、W4、W5（見えた範囲で）。

## 5. 観測不能・判断不能な事項

- W8。TLS と DTLS の中身。

## 6. 追加調査に必要なデータ

- ファームウェアの版。
- 平文で受け取った証明書を機器がどう使うか（Withings の技術文書。見つからなかった）。

## 断定できる範囲／できない範囲

- **断定できる**：認証局の証明書の一覧の取得が平文の HTTP だったこと。ほかの外部との通信は TLS か DTLS だったこと。
- **断定できない**：文書の「AES-256」が通信のことか。

## 前回との違い

- 前回は「食い違いの候補（T1a、T2）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。
- 前回「本文つきの平文の POST が 4 回」としたものの中身（認証局の証明書の取得）を、今回確かめた。
