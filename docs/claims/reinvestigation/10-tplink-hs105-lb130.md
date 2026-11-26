# 10. TP-Link HS105（プラグ）と LB130（電球）（YourThings、2018-03〜04）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- LB130 のファームウェアの版：2026-11-26 に、LAN の応答（XOR を戻したもの）で確かめた（下）。
- アプリ（Kasa）の版：**未確認**。
- LAN の操作（tcp/9999）は 04-15 の 16:15〜16:31 にある。2026-11-26 に外付けディスクの 04-15 の全体（288 の 5 分のファイル）で確かめ直した。04-13 には 9999 番の通信はなかった。

## 調査対象と前提条件

| 項目 | HS105 | LB130 |
|---|---|---|
| 型番 | HS105（DHCP のホスト名。US 版、更新のファイル名 `smartPlug_FCC_HS105US`） | LB130（DHCP のホスト名） |
| MAC・IP | b0:4e:26:20:15:8a、192.168.0.37 | 50:c7:bf:92:a6:4a、192.168.0.51 |
| ファームウェア | 2018-04-13 19:50 に 1.5.1（Build 171109）を取得（L3）。04-15 の LAN の応答で `HS105(US)`、`sw_ver 1.5.1 Build 171109 Rel.165500`、`hw_ver 1.0`。取得の前の版は未確認 | 04-15 の LAN の応答で `LB130(US)`、`sw_ver 1.7.1 Build 171109 Rel.163935`、`hw_ver 1.0` |
| 収録日時（UTC） | 03-20、03-21、04-11、04-12、04-13、04-15 | 同じ |
| データセット | YourThings | |
| 観測できた通信フェーズ | クラウドとの常時接続、LAN でのアプリの操作、ファームウェアの更新（HS105）、時刻合わせ | 同じ（更新なし） |

**使用した公式文書**

| # | 文書 | 発行元 | 保存 | 収録との関係 |
|---|---|---|---|---|
| A | Privacy Policy（米国） | TP-Link | [2018-01-31](https://web.archive.org/web/20180131001047/http://www.tp-link.com:80/us/privacy) | 収録前 |
| B | Kasa のファームウェアの FAQ | TP-Link | 2018-01-13（claims.tsv 746、748 行） | 収録前 |
| C | WPA2 の脆弱性（KRACK）についての声明 | TP-Link | 2018-01-20（claims.tsv 494〜498 行） | 収録前 |

- 文書 A：「We have implemented measures, including encryption and SSL technology, designed to secure your personal information from accidental loss and from unauthorized access, use, alteration, and disclosure.」
- 文書 B：「our Smart Device will download firmware from our cloud and it will update the firmware automatically」「The firmware on TP-Link smart devices can only be updated by using the TP-Link Kasa App.」
- 文書 C：修正済みの版として「HS105(US) with firmware version v1.5.1 or later.」

**最も限定的な読み方**：文書 A は、対策の中に暗号化と SSL が「含まれる」と言っている。すべての通信、LAN の通信まで暗号化するとは書いていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| L1 | LAN の操作 | アプリ（192.168.0.159）が tcp/9999 で問い合わせ、プラグと電球が応答（04-15 の 16:15〜16:31）。中身は公開されている鍵の XOR で隠しただけで、誰でも戻せる。応答にクラウドのアカウント名（メールアドレス）、プラグの**設置場所の緯度・経度**（`latitude_i`、`longitude_i`）、deviceId、MAC、名前、版（値の一部は quarant-results） | 「measures, including encryption and SSL technology, designed to secure your personal information」 | 公式文書に記載なし | `eth1-20180415.1615.1523826900` 2018-04-15 16:15:05.693377（電球のアカウント名）、16:15:06.935922（プラグ）、`eth1-20180415.1630.1523827800` 16:31:53.493984（プラグの位置と deviceId） | 文書 A | 高 | XOR は暗号化と言えない。ただし文書はすべての通信の暗号化を約束していない（最も限定的な読み方）。位置は利用者の個人情報に当たりうるので、文書の「personal information」を守る「encryption and SSL」に入ると広く読めば矛盾 |
| L2 | クラウドとの接続 | `deventry.tplinkcloud.com`、`devs.tplinkcloud.com`（443、50443、60443 番）、`use1-api.tplinkra.com`、`events.tplinkra.com` へ TLS 1.2、`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 「encryption and SSL technology」 | 一致 | `eth1-20180321.1800.1521673200` 2018-03-21 18:02:15.140699（プラグ）、`eth1-20180320.1720.1521584400` 2018-03-20 17:24:55.519397（電球） | 文書 A | 高 | |
| L3 | ファームウェアの更新（HS105） | `GET http://download.tplinkcloud.com/firmware/smartPlug_FCC_HS105US_1.5.1_Build_171109_Rel._1512618028940.bin` を平文の HTTP で取得（下り 1.1 MB、User-Agent `IOE Client`）。直後に `devs.tplinkcloud.com` などへ TLS | 「our Smart Device will download firmware from our cloud and it will update the firmware automatically」 | 一致（クラウドから取る） | `eth1-20180413.1950.1523667000` 2018-04-13 19:50:38.690312 | 文書 B | 高 | 取得の方法（HTTP）は文書に記載なし。署名の有無は見えない |
| L4 | 同上 | 取得したのは 1.5.1 | 「HS105(US) with firmware version v1.5.1 or later」（KRACK の修正） | 一致（参考） | 同上 | 文書 C | 中 | 収録の前半は修正前の版だったとみられる（推測） |
| L5 | 時刻合わせ | `pool.ntp.org`、`time-a.nist.gov` へ平文の NTP | 記載なし | 公式文書に記載なし | `eth1-20180321.1800.1521673200` 2018-03-21 18:02:05.995294 | — | 高 | |
| L6 | 応答のない通信 | プラグから `devs.tplinkcloud.com`（34.231.177.207）の 50443 番・443 番へ、04-13 に約 440 の接続で上りだけ（下りなし） | 記載なし | 公式文書に記載なし | `eth1-20180413.1505.1523649900` 2018-04-13 15:07:43.252553 | — | 中 | 再送や接続の失敗とみられる（推測） |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- L1：LAN の操作が XOR だけで、アカウント名（メールアドレス）を返す。
- L3 の取得方法（平文の HTTP）、L5、L6。

## 4. 公式文書と一致した事項

- L2、L3（クラウドからの自動の更新）、L4（参考）。

## 5. 観測不能・判断不能な事項

- 更新のファイルの署名。TLS の中身。

## 6. 追加調査に必要なデータ

- 04-14、04-16〜19（今回は取り直していない）。

## 断定できる範囲／できない範囲

- **断定できる**：LAN の操作の応答が XOR だけで、アカウント名が戻せる形で流れたこと。HS105 が 1.5.1 のファームウェアを平文の HTTP で取得したこと。
- **断定できない**：文書の「encryption and SSL technology」が LAN の操作まで含むか。

## 前回との違い

- 前回は「食い違いの候補（T1a）」。新しい決まり（最も限定的な読み方）で「公式文書に記載なし」にした。HS105 のファームウェアの平文での取得（1.5.1）を新しく確かめた。
