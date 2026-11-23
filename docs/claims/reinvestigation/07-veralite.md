# 7. MiCasaVerde VeraLite（YourThings、2018-03〜04）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- 比べる文書（Vera の wiki）は、2010〜2014 年に書かれた UI5 のころの説明。機器のファームウェアは **1.7.855（UI7）** で、説明がそのまま当てはまるかは**未確認**（下の V1〜V3 の条件）。
- アプリ（Vera のスマートフォンアプリ、ウェブの画面）の通信は収録にない。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | MiCasaVerde VeraLite（YourThings の機器一覧の名前） |
| MAC・IP | 94:4a:0c:08:7e:72、192.168.0.34 |
| ハードウェア／ファームウェア | ファームウェア 1.7.855、Z-Wave 3.67、DistributionBuild 88、Oem micasaverde（機器自身のログの `ReportStatus` の記録による。下の V4）。SSDP の名乗り `Linux/2.6.37.1, UPnP/1.0, Portable SDK for UPnP devices/1.6.6` |
| 収録日時（UTC） | 2018-03-20、03-21、04-11、04-12、04-13（今回取り直した 5 日） |
| データセット | YourThings（Alrawi ほか、IEEE S&P 2019）。米国の実験室。全パケットが 2 回ずつ入っているので重複を除いた |
| 観測できた通信フェーズ | 遠隔接続（SSH のトンネル、TLS）、クラウドへの状態の報告、ログの送信（FTP）、時刻合わせ、LAN のカメラなどの探索。作成者の検査用の機器（192.168.0.200）からのポートスキャンは除いた |

**使用した公式文書**

| # | 文書 | 発行元 | 最終更新 | 保存 | 収録との関係 |
|---|---|---|---|---|---|
| A | Secure Remote Access TechInfo（wiki） | MiCasaVerde（wiki.micasaverde.com） | 2011-07-31 | [2016-10-13](https://web.archive.org/web/20161013232847/http://wiki.micasaverde.com:80/index.php/Secure_Remote_Access_TechInfo) | 収録前。UI5 のころの説明 |
| B | Secure Remote Access（wiki） | 同上 | 2010-04-17 | [2018-01-09](https://web.archive.org/web/20180109123704/http://wiki.micasaverde.com:80/index.php/Secure_Remote_Access) | 収録前。FindVera のころ |
| C | Security Concerns（wiki） | 同上 | 2014-10-23 | [2017-05-12](https://web.archive.org/web/20170512182519/http://wiki.micasaverde.com:80/index.php/Security_Concerns) | 収録前。Vera1/UI2 向けと書いてある |
| D | 「How secure is my Vera system?」 | Vera Control（support.getvera.com） | 不明 | [2017-07-03](https://web.archive.org/web/20170703144526/http://support.getvera.com/customer/en/portal/articles/1719039-q-how-secure-is-my-vera-system-) | 収録前 |

- 文書 A：「his username and an MD5 hash (security checksum) of the password, along with the serial number and hardware key, are sent to the remote access server using the https: (SSL encryption) protocol.」「The Vera then uses ssh with a pre-defined ssh username and shared key to make a connection to the remote access server.」「NetworkMonitor runs on Vera and calls a php page on the remote access server using https, passing in the serial number and hardware key …」「So we ship Vera with WPA2 encryption turned on, and a random Wi-Fi password consisting of two dictionary words plus a number, which is printed on the bottom of Vera.」
- 文書 B：「… Vera makes a secure connection to FindVera.com automatically.」
- 文書 D：「This system incorporates 128-bit encryption, among other security measures.」（Z-Wave の無線の話）

**最も限定的な読み方**：文書 A は「遠隔接続のサーバー」に送るときの方法を説明している。ほかの送り先（ログのサーバー）に同じ値を送らないとは書いていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| V1 | 遠隔接続の認証 | `vera-us-oem-authd11.mios.com`、`vera-us-oem-device11`、`account11`、`relay11` などの 443 番へ TLS 1.2（5 日の分）。サーバー証明書は `*.mios.com`（Go Daddy G2、2017-07-03〜2018-07-06、名前は一致）。relay は `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`、ほかは `TLS_RSA_WITH_AES_256_CBC_SHA` など | ユーザー名、パスワードの MD5、シリアル番号、ハードウェアキーを「remote access server」に https で送る | 一致 | `eth1-20180320.0730.1521549000` 2018-03-20 07:34:58.716308（device11）ほか | 文書 A | 中 | 中身は見えない。ハブのログの記録（V4）では、ハードウェアキーを `https://vera-us-oem-authd11.mios.com/locator/…` に送っている |
| V2 | 遠隔接続のトンネル | `vera-us-oem-relay11.mios.com`（54.187.71.199）の 232 番へ SSH（5 日の分） | 「uses ssh … to make a connection to the remote access server」 | 一致 | `eth1-20180320.0000.1521522000` 2018-03-20 00:00:37.534496 | 文書 A | 高 | |
| V3 | ログの送信 | 毎日 2 回（08:35〜08:40 ごろと 20:35〜20:40 ごろ）、`oem-log6.mios.com`（82.77.228.112）の 21 番へ**平文の FTP** でログインし（共通のユーザー名とパスワードとみられる。値は quarant-results）、約 20 のログ（gzip）を上げる。組み立てた 9 回すべての `MiOSRestApi.log` に**ハードウェアキー**と 3 つのサーバーの**セッションキー**（MMSSession）。夜の回は `mios_services.log` にもハードウェアキー | ハードウェアキーは remote access server に https で送る | 公式文書に記載なし | `eth1-20180320.0840.1521553200` 2018-03-20 08:41:15.852617（USER、元のフレーム 25011）、08:41:16.005235（PASS、元のフレーム 25048）、MiOSRestApi.log の STOR（元のフレーム 29838）。`eth1-20180320.2040.1521596400`、`eth1-20180321.0840.1521639600`、`eth1-20180321.2040.1521682800`、`eth1-20180411.0835.1523453700`、`eth1-20180411.2035.1523496900`、`eth1-20180412.0835.1523540100`、`eth1-20180412.2035.1523583300`、`eth1-20180413.0835.1523626500` も同じ | 文書 A | 高 | 送り先は遠隔接続のサーバーではない。限定的な読み方では矛盾しない。広く「キーは https でしか送らない」と読めば明確な矛盾 |
| V4 | 同上（ログの中身） | ログにファームウェアの版（1.7.855）、MAC、LAN の IP、アカウントの番号、設定のバックアップの鍵、遠隔接続の SSH の設定（鍵のファイルの場所とポート）、**ハブの Wi-Fi の設定（SSID とパスワード）**（`Report_AP.log`、03-20・03-21 の各回と 04-11・04-12 の夜の回。`WifiSettings_UseWifi=0` で使っていない設定） | 「a random Wi-Fi password … which is printed on the bottom of Vera」 | 公式文書に記載なし | 同上（`Report_AP.log`） | 文書 A | 高 | パスワードは「辞書の単語 2 つと数字」の形で、文書の説明と合う。送ることは書いていない |
| V5 | LAN の機器の探索 | LAN のカメラなどの 80 番へ平文の HTTP で、`/check_user.cgi?user=test&pwd=test`、`/cgi-bin/CGIProxy.fcgi`、`/SDK/activateStatus`、`/common/info.cgi` などを要求（03-20〜21 に 5 台、各数回） | 記載なし | 公式文書に記載なし | `eth1-20180320.0305.1521533100` 2018-03-20 03:08:27.613351（192.168.0.35） | — | 高 | カメラの自動検出とみられる（推測）。ログにも同じ要求の記録 |
| V6 | 接続確認 | `google.com`、`yahoo.com` の 80 番へ約 1 時間おき（中身は TCP の接続だけ） | 記載なし | 公式文書に記載なし | `eth1-20180320.0015.1521522900` 2018-03-20 00:17:37.225628 | — | 中 | |
| V7 | 時刻合わせ | `*.openwrt.pool.ntp.org` へ平文の NTP | 記載なし | 公式文書に記載なし | `eth1-20180320.0000.1521522000` 以降 | — | 高 | |
| V8 | 無線の暗号 | — | 「128-bit encryption」（Z-Wave） | 観測不能 | Z-Wave は収録にない | 文書 D | — | |
| V9 | FindVera | `*.mios.com` との接続は TLS と SSH | 「Vera makes a secure connection to FindVera.com automatically」 | 判断不能 | 上の V1・V2 | 文書 B | — | 文書は 2010 年の FindVera のころの説明で、今の遠隔接続と同じかが分からない |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。

## 3. 公式文書に記載のない観測事項

- V3・V4：ハードウェアキー、セッションキー、Wi-Fi の設定などを含むログを、共通のパスワードの平文の FTP で毎日 2 回送っている。
- V5：LAN の機器に、決まった仮の資格情報（`user=test&pwd=test`）で平文の HTTP の要求を送る。
- V6、V7。

## 4. 公式文書と一致した事項

- V1（遠隔接続のサーバーへは TLS）、V2（SSH のトンネル）。

## 5. 観測不能・判断不能な事項

- V8（Z-Wave）、V9（2010 年の説明が今も当てはまるか）。

## 6. 追加調査に必要なデータ

- UI7（1.7.x）の遠隔接続とログの送信についての Vera の技術文書（今回は見つからなかった）。
- ログの送信を利用者が止められるかの説明。

## 断定できる範囲／できない範囲

- **断定できる**：ハブが、ハードウェアキー、セッションキー、Wi-Fi の設定を含むログを、平文の FTP で毎日送っていたこと（5 日、9 回で確認）。遠隔接続そのものは TLS と SSH だったこと。
- **断定できない**：wiki の説明（UI5 のころ）が、ファームウェア 1.7.855 に当てはまるか。ログの送信が利用者の設定によるものか。

## 前回との違い

- 前回（2026-11-23 の朝）は 1 回分だけを確かめ、「食い違いの候補（T1a）」にした。新しい決まり（最も限定的な読み方）では、文書の対象は遠隔接続のサーバーだけなので「公式文書に記載なし」になる。
- 9 回すべてでキーが入っていること、Wi-Fi の設定、ファームウェアの版（1.7.855）、LAN の機器の探索を新しく確かめた。
