# 第三者の観測と公開の記録（Sonos・Canary、2026-11-27）

[まとめに戻る](fixes-sonos-canary.md)

- 作成：2026-11-27。WebSearch、WebFetch、curl（公開 URL の読み取りだけ）を使った。ブラウザは使っていない。
- 「観測」は資料に書いてあること、「推測」は私の読み。
- URL の中のキャンペーン用の文字列（パスの乱数部分）は `[tok]` に置き換えた。他人の製造番号は書いていない。
- 検索で利用者本人のリポジトリ（SaeYoshizaki/Quarant の PR #14、#16）が出たが、第三者ではないので外した。

## 先に要点

1. **Sonos (b) ファームの取得は直っていない。** 2019 年から 2026 年 11 月まで、平文の HTTP で取りに行くという観測と記録が続いている。根拠は AV-TEST（2019）、Sonos 掲示板（2025-01）、GitHub の取得記録（2026-11）。スピーカー自身が知らせる更新 URL も、公開されているマニフェストも、今も `http://update-firmware.sonos.com/...` になっている。
2. **Sonos (a) 更新の確認**：「Sonos のサーバーとの通信は基本的に TLS 1.2、ファームの取得だけが例外」という第三者の観測がある（AV-TEST、2019-04）。これはデータセットの「2021 年には TLS」と合う。ただし、2024 年以降に機器が知らせるマニフェストの URL は `http://update.sonos.com/...update.upm` である。これを平文で取りに行くかは観測が見つからなかった。
3. **Sonos (c) 使用データ（msmetrics）**：通信が HTTP か HTTPS かを書いた第三者の資料は見つからなかった。2020〜2025 年の資料は、Pi-hole で名前の問い合わせを止めたという話だけ。
4. **Canary**：2019 年以降に `h.canaryis.com` の平文 htpdate を観測した第三者の資料は見つからなかった。2026-11-27 にサーバーへ平文で HEAD を送ると、まだ 301 と Date が返る。ただしこれはサーバー側の確認で、機器が今も送っているかは分からない。
5. **勧告・CVE**：Sonos と Canary のどちらにも、平文の更新や平文の通信を扱った勧告・CVE は見つからなかった。

---

## Sonos (a) 更新の確認（`update.sonos.com/firmware/latest/default-1-1.ups`）

### 直ったという証拠

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| 2019-04-04 | 書かれていない（アプリ 10.0） | AV-TEST「Sonos Play:1」Dennis Henke | https://www.iot-tests.org/2019/04/sonos-play1-turn-it-up/ | 観測：「Basically, communication with Sonos servers is TLS1.2 encrypted」。例外はファームの取得だけ。ホスト名は書かれていないので、更新の確認が TLS だというのは推測。 |

### まだ平文という証拠

見つからなかった（下の「どちらとも言えない」を参照）。

### どちらとも言えない資料

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| 2019-04-10〜05-05（測定期間） | 不明 | Huang ほか「IoT Inspector」arXiv 1909.09848v1、§6.1、表 5（PDF 10 枚目） | https://arxiv.org/pdf/1909.09848 | 観測：Sonos 186 台の TLS ClientHello はすべて TLS 1.2 で、弱い暗号はなかった。ポート 80 を使ったかは業者ごとに書かれていない（図 7 は全体の集計だけ）。 |
| 2024-11-23 | S1 57.22-59130、S2 81.1-58210 | Home Assistant core issue #131381（Heinz-bit）の診断データ | https://github.com/home-assistant/core/issues/131381 | 観測：機器が知らせる `ManifestURL="http://update.sonos.com/firmware/Prod/...[tok].../update.upm"`。URL の表記が http だということしか分からない。 |
| 2025-09-27 | 91.0-68261 | openHAB issue #19158 のコメント（openhabgs） | https://github.com/openhab/openhab-addons/issues/19158 | 観測：`ManifestURL="http://update.sonos.com/firmware/Prod/2025-Sonos-19-[tok]..."`。表記だけ。 |
| 2026（ページに日付なし） | 94.1-76070 | ReverseTelnet「Manifest File Provenance and Research」 | https://github.com/ReverseTelnet/sonos_update_manifests/blob/master/docs/manifest_files_provenance_and_research.md | 観測：ZoneGroupTopology の応答例に `'manifestURL': 'http://update.sonos.com/firmware/Prod/2026-Sonos-09-[tok]-GA-1/update.upm'` とある。表記だけ。 |
| 2023-04-21（初回コミット） | — | blasty/sonos の sonostool | https://github.com/blasty/sonos/blob/27be43832f6106d068541534ed0f151b841d1fa4/sonostool/sonostool.py#L47-L55 | 研究者の道具が `https://update.sonos.com` を使っている。サーバーが HTTPS で応えることは分かるが、機器の動きではない。 |
| 2026-11-25 | 応答は S2 98.0-83230、S1 57.23-83121 | BookCatKid「Sonos discovery methods」 | https://github.com/BookCatKid/sonos-firmware-archive/blob/main/docs/sonos-discovery-methods-research.md | 観測：`default-1-1.ups` と `swgen/{1,2}/latest/update.upm` は、渡した版の値に関係なく最新を返す。サーバー側の話。 |

推測：2021 年のデータで TLS になった `default-1-1.ups` と、機器が今知らせている `update.upm` は別の要求である。後者の取り方（HTTP か HTTPS か）は、第三者の観測では決められない。

---

## Sonos (b) ファームの取得（`update-firmware.sonos.com` の `.upd`、毎日の `update.upm`、`timezones.xml`）

### 直ったという証拠

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| — | — | — | — | スピーカー本体のファームが HTTPS になったという資料は見つからなかった。2026-11 のマニフェストで https になっているのは付属機器の 2 件だけ（model 44 と 53。下の表を参照）。 |

### まだ平文という証拠

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| 2019-04-04 | 書かれていない（アプリ 10.0） | AV-TEST「Sonos Play:1」Dennis Henke | https://www.iot-tests.org/2019/04/sonos-play1-turn-it-up/ | 観測：「the firmware update downloaded over an unencrypted connection」「Although the update itself is encrypted … not downloaded via the available HTTPS endpoint」。画像の説明は「Download of the firmware update via http」。 |
| 2021-04-24 | 62.1-86220（マニフェストは 62.1-88070） | openHAB issue #10569（mlommers）のログ | https://github.com/openhab/openhab-addons/issues/10569 | 観測：`UpdateURL="http://update-firmware.sonos.com/firmware/Prod/62.1-86220-v13.0-[tok]-GA-1/^62.1-86220"`、`ManifestURL="http://update-firmware.sonos.com/.../62.1-88070.../update.upm"`。機器が知らせる URL の表記（通信を捕まえたものではない）。 |
| 2022-04-09 | 67.1-27100 | Home Assistant core issue #69759（oSourceSE） | https://github.com/home-assistant/core/issues/69759 | 観測：UpdateURL と ManifestURL がどちらも `http://update-firmware.sonos.com/...67.1-27100...`。表記だけ。 |
| 2023 年ごろ（推測。論文の中にファイルの日付 2023-07-12 とある） | Play:3、54.2-72031〜57.13-34140 の 14 版 | Ashley Andrews 博士論文（Univ. of Bristol、2025-01）。付録 B 表 B-1（印刷 p.141 ／ PDF p.158）、4.4.2 節（p.45） | https://research-information.bris.ac.uk/ws/portalfiles/portal/458790302/Fine-Grained_IoT_Device_Fingerprinting_From_Passive_Network_Traffic_to_Improve_Network_Security_FINAL_CORRECTED.pdf | 観測：Sonos Play 3 の更新の欄は「Possibly TLS on port 80」。推測：ポート 80 で中身が暗号のように見えた、ということ。`.upd` 自体が暗号化されているので（AV-TEST の記述）、TLS と見誤った可能性がある。 |
| 2024-11-23 | S1 57.22-59130、S2 81.1-58210 | Home Assistant core issue #131381 | https://github.com/home-assistant/core/issues/131381 | 観測：`UpdateURL="http://update-firmware.sonos.com/firmware/Prod/57.22-59130-..."` と `"…/81.1-58210-..."`。表記だけ。 |
| 2025-01-21 | 取りに行った包みは 82.3-60160（`-1-21.upd`）。今の版は書かれていない | Sonos Community「Anyone else having problems updating firmware?」Lobstonicus | https://en.community.sonos.com/speakers-229128/anyone-else-having-problems-updating-firmware-6926210 | 観測：パケットを見て「my speaker is making an HTTP GET request to http://update-firmware.sonos.com/firmware/Prod/82.3-60160-v16.5.1-[tok]-GA-1/82.3-60160-1-21.upd」。本文の URL に**クエリ（serial= など）は書かれていない**（省いたかは不明）。更新はエラー 30 で失敗。HTTP はサーバーが切り、HTTPS ならブラウザで取れた。行き先は Akamai。解決は書かれていない。 |
| 2025-02-15、02-23 | Connect:Amp、76.2-47270 | trulyspinach/sonos-fenway issue #2（moriceh）の機器のログ | https://github.com/trulyspinach/sonos-fenway/issues/2 | 観測：`upgrade:URL is http://update-firmware.sonos.com/firmware/Prod/...upd?cmaj=76&cmin=2&cbld=47270&subm=3&rev=1&reg=2&serial=…&sonosid=&householdid=`。更新の仕組みが URL に製造番号を足すことが分かる。ただし URL は本人が手で渡したもので、診断用の状態の機器（sonosid と householdid は空）。 |
| 2025-09-27 | 91.0-68261 | openHAB issue #19158（openhabgs） | https://github.com/openhab/openhab-addons/issues/19158 | 観測：`UpdateURL="http://update-firmware.sonos.com/firmware/Prod/91.0-68261-v17.4-[tok]-RC-1/^91.0-68261"`。表記だけ。 |
| 2026（文書に日付なし。97.1-80312 は 2026-09-08 公開と書かれている） | 94.1-76070、97.1-80312 | ReverseTelnet「Manifest File Provenance and Research」 | https://github.com/ReverseTelnet/sonos_update_manifests/blob/master/docs/manifest_files_provenance_and_research.md | 観測：機器の応答例は `updateURL: http://update-firmware.sonos.com/...94.1-76070...`。マニフェストの `base_url` も `http://update-firmware.sonos.com/...`。集め方は「local Network DNS queries and packet-capture files」。 |
| 2026-11-13（GitHub に入った日） | system_version 98.0-82170、sonos_version 27.4.1 | ReverseTelnet が保存したマニフェスト `2026-Sonos-22-[tok]-SP-1` | https://github.com/ReverseTelnet/sonos_update_manifests/tree/master/manifest_files | 観測（中身を数えた）：`http://update-firmware.sonos.com` が 52 件、`https://` は 2 件だけ（model 44 と 53 の付属機器）。スピーカーの `base_url` は http。 |
| 2026-11-03（取得）、11-04（報告） | 98.0-82170（S2）、86.11-82170（旧機種） | BookCatKid/sonos-firmware-archive issue #14（skankmoses） | https://github.com/BookCatKid/sonos-firmware-archive/issues/14 | 観測：「transparent HTTP tee-proxy (DNS rewrite → local capture host; TLS passed through untouched)」で 4 つの `.upd` を取った。更新は普通に終わった。推測：HTTP の中継で中身が取れたのだから、2026-11 も平文で取りに行っている。ポート番号は書かれていない。 |

### どちらとも言えない資料

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| 2026-10-11 | ZP5 第 1 世代、16.x→34.16→57.23 | r-u-t-r-A の gist | https://gist.github.com/r-u-t-r-A/1a6dbf8a841162d150877b8f9d4fc24b | 観測：古い 16.x の機器は Sonos から取ろうとすると内蔵の wget が失敗する。LAN で配るときは「Use plain http://: the old firmware can't do modern HTTPS」。16.x も 34.16 も URL にクエリを足す。古い機種だけの話。 |
| 2026-11-13、11-27 | — | BookCatKid issue #24（ReverseTelnet） | https://github.com/BookCatKid/sonos-firmware-archive/issues/24 | `http://update-firmware.sonos.com/firmware/Prod/JFFS_Static_Link/connectx.upd` などの URL を挙げている。手で使う URL で、機器の動きではない。 |
| 2026-01-22 | — | Wayback Machine の記録 | http://web.archive.org/cdx/search/cdx?url=update-timezone.sonos.com* | 観測：`http://update-timezone.sonos.com/timezone/timezones.xml` を平文で取って 200（クローラーが取ったもの）。機器が今も平文で取るかは分からない。`timezones.xml` を機器で観測した第三者の資料は見つからなかった。 |
| 2021-04 → 2024-11 | 62.1、67.1 → 57.22、81.1、91.0 | 上の openHAB と Home Assistant の記録 | （上の表） | 観測：毎日取る `update.upm` の URL のホストが `update-firmware.sonos.com`（2021、2022）から `update.sonos.com`（2024 以降）に変わった。どちらも表記は http。 |

---

## Sonos (c) 使用データ（`msmetrics.ws.sonos.com/HRMetrics/submit.aspx`）

### 直ったという証拠

第三者の資料は見つからなかった（データセットでは 41.3 以降が TLS）。

### まだ平文という証拠

見つからなかった。

### どちらとも言えない資料

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| 2018-11-10 | 「8.4」（アプリかファームか不明） | Sonos Community「Why do sonos apps/speakers call home so much?」 | https://en.community.sonos.com/advanced-setups-229000/why-do-sonos-apps-speakers-call-home-so-much-6815214 | Pi-hole で止めても影響なし。「I'm sure it is all encrypted」は本人の予想で、観測ではない。 |
| 2020-11-08〜2021-08-11 | 「quite old」とだけ | Sonos Community「Sonos no longer works if I block their metric tracking DNS」 | https://en.community.sonos.com/components-and-architectural-228999/sonos-no-longer-works-if-i-block-their-metric-tracking-dns-6850485 | Pi-hole で名前の問い合わせを止めた話だけ。HTTP か HTTPS かは書かれていない。 |
| 2024-06-20 | — | simojenki/bonob issue #205（gravelld） | https://github.com/simojenki/bonob/issues/205 | hosts に `127.0.0.1 msmetrics.ws.sonos.com` と書いた例だけ。 |
| 2025-07-05 | — | music-assistant/support issue #4021（eikehein） | https://github.com/music-assistant/support/issues/4021 | Pi-hole のログで止まっていたのは msmetrics だけ、という話。アプリからか機器からかは不明。 |
| 2015-07〜2019-07 | — | Wayback Machine の記録 | http://web.archive.org/cdx/search/cdx?url=msmetrics.ws.sonos.com* | `http://msmetrics.ws.sonos.com:80/` に 404（クローラー）。サーバー側の話。 |

---

## Canary（初代 All-in-One、CAN100）：`h.canaryis.com` への htpdate と connman の接続確認

### 直ったという証拠

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| — | — | — | — | 機器が HTTPS や NTP に変わったという第三者の観測は見つからなかった。 |

### まだ平文という証拠

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| — | — | — | — | 2019 年以降に機器の平文 htpdate を観測した第三者の資料は見つからなかった。 |

### どちらとも言えない資料

| 日付 | ファームの版 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|---|
| プロファイルの更新日 2025-04-01。元の通信の時期は書かれていない（2018 年の論文の実験と同じ時期と推測） | 不明 | UNSW の MUD プロファイル `canaryCameraMud.json`。論文は Hamza ほか「Clear as MUD」HotNets 2018（arXiv 1804.04358） | https://iotanalytics.unsw.edu.au/mud/canaryCameraMud.json | 観測：機器から `h.canaryis.com` へ TCP 80 と 443、`ipv4.connman.net` へ TCP 80、`i.canaryis.com` へ TCP 80 と 443 を許可している。古い通信から作ったもの。 |
| 2019-12-20 | 不明 | AdguardForiOS issue #1386（moust4ki） | https://github.com/AdguardTeam/AdguardForiOS/issues/1386 | `canary.is` と `canaryis.com` を許可すると動いた、という話。名前の問い合わせだけ。 |
| 2017-06-01〜2018-02-24 | — | Wayback Machine の記録 | http://web.archive.org/cdx/search/cdx?url=h.canaryis.com* | 観測：`http://h.canaryis.com/` は 301（nginx）。2017 年の Location は `https://ip-10-10-89-76/`（中の名前が出ていた）。2023-11-15 の記録は 2018 年の記録への転送で、新しい応答ではない。 |
| 2026-08-18、2026-11-24 | 不明 | Home Assistant core issue #179519、#194297 | https://github.com/home-assistant/core/issues/179519 、https://github.com/home-assistant/core/issues/194297 | Canary のクラウド（`my.canary.is` の API）は 2026 年も動いている。ファームや時刻合わせの話はない。 |
| （上流の文書） | — | ConnMan の README「Online check」 | https://kernel.googlesource.com/pub/scm/network/connman/connman/+/refs/heads/master/README | 観測：接続確認は `http://ipv{4|6}.connman.net/online/status.html` を取りに行く、と書いてある。推測：Canary の接続確認は ConnMan の初期設定のままの動き。 |
| （上流の文書） | htpdate 1.1.2 → 1.3.0 | twekkel/htpdate の Changelog | https://github.com/twekkel/htpdate/blob/master/Changelog | 観測：1.1.2 には HTTPS がない。1.3.0 で「HTTPS support has been added (no certificate validation!)」。Canary が新しい版にしたかは分からない。 |

---

## 本作業での確認（2026-11-27 04:39 UTC、サーバー側だけ。機器の動きではない）

識別子を入れない公開 URL に、HEAD と名前の問い合わせだけを送った。

| 対象 | 結果 |
|---|---|
| `h.canaryis.com` の DNS | CNAME は `ingress-k8s-prod-edge.canaryis.com`。`htpdate.prod.canaryis.com` は今は `h.canaryis.com` を指す。`lvs-htpdate.prod.canaryis.com` は答えがない。名前は残したまま、裏の仕組みが変わった。 |
| `HEAD http://h.canaryis.com/`（UA `htpdate/1.1.2`） | `301`、`Server: nginx/1.31.9`、`Date: Fri, 27 Nov 2026 04:39:24 GMT`、`Location: https://h.canaryis.com/`。推測：htpdate は 301 の Date を読むので、古い機器は今も平文で時刻を合わせられる。 |
| `https://h.canaryis.com/` | 証明書は Canary Connect, Inc. の自前の CA（Root CA 1 → Server CA 1 → `*.canaryis.com`）。一般の CA ではない。 |
| `update.sonos.com`、`update-firmware.sonos.com`、`update-timezone.sonos.com` | どれも CloudFront（`update-prod-cf.ws.sonos.com`）。HTTP と HTTPS の両方が 200 で、HTTPS への転送はない。 |
| `HEAD http://update-firmware.sonos.com/firmware/Prod/82.3-60160-v16.5.1-[tok]-GA-1/82.3-60160-1-21.upd`（2025 年の掲示板の URL） | HTTP と HTTPS の両方が `200`、長さ 55,686,866。2025-01 の「HTTP は切られる（Akamai）」とは今は違う。 |
| `HEAD http(s)://update-timezone.sonos.com/timezone/timezones.xml` | 両方 `200`、長さ 7,293。 |
| `HEAD http(s)://msmetrics.ws.sonos.com/` | 両方 `404`。 |

---

## 論文（2019〜2026）

| 論文 | 年 | Sonos・Canary について | 場所 |
|---|---|---|---|
| Ren ほか「Information Exposure From Consumer IoT Devices」（Mon(IoT)r）IMC | 2019 | 本文に Sonos も Canary も出てこない（PDF の文字を検索） | https://moniotrlab.khoury.northeastern.edu/wp-content/uploads/2019/09/ren-imc19.pdf |
| Huang ほか「IoT Inspector」arXiv 1909.09848（IMWUT 2020） | 2019 | Sonos 186 台は TLS 1.2 だけで弱い暗号なし。Sonos のポート 80 には触れていない。時刻合わせの話もない | §6.1、表 5（PDF 10 枚目） |
| Paracha ほか「IoTLS」IMC | 2021 | Sonos も Canary も出てこない | https://par.nsf.gov/servlets/purl/10351281 |
| Bradley・Barrera「Towards Characterizing IoT Software Update Practices」FPS 2022（arXiv 2209.09855） | 2022 | Ren ほかのデータを使っていて、Sonos も Canary も出てこない | https://arxiv.org/pdf/2209.09855 （データは §2） |
| Prakash ほか「Software Update Practices on Smart Home IoT Devices」arXiv 2208.14367 | 2022 | 出てこない | https://arxiv.org/pdf/2208.14367 |
| Mandalari ほか「Blocking Without Breaking」PETS 2021（arXiv 2105.05162） | 2021 | 出てこない。別の業者（Wansview）の `htpdate.ajcloud.net` が載っている（p.9、p.20） | https://arxiv.org/pdf/2105.05162 |
| Alrawi ほか「SoK … YourThings」IEEE S&P | 2019（データは 2018） | Canary と Sonos が対象。Sonos は 1024 ビットの短い SSL 鍵（p.11）。表 II（p.10）の Sonos の「Encryption」の記号は、PDF から文字を抜き出した限りでは「一部暗号化」に見えるが、要確認。更新の HTTP や時刻合わせの話は見当たらない | https://coeus.ece.gatech.edu/articles/sok_sp19.pdf |
| Mazhar・Shafiq「Characterizing Smart Home IoT Traffic in the Wild」IoTDI | 2020（データは 2018-02） | Sonos は種類の例として出るだけ。HTTP の割合は種類ごとの集計 | https://web.cs.ucdavis.edu/~zubair/files/smarthome-iot-iotdi2020.pdf （表 1、図 11） |
| Andrews 博士論文（Univ. of Bristol） | 2025-01 | Sonos Play 3 の更新は「Possibly TLS on port 80」。14 の版の通信に HTTP がある（LAN の HTTP も入っているかもしれない） | 付録 B 表 B-1（印刷 p.141）、6.5.2 節 表 6-17（PDF p.94） |
| Hamza ほか「Clear as MUD」HotNets 2018、Hamza ほか arXiv 1902.02484 | 2018、2019 | Canary camera が実験の機器に入っていて、MUD プロファイルが公開されている（上の Canary の表） | https://arxiv.org/pdf/1804.04358 |
| Herrera・Plaskett（NCC Group）Black Hat USA | 2024-08 | スライド p.42 にファームの取得には blasty の sonostool を使う、とあるだけ。更新の通り道の話はスライドにはない。白書は取れなかった | https://i.blackhat.com/BH-US-24/Presentations/US-24-Herrera-Listen-Up-Sonos-Over-The-Air-Exploitation-and-Covert-Wiretap-Thursday.pdf |

## 勧告・CVE・バグ報奨

| 対象 | 結果 | URL |
|---|---|---|
| Sonos Security Advisory の一覧 | 2024-0001（2024-08-01、Wi-Fi ドライバと U-Boot）、2024-0002（2025-02-12、HLS・MPEG-TS・SMB2）、2025-0001（2025-06-10、AirPlay）、2025-0002（2025-08-25、UPnP でトークンが漏れる）、2026-0001（2026-03-25、SMB）。平文の更新、TLS、使用データ、時刻合わせを扱ったものはない。2026-0001 の「downgrade」は SMB のプロトコルの話 | https://www.sonos.com/en-us/security-advisory |
| NVD で「Sonos」 | 23 件。平文の通信（CWE-319）や更新の通り道の CVE はない | https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Sonos |
| Sonos のバグ報奨 | 検索の要約では「外部向けのバグ報奨はない、届け出はメール」。本文は未確認 | https://www.sonos.com/en-us/vulnerability-disclosure-policy |
| NVD で「Canary Connect」 | Canary のカメラの CVE はない（ヒットした 5 件は別の製品） | https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Canary%20Connect |
| Canary のバグ報奨・脆弱性の報告 | 見つからなかった | — |

## Canary の会社と製品の状態

| 日付 | 資料 | URL | 何が書いてあるか |
|---|---|---|---|
| 2018-10-15 | TechCrunch、Brian Heater「IoT company Smartfrog takes controlling interest in Canary」 | https://techcrunch.com/2018/10/15/iot-company-smartfrog-takes-controlling-interest-in-canary/ | Smartfrog が 2,500 万ドルを出して支配権を得た。CEO は Smartfrog の Charles Fraenkl。Canary は独立したブランドとして続ける。古い機器のサポートの話はない。 |
| 2018-10-16 | The Irish Times「Smartfrog takeover of Canary is music to homeowners' ears」 | https://www.irishtimes.com/business/technology/smartfrog-takeover-of-canary-is-music-to-homeowners-ears-1.3664511 | 同じ話。金額は「€25 million」（TechCrunch はドル。通貨が食い違う）。 |
| 2019-10-29 | Canary Community の告知「Canary Pro, Canary Flex, Canary View - 5.0.0 and 5.1.x Release Notes」（Wayback 2019-11-20） | http://web.archive.org/web/20191120114337/https://community.canary.is/t/canary-pro-canary-flex-canary-view-5-0-0-and-5-1-x-release-notes/4437 | Pro と View は 5.1.1、Flex は 5.1.0。2019-11-11 の利用者の書き込みは「Nice to see an update since the Smartfrog acquisition as it has been over a year」。中身（公式の告知）は別の担当。 |
| 日付なし（2022 年より後） | Canary のページ「Smartfrog and Canary Joined Forces」 | https://caughtby.canary.is/smartfrog-uk | Smartfrog のサービスは 2022-09-16 に Canary の仕組みへ移って終わった。Canary は Smartfrog Group が運営を続ける。ファームの話はない。 |
| 2026-08、2026-11 | Home Assistant の issue（上の Canary の表） | （上） | クラウドは 2026 年も動いている。 |
| — | — | — | 初代 Canary（CAN100）のサポート終了の告知や報道は見つからなかった。 |

---

## 検索語の一覧

- WebSearch：`"update-firmware.sonos.com"`、`"msmetrics.ws.sonos.com"`、`"update.sonos.com" firewall port 80 OR http`、`"update-timezone.sonos.com"`、`"default-1-1.ups" sonos`、`"update.sonos.com" pihole OR pfsense OR opnsense OR adguard`、`sonos firmware update http plaintext "update-firmware" reddit`、`sonos "http://update-firmware.sonos.com" log`、`sonos firmware ".upd" download URL "update-firmware" github`、`Sonos speakers update fails "port 80" blocked firewall community`、`Sonos One firmware update downloaded over HTTP not HTTPS security researcher blog`、`sonos "timezones.xml" OR "X-Sonos-Id-Hash" OR "update.upm"`、`Sonos security advisory firmware update unencrypted HTTP CVE`、`Sonos security advisories list SSA 2026`、`Sonos bug bounty program HackerOne OR Bugcrowd`、`NCC Group "Listen Up" Sonos …`、`Sonos Era 100 secure boot NCC Group firmware ".upd"`、`"h.canaryis.com" OR "htpdate.prod.canaryis.com" OR "canaryis.com" htpdate`、`"canaryis.com" pihole OR adguard OR reddit OR firewall`、`canary camera firewall rules ports "canary.is" OR "canaryis.com"`、`"connman.net" "online/status.html"`、`Canary security camera vulnerability research firmware network traffic unencrypted`、`Canary Connect security camera CVE vulnerability OR "bug bounty" OR hackerone`、`Canary Smartfrog merger acquisition Canary Connect`、`"Smartfrog Group" Canary 2023 OR 2024 OR 2025 OR 2026`、`Canary All-in-One original CAN100 end of support OR discontinued`、`"Canary Pro" firmware release notes …`、`Canary security company layoffs OR shutdown …`、`Smartfrog Canary Insolvenz OR Übernahme …`、`Bradley Barrera "Towards Characterizing IoT Software Update Practices"`、`Paracha IMC 2021 IoTLS … Sonos`、`"IoTLS 2.0"`、`IoT traffic measurement study "Sonos" firmware update "HTTP" unencrypted paper`、`YourThings Alrawi … Sonos Canary`、`UNSW MUD profiles IoT devices Canary camera`、`MUD profile Sonos`
- GitHub の issue 検索（API）：`"update-firmware.sonos.com"`、`"update.sonos.com"`、`"msmetrics.ws.sonos.com"`、`"update-timezone.sonos.com"`、`canaryis.com`、`"canary.is" htpdate`、`"timezones.xml" sonos`、`"X-Sonos-Id-Hash"`、`"update.upm" sonos`、`htpdate canary`、`repo:home-assistant/core canary in:title`
- そのほか：Wayback CDX（`h.canaryis.com*`、`update-timezone.sonos.com*`、`msmetrics.ws.sonos.com*`）、NVD（`Sonos`、`Canary Connect`）、論文の PDF の文字検索（`sonos|canary|htpdate|connman`）

## 未確認の一覧

- Endian Firewall の掲示板 https://www.efw-forum.de/forum/thread/2194-proxy-deezer-sonos/ ：検索の要約では、止められた `http://update.sonos.com/firmware/latest/default-1-1.ups` が載っている。本文は 503 と取得の拒否で読めず、日付と版は分からない。
- NCC Group の白書 https://www.nccgroup.com/media/uzbp3ttw/bhus24_sonos_whitepaper.pdf ：403 で読めなかった。
- Sonos Community「Firewall rules to be configured to allow Sonos traffic」（6733951）：403 で読めなかった。
- Canary のヘルプ「How do I connect through a firewall?」 https://help.canary.is/hc/en-us/articles/211590367-How-do-I-connect-through-a-firewall ：検索の要約では TCP 443 と UDP 123（NTP）とある。本文は読んでいない（公式の記事なので別の担当）。もし本当なら、新しいファームは NTP に変わった可能性がある（推測）。
- Canary のヘルプ「What is Canary Pro?」 https://help.canary.is/hc/en-us/articles/360021743594-What-is-Canary-Pro ：検索の要約では「All-in-One の名前を変えたのが Pro」。本文は読んでいない（別の担当）。
- 旧 Canary Community のほかのスレッド（`community.canary.is` は `help.canary.is` に転送され、403）。
- 2019 年以降に初代 Canary（CAN100）の通信を観測した第三者の資料：見つからなかった。今の機器が htpdate を送るかは不明。
- 2021 年以降の `timezones.xml` を機器で観測した第三者の資料：見つからなかった。
- `msmetrics` の通信が HTTP か HTTPS か（2019 年以降）：第三者の資料は見つからなかった。
- 機器が知らせる `http://` の URL を、更新の仕組みが中で `https://` に変えて使うか：表記からは分からない（2025-01 と 2026-11 の観測は平文を示している）。
- 「IoTLS 2.0」（EuroSec 2026）：要旨だけで、対象の機器に Sonos と Canary が入っているかは分からない。
- IoT Inspector と Mon(IoT)r の生データ：申し込みが要るので見ていない。
- YourThings の表 II の Sonos の記号：PDF の文字の抜き出しが崩れているので、原本で要確認。
- Canary の持ち主について：Crunchbase の「2020 年に Smartfrog Group が買収」、別の解説サイトの「Arlo が持つ」「Lowe's が買った」はどれも出どころが弱く、確かめていない。JustAnswer の「最新ファーム 1.4.2」も確かめていない。
