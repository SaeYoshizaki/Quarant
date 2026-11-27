# Sonos と Canary：問題はその後直ったか（2026-11-27）

[確かめ直しに戻る](README.md)

論文の中心にする 2 件（[Sonos](sonos.md)、[Canary](canary.md)）について、最新のファームウェア、更新とパッチの記録、第三者の観測を検索で調べた。ファームウェアの解析はしていない。第三者の資料の一覧は [fixes-thirdparty.md](fixes-thirdparty.md)。

- 調べ方：公式のページ（リリースノート、セキュリティの勧告、ヘルプ）を直接と Wayback で読んだ。第三者の資料（GitHub、掲示板、論文、NVD）を検索した。サーバーが今も平文の HTTP に答えるかを、機器の識別子を入れない要求（HEAD と GET）で確かめた（2026-11-27 04:36 UTC ごろ）。
- ブラウザの拡張はつながらなかったので使っていない。Canary のヘルプ（help.canary.is）は今のサイトが取得を拒む（403）ので、Wayback の保存を読んだ。
- **サーバーが平文に答えることは、機器が今も平文で送ることの証拠ではない。** 機器の動きは第三者の観測だけで判断した。

## まとめ

| 問題 | データで見たもの | その後 | 今（2026-11） |
|---|---|---|---|
| Sonos (a) 更新の確認（製造番号つきの `update.sonos.com/…/default-1-1.ups`） | 2018 は平文、2021 は TLS | AV-TEST（2019-04）が「Sonos のサーバーとの通信は基本的に TLS 1.2、ファームの取得が例外」 | **直った**（2019 年ごろまでに。版は未確認） |
| Sonos (b) ファームの取得（`update-firmware.sonos.com` の `.upd`、URL に製造番号など） | 2018 も 2021 も平文 | 2019-04（AV-TEST）、2025-01（Sonos の掲示板）も平文 | **直っていない**：2026-11-03 の更新（旧製品の 86.11-82170 と 98.0-82170）が HTTP の中継で取れた（第三者）。URL に製造番号が付くかは 2026 年は未確認（2025-02 の機器のログでは付く） |
| Sonos (c) 使用データ（`msmetrics.ws.sonos.com` への平文の POST） | 2018 の古い版 33.15 だけ。41.3 以降は TLS | — | **直った**（2018 年のうちに） |
| Canary（`h.canaryis.com` への平文の HEAD、時刻合わせ） | 2016-17 も 2018 も平文 | 2019 年以降に機器を観測した第三者の資料なし | **分からない**。サーバーは今も平文で時刻（Date）を返す。公式の FAQ は 2025-10 も「すべて TLS」のまま |

## Sonos

**今の公式の発表**

- プライバシーの声明（v1.13、2026-09）は今も「データはインターネットでの送信時に TLS などで暗号化して守る」と書く（[firmware-vs-docs](../firmware-vs-docs-2026-11-26.md) の B）。
- ファイアウォールの記事（[今の版](https://support.sonos.com/en-us/article/configure-your-firewall-to-work-with-sonos)、2026-11-27 に取得）：TCP 80 と 443 は「Content services, radio, and Sonos account」、4444 は「System updates」。2017 年の版にあった「80 番を更新に使う」は、もう書かれていない。つまり**今の公式の文書には、平文の更新を示す記述がない**。
- [リリースノート](https://support.sonos.com/en/article/release-notes-sonos-system-updates)（2024-10〜2026-11、今の版は Sonos 27.398.0-82170、旧製品は 86.11-82170、どちらも 2026-11-03）に、更新の通信を HTTPS にしたという記載はない。
  - 「Security improvements」（83.1-61130、2025-01-28 と 83.1-61240、2025-02-04）は、勧告 SSA-2024-0002（Pwn2Own の HLS・MPEG-TS・SMB）の修正の版と同じ。
  - 「Introduction of additional security controls」（85.0-66270、2025-07-08）は、[Connection Security の設定](https://support.sonos.com/en/article/adjust-connection-security-settings)（LAN とクラウドの API の認証、UPnP、ゲスト）のこと。
- PLAY:1 は 2025-08 から「旧製品」で、別の版の系統（今は 86.11-82170）で更新が続く（[Legacy Product Update](https://support.sonos.com/en/article/legacy-product-update)）。
- [セキュリティの勧告](https://www.sonos.com/en-us/security-advisory) は 5 件（SSA-2024-0001〜SSA-2026-0001）。U-Boot、Wi-Fi のドライバ、HLS、MPEG-TS、SMB、AirPlay、UPnP でトークンが漏れる件で、平文の更新や使用データを扱ったものはない。

**第三者の観測（ファームの取得）**

- AV-TEST「Sonos Play:1 – Turn it up!」（Dennis Henke、[2019-04-04](https://www.iot-tests.org/2019/04/sonos-play1-turn-it-up/)）：「Basically, communication with Sonos servers is TLS1.2 encrypted. However, one of the exceptions was the firmware update downloaded over an unencrypted connection.」ファイルそのものは暗号化されているとも書く。
- Sonos の掲示板（2025-01-21）：利用者がパケットを見て、スピーカーが `http://update-firmware.sonos.com/…/82.3-60160-1-21.upd` を平文の GET で取りに行くのを見た。書かれた URL にクエリはない（省いたかは不明）。
- trulyspinach/sonos-fenway の issue #2（2025-02、Connect:Amp、版 76.2-47270）：機器の更新の仕組みが `http://update-firmware.sonos.com/…/34.16-37101-1-17.upd?…&serial=<製造番号>&sonosid=&householdid=` を作る（本文で確かめた）。URL は本人が渡したもので、ID の 2 つは空。**今の更新の仕組みも URL に製造番号を足す**ことが分かる。
- BookCatKid/sonos-firmware-archive の [issue #14](https://github.com/BookCatKid/sonos-firmware-archive/issues/14)（skankmoses、2026-11-04 投稿）：2026-11-03 の更新を「transparent HTTP tee-proxy (DNS rewrite → local capture host; TLS passed through untouched)」で取った。取れたのは旧製品の `86.11-82170-1-8`・`-1-9`・`-1-20` と `98.0-82170-1-27`。更新は普通に終わった（本文で確かめた）。TLS を素通しにする中継で中身が取れたので、**2026-11 の更新も平文の HTTP で取りに行っている**（推測。ポートとクエリは書かれていない）。
- 機器が LAN で知らせる更新の URL（openHAB、Home Assistant の 2021〜2025 年のログ）と、2026-11 のマニフェスト（ReverseTelnet が保存。スピーカーの `base_url` は http が 52 件、https は付属機器の 2 件だけ）も `http://update-firmware.sonos.com/…`。
- サーバー：`update-firmware.sonos.com` と `update-timezone.sonos.com` は今も HTTP と HTTPS の両方で 200（HTTPS への転送なし）。`msmetrics.ws.sonos.com/HRMetrics/pollInterval.htm` も HTTP で 200。

**判定への意味**：(b) は 2026 年も続いていて、今のプライバシーの声明（2026-09）とも食い違う。しかも今のファイアウォールの記事は、もう「80 番を更新に使う」と書いていない。ただし、2026 年の取得の URL に製造番号が付くことは、直接は確かめていない（2025-02 の機器のログからの推測）。

## Canary

**ファームの記録**（Canary Community の公式の告知、Wayback）

| 版 | 日付 | 内容 |
|---|---|---|
| 4.0.0（All-in-One、Flex、View） | 2018-06-03 ごろ | 告知のスレッド（[保存](https://web.archive.org/web/20191016144933/https://community.canary.is/t/canary-all-in-one-canary-flex-canary-view-4-0-0-release-notes/3157/22)）。最初の投稿は保存されていない。UNSW 2018 の機器は 2018-05-30 に 35.6 MB の更新とみられる受信をしていて、これが 4.0.0 だった可能性がある（推測）。その後も平文の HEAD は続いた |
| 5.0.0、5.1.1（Pro、View。Flex は 5.1.0） | 2019-10-29 | 「Additional bug fixes and security updates」など（[保存](https://web.archive.org/web/20191120114337/https://community.canary.is/t/canary-pro-canary-flex-canary-view-5-0-0-and-5-1-x-release-notes/4437)） |
| 5.2.0 | 2020-04-16 | 映像の処理とメモリの修正など（[保存](https://web.archive.org/web/20200808230841/https://community.canary.is/t/canary-pro-flex-view-5-2-0-release-notes/4725)） |
| 5.3.0 | 2020-11-05 | LED を暗く、マイクを切る、人物検出の改善など（[保存](https://web.archive.org/web/20201202065219/https://community.canary.is/t/canary-pro-flex-view-5-3-0-release-notes/5012)） |
| それ以後 | — | 公開の告知は見つからない（掲示板はヘルプに移り、今は 403）。ヘルプの記事（2024-03 の保存）は、最新の版にしたいときは製造番号を書いてサポートにメールする、とする |

どの告知にも、時刻合わせや HTTPS の変更の記載はない。

**今の公式の発表**

- 「Canary Pro FAQ」（初代の「Original Canary FAQ」と同じ記事。2025-10 に古い名前から転送）は、2021-12-06、2022-08-16、**2025-10-18** の保存でも「All communication between your Canary device, the Canary Cloud, and your smartphone is encrypted over TLS/SSL (HTTPS).」のまま（[2025-10-18 の保存](https://web.archive.org/web/20251018194402/https://help.canary.is/hc/en-us/articles/206619098-Canary-Pro-FAQ)）。
- ファイアウォールの記事（2024-02-22 の保存）は今もポートを TCP 443 と UDP 123 とする。
- 「How do I know my Canary's connection is secure?」（2024-03-03 の保存）は「Canary connects directly to Canary Services through authenticated and encrypted channels.」
- プライバシーポリシー（Last Updated: October 5, 2026）は「generally accepted industry standards」だけ（方法を書かない評価の言葉）。
- Canary Pro は 2026-11 も canary.is で売られている。会社は 2018-10 に Smartfrog が支配権を得て、今も Smartfrog Group が運営（第三者の資料）。

**サーバーと第三者の観測**

- `http://h.canaryis.com/` に HEAD（User-Agent `htpdate/1.1.2`）を送ると、今も `301`、`Server: nginx/1.31.9`、`Date: …`、`Location: https://h.canaryis.com/` が返る。名前の行き先は `ingress-k8s-prod-edge.canaryis.com` で、`i.canaryis.com` と同じ。**時刻合わせの平文の口は今もある**。
- 2019 年以降に機器の平文の htpdate を観測した第三者の資料は見つからなかった。htpdate は 1.3.0 で HTTPS に対応した（証明書の確認なし）が、Canary が上げたかは分からない。

**判定への意味**：直ったかは分からない。公式の FAQ は 2025-10 も同じ言い切りで、サーバーは平文に答える。確かめるには、今の Canary Pro の通信を自分の機器で取る必要がある。

## 未確認

- Sonos：2026 年の平文の取得の URL に製造番号などが付くか。毎日の `update.upm` と `timezones.xml` が今も平文か（2021 年のデータでは平文）。
- Canary：2020-11 より後のファームの版と内容。今の機器が平文の HEAD を送るか。
- NCC Group の Sonos の白書（Black Hat USA 2024）は 403 で読めていない。
