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

## ファームウェアの本体と更新の履歴（2026-11-27 の追加の調べ）

ファームの本体がウェブで取れるか、更新の履歴が分かるかを、GitHub、公式のヘルプ（Chrome で今のサイトを読んだ）、Wayback で調べた。本体は落としていない（場所と大きさだけ。ダウンロードと解析は利用者に聞いてから）。

### Sonos：本体は取れる。版の履歴もそろう

- **公式の配布元**：`update-firmware.sonos.com`（CloudFront）。新しい版は今も HTTP でも HTTPS でも取れる（2025 年の版で確かめた。上の「サーバー」）。
- **第三者の保管庫**：[BookCatKid/sonos-firmware-archive](https://github.com/BookCatKid/sonos-firmware-archive)（2026-08 開始、2026-11-27 も更新中）。`data/catalog.json`（2026-11-27 に取得、外付けディスクの `~/datasets/claims/verify5-20261127/fwhist/catalogs/sonos-catalog.json`）に、更新ファイル 1,504 件の出どころ、大きさ、SHA-256、GitHub Releases の写しがある。機種の番号は、PLAY:1 が 8（「Fenway family」）、Sonos One（第 2 世代）が 26。
  - **PLAY:1（8）**：39 件の記録、うち 33 件は本体が保存されている。版（表示の版）：28.1（5.2）、**34.16-37101（7.1）**、47.2（9.3）＊、55.1（11.0）、57.5〜57.23（11.2.6〜11.16.2、S1 の系統）、62.1（13.0）、64.3（13.2）、65.1（13.3）、66.4（13.4）、67.1（14.4）、73.0（15.5）、76.2（15.11）、80.1（16.3、16.3.3）、81.1（16.4.2、16.4.4）、82.2（16.5）、82.3-60160（16.5.1）、86.1（17.2.1）、86.8（17.2.6）、86.10（17.2.7）、**86.11-82170（27.3、2026-11-03 の今の版）**。＊は公式の配布元から消えたもの。2025-08 から PLAY:1 は 86.x の旧製品の系統に分かれたので、90.0 以降の通常の系統の版は PLAY:1 用には配られていない（記録はあるが配布元にない）。
  - **Sonos One（26）**：33 件、うち 32 件が保存。CIC の収録で見た 64.3-19080、65.1-21040、66.4-23090 もある。今の版は 98.0-82170（27.3）。
  - **データとの照合**：YourThings の PLAY:1 が 2018-03-20 に平文で取得した 34.16 の大きさ（8,306,684 バイト）は、保管庫の `34.16-37101-1-8.upd` の大きさと一致する。YourThings で見た 33.15、41.3、42.2 は保管庫にない。
  - 更新ファイルは暗号化されている（AV-TEST 2019、保管庫の説明）。保管庫は一部の鍵の回収と復号の手順も公開しているが、ここでは扱わない。
- **更新の履歴**：
  - 公式の[リリースノート](https://support.sonos.com/en/article/release-notes-sonos-system-updates)は 2024-10（81.1）〜2026-11（27.398.0 と旧製品の 86.11）。それより古いもの（support.sonos.com の記事 3521、2019〜2022 年の保存がある）は、JavaScript で描くページで、Wayback の保存を Chrome で開いても中身が出なかった（未確認）。
  - 上の版の一覧と第三者の観測を合わせると、**更新の確認が TLS になったのは 42.2（8.5、2018-04）より後、AV-TEST の試験（2019-04、アプリ 10.0）より前**。その間の版の通信は見ていない。
  - 公式の告知のどれにも、更新の確認・取得を HTTPS にしたという記載はない（上）。

### Sonos：落としたファームの中身（2026-11-27、利用者の依頼で 2 本だけ）

公式の配布元（HTTPS、CloudFront 3.169.5.39）から 2 本を落とした。置き場所は外付けディスクの `~/datasets/claims/verify5-20261127/fwhist/downloads-sonos/`（リポジトリには入れない）。**復号はしていない**。ファイルの中で、もともと平文のまま入っている文字列だけを読んだ。

| ファイル | 大きさ | SHA-256 | 保管庫の記録との一致 | 中身 |
|---|---|---|---|---|
| `34.16-37101-1-8.upd`（PLAY:1、2018-03 にデータの機器が取得した版） | 8,306,684 | `3e1c8270…08482a` | 一致 | 先頭の見出し（`49 7f 16 35`）のあとは全部が高エントロピー（64 KiB の 127 ブロックすべて 7.5 以上）。読める URL や関係する文字列はない |
| `86.11-82170-1-8.upd`（PLAY:1 の今の版、2026-11-03） | 21,423,961 | `b4774d97…aafd0b` | 一致 | 327 ブロックのうち 219 が低エントロピーで、平文の部分が多い |

- 34.16 は 2026 年の今も公式の配布元から取れる。

**86.11-82170（今の版）の平文の文字列**（ファイルの中の位置つき）：

- 更新の URL を作る書式：
  - `0xcb3ee3`：`%supdate.upm?cmaj=%u&cmin=%u&cbld=%u&subm=%u&rev=%u&reg=%u&serial=%s`
  - `0xcb3f2b`：`%s%s-%u-%u.upd?cmaj=%u&cmin=%u&cbld=%u&subm=%u&rev=%u&reg=%u&serial=%s`
  - `0xcb3f73`：`&sonosid=%s&householdid=%s`
  - 2018 年（YourThings）と 2021 年（CIC）のデータで平文だった URL と同じ形。**今のファームも、更新の一覧とファームの取得の URL に製造番号、Sonos ID、household ID を入れる作りのまま**。先頭の `%s`（配布元の URL）はファームの外（機器の設定やマニフェスト）から来る。第三者の記録では、機器が知らせる `UpdateURL` と `ManifestURL`、2026-11 のマニフェストの `base_url` は `http://` で、このファイルそのもの（`86.11-82170-1-8`）が 2026-11-03 に HTTP の中継で取られている（上の issue #14）。だから、今も平文の HTTP で製造番号などが送られていると推測できる。ただし、今の機器の通信は取っていない（推測）。
- 時刻帯の表：`0xc3a57f`：`http://update-timezone.sonos.com/timezone/timezones.xml`。**http がファームに直接書かれている**。
- 使用データ：`O_HRMETRICS_URL`（`0xc88187`）、`/HRMetrics/`、`%s%s?hhid=%s`（`0xca76eb`）、`pollInterval.htm`、`submit.aspx`、`<UsageMetrics>`。送り先の URL は設定（`O_HRMETRICS_URL`）から来るので、http か https かはファームの文字列からは分からない。2018 年のデータでは 41.3 以降が TLS。
- ヘッダ：`X-Sonos-Id-Hash: %s`（`0xc85c47`）。2021 年のデータで平文の要求に付いていた見出しと同じ。
- `https://` で書かれた Sonos のホストは `https://sonar.ws.sonos.com` の 1 つだけ。更新の配布元を https で書いた文字列はない。
- 先頭近く（`0x2c`〜）に `2021_11_PATCHES:`、`2022_02_PATCHES:`、`UBI_RED_KEY_WITH_NONCE:`、`2023_01_PATCHES:`、`MAX_MDP_VERSION_6:`、`2023_12_PATCHES:`、`2024_12_PATCHES:` という名前が並ぶ。日付つきのパッチの集まりの名前に見えるが、中身は書かれていない（推測。更新の仕組みの互換の印かもしれない）。

**限界**：文字列があることは、その機能が使われることの証明ではない。どのプログラムの文字列かも確かめていない（中の ELF の解析はしていない）。

**論文に向けたメモ（2026-11-27）**：Sonos の食い違い（「送信時に TLS で保護」に対して平文の HTTP で製造番号などを送る）は、2018 年のデータだけの話ではない。

- 今の公式の声明（v1.13、2026-09）は「送信時に TLS で保護」と言い切ったまま。
- 今の PLAY:1 のファーム（86.11-82170、2026-11-03）は、更新の URL を `serial=%s&sonosid=%s&householdid=%s` で作る書式と、`http://update-timezone.sonos.com/...` を平文のまま持っている。
- このファーム自身が 2026-11-03 に平文の HTTP の中継で取得された（第三者、issue #14）。
- → 食い違いは**今も続いている可能性が高い**（推測）。論文では 2018 年を主の証拠にし、今のファームと今の声明を「問題が残っているとみられる」根拠として添える。**確定には今の実機の収録が 1 回要る**（パッシブの範囲内。能動的な検査ではない）。これは判断待ち（メーカー連絡・実機の収録、decisions-pending の D5・D6）に関わる。

深掘りのファームウェア解析（Ghidra、暗号化版の扱い）は [firmware-analysis-2026-11-27.md](firmware-analysis-2026-11-27.md) に分けた。

### Canary：本体は公開されていない。版の番号は 9.x まで分かる

- **本体**：公開の場所は見つからなかった。GitHub のコードの検索（`canaryis.com` で 119 件、`device-ota.prod.canaryis.com`、`o.canaryis.com`）は、Home Assistant の連携、MUD のファイル、本研究のリポジトリ、DNS の研究の付録だけ。FCC の届け出（FCC ID 2ACDL-C100）は中の写真だけ。2015 年の試験記事（CSO Online）は SD カードから入れる偽のファームを試したとあるが、本体の配布ではない。機器は更新を `o.canaryis.com`（`device-ota.prod.canaryis.com`）から TLS で受ける（2018 年のデータ）ので、外から取れないとみられる（推測）。
- **公式の版の告知**：Canary Community に 4.0.0（2018-06 ごろ）、5.0.0・5.1.1（2019-10-29）、5.2.0（2020-04-16）、5.3.0（2020-11-05）の告知がある（上の表）。それより後の版ごとの告知は、今のヘルプ（Chrome で検索。Announcements は 5 件で、ファームの告知はない）にも Wayback にも見つからなかった。
- **今のヘルプの記事に出てくる版**（2026-11-27 に Chrome で読んだ）：
  - 「How do I remove and deactivate a Canary?」：機器の版 7.0.0 以上。
  - 「What are Smart Detections?」：7.2.0 以上。
  - 「How do I set up masks?」：Canary Pro・Flex・View とも機器の版 9.0.0 以上、アプリ 9.1.0 以上。
  - 「How does Two-way Talk work?」と「Continuous Video Recording FAQ」（作成は約 5 か月前）：機器の版 9.0.0 以上。
  - 「What firmware version is my device using?」：Canary は時々、新しいセキュリティの更新や機能の更新でファームを自動で更新する、とする。
  - つまり **Canary Pro のファームは 2020 年の 5.3.0 の後も 9.x まで更新が続いている**。ただし版ごとの変更の内容は公開されていない。
- **今の公式の文**：「Canary Pro FAQ」は**今日（2026-11-27）も**「All communication between your Canary device, the Canary Cloud, and your smartphone is encrypted over TLS/SSL (HTTPS).」を載せている（Chrome で今のサイトを読んで確かめた）。
- **2026 年の第三者の観測**：GitHub の Dicklesworthstone/franken_surveillance_system（所有者が許した機器の検査の記録、2026-10）に、Canary の機器（MAC 7C:70:BC:5D:4C:09、機種と版は書かれていない）の DNS（`i.canaryis.com` → `ingress-k8s-prod-edge.canaryis.com`）と SNI（`o.`、`v.canaryis.com`）がある。機器はほとんど眠っていて、`h.canaryis.com` や TCP 80 の記載はない。平文の時刻合わせが続くかどうかの材料にはならない。

## 未確認

- Sonos：2026 年の平文の取得の URL に製造番号などが付くか。毎日の `update.upm` と `timezones.xml` が今も平文か（2021 年のデータでは平文）。
- Canary：2020-11 より後のファームの版と内容。今の機器が平文の HEAD を送るか。
- NCC Group の Sonos の白書（Black Hat USA 2024）は 403 で読めていない。
