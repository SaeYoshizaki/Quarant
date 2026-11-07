# Sonos PLAY:1：深掘り（2026-11-07）

[triage.md](triage.md) の深掘り 1。PCAP は `~/datasets/claims/sonos13/`（リポジトリの外）、スクリプトは `scripts/claims/hue/http_scan.py`、`hue/tls_quick.py`、`sonos/ident_check.py`。

## 判定の案

**食い違いの候補を維持する（強い）。** 収録の直前に有効だった Sonos のプライバシー文書は、製品から集めるデータにシリアル番号を挙げ、インターネット上の転送は暗号化（TLS など）で守ると書く。実際には、13 日すべてで、シリアル番号、世帯 ID、Sonos ID を URL に入れた更新の確認を平文の HTTP で送っていた。

## 主張（claims.tsv 217〜219）

- **文書**：Privacy Statement、最終更新 2017-08、[2018-02-02 の版](https://web.archive.org/web/20180202085145/https://www.sonos.com/en-us/legal/privacy)。Security の節とその FAQ に、インターネット上の転送を暗号化で守るという 3 文。
- **範囲**：同じ文書の「Using Sonos Products」の節が、製品から集める Registration data に Product serial number と IP address を、System data に製品の種類やソフトの版などを挙げる。機器の通信に当てはまる。
- **時期**：次の版は 2018-04-24 の取得で、最終更新 2018-04。Security の節の 2 文（217、218）は書き換わったが、FAQ の 1 文（219）は残る。収録の期間（2018-03-20〜04-19）を通して、少なくとも 219 は有効。
- **ほかの文書**：前回の調査（coverage.tsv の D1〜D6）で、セキュリティのページ、製品ページ、PLAY:1 のガイド、サポート記事、リリースノートを探した。暗号化について書いたのは、この文書と SonosNet（スピーカー間の無線）の説明だけ。

## 観測（自分で確認。ファイル名は `eth1-` で始まる元の 5 分のキャプチャ）

| 内容 | 日 | ファイル | フレーム | フィールド |
|---|---|---|---|---|
| 更新の確認（版 33.15） | 03-20 | `eth1-20180320.1400.1521572400` | 60977 | `GET update.sonos.com/firmware/latest/…`。クエリの `serial`（16 進 13 文字）、`sonosid`（数字 9 桁）、`householdid`（32 文字）、`cmaj`・`cmin`・`cbld`（版） |
| 同（41.3） | 03-21 | `eth1-20180321.2200.1521687600` | 84653 | 同じ 3 つの識別子。13 日とも同じ値 |
| 同（42.2） | 04-14 | `eth1-20180414.1725.1523744700` | 130971 | 同じ 3 つの識別子。13 日とも同じ値 |
| ファームウェアの取得 | 03-20 | `eth1-20180320.2140.1521600000` | 133992→133996 | `GET update-firmware.sonos.com/firmware/Gold/…`（同じ識別子つき）。応答 `filename=34.16-37101-1-8.upd`、8,306,684 バイト |
| 同 | 03-20 | 同上 | 178481→178487 | `41.3-50131-1-8.upd`、8,805,698 バイト |
| 同 | 04-13 | `eth1-20180413.1630.1523655000` | 141952→141956 | `42.2-51240-1-8.upd`、8,826,617 バイト |
| 利用状況の送信（33.15 のときだけ） | 03-20 | `eth1-20180320.1235.1521567300` | 61241 | `POST msmetrics.ws.sonos.com/HRMetrics/submit.aspx`、本文は平文の XML 594 バイト。タグは `UsageMetrics`、`hh`、`sn`、`cu`、`md`、`ver`、`uptime`、`wifi`、`temperatures` など |

- **13 日の数**：平文の更新の確認は 03-20 に 7 回、04-11 に 3 回、04-13 に 6 回、04-15 に 3 回、ほかの日は 1 回ずつ（13 日すべて）。ファームウェアの取得は 3 回。
- **識別子の一致**（値は記録していない）：XML の `<hh>` は URL の `householdid` と、`<cu>` は `sonosid` と同じ値。`<sn>` は 19 文字で、URL の 13 文字の `serial` とは表記が違う（一致は未確認）。
- **版で変わったこと**：利用状況の送信は、03-20 21:43 の更新のあとは `msmetrics.ws.sonos.com` への TLS だけになった（1 日 26〜41 回）。**更新の確認とファームウェアの取得は、33.15、41.3、42.2 のどの版でも平文**。
- **ファームウェアの中身**：エントロピーは 7.985〜7.999 で、暗号化か圧縮がされている。署名の有無は通信からは分からない（未確認）。
- **第三者**：ラジオの配信（TuneIn、StreamTheWorld）、Spotify の SDK への平文の要求もある。利用者の操作によるもので、Sonos が送るデータとは区別する。ただし 04-13 以降、TuneIn（`legato.radiotime.com/Tune.ashx`）への平文の要求 20 回の URL に、19 文字の `serial` が入る（XML の `<sn>` と同じ長さ。一致は未確認）。

## 先行研究

| 資料 | 対象と時期 | 観測・検証した内容 | 今回との関係 | 判定 |
|---|---|---|---|---|
| S. Hilt（Trend Micro）, [The Sound of a Targeted Attack](https://documents.trendmicro.com/assets/pdf/The-Sound-of-a-Targeted-Attack.pdf), 2017-12（PDF の作成日 2017-12-26） | PLAY:1。版の記載は一部のみ | LAN とインターネットに開いた状態ページからの情報の漏れ（p.3、8）。状態ページの `upgrade.log` の URL でファームウェアを取得でき、中身は gzip に独自の形式（p.37–38） | ファームウェアの URL が分かることは同じ方向。更新の確認の URL に識別子が入ることは書いていない | 関連する別の問題 |
| O. Alrawi ほか, [SoK, IEEE S&P 2019](https://coeus.ece.gatech.edu/articles/sok_sp19.pdf)（YourThings の出典） | 同じ PLAY:1（YourThings の評価：版 8.3、2018-03-20） | 機器が LAN に出すサービスの TLS の鍵が 1024 ビット、UPnP で LAN から操作できる（p.11）。評価の表で Encryption Device-to-Cloud は 2/4（[yourthings-scorecards.tsv](yourthings-scorecards.tsv)） | 作成者の評価も、機器とクラウドの間の暗号化に問題があるとしている。何が平文かは書いていない | 関連する既知の観測（詳細は未確認） |
| S. P. Kavalaris, E. Serrelis, Security issues of contemporary multimedia implementations: the case of Sonos and SonosNet, ISDF 2014 | | LAN の認証のないサービス。本文は [sonos-paper.md](sonos-paper.md) で確認 | LAN 側だけ | 関連する別の問題 |

## まとめ

- **既知の再確認にとどまる点**：ファームウェアの URL が分かること（Trend Micro）。機器とクラウドの間の暗号化に問題があること（YourThings の評価）。
- **追加検証する価値がある点**：シリアル番号、世帯 ID、Sonos ID が、13 日すべて、3 つの版すべてで平文の URL に出ること。利用状況の XML が旧版だけ平文で、更新後に TLS に移ったこと（Ring、Hue と同じく、版で変わる）。
- **判断に不足する証拠**：更新の確認の応答の中身（text/html、771 バイト）の形。ファームウェアの署名。YourThings の評価の「2/4」が何を数えたか。Kavalaris ほか 2011 の本文。
- **2026-11-07 の追記**：上の 4 点のうち、応答の形、評価の意味、Kavalaris（2014 年の誤り）は [sonos-paper.md](sonos-paper.md) で確かめた。ファームウェアの署名は今も未確認。
