# Sonos：論文に向けた整理（2026-11-07）

[sonos-check.md](sonos-check.md) の続き。論文で使えるように、根拠と先行研究をそろえた。PCAP はリポジトリの外にある（2018 年分は `~/datasets/claims/sonos13/`、2021 年分は `~/datasets/claims/sonos-cic/`）。

## 結論の案

1. **2018 年**：Sonos PLAY:1 は、シリアル番号、Sonos ID、世帯 ID を URL に入れた更新の確認を、平文の HTTP で送っていた。13 日すべて、3 つの版すべてで送り、13 日で 28 回。ファームウェアの取得 3 回にも同じ識別子が入る。同じ時期の Sonos のプライバシー文書は、インターネット上の転送を TLS などで暗号化すると書き、集めるデータにシリアル番号を挙げていた。
2. **2021 年**（CIC IoT 2022、Sonos One）：更新の確認は TLS に移っていた。ただしファームウェアの取得は平文の HTTP のままで、URL に同じ 3 つの識別子が入っていた。30 日で 2 回で、どちらも版が上がった日。この時期のプライバシー文書（最終更新 2020-11）も、インターネット上の転送を TLS などで暗号化すると書き、シリアル番号を集めるデータに挙げている。
2. **識別子の中身**：`serial` は、機器が LAN の UPnP で自分のシリアル番号として返す値と同じで、先頭 12 文字は機器の MAC アドレス。`householdid` は、機器が LAN の SSDP で知らせる世帯 ID と同じ。2018 年も 2021 年も同じ。
3. **先行研究**：この URL の形（クエリにシリアル番号と ID が入ること）は、Geissler（HITB 2023）が公開している。ただし示している URL は HTTPS で、機器が平文で送っていたことは書いていない。読んだ範囲では、平文で送っていたことや、メーカーの説明との食い違いを報告した資料はなかった。資料が見つからないことは、新規性の根拠にしない。

## メーカーの説明

文書は Sonos の Privacy Statement（`www.sonos.com/en-us/legal/privacy`）。

| 版 | 最終更新 | アーカイブの日時 | 暗号化について | 識別子について |
|---|---|---|---|---|
| [2018-02-02 の版](https://web.archive.org/web/20180202085145/https://www.sonos.com/en-us/legal/privacy) | 2017-08 | 2018-02-02 08:51 | Security の節に 2 文。インターネットで送るときに暗号化（TLS など）で守る、と書く。FAQ にも「Any data we transmit over the internet is protected using encryption.」 | 「Using Sonos Products」の節で、Registration data に Product serial number と IP address を挙げる。登録のときに「unique alpha-numeric identification number」を作り、メールアドレス、シリアル番号、IP アドレスと結び付ける、と書く |
| [2018-04-24 の版](https://web.archive.org/web/20180424223112/https://www.sonos.com/en-us/legal/privacy) | 2018-04 | 2018-04-24 22:31 | TLS の文は言い回しを変えて残る。FAQ の文はそのまま残る | 同じ |

| [2021-11-03 の版](https://web.archive.org/web/20211103210434/https://www.sonos.com/en-us/legal/privacy)、[2021-12-21 の版](https://web.archive.org/web/20211221204711/https://www.sonos.com/en-us/legal/privacy) | 2020-11 | 2021-11-03 21:04、2021-12-21 20:47 | Security の節に TLS の文（2018-04 の版と同じ文）。FAQ の文はない | 同じ（Registration data に Product serial number。ID とシリアル番号を結び付ける文も同じ） |

- **対象**：2018 年の版は「It applies to all Sonos Products」、2021 年の版は「It applies to all products offered by Sonos」。機器に当てはまる。
- **2018 年の収録期間中の版**：期間（2018-03-20〜04-19）の記録は、2018-03-24〜25（ほかの地域の URL）と 2018-04-04 にあるが、どれも転送（302）だけ。転送先（`/on/demandware.store/…/Search-ShowContent?fdid=privacy`）は、期間中の記録がない。期間の前後の版に同じ趣旨の文があるので、期間中も有効だったと考える。ただし期間中の本文は確かめていない。
- **2021 年**：2 つの版は CIC の待機時の収録（2021-11-02〜12-23）をほぼ挟む。最終更新は同じ 2020-11。
- URL の `householdid` が、文書の「unique alpha-numeric identification number」と同じものかは未確認。
- 前回の調査（[coverage.tsv](coverage.tsv) の D1〜D6）で、ほかの文書（製品ページ、PLAY:1 のガイド、サポート記事、リリースノート、EULA）には、機器とクラウドの間の暗号化の記述がなかった。

## 観測

### 識別子の中身（2018 年と 2021 年で同じ結果）

`scripts/claims/sonos/ident_meaning.py` で、値を出さずに一致だけを調べた。

| URL のパラメータ | 比べた相手 | 結果 |
|---|---|---|
| `serial`（13 文字） | 機器が tcp/1400 で返す UPnP の機器説明の `<serialNum>`（形は `hh-hh-hh-hh-hh-hh:h`）。2018 年は `eth1-20180320.0000.1521522000` のフレーム 4429、2021 年は `2021_11_17_Idle.pcap` のフレーム 642228 | 区切りを除くと一致 |
| `serial` の先頭 12 文字 | 機器の MAC アドレス（Ethernet の送信元）、SSDP の `uuid:RINCON_…` | 一致 |
| `serial` | 2018 年の利用状況の XML の `<sn>`（19 文字） | 区切りを除くと一致（[sonos-check.md](sonos-check.md) の「一致は未確認」を解消） |
| `householdid`（32 文字、`Sonos_` で始まる） | 機器が SSDP で知らせる `X-RINCON-HOUSEHOLD` | 一致 |
| `sonosid`（10 進 9 桁） | 2018 年の XML の `<cu>` | 一致（意味は未確認） |

- **分かること**：URL の `serial` は、機器が自分で名乗る製品のシリアル番号。その中に MAC アドレスが入っている。MAC アドレスと世帯 ID は、ふつう家の LAN の中でしか見えない値だが、平文の URL でインターネットに出ている。
- ヘッダーには識別子はない（User-Agent は `Sonos` か `Wget`）。

### 2018 年（YourThings、PLAY:1）

既存の表は [sonos-check.md](sonos-check.md)。今回、次を確かめた。

- **識別子つきの平文の要求**：更新の確認 28 回とファームウェアの取得 3 回。クエリのキーは `cmaj`、`cmin`、`cbld`、`subm`、`rev`、`reg`、`serial`（16 進 13 文字）、`sonosid`（10 進 9 桁）、`householdid`（32 文字）。値は記録していない。
- **更新の確認の応答**：771〜773 バイトのバイナリ。読める部分は、`update-firmware.sonos.com` のファームウェアを指す `http://` の URL 2 つだけで、要求の識別子は入っていない（`eth1-20180320.1400.1521572400` のフレーム 60977 への応答、`eth1-20180413.1630.1523655000` の応答。`scripts/claims/sonos/resp_shape.py`）。
- **TLS**：13 日間、`update.sonos.com` を SNI に持つ TLS は 1 回もない（既存の `tlsq-*.json` の集計）。
- **第三者へのシリアル番号**：版 42.2 になった 04-13 から、ラジオの局の情報を返すサービス（`GET legato.radiotime.com/Tune.ashx`）への平文の要求の URL に `serial`（19 文字、`hh-hh-hh-hh-hh-hh:h` の形）が入る。7 日で 20 回、値はすべて同じで、機器のシリアル番号と一致する（最初は `eth1-20180413.1730.1523658600` のフレーム 87774）。利用者がラジオを再生したときの通信だが、シリアル番号を付けているのは Sonos の機器。
- **作成者の試験との関係**：YourThings の作成者は、03-20、21、28 にポートスキャン、04-10〜13 と 04-15 に中間者の試験をしている。平文の更新の確認は、試験のない 04-14、04-16〜19 にも 1 日 1 回ある。中間者の試験より前の日も平文なので、試験が平文の原因ではない。回数が多い日（03-20 に 7 回、04-13 に 6 回など）は試験や更新の日と重なるので、回数そのものは機器の通常の頻度として扱わない。

### 2021 年（CIC IoT 2022、Sonos One）

- **データ**：`2-Idle` の 30 日分（2021-11-02〜12-23。1 日約 11 時間、40 台の機器が待機中）。機器の MAC で切り出した（`scripts/claims/sonos/cic_prep.sh`）。電源投入（`1-Power`）の 3 本と操作（`3-Interactions`）の 12 本も見た。機器一覧の名前は「Sonos One Speaker」。世代は未確認。
- **版**：SSDP の `SERVER` では 65.1-21040 → 66.4-23090（`2021_11_17`）→ 66.4-23300（`2021_12_09`）。
- **更新の確認**：`update.sonos.com` への TLS が 30 日すべてで 1 日 1 回（版が上がった日は 2 回）。平文の `update.sonos.com` はない。
- **目録**：`GET update-firmware.sonos.com/firmware/Prod/…/update.upm` を、クエリなしの平文の HTTP で 28 日に 30 回（例：`2021_11_02_Idle.pcap` のフレーム 937946）。応答は約 7.4 KB の XML。機種ごとのファームウェアを指す `http://` の URL が並び、末尾に `SIGNATURE` のコメント（16 進 512 文字）がある。識別子は入っていない。
- **ファームウェアの取得（平文）**：

| 日時（UTC） | ファイル | フレーム | 内容 |
|---|---|---|---|
| 2021-11-18 07:14 | `2021_11_17_Idle.pcap` | 591779（`update.sonos.com` への TLS）→ 592023（GET） | `66.4-23090-1-26.upd`、47,489,420 バイト。クエリに `serial`（16 進 13 文字）、`sonosid`（10 進 9 桁）、`householdid`（32 文字） |
| 2021-12-10 07:48 | `2021_12_09_Idle.pcap` | 812971 → 813200 | `66.4-23300-1-26.upd`、49,815,981 バイト。キーも値も上と同じ |

- **電源投入と操作の 15 本**：Sonos のサーバーへの平文の要求はない（平文はラジオの配信だけ）。
- **Active の 1 本と Scenarios の 18 本**：Sonos のサーバーへの平文の要求はない。`opml.radiotime.com/Tune.ashx` への平文の要求が 2 回あり（`IoTNonIoT_1.pcap` のフレーム 39444、41352）、URL に `serial` が入る。ただし 28 文字の別の値で、機器のシリアル番号とは一致しない。2018 年と違い、第三者にはシリアル番号そのものは送っていない。

### 2 つのデータを比べるときの注意

- 機種が違う（PLAY:1 と One）。同じ機器の経年変化ではない。
- 収録の場所、時期、ネットワーク、利用のしかたが違う。CIC は待機中の夜間だけで、2018 年のように利用者の操作を含まない。
- いつ更新の確認が TLS に移ったかは、この 2 つからは分からない（2018-04 から 2021-11 の間。未確認）。

## 先行研究

本文を読んだもの。

| 資料 | 対象と時期 | 観測・検証した内容 | 今回との関係 | 判定 |
|---|---|---|---|---|
| P. Geissler, [Smart Speaker Shenanigans: Making the SONOS One Sing Its Secrets](https://conference.hitb.org/hitbsecconf2023ams/materials/), HITB Amsterdam 2023（資料のファイル日付 2023-04-21） | Sonos One。版の記載なし | p.58「SONOS OTA: HTTP」：`update.sonos.com/firmware/latest/default-1-1.ups` への GET。クエリにシリアル番号といくつもの ID が入り、機微な値だと書く。応答は TLV の独自のバイナリで、ファームウェアの URL の元を含む。示す URL は `https://` | URL の形とクエリの識別子は同じ。平文で送っていたことは書いていない | **同じ要求の形は既知**。平文であることは別 |
| P. Geissler, [blasty/sonos](https://github.com/blasty/sonos)（`sonostool/sonostool.py`） | | 同じ URL を組み立てるツール。`UPDATE_URI_BASE` は `https://update.sonos.com`。クエリのキーは今回と同じ 9 つ | 同上 | 同上 |
| Dicklesworthstone, frankensonos の `docs/UPDATE_FEED_AND_SIGNATURE.md`（2026-10-22） | S1 の版 57.23 | 機器は更新の URL に同じクエリ（serial、sonosid、householdid を含む）を付ける。Sonos のホスト名には HTTPS を使う、と書く | 2026 年の S1 では HTTPS。2018 年の平文とは時期が違う | 関連する別の観察 |
| S. Hilt（Trend Micro）, [The Sound of a Targeted Attack](https://documents.trendmicro.com/assets/pdf/The-Sound-of-a-Targeted-Attack.pdf), 2017-12 | PLAY:1 ほか | LAN とインターネットに開いた状態ページからの情報の漏れ。`upgrade.log` でファームウェアの URL が分かる（p.37–38） | ファームウェアの場所が見えることは同じ方向。経路は LAN の状態ページで、通信の盗み見ではない | 関連する別の問題 |
| S. P. Kavalaris, E. Serrelis, Security Issues of Contemporary Multimedia Implementations: The Case of Sonos and SonosNet, ISDF 2014（テッサロニキ、pp.63–74）。[Wayback の PDF](https://web.archive.org/web/2019id_/http://sdiwc.net/digital-library/request.php?article=8ae1333ede7bbc66cbcb756414427a41) | Sonos。型番と版の記載なし | LAN の試験：tcp/1400 の認証のない HTTP の管理ページ、`upgrade.log` からファームウェアの場所が分かること（p.69）、SonosNet の鍵の取り出しなど。ファームウェアを中間者で差し替える攻撃は「できる可能性」にとどまる（p.69–70）。インターネット側は扱わない | LAN 側だけ | 関連する別の問題 |
| O. Alrawi ほか, [SoK: Security Evaluation of Home-Based IoT Deployments](https://alrawi.github.io/static/papers/alrawi_sok_sp19.pdf), IEEE S&P 2019 | 同じ YourThings の PLAY:1（同じ 2018 年の収録） | p.18 Table VII で、機器とクラウドの間の暗号化を「部分的」（◐）とする。p.11 の 1024 ビットの鍵は、機器が LAN に出すサービスの TLS の話（§V-D）。どの通信が平文かは書いていない | 同じ機器、同じ期間。「部分的」の中身は書いていない | 関連する既知の観測（中身は未記載） |
| [YourThings の Sonos のページ](https://yourthings.info/devices/sonos)と評価表の CSV | PLAY:1、Firmware Version 8.3、評価日 2018-03-20 | 機器とクラウドの間の暗号化 2/4（部分的。点が高いほど悪い）。HTTP の欄はページでは 0/1、CSV では 1 で、食い違う | 「部分的」の定義はない。8.3 と今回の版番号（33.15、41.3、42.2）の対応は未確認 | 同上 |
| D. Y. Huang ほか, [IoT Inspector](https://arxiv.org/abs/1909.09848), arXiv v1 2019 | 利用者の家の Sonos 310 台（2019-04〜05）。ペイロードなし | Sonos の 186 台はすべて TLS 1.2 で、弱い暗号を提示しない（Table 5, p.10） | TLS の質だけ。平文の中身は分からない | 比較できない |
| A. Mazhar, Z. Shafiq, [Characterizing Smart Home IoT Traffic in the Wild](https://arxiv.org/pdf/2001.08288), IoTDI 2020 | 220 世帯のフローログ（2018-02）。Sonos を含むスピーカー 29 台 | HTTP と HTTPS の割合は種類ごとの集計だけ（Fig. 11） | 機器ごとの中身はない | 比較できない |

- **Sonos が対象に入っていないもの**（機器の表と本文で確認）：Ren ほか IMC 2019（Mon(IoT)r）、Paracha ほか IMC 2021（IoTLS）、Girish ほか IMC 2023、Mandalari ほか PETS 2021、Saidi ほか IMC 2020。
- **関連する CVE**：CVE-2018-11316（UPnP の HTTP サーバーへの DNS rebinding。LAN 側）。NVD で「Sonos」を検索した 22 件に、平文の通信や更新の確認についてのものはない（2026-11-07）。
- **報道**：The Register, 2017-10-12（T. Claburn）。2017-08 のプライバシーポリシーの変更の記事で、通信の暗号化には触れていない。
- **読めなかったもの（未確認）**：Kavalaris と Serrelis の論文誌版（IJCSDF 4(3), 2015。DOI の行き先が乗っ取られたドメインで、Wayback に PDF なし）、Andrews ほか, An analysis of IoT device update mechanisms, Computers & Security 2026（ScienceDirect が 403。Sonos を含むか不明）。

**まとめ**：更新の確認の URL にシリアル番号などが入ることは、2023 年に公開されている。新しく言えるのは次の 3 点。

1. 2018 年の機器は、それを平文の HTTP で送っていた。
2. それは、メーカーが暗号化を書いていた時期と重なる。
3. 2021 年にも、ファームウェアの取得で同じ識別子が平文で出ていた。

ただし、資料が見つからないことは、新規性の根拠にしない。

## 論文で言えること・言えないこと

- **言えること**
  - メーカーが暗号化を書いていた時期に、シリアル番号を含む識別子を、平文の HTTP でインターネットに送っていた。前後の文書の版で時期を挟み、13 日すべて、3 つの版すべてで確かめた。
  - 2021 年の別の機種では、更新の確認は TLS に移っていた。一方で、ファームウェアの取得の URL には同じ識別子が平文で残っていた。
  - どちらも、復号も機器の操作もせず、パッシブな観測だけで確かめられる。
- **言えないこと（未確認）**
  - 識別子を第三者が見たときに何ができるか。試していない。
  - 今の製品の動き。2026 年の第三者の解析（frankensonos、S1 の版 57.23）は、目録のファームウェアの URL は今も `http://` だが、機器は Sonos のホスト名に HTTPS を使う、と書く。S2 の今の版は分からない。
  - 更新の確認が TLS に移った時期と、その理由。
  - 平文で取得したファームウェアを改ざんされたときに、機器が拒むか。2021 年の目録には署名の欄があるが、機器が検証しているかは通信からは分からない。2018 年の応答に署名があるかも分からない。
  - 2021 年の TLS の更新の確認の中身。
  - `householdid` と文書の ID が同じものか。
