# 製造者の主張と通信の突き合わせ

データセットにある IoT 機器について、製造者が公開しているセキュリティの主張を集め、実際の通信（PCAP）と食い違う箇所を探す（D31、D32）。セキュリティの主張が中心で、プライバシーの主張は補助として扱う。

## 文書

| ファイル | 中身 |
|---|---|
| [method.md](method.md) | 進め方：集める文書、主張の書き方の分類、主張の型と食い違いの条件、判定、記録の列 |
| [devices.md](devices.md) | データセットの機器の一覧（7 データセット、116 製品）。元の表は [devices.tsv](devices.tsv)（手で作成）、[devices.json](devices.json) はスクリプトの出力 |
| [claims.tsv](claims.tsv) | 集めた主張。1 行が主張 1 つ |
| [coverage.tsv](coverage.tsv) | 製品 × 文書の種類（D1〜D6）ごとに、探した結果（見つかった、アーカイブにない、読めない、製造者が出していない） |
| [unreadable.md](unreadable.md) | アーカイブにはあるが読めなかった文書の一覧（ブラウザで開く用） |
| [handoff.md](handoff.md) | 引き継ぎ：候補の一覧（強い順）、Ring のパケット単位の再確認、未完了の作業、データと道具の場所 |
| [ring-prior-work.md](ring-prior-work.md) | Ring：先行研究 4 本との比較表、版ごとのパケット単位の確認、当時の文書、handoff の訂正 |
| [cloud-research-brief.md](cloud-research-brief.md) | クラウドのセッションへの調査の指示（製造者の文書と先行研究、結果は research/ に書く） |
| [triage.md](triage.md) | 候補の一次ふるい（時期・範囲・観測）と深掘りの順番、Hue の 13 日分 |
| [sonos-check.md](sonos-check.md) | Sonos PLAY:1 の深掘り：主張の範囲と時期、13 日分の平文の識別子とファームウェア、先行研究 |
| [sonos-paper.md](sonos-paper.md) | Sonos の論文に向けた整理：収録の前後の文書の版、2018 年と 2021 年（CIC）の観測、先行研究の表 |
| [deep-checks.md](deep-checks.md) | 深掘り 2〜4（Withings Home、Wink Hub 2、TP-Link）の短い確認と判定の案 |
| [review-yourthings.md](review-yourthings.md) | 人が確かめる 23 件（食い違いの候補、文言の上で食い違い、確かめが要る一致）の確認用の表。各項目の「確認」に結果を書く |
| [results-yourthings.md](results-yourthings.md) | 結果：YourThings 2018 の 44 製品。暗号化の主張に絞った結果が中心 |
| [encryption-yourthings.md](encryption-yourthings.md) | 暗号化の主張と観測の表、44 製品の観測した暗号化、すべてのフロー、中間者の検査への反応（スクリプトで作る） |
| [versions-yourthings.md](versions-yourthings.md) | 平文の通信に出ていた機器の版（日ごと）、作成者の評価の版、リリースノートに載っているか（スクリプトで作る） |
| [yourthings-scorecards.tsv](yourthings-scorecards.tsv) | YourThings の作成者の評価（yourthings.info）のうち、暗号化に関わる項目と、評価したファームウェアの版・日付 |
| [pilot-yourthings.md](pilot-yourthings.md) | 試し：YourThings 2018 の 5 製品（Ring、Canary、Nest Cam、Belkin NetCam HD、Hue） |
| [related-work.md](related-work.md) | 先行研究と、本研究の位置づけ |

## スクリプト

| スクリプト | 使い方 |
|---|---|
| `scripts/claims/build_catalog.py` | `python3 scripts/claims/build_catalog.py docs/claims/devices.tsv ~/datasets docs/claims/devices.md docs/claims/devices.json`：機器の一覧に、解析結果から見えた期間を付ける |
| `scripts/claims/claim_offsets.py` | `python3 scripts/claims/claim_offsets.py docs/claims/claims.tsv docs/claims/devices.json`：主張ごとに、キャプチャの期間とアーカイブの日付のずれを付ける |
| `scripts/claims/check_quotes.py` | `python3 scripts/claims/check_quotes.py ~/datasets/claims/snapshots docs/claims/claims.tsv`：引用が保存した版に原文どおりあるかを確かめる |
| `scripts/claims/run_flows.sh` | `scripts/claims/run_flows.sh <その日の PCAP のディレクトリ> ~/datasets/claims/flows-yt/yt-<日>`：1 日分を時間順に読み、`flowscan.py` と Zeek（conn、ssl、x509、`tls_records.zeek`）にかける |
| `scripts/claims/flowscan.py` | すべての TCP・UDP のフローを、構造かエントロピーで分類する（暗号化、平文、分からない）。FTP のデータの接続は制御の接続から見つける。`run_flows.sh` から呼ぶ |
| `scripts/claims/mitm_sessions.py` | `python3 scripts/claims/mitm_sessions.py docs/claims/devices.tsv yourthings ~/datasets/claims/flows-yt thing-catcher.gtisc.gatech.edu ~/datasets/claims/mitm-yourthings.tsv`：データセットの作成者の中間者の検査の接続と、機器の反応（拒んだ、握手だけ、データを送った） |
| `scripts/claims/flows_summary.py` | `python3 scripts/claims/flows_summary.py docs/claims/devices.tsv yourthings ~/datasets/claims/flows-yt ~/datasets/claims/flows-yourthings.json 192.168.0.200 thing-catcher.gtisc.gatech.edu`：製品ごとのフローの分類と証明書の鍵（スキャンの端末と検査の証明書は分けて数える） |
| `scripts/claims/check_roles.py` | `python3 scripts/claims/check_roles.py <flowscan の 1 フロー 1 行の出力> <Zeek の conn.log>`：flowscan の接続の向きの推定を、SYN が見えた接続で Zeek と突き合わせる（flowscan.py の 5 つ目の引数で 1 フロー 1 行を出す） |
| `scripts/claims/versions.py` | `python3 scripts/claims/versions.py docs/claims/devices.tsv yourthings - ~/datasets/claims/versions-yt/yt-<日>.json`（標準入力に 1 日分の PCAP）：平文に出ている機器の版 |
| `scripts/claims/versions_summary.py` | `python3 scripts/claims/versions_summary.py ~/datasets/claims/versions-yt docs/claims/devices.tsv docs/claims/yourthings-scorecards.tsv docs/claims/coverage.tsv ~/datasets/claims/snapshots docs/claims/versions-yourthings.md`：製品ごと・日ごとの版の表 |
| `scripts/claims/packet_entropy.py` | 1 つの機器・ポートの、パケットごとのエントロピー（独自のプロトコルが暗号化されていそうかの推定。Nest の tcp/11095 に使った） |
| `scripts/claims/scorecards.py` | `python3 scripts/claims/scorecards.py <保存した yourthings.info のページ> docs/claims/devices.tsv docs/claims/yourthings-scorecards.tsv`：YourThings の作成者の評価から、暗号化に関わる項目を取り出す |
| `scripts/claims/observations.py` | `python3 scripts/claims/observations.py docs/claims/devices.tsv yourthings ~/datasets/gt-yt ~/datasets/runs-yt5 ~/datasets/claims/obs-yourthings.json ~/datasets/claims/mitm-yourthings.tsv`：機器ごとの観測（TLS、HTTP の形、FTP、Quarant の検出）をまとめる。検査の接続は TLS の集計から外す |
| `scripts/claims/sweep.py` | `python3 scripts/claims/sweep.py ~/datasets/claims/snapshots docs/claims/claims.tsv ~/datasets/claims/sweep.tsv`：保存した文書から、セキュリティの言葉を含むのに主張の表にない文を取り出す（読み落としの確認。出力は製造者の文章なのでリポジトリの外に置く） |
| `scripts/claims/encryption_view.py` | `python3 scripts/claims/encryption_view.py docs/claims/claims.tsv ~/datasets/claims/obs-yourthings.json yourthings docs/claims/encryption-yourthings.md ~/datasets/claims/flows-yourthings.json docs/claims/yourthings-scorecards.tsv ~/datasets/claims/mitm-yourthings.tsv`：暗号化の主張に絞った表、製品ごとの観測した暗号化、すべてのフロー、中間者の検査への反応 |
| `scripts/claims/summarize.py` | `python3 scripts/claims/summarize.py docs/claims/claims.tsv yourthings`：判定の集計 |
| `scripts/claims/collect_hints.py` | 解析結果から型番の手がかりを集める。シリアル番号や人の名前が入るので、出力はリポジトリの外（`~/datasets/claims/`）に置く |

## リポジトリの外にあるもの

- 取得したアーカイブの版（HTML と、取り出した文字）：`~/datasets/claims/snapshots/`。著作物なので、リポジトリには URL と引用だけを入れる。
- 通信の記録：Zeek の記録 `~/datasets/gt-yt/`（値は含まない）、Quarant の解析結果 `~/datasets/runs-yt5/`（03-20 は、スキャンの端末のパケットを除いて解析した）、全フローの分類と Zeek の conn・ssl・x509 `~/datasets/claims/flows-yt/`、中間者の検査の接続 `~/datasets/claims/mitm-yourthings.tsv`。`~/datasets` は外付けディスク QuarantData にある。
- YourThings の評価のページ（yourthings.info/devices/、45 機器）は、取り出した値だけを [yourthings-scorecards.tsv](yourthings-scorecards.tsv) に入れた。

## 今の状態（2026-10-31）

- YourThings の 44 製品は、全製品で D1〜D6 を探し、読み落としの確認まで済んだ（D33）。主張 678 件（最初に読めなかった 34 文書のうち 14 文書を、ブラウザと OCR で読み直した。D37）。結果は [results-yourthings.md](results-yourthings.md)。研究の範囲は暗号化（暗号の方法と、暗号化しているか）に絞った（D34）。暗号化の主張は 145 件で、通信は公開されている 13 日分すべて（D38）。食い違いの候補は 6 製品（2026-11-07 の一次ふるいで 6 製品を、11-02 に Ring を除外。[triage.md](triage.md)）。元の候補は Hue、Sonos、TP-Link の 2 製品、Apple HomePod、Withings Home、Harman Kardon Invoke、Wink Hub 2、Canary、Logi Circle、iRobot Roomba）。観測を HTTP・TLS・FTP 以外のすべてのフローに広げ、データセットの作成者の検査（ポートスキャン、中間者）の通信を外した（D35）。キャプチャの期間に 03-20 を含め、機器の版と作成者の評価を観測と並べた（D36）：キャプチャの期間中に 8 製品の版が変わっていた。
- 次：候補を人が確かめる。読めなかった文書（[unreadable.md](unreadable.md)）。ほかのデータセットに広げる。
