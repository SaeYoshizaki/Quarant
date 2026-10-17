# 現在の開発状況

最終更新：2026-10-17

## できること（実装済み・テスト済み）

- **PCAP の解析**：`quarant analyze <pcap>`。出力は `events.jsonl`、`flows.jsonl`、`observations.jsonl`、`device_inventory.json`、`findings.json`（機器 × 状態の要約）。
  - 時刻：キャプチャ時刻を使う。
  - 監視範囲：`--local-net` で指定できる。
  - 実行場所：リポジトリの外からでも実行できる（知識ベースを組み込み済み）。
- **機器識別**：MAC、OUI ベンダー（ランダム化された MAC を判別する）、DHCP（ホスト名、vendor class、option 55）、mDNS、SSDP、DNS クエリ。
  - 識別情報ごとに根拠の種類と出典を付ける。
- **平文での認証情報露出**：HTTP、MQTT、Telnet（値はマスクする）。
- **TLS**：古いバージョン、弱い暗号の提示と選択、証明書の異常（TLS 1.2 以下）、JA3。
  - TLS は、ポートに関係なく内容で判定する。
  - パーサは、標準実装（`crypto/tls`、`net/http`、mochi-mqtt）との差分検査で検証済み（[EXPERIMENTS.md](EXPERIMENTS.md) E2、E2b）。
- **振る舞い**：
  - 外向き、縦方向、LAN 内のスキャンの疑い
  - 周期通信（文脈フラグつき）
  - IP と MAC の対応の変化
- **根拠の種類**：すべてのイベントに `basis`（observed／inferred／reference_match）を付ける。
- **知識ベースとの照合**：I3〜I6（カテゴリ方針、脆弱性候補。適用可否は未確認として扱う）。
- **公開データセットでの評価**：`quarant dataset-eval iot23|unsw|unsw-attacks`。結果は [EXPERIMENTS.md](EXPERIMENTS.md) を参照。
  - ARP スプーフィング：27/27 を検出。
  - IoT-23：検出器のあるラベル 10 種類のうち 5 種類を検出。
  - UNSW の正常データ：誤検知候補の WARNING は 1 日あたり約 0.8 件。
- **レポート**
  - `quarant devices`：機器単位のレポート（見えなかったことも出す）。
  - `quarant findings`：既存の解析結果から `findings.json` を作り直し、機器 × 状態の表を出す。
  - `quarant label-eval`：正解ラベルとの比較。
  - `quarant synth`：合成シナリオの生成。
- **外部ログの取り込み**：OpenWrt、Suricata、Zeek（TSV と JSON）、Snort。統合、インシデント化、緩和計画（dry-run）、before/after 評価、研究レポート。
- **ローカル Web API**：loopback だけを許可する。UI は未ビルド。

## 一部だけ実装されていること

- **ライブキャプチャ**：`quarant live --iface`。動作の確認は未実施。
  - Ctrl-C を押すとフローを確定してから終了する。
  - 振る舞い検知に渡るのは、終了したかアイドルになったフローだけ。TCP の TTL が 1 時間なので、継続中の接続はライブ中の評価に入るのが遅れる。
- **UDP**：識別と活動の記録はできるが、UDP のフローは記録しない。そのため UDP のビーコンやスキャンは検出できない。
- **TCP の再組み立て**：方向ごとに、シーケンス番号の順に 16KB まで組み立てる。再送は捨て、並べ替えは直し、キャプチャ側の欠落は ACK から判定して数える（`capture_gaps`）。
  - 限界：SYN を観測しておらず、最初のセグメントが逆順に届いた通信は、まだ正しく組み立てられない。
  - HTTP は最初のリクエストしか解析しない。
- **Web UI**：Next.js の UI はあるが未ビルドで、新しい項目（basis、識別の根拠、振る舞い）は表示されない。

## 未実装

脅威情報との照合、NVD／KEV／EPSS、相関エンジン、SQLite、時系列比較、ベースライン学習、JA4、CoAP／RTSP／ONVIF の詳細解析、DNS トンネリング、パケット欠落の計測（TCP のペイロードを蓄積するフローだけは、ACK から欠落を数える）、実機 OpenWrt での検証。詳細は [ROADMAP.md](ROADMAP.md) を参照。

## 既知の問題

1. **イベントの冗長性**：同じ条件について複数のルールが発火し、ルールは通信ごとに報告する。
   - 対処：`findings.json`（機器 × 種類、機器 × 状態）を加えた（D19）。UNSW の正常データでは、IoT 機器のイベント 1 日 1,579〜4,593 件が、状態 49〜54 件にまとまる。
   - `quarant devices` の機器レポートにも、状態の表を出す。
   - 残り：`events.jsonl` 自体は通信ごとのまま。時間窓をまたぐ相関（Phase 2）は未実装。Web UI は未対応。
2. **重みの根拠**：`internal/reportapi/precision.go` の加重スコアには根拠が文書化されていない。研究方針 6.4 に沿って見直しが必要。
3. **知識ベースの出典**：対処済み（D20、[assessment/i5-references.md](assessment/i5-references.md)）。CVE 14 件を NVD で確かめ、製品の合わない 5 件（CVE-2023-1389 など）を外した。確認済みの CVE がない 13 項目は照合しない。キーワードは単語の単位で照合し、共有クラウドの名前を外した。残り：`i4_known_vuln_candidates.json` など、ほかの知識ファイルの出典は未確認。
4. **ルールの誤検知の可能性**（AUDIT にあるもののうち未修正）：
   - I4 の `ota` 部分一致
   - `I9_DEFAULT_HOSTNAME_PATTERN` が接続先のホスト名で判定している
   - 同じ弱い暗号について SELECTED と SUITE_OBSERVED の 2 件が出る
5. **合成 PCAP の再現性**：TLS 部分のバイト列は実行のたびに変わる（解析結果は同じ）。
6. **巨大ファイル**：`precision.go`、`mitigation.go`、`web/app/page.tsx`。分割は Phase 2 で行う。

7. **識別子の分類**：シリアル番号などの識別子が、`INSECURE_HTTP_TOKEN`（トークンの平文送信）として出力される。機密情報（CSP）ではなく識別子・個人データとして扱うべきで、イベントの種類を分ける必要がある（E4 の監査で判明。E4 の集計では除外している）。
8. **既定外のポートの HTTP**：UNSW では、HTTP リクエストの 52〜84% が既定の HTTP ポート（80、8000、8080、8888）以外で流れていて、既存の HTTP の検出の対象外になっている（E2b）。大半は LAN 内の UPnP の通信。外部への通信にも、8899 番ポートでの平文のログのアップロードなどが含まれる。LAN 内は D17 の範囲で扱う予定。外部への通信を対象にするかは未決定。
9. **機器カテゴリの推定**：機器自身の名乗りを使うように直した（D21、C1b）。UNSW 2016 の評価用 10 日で、付けたカテゴリの正解率は 38% → 77%、IoT ではない機器の誤分類は 10 → 0。確信度は当たり外れと対応するようになった。残り：IoT 機器の 72% が保留のまま。ルーターも名乗るカメラの扱い（C1b）。
   - 手がかりの棚卸し（C2、[assessment/signal-audit.md](assessment/signal-audit.md)）：19 台のうち、カテゴリそのものを名乗る機器が 6 台、製品名だけを名乗る機器が 5 台、名乗らない機器が 8 台。名乗りを日をまたいで覚えず、IP アドレスごとに分けているため、名乗りを取りこぼしている。名乗らない機器のうち、常時アップロードするカメラと 1 日に数分しか通信しないセンサーは、通信の形で見分けられそう。待機中のカメラ、プラグ、Hub は、通信量だけでは区別できない。

## 次に行う作業

### 最優先：論文の前に精度を上げる（2026-10-17 に利用者と合意）

テーマが「パッシブでどこまで判定できるか」なので、数字の信頼性を先に固める。正しさ（誤検出）は E4〜E10 で抜き取り確認済み。網羅性（見逃し）は E11 で測った。次の順で進める。

1. **見逃しを測る**：済み（E11、[assessment/miss-audit.md](assessment/miss-audit.md)）。Zeek と生パケットの検索で、Quarant とは独立に正解を作って比べた。
   - 古い TLS：36 台のうち 34 台を検出。平文の秘密情報：UNSW 2016 で 9 台のうち 3 台（ほかのデータは全件）。メディアの平文送信：5 台のうち 3 台。
   - 見逃し 11 件（10 台）の原因：要件への対応づけ漏れ 5、機器の帰属 1、解析の範囲 4、検出条件の不備 1。
2. **見つかった見逃しを直す**（次の作業）：直したら `scripts/accuracy/compare_misses.py`（判定は `docs/assessment/miss-judgments.json`。判定のない候補は unjudged と表示される）で測り直し、効果を数字で示す。正解（`~/datasets/gt-e10/`）は作り直さなくてよい。
   - 対応表：`INSECURE_HTTP_BODY_SECRET`（ほか MQTT、Telnet のペイロードの秘密情報）を 5.5-6 に入れるか判断する。入れる前に精度を抜き取りで確かめる（ROADMAP では誤検知の疑いがあるとしていた）。
   - 帰属：TLS のサーバー側が古い版を選んだときは、サーバー側の機器の証拠にもする。
   - TLS の中身による判定：レコードヘッダだけのパケット（5 バイト）でも TLS と認識する（`looksLikeTLSRecord`）。
   - メディア：multipart のすべての部分の Content-Type を見る。
   - 誤検出：Authorization の方式名（OSS など）をイベントに残し、要求ごとの署名を 5.5-6 から外す。
   - 集計：UNSW 2018 の IoT ではない 4 台（kali、HP Compaq の PC 2 台、MacBook Pro）を除外リストに加え、E4 の表を集計し直す。E4 の UNSW 2018 の 5.8-1（1 台）は MacBook Pro だった。
   - 範囲を広げるか利用者と相談すること：LAN 内の既定外ポートの HTTP（D17 の範囲）、UDP の中身、HTTP 以外のプロトコルの中のメディアの署名。
3. **候補止まりを確定に近づける**：パッシブのまま判定できる範囲を広げる。例：初期パスワード（5.1-1）は、値を保存せずに、公開されている初期パスワードの一覧とメモリ上で照合し、一致したかどうかだけを記録する。
4. **人による確認**：正しさの判定は Claude 1 人だけ。抜き取った 30〜50 件を利用者にも判定してもらう（E3 の human-review.md と同じ形）。

**作業の前提（引き継ぎ用）**
- 最新の解析結果：`~/datasets/runs-e10/`（全データ、`abf5d92` 時点）。各 run には `events.jsonl` と `device_inventory.json` だけを残す（容量のため）。
- 元データ：USB ドライブ `/Volumes/Untitled/quarant-datasets/`（UNSW 2016・2018、IoT-23、CIC IoT 2022）。`~/datasets/<名前>` からリンクしている。解析する前に USB をつなぐ。CIC のアーカイブは `/Volumes/Untitled/CIC_IOT_Dataset2022/`。
- 全データの再解析：`~/datasets/scripts/rerun-e10.sh`（バイナリと出力先を書き換えて使う。1 時間ほどかかる）。
- 出現率の集計：`python3 scripts/assessment/evidence_rates.py docs/assessment/evidence-map.json $HOME/datasets/runs-e10 docs/assessment/evidence-rates.md <samples.json> docs/assessment/non-iot-macs.txt`
- 機器の対応づけは、run ごとの `device_inventory.json` で行う。IP アドレスは日によって変わるので、run をまたいで IP で機器を特定しない（E7 で一度まちがえた）。
- 要件と検出の対応、精度の監査の記録：`docs/assessment/evidence-map.json`、`precision-audit.md`、見逃しの監査：`miss-audit.md`。実験の記録：`docs/EXPERIMENTS.md` の E4〜E11。
- 見逃しの正解：`~/datasets/gt-e10/<run>/`（`gt.log` は Zeek、`raw.jsonl` は生パケットの検索。名前だけで値は含まない）。作り方は `scripts/accuracy/run_gt.sh`。tshark は Homebrew の Lua の不整合で起動しない。

### 研究の全体（ROADMAP）

[ROADMAP.md](ROADMAP.md) の Step 0〜5 の順に進める。直近の作業は次のとおり。

1. **Step 0**：問いと関連研究の整理は済み。残りは教授との合意（[RESEARCH-SUMMARY.md](RESEARCH-SUMMARY.md) を使う）。
2. **Step 1**：
   - TS 103 701 による可観測性の分類（E3）は、独立した 2 回の分類と裁定まで済み（モデル N で一致率 0.85、κ 0.52）。人による抜き取り確認（10 件）も済み。
   - E4（証拠が実際に現れる率と精度）は済み：違反を示せる 23 要件のうち、精度を確かめた検出で実際に証拠が出たのは 5 件。
   - E5（5.5-4 認証なしの機器操作、5.12-1 UPnP のポート開放の検出を追加）は済み。
   - E6（CIC IoT 2022 の起動時の通信、40 台）は済み：古い TLS は 2016 年の 48% から 10% に減った。
   - E7（CIC IoT 2022 の待機時、39 台・30 夜）は済み：古い TLS は 8%、平文の認証情報は 5%。起動時とほぼ同じ機器だった。Zeek・Suricata との比較（Step 2）は S2 で済み。
   - E8（CIC IoT 2022 の操作時・生活場面）は済み：新しい種類の証拠は出なかった。LAN 内の操作はデータに含まれていない。
   - E9（RTSP の総当たりへの応答と、認証なしの映像アクセス）は済み：5.1-5 は候補止まり（締め出し中の 401 と区別できない）。認証なしで映像を出すカメラが 2 台あった。
   - 次：S2 を最近の機器（CIC IoT 2022）でも行う。論文の構成を決める。カメラの画像の平文アップロード（5.8-1）は E10 で検出を追加した（2022 年のカメラ 2 台）。
   - データの置き場所：元データは USB ドライブ（/Volumes/Untitled/quarant-datasets）にあり、~/datasets からリンクしている。
3. **Step 2**：Zeek、Suricata との比較は済み（S2）。フラッド系の検出器は今は作らない（D19）。残りは CIC IoT 2022 での比較。
