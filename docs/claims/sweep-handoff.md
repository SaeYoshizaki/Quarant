# 引き継ぎ：公式文書と通信の食い違いを探す（2026-11-11）

次の会話はここから始める。利用者は、この作業を終わるまで任せている（2026-11-11）。これまでの結果は [sweep-results.md](sweep-results.md)、決めたことは [../DECISIONS.md](../DECISIONS.md) の D41、記録は [../EXPERIMENTS.md](../EXPERIMENTS.md) の E16。

## 1. 目的（2026-11-11 に利用者と確認）

**企業の公式文書に書いてあることと、実際の通信が違うところを探す。** 通信を見て分かる範囲の食い違いなら、何でも対象にする。

| 主張の種類 | 通信で見えること | 例 |
|---|---|---|
| 暗号化しているか | 平文か、TLS などか | 「すべて暗号化」なのに平文の HTTP |
| 暗号の方式 | TLS の版、選ばれた暗号、鍵の長さ、前方秘匿性 | 「AES-256」なのに AES-128。「TLS 1.2」なのに 1.0 |
| 証明書の扱い | 偽の証明書を受け入れたか（YourThings の作成者の検査の記録だけ） | 「certificate pinning」なのに受け入れた |
| 送るデータ | 平文なら中身、暗号化なら宛先と量 | 「識別子は送らない」なのに MAC を送る |
| 機器の中で処理するか | クラウドへの送信があるか | 「映像は機器の中で処理」なのに画像を送る |
| 更新 | 取得が HTTP か | 「更新は暗号化して配信」なのに HTTP |
| 送り先 | 第三者への送信 | 「第三者に送らない」なのに広告のサーバーへ |

通信から見えないもの（保存時の暗号化、署名の検証、エンドツーエンドかどうか、暗号化された中身）は「見えない」と記録する。

## 2. 決まり

### 判定

- 主張ごとに **食い違い／一致／見えない／未確認** のどれかにする。
- 比べる文書は、収録の時点までに公開されていて、その機器に当てはまるもの。公開日、改訂日、アーカイブの取得日を分けて書く。時期や範囲を確かめられなければ「未確認」。
- 文書の集め方は [method.md](method.md)（D1〜D6、Wayback、`coverage.tsv`、`claims.tsv`）。
- 公式文書が見つからない観測は外さない。「文書なし」として、食い違いの一覧とは分けて残す。

### 先行研究

- **同じ食い違いを指摘した資料があるか**で分ける。通信の問題が既知かどうかも、あわせて記録する。
- **除く**：IEEE S&P、USENIX Security、ACM CCS、NDSS の論文が、同じ機器（または同じ系列）の同じ問題を詳しく示しているもの。**除いたものには、理由（論文、表か節、ページ）を必ず書く。**
- **論文で一部**：IMC、PETS、ほかの会議の論文、集計だけ、同じメーカーの別の機種、問題の別の面。どの論文かを書く。
- **ブログ等のみ**：ブログ、勧告、CVE、講演、GitHub。メモして残す。
- **見つからず**：探した範囲で報告がない（検索語を残す）。新しいとは言わない。

### 値

- 伏せない。ツールの出力と利用者への報告に、値をそのまま出す。
- 識別子（MAC、シリアル番号、機器 ID）は、このリポジトリの文書に書いてよい。
- 認証情報（パスワード、トークン、セッション ID、アクセスキー ID、署名）は、非公開のリポジトリ `SaeYoshizaki/quarant-results` の `claims/` にだけ書く。手元は `~/Desktop/quarant-results`（`claims/` だけを取り出してある。書く前に pull する）。
- 洗い出しの記録には値がない（鍵付きのハッシュだけ）。値は根拠のフレームを tshark で開いて読む（`scripts/claims/sweep/verify.py`）。

### 進め方

- **止まらない。** 利用者が離席している間も、できる限り作業を続ける。判断が要るものは、下の「判断待ち」に書き足して、ほかの作業を進める。利用者の返事を待って止まることはしない。
- **報告は、利用者が話しかけたときにまとめて出す。** 日本語で、確認済み、未検証、未確認、判断待ちを分ける。
- **エージェント**：並列で使ってよい。同時に 5 体まで、1 体あたり製品 5〜10 件。終わるまで回し続けてよい。エージェントへの指示には、この節の決まり（根拠の付け方、未確認、値の書き場所）を毎回書く。
- **git**：2026-11-11 から PR は作らない（Pull Shark の称号を取ったため）。main にコミットして直接 push する（確認は要らない）。quarant-results でも同じ。コミットに Claude の署名を入れない。PCAP は入れない。
- **根拠**：PCAP にはファイル名、フレーム番号、フィールド。文献には資料名、著者、年、URL、ページか節。読めないものは「未確認」。ホスト名やポートだけで目的を決めない。
- **文書**：短く平易に。教授が読む文書に「Claude がやった」と書かない。

## 3. 作業の順番と進み具合（2026-11-11 の終わり）

0. **済み**：先行研究の区分を新しい基準で直した（D42）。
1. **済み**：UNSW 2016、UNSW-IoTraffic、CIC IoT 2022、Deakin 2023 の製品（68 の製品とデータの組）の公式文書を集めた（[claims.tsv](claims.tsv) 2,112 行）。YourThings と重なる製品は 2016〜17 年の版を集め直した。
2. **済み**：主張ごとに判定した（[compare-sweep.md](compare-sweep.md)）。
3. **済み**：「論文で一部」の 41 件、TLS の 109 件、取りこぼしていたダウンロード 11 件をパケットで確かめた（[sweep-results.md](sweep-results.md)）。
4. **済み**：食い違いの候補の先行研究（[sweep/prior-claims.tsv](sweep/prior-claims.tsv)）。同じ食い違いの指摘は見つからなかった。Deakin のやり直しで出た TLS の 4 件（Echo Show 8、M80B、TOPERSUN、Perfk）は、まだ候補ごとに探していない。
5. **済み**：文書にした（compare-sweep.md、sweep-results.md、E17）。

次にやること：判断待ち（下の 4）への返事を受けて、候補の判定と区分を直す。人が確かめる表 [review-sweep.md](review-sweep.md)（18 行）の「確認」の欄を利用者が埋める。Deakin のやり直しで出た TLS の 4 件の先行研究を探す。

## 4. 判断待ち（利用者が戻ったときにまとめて聞く）

- アプリストアの説明を公式文書に含めるか。[method.md](method.md) では見ないことにしているが、製造者が書いた文書でもある。決まるまでは、集めて別に記録する。
- 分類（先行研究の区分）の、人による確認。
- メーカーへの連絡。実機を使う能動的な検証。
- Alrawi ほか（S&P 2019、Table V p.17）を理由に除いた証明書の 7 件。論文の印は自己署名と「vuln SSL」、こちらの観測は SHA-1 や RSA 1024 の証明書で、性質が違うかもしれない。「論文で一部」に移すか（2026-11-11、[sweep-results.md](sweep-results.md) の TLS の節）。

- 主張の読み方（2026-11-11）。どれも claims.tsv の note に書いた。
  - SimCam：「video」を対象にした文（「processes and stores video locally」）が、人物検知の静止画の送信まで含むか。製品ページ（「Everything is processed and stored locally」）と、同じ会社のアプリのポリシー（「image data will be transferred ... via the server」）が食い違っている。
  - D-Link DCH-S161：「SSL ... for better securing all logs of settings and Services of your devices」に、平文のファームウェアの確認（`/fw-upgrade?device_id=<MAC>`）が入るか。今は弱い候補。
  - Awair：「encrypts and stores all information over TLS and AES 256 bit encryption」の AES 256 が、通信のことか保存のことか。今は候補（握手の 9 割が AES-128）。
- 機種が分からない製品（Amcrest、Globe、Gosund、Atomi、HeimVision、Insteon Camera、HP ENVY、iHome）で、どの製品ページを使うか。今は共通の文書（プライバシーなど）だけで判定した。
- 地域の版：CIC はカナダ、UNSW と Deakin はオーストラリアの収録だが、集めた文書の多くは米国版。
- 製造者でない会社の文書（Borun の V380 アプリ、Amcrest Cloud を運営する Camcloud、BlipCare に対する Carematix）を含めるか。
- 収録よりかなり古い文書（dropcam.com の 2015 年の版、収録の約 21 か月前）を比べる対象に入れるか。

- 2026-11-11 の文書集めで出たもの。
  - 製造者以外が書いた文書：Nest Mini の ioXt の評価報告（NCC Group が作り、Google が公開）。今は製造者の文書として判定した（文言の上で食い違い）。
  - 範囲が狭いかもしれない文書：Withings の Data Security のページ（「専門家との活動だけが対象」と要約に書いてある）。今は一致として判定した。
  - 収録の後にしか保存がない文書（Tapo の FAQ 671、Nest のヘルプ、Samsung の PSTI 宣言など）を判定に使うか。今は使い、note に書いた。
  - 文書のない製品（TOPERSUN、Perfk は Tuya の OUI）で、Tuya のプラットフォームの文書を使うか。Luohe を「文書なし」としてよいか。
  - Triby の候補：airable（Invoxia の取引先として airable のサイトに載っている）が「unaffiliated」に当たるか。
  - Ring Alarm のポートの記事（「HTTP は Base Station には当てはまらない」）と接続確認の GET を、文言の上での食い違いとして数えるか。
- メーカーへの連絡（SimCam、Samsung など）。

（作業中に判断が要るものが出たら、ここに書き足す。）

## 5. 環境とはまりどころ

- 道具（2026-11-11 に追加）：`verify.py` は値をそのまま出す（出力に認証情報が入るので、公開のリポジトリに置かない）。`verify.py tls` と `verify_tls_all.py` で TLS の候補をパケットで確かめる。文書集めのエージェントへの共通の指示は `~/datasets/claims/collect/BRIEF.md`、結果は `~/datasets/claims/collect/G1〜G5/`。洗い出しの製品ごとの表（report.py の出力）は `~/datasets/claims/sweep/report/`、パケットの確認の出力は `~/datasets/claims/sweep/verify/`。

- 外付けディスク QuarantData（`~/datasets` はここへのリンク）。つながっていないときは、ディスクの要らない作業（文書集め、先行研究）を進め、判断待ちに「ディスクをつなぐ」と書く。
- 外付けディスクから同時に読むのは 3 本まで。多いと詰まる。
- `tarfile` に大きな bufsize を渡さない。gzip は別のプロセスで展開する（`expose.py`）。
- YourThings の tgz の中のパスは日によって違う（03-20、03-21、03-28、04-15 は `2018/MM/DD/eth1-…`、04-10〜14 と 04-18 は `DD/eth1-…`）。`tar -xzf <tgz> -C <先> '*eth1-…'` のように名前の型で取り出せる（1 日分で 5〜10 分）。03-20 と 04-10 は全部、ほかの日は確認に使ったファイルだけが `/Volumes/QuarantData/yt-extract/<日付>/` にある。前の会話で取り出した UNSW 2016 の 09-28、09-30 と YourThings の一部は `~/datasets/claims/sweep/verify-prev/`。UNSW 2016 の元は `~/datasets/raw/unsw-iot-traces/16-MM-DD.tar.gz`。
- シェルは zsh。`ROOTS="a b"` のような変数は空白で分けられず、1 つの引数になる（`verify_all.py` が全件「ファイルなし」になった）。複数のパスは bash のスクリプトの配列で渡す。
- `verify.py tls` は根拠のフレームから 20,000 パケットまでしか読まない。全体の数は `VERIFY_TLS_ALL=1`。
- Deakin は Linux cooked の形式（送信元の MAC は `sll.src.eth`。`verify.py` の `src()` で対応済み）。
- devices.tsv で製品を探すときは label で引く。名前の一部で探すと取り違える（TP-Link Tapo と Samsung の Pan/Tilt）。
- tshark は CRLF を `\r\n` の文字で出す（`verify.py` で対応済み）。非標準のポートの HTTP は `VERIFY_DECODE="tcp.port==8802,http"` のように指定する。
- YourThings は全パケットが 2 回ずつ入っている。作成者の中間者の検査の証明書（発行者 `thing-catcher.gtisc.gatech.edu`、04-10〜13）とポートスキャン（03-20、21、28）は、機器の挙動に入れない。
- Wayback は `scripts/claims/wb.py` で取得する（間隔を空ける。保存先 `~/datasets/claims/snapshots/`）。
- 作業用の一時フォルダ（`/private/tmp/…`）は、Mac を再起動すると消える。
- Mac のメモリは 16 GB。大きなキャプチャ（Deakin の 1 日分は約 700 MB、IoTraffic の August は 6 GB）は 1 本ずつ扱う。
