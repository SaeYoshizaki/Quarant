# 引き継ぎ：公式文書と通信の食い違いを探す（2026-11-11）

次の会話はここから始める。利用者は、この作業を終わるまで任せている（2026-11-11）。これまでの結果は [sweep-results.md](sweep-results.md)、決めたことは [../DECISIONS.md](../DECISIONS.md) の D41、記録は [../EXPERIMENTS.md](../EXPERIMENTS.md) の E16。

## 0. 最新の状況（2026-11-27）

24 件の調べ直しは完了し、**利用者が読むまとめ**は [reinvestigation/README.md](reinvestigation/README.md)（結果の表と各報告）。その後の追加調査：

- **外付けディスクで未確認だった分を確かめ直した**（2026-11-26）：CIC・UNSW-IoTraffic・IoT-23・YourThings 04-15。判定は変わらず。前回の記録の誤り（Hue の回数、報告 15 の根拠ファイル名）を直した。切り出し＝`~/datasets/claims/recheck-20261126/`。
- **問題のある機器の最新ファームを調べた**：ネットで取れるか＝[reinvestigation/firmware-2026-11-26.md](reinvestigation/firmware-2026-11-26.md)。最新の公式文書との形式の照合と Ghidra／オフライン解析＝[reinvestigation/firmware-vs-docs-2026-11-26.md](reinvestigation/firmware-vs-docs-2026-11-26.md)。
- **新しい所見**：Sonos の 2026-09 の声明は「データは送信時に TLS で保護」と言い切るが、観測はシリアル・ID・利用状況・ファームが平文 HTTP（最新文書に対する形式の矛盾）。
- **今の手詰まり**：取れた 5 台のファームは 4 台が暗号化／独自形式で、オフラインでは平文が直ったか判定できない（実機の収録が要る）。Triby だけ一部復元。Invoxia のサポート記事は未読（下の 4）。

詳しい経緯は下の 3、判断待ちは下の 4。

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
4. **済み**：食い違いの候補の先行研究（[sweep/prior-claims.tsv](sweep/prior-claims.tsv)）。同じ食い違いの指摘は見つからなかった。Deakin のやり直しで出た TLS の 4 件（Echo Show 8、M80B、TOPERSUN、Perfk）は 7 で済んだ。
5. **済み**：文書にした（compare-sweep.md、sweep-results.md、E17）。

6. **済み（2026-11-11、利用者の依頼）**：データセットを広げる。UNSW 2018（SOSR 2019 のデータ、正常な 27 日、38.4 GB、MIT-0）を `~/datasets/raw/unsw-iot-2018/benign/` に落とし、洗い出しにかける（`run_all.sh unsw2018`）。2018 年の文書はエージェント U1〜U4 が `~/datasets/claims/collect/U1〜U4/` に集めている。**状態（2026-11-11 夜）**：済み。洗い出し、2018 年の文書（U1〜U4）の判定、パケットでの確認、[compare-sweep.md](compare-sweep.md) への反映まで終えた。devices.json の UNSW 2018 の期間は正常な日のデータで直した。先行研究（SmartCam の映像、Google の更新、HP、Tuya）も済み（[sweep/prior-claims.tsv](sweep/prior-claims.tsv) の最後の 4 行）。同じ食い違いの指摘は見つからなかった。Jia ほか（S&P 2020）の本文は読めていない（未確認）。
7. **済み（2026-11-11）**：IoT-23 の正常な 3 シナリオ（Hue、Echo Dot、Somfy）を `~/datasets/raw/iot-23-benign/` に落とし、洗い出し（`run_all.sh iot23`）、文書の判定（Hue と Echo は UNSW 2018 の文書を写した。Somfy はエージェント I1）、[compare-sweep.md](compare-sweep.md) への反映まで終えた。Somfy の候補の先行研究（P5）も済んだ。同じ食い違いの指摘は見つからなかった。Deakin の TLS 4 件の先行研究（P4）も済んだ。

ほかの候補：CICIoT2023（フォームが要る）、南開大学の 77 機器（2024〜25、メールでの依頼が要る）、Mon(IoT)r と PingPong（約束への同意とメールが要る）。

次にやること：判断待ち（下の 4）への返事を受けて、候補の判定と区分を直す。人が確かめる表 [review-sweep.md](review-sweep.md)（24 行）の「確認」の欄を利用者が埋める。メールやフォームが要るデータセットは、依頼するかを利用者が決める。

2026-11-13：候補 34 行（YourThings を含む）の引用元を見直した。製造者以外の文書は Nest Mini の 1 件（NCC Group の報告書）だけ。FAQ・Q&A は 9 行。あいまいな言い方（方法を書かない、help・designed to などのぼかし、AES-256 が通信か保存か分からない、対象が個人情報だけ）の行も多い。表に列は足さず、一旦このままにする（利用者）。

2026-11-15：強い候補を 1 つの報告にまとめた（[report-2026-11-15.md](report-2026-11-15.md)。根拠の通信、公式文書の原文、似た資料、別の読み、足りない根拠）。書く途中で、洗い出しが STARTTLS のあとの TLS を読んでいないことが分かった。Samsung のカメラの XMPP（tcp/5222）では、サーバーが AES-256 を選んでいた（SNH-P6410BN、SNH-V6410PN）。claims.tsv、sweep-results.md、prior-claims.tsv を直した。次は `expose.py` で STARTTLS を扱い、洗い出しをやり直す（影響は Samsung のカメラ、Withings Aura、HP ENVY の接続）。

2026-11-16：教授の方針（ブログ程度で、論文になっていないものは入れてよい）を受けて、[blog-level.md](blog-level.md) にまとめた。新しく Eufy（CIC）を確かめた：アプリの映像は音声が平文、映像も先頭 128 バイトのほかは平文で、「Data during transmission is encrypted.」と合わない。報道（2022）はウェブポータルの映像だけを、論文（WOOT 2024）はアプリの映像を暗号化ありとしている。エントロピーだけで「暗号化」とした判定がほかに 18 行あり、Deakin の Ring（映像）を同じ方法で確かめるのが次。

2026-11-22：STARTTLS への対応と洗い出しのやり直し（`~/datasets/claims/sweep-v2/`）、エントロピーだけの判定の確かめ直し（Nest Protect は Weave の見出し、Ring は RTP の中身）、Withings Home の XMPP（認証は TLS の中）を済ませた（[sweep-results.md](sweep-results.md) の最後の 2 節、E18）。8 つ目のデータセットとして Passive-Mode-Study を加えた（[pms.md](pms.md)）。残り：YourThings の Nest Protect と Nest Guard を `weave_check.py` で確かめる。sweep-v2 で report.py と longitudinal.md を作り直す（平文の割合が XMPP の分だけ下がる）。Passive-Mode-Study のほかの製造者の 2023〜24 年の文書。

2026-11-22（2）：年ごとの表を sweep-v2 と新データセットで作り直した。Passive-Mode-Study のほかの製造者（Amazon、TP-Link、Google、Microsoft、Meta、Magic Leap、D-Link、Sony、Philips）の文書を集めた（pms.md）。上限 256 KB と送り先の名前で洗い出し直し（`~/datasets/claims/sweep-v3/`、E19）、Belkin NetCam HD の記録の送信に SSID などが平文で入っていたのが分かった。判断待ちはおすすめつきの一覧（[decisions-pending.md](decisions-pending.md)）にした。残り：A6（読めない文書、地域版。決まってから）、判断待ちへの返事。

2026-11-23：利用者が自分で判定するための一覧を作った（[judge-2026-11-23.md](judge-2026-11-23.md)、24 件と参考の表）。平文の欄の名前で 8 つのデータセットを探し直し、VeraLite のログの平文の FTP にハードウェアキーとセッションキーが入っていたのを見つけた（新しい候補、[sweep-results.md](sweep-results.md) の「平文の欄の名前で探し直す」）。確かめたのは 1 回分だけで、ほかの回はディスクをつないで確かめる。

2026-11-23（2）：24 件を利用者の調査の手順（6 つの区分、最も限定的な読み方、収録時点の文書）でやり直した（[reinvestigation/README.md](reinvestigation/README.md)）。外付けディスクがないので、UNSW 2018（27 日）、YourThings（5 日）、Deakin（4 日）、Passive-Mode-Study、UNSW 2016（20 日）を Mac に取り直し、機器ごとに切り出した（`~/qlocal/`、`scripts/claims/fetch/fetchfilter.py`、`scripts/claims/sweep/profile.py`）。CIC、UNSW-IoTraffic、IoT-23 は取り直していない（利用者の判断）。明確な矛盾は Sonos と Canary、条件付きは SmartCam、SimCam、Eufy。

2026-11-26：外付けディスクをつないだ。`~/qlocal/`（約13 GB）を HDD の `qlocal-20261123/` に同期（チェックサム差 0）して消した。2026-11-23 に取り直していなかった分を確かめ直した：CIC IoT 2022（8 台）、UNSW-IoTraffic（Awair・Hue・Triby・Canary・SmartCam）、IoT-23（Somfy）、YourThings 04-15 の全体（TP-Link 2 台）。判定はどれも変わらず。前回の記録の誤りを 2 つ直した：Hue の CIC の回数（4,760→246、1,017→682。項目の数を数えていた）、報告 15 の IoTraffic の根拠のファイル名（Belkin のファイル→SmartCam 自身のファイル）。新しく、TP-Link のプラグの LAN の応答に設置場所の緯度・経度（値は quarant-results）。切り出し＝`~/datasets/claims/recheck-20261126/`。

2026-11-26（2）：問題のある機器の最新ファームが取れるか、更新の記録に修正の記載があるかを調べた（[reinvestigation/firmware-2026-11-26.md](reinvestigation/firmware-2026-11-26.md)）。取れたのは Hue・Sonos・HomePod・Triby・DCS-8300LH V2。修正の記載があったのは SmartCam の CVE-2018-6295 だけ（版番号なし）。Sonos・Triby・TP-Link・Govee は、機器が使ったファームの URL が今も平文 HTTP で取れる。

2026-11-26（3）：取れたファームと最新の公式文書を照合した（[reinvestigation/firmware-vs-docs-2026-11-26.md](reinvestigation/firmware-vs-docs-2026-11-26.md)）。形式がはっきり食い違うのは Sonos だけ（2026-09 の声明「データは送信時に TLS で保護」に対し、シリアル・ID・利用状況・ファームが平文 HTTP）。候補：Triby のサポート記事「encrypted protocols」（未読）。Hue・HomePod・D-Link は、最新文書が送信の方式を明記していないので「宣言と違う形式」には当たらない。

2026-11-27：取れた 5 台のファームを Ghidra／オフラインで踏み込んで解析（同ファイルの C 節）。暗号・署名は破っていない。Hue（.fw2 は `BSB002` ヘッダ＋高エントロピー）と D-Link V2（.bin 先頭 `Salted__`＝OpenSSL 暗号）は暗号化→復号せず。Triby（.pup）は暗号ではなく xz-squashfs だが、`.pup` が独自に分割（split）していて完全展開には容器の解析が要る→保留。xz ストリーム 884 個を個別に展開しルート FS の約 22 MB を復元＝PJSIP（TLS/SIPS 対応）・Alexa・`developer.invoxia.com`。ただし `sip.invoxia.com`・5228・`airable.io` は復元範囲になく、最新ファームで平文が続くかは未確認。結論は変わらず「確かめるには実機の収録が要る」。

## 4. 判断待ち（利用者が戻ったときにまとめて聞く）

答えやすい形の一覧（おすすめつき）：[decisions-pending.md](decisions-pending.md)（2026-11-22）。

- **Invoxia のサポート記事（未読）**：`https://support.invoxia.com/hc/en-150/articles/4405494832017--Data-Protection-and-Security` が「encrypted protocols」と書いているか確かめたい（書いてあれば Triby の平文 SIP/RTP と食い違う候補）。ライブは 403、Wayback と直接 curl はこのセッションの sandbox が拒否、ブラウザ拡張（Claude in Chrome）も未接続。読むには、拡張をつなぐ（claude.ai/chrome）か、利用者が本文を貼るか、Bash の許可ルールを足す。
- **最新ファームで平文が直ったかの確定（未了）**：オフラインでは 4 台が暗号化／独自形式で判定不能。確定には最新ファームの実機の通信を取るか、Triby の `.pup` 容器を解いて完全展開＋Ghidra が要る。

- Passive-Mode-Study（2026-11-22、[pms.md](pms.md)）：
  - データの利用条件が書かれていない（コードは GPL v3）。論文に使ってよいか、著者に聞くか。
  - DreamGlass Air は機器の文書が見つからない（製造者のサイトは通販のポリシーだけ）。「文書なし」の重い問題として扱ってよいか。
  - Netvue のポート転送（UPnP）と Roborock の TLS 1.0 は、文書に主張がない。食い違いの一覧とは別に「重い問題」として載せるか。
  - Govee の「state-of-the-art data security tools」を、文言の上での食い違いとして数えるか。
  - 著者の文書集（PrivacyPolicyDataset）を、比べる文書の出どころに使うか。今は手がかりにだけ使い、引用は Wayback の版から取った。

- アプリストアの説明を公式文書に含めるか。[method.md](method.md) では見ないことにしているが、製造者が書いた文書でもある。決まるまでは、集めて別に記録する。
- 分類（先行研究の区分）の、人による確認。
- メーカーへの連絡。実機を使う能動的な検証。
- Alrawi ほか（S&P 2019、Table V p.17）を理由に除いた証明書の 7 件。論文の印は自己署名と「vuln SSL」、こちらの観測は SHA-1 や RSA 1024 の証明書で、性質が違うかもしれない。「論文で一部」に移すか（2026-11-11、[sweep-results.md](sweep-results.md) の TLS の節）。

- 主張の読み方（2026-11-11）。どれも claims.tsv の note に書いた。
  - SimCam：「video」を対象にした文（「processes and stores video locally」）が、人物検知の静止画の送信まで含むか。製品ページ（「Everything is processed and stored locally」）と、同じ会社のアプリのポリシー（「image data will be transferred ... via the server」）が食い違っている。
  - D-Link DCH-S161：「SSL ... for better securing all logs of settings and Services of your devices」に、平文のファームウェアの確認（`/fw-upgrade?device_id=<MAC>`）が入るか。今は弱い候補。
  - Awair：「encrypts and stores all information over TLS and AES 256 bit encryption」の AES 256 が、通信のことか保存のことか。今は候補（握手の 9 割が AES-128）。
- 機種が分からない製品（Amcrest、Globe、Gosund、Atomi、HeimVision、Insteon Camera、HP ENVY、iHome）で、どの製品ページを使うか。今は共通の文書（プライバシーなど）だけで判定した。（2026-11-15：HP ENVY は 5540 series と 6400 series、iHome は iSP5 と、機器の mDNS の名乗りで分かった。製品ページを集め直すかを決める。）
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
- IoT-23 で出たもの（2026-11-11）。
  - Somfy：直営店のロックとゲートウェイのセットのページの「Connexion sécurisée par cryptage normé AES 256」が、ゲートウェイとサーバーの TLS まで含むか。ロック単体のページとマニュアルでは、同じ AES 256 がスマートフォンとロックの間（Bluetooth）と書かれている。今は弱い候補。材料：Opendoors の販売資料（PDF 作成 2018-09-10、p.181 の仕様表）では、AES 256 の行はロックとバッジリーダーにだけあり、ゲートウェイにはない（P5 が読んだ。Somfy のドメインではない）。CE Pro（2016-12-29）によると、Somfy は 2016-01 に OpenWays（Okidokeys の会社、のちに OpenDoors）を買った。
  - Somfy：App Store の Somfy Keys のプライバシーのリンク先は opendoors の CGS（documents.opendoors.net）。Somfy のドメインではないので主張に入れていない。含めるか。Somfy のフォーラムの社員（「Equipe」）の回答を公式文書に含めるか。
  - IoT-23 の README には「Stratosphere Lab の許可が要る」とあるが、Zenodo の記録は CC BY 4.0。CC BY として扱った。
- UNSW 2018 で出たもの（2026-11-11）。
  - SmartCam 2018：映像の宛先は UNSW の別のアドレス（129.94.5.83）で、クラウドではない。仕様の「Security SSL (AES 256bit)」がこの経路まで含むか。比べた仕様は SNH-C6417BN と SNH-V6414BN のもので、UNSW の機器（MAC 00:16:6c:ab:6b:88）の機種は分からない。今は候補。
  - データセットのメールでの依頼（南開大学、Mon(IoT)r、PingPong）と、CICIoT2023 のフォームへの入力。利用者が決める。
- 根拠の補強で出たもの（2026-11-15、[sweep-results.md](sweep-results.md) の「根拠の補強」）。
  - SmartCam：機種は SNH-P6410BN（UPnP）。SNH-P6410BN 自身のデータシート（Wayback 2016-06-23）にも「Security SSL ( AES 256bit )」があり、候補の行として加えた。これまでの別機種の仕様の行（productId 6502、SNH-C6417BN、SNH-V6414BN）を残すか、外すか。
  - SmartCam：映像の暗号化は「Image encrypting」という任意の設定で、SNH-P6410BN だけにある（マニュアル p.22、Android のガイド 2015-11）。初期値は書いていないが、画面の写真ではオフ。平文の映像を食い違いとして数えるか、「初期値で暗号化されない」として別に数えるか。
  - SmartCam：マニュアルの本文は 2024 年のコピーしか読めない（2016〜2017 年のサポートページが同じファイル名にリンク）。同じ文書として扱ってよいか。
  - SimCam：中国語版の SimHome のポリシー（本文は 2021-09-06 の版、アーカイブは 2022-06-25）を、収録期間の文書として使うか。App Store の「5MP snapshot」付きの通知の説明を比べる対象にするか。別の機種（Ango）のクラウド保存の売り物を文脈に使うか。
  - Nest Cam（CIC 2021）は TLS 1.0 だけだった（RFC 8996 で廃止された後）。Nest の FAQ（2022-01-31）の「fully encrypted using the state-of-the-art security tools」と比べて、文言の上での食い違いとするか。今は一致。
  - 取り出した画像・映像・音声（`~/datasets/claims/dig/`）を、報告や論文に載せてよいか。人や実験室が写っている（公開データセットの中身）。
- ~~Withings Home の XMPP~~：済み（2026-11-22。STARTTLS のあと TLS で、平文の認証は見えない。sweep-results.md）。
- Eufy（2026-11-16、[blog-level.md](blog-level.md)）：候補に入れるか。取り出した音声（80 秒、`~/datasets/claims/dig/eufy/`）を見せてよいか。（Deakin の Ring は 2026-11-22 に RTP の中身で確かめた：SRTP）

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
