# Philips Hue Bridge v2（BSB002）：問題はその後直ったか（2026-11-27）

担当：Philips Hue Bridge v2（BSB002）。下敷きは[報告 05](../../../Desktop/research/Quarant/docs/claims/reinvestigation/05-philips-hue-bridge.md)、既存のファームの調べ（[firmware-2026-11-26.md](../../../Desktop/research/Quarant/docs/claims/reinvestigation/firmware-2026-11-26.md) の §5、[firmware-vs-docs-2026-11-26.md](../../../Desktop/research/Quarant/docs/claims/reinvestigation/firmware-vs-docs-2026-11-26.md) の A/B/C）。その続きをやる。

- 調べ方：公式の更新の窓口とリリースノート、今の公式のプライバシー文書を直接読んだ。問題のホストが今も平文の HTTP に答えるかを、機器の識別子を入れない HEAD/GET/空 POST で確かめた（2026-11-27 06:39〜06:41 UTC）。第三者の資料（SSTIC 2026 の論文、GitHub、Home Assistant、CVE）を検索した。ブラウザ拡張は使っていない（親が使う）。
- **サーバーが平文に答えることは、機器が今も平文で送ることの証拠ではない。** 機器の動きは手元の収録と第三者の観測だけで判断する。
- APK は落としていない。理由：この食い違い（診断の報告・CBAuth のトークンが平文の HTTP）は**ブリッジのファームウェア自身**の送信で、スマホのアプリの送信ではない。APK を読んでもブリッジの診断の送り先の方式は分からないので、「いちばん楽な経路」としてファーム・エンドポイント・リリースノート・公式文書を優先した（これは推測ではなく、報告 05 の H1・H4・H5 がブリッジの通信と明記していることによる）。

## 1. 食い違いの要点

- ブリッジの通信の多くが平文の HTTP。診断の報告 `diagnostics.meethue.com/v2/diagnostics/report?…&sso=<トークン>`、`dcp.cpp.philips.com:80`／`dcp.dc1.philips.com:80`／`www.ecdinterface.philips.com:80` への `Authorization: CBAuth`（ブリッジ ID・SSO トークン入り）。2016-17〜2024 年の 3 つの収録で一貫して観測（報告 05 の H1・H4・H5）。
- 公式文書との関係：2016-17 年のプライバシー通知（文書 A）は「transfers data securely (using SSL)」と書くが、ブリッジの送信全体を SSL にするとは言っていない（最も限定的な読み方では矛盾にならない。広く読めば矛盾）。この文は 2017-11 の改訂で消えた。2021-24 年の文書（B・C）とその後の文書は、ブリッジの送信時の方式を明記していない。

## 2. ファームウェアの入手

公開の更新の窓口から本体は取れる。ただし**暗号化**されていて、復号には**root を取った実機から鍵を抜く**必要があり、ダウンロードだけでは中身を読めない。

| 入手元の種類 | URL | 版 | 日付 | 大きさ | 素性 | 取れたか |
|---|---|---|---|---|---|---|
| 公式の更新窓口（機器 ID を送らない） | `https://firmware.meethue.com/v1/checkupdate?deviceTypeId=BSB002&version=1964000000` | 6.6.1978753000（`version:1978753000`） | 作成 2026-11-26 | JSON（13,660,409 バイトと md5 を通知） | 平文の JSON | 取れた |
| ファーム本体（.fw2、先頭 64 KB のみ） | `https://firmware.meethue.com/storage/bsb002/1978753000/d358235c-c0ec-428c-8a8a-63ebd9f1e047/BSB002_1978753000.product.RSA_prod_01.fw2` | 同上 | 同上 | 全体 13,660,409 バイト（md5 `63aa1c93453670ab53478f5fd8bd60f8`）。手元は先頭 64 KB のみ | **暗号化**（先頭 `BSB002` マジック＋版番号の ASCII、以降エントロピー 7.997 bits/byte） | 先頭だけ取れた（本体は落とさず） |

- 手元に置いたファイル（`V/dl-hue/`）：
  - `fw2-head.bin`（48 バイト、sha256 `951a62122d76d54d2a0e74c3e7588da46e6f7e4179d85fc4ce92ad63b0060c61`）。先頭 48 バイト：`42 53 42 30 30 32 00 02 …`＝`BSB002`、続いて `root`、版番号 `1978753000`。
  - `fw2-64k.bin`（65,536 バイト、sha256 `7b2fe5f50cdbb29c700ded5a26719578b65c23784eb78cd78f52864d5cd7b612`）。先頭 256 バイトを除いた本体のエントロピーは 7.9974（ほぼ 8.0）＝暗号化。報告 05 と firmware-vs-docs の C（`.fw2` は `BSB002` ＋高エントロピー＝暗号化）と一致。新しい版（6.6.x）でも形式は同じ。

**公開の復号・展開の手法**（調べた結果）：

- 抽出ツールは公開されている：**`unfw2`**（Andreas Oberritter、<https://github.com/mtdcr/unfw2>）。`.fw2` を `.tgz` に展開する。
- ただし**鍵が要る**。SSTIC 2026 の論文（下）は手順をこう書く：(1) 更新窓口で `binaryUrl` を取り本体を落とす、(2) **すでに root を取ったブリッジの `/home/swupdate/certs/enc.k` から暗号鍵を取る**、(3) `unfw2` の `./certs/enc.k` に置いて実行、(4) `.tgz` が得られる。→ **鍵なしでは復号できない**。鍵を得るには UART でハードウェアを触って root を取る（Colin O'Flynn 2016、Michal Jirků 2024 の手順）。当方は復号も root 取りもしない。
- O'Flynn（Black Hat USA 2016、`us-16-OFlynn-A-Lightbulb-Worm-wp.pdf`）も「Hue のファイルは常に暗号化され、別機器による書き換えを防ぐため署名されている」とする。

**GPL のソース公開**（調べた結果）：

- Signify は BSB002（Hue Bridge 2.0）の GPL 部分のソースを公開している。第三者のミラー：<https://github.com/rettichschnidi/bsb002-legal-sources>（版 1802201122、アーカイブ済みで読み取り専用）、<https://github.com/hauke/philips-hue-bsb002>。公式の窓口は書面請求（英語・製品名を明記、`open.source.lighting@signify.com`。製品の購入／更新から 3 年間有効）。
- **限界**：GPL のソースは OpenWRT・Linux カーネル・BusyBox などの GPL パッケージだけ。診断の報告や CBAuth を送る**独自のアプリのバイナリは含まれない**ので、送り先が http か https かはこのソースからは分からない（推測ではなく、GPL の対象範囲の性質による）。

**ARM 機のダンプ**：BSB002 は ARM ではなく Qualcomm Atheros QCA9533（MIPS32）＋ OpenWRT（SSTIC 2026）。公開の平文ダンプは見つからなかった（root 取り＋`unfw2`＋鍵の組で復元する例ばかり）。

## 3. パッチ・更新の履歴

[ブリッジのリリースノート](https://www.philips-hue.com/en-ca/support/release-notes/bridge)（2026-11-27 に取得、2014〜2026 年の全件）を読んだ。セキュリティや接続に触れた行は次のとおり。**どれも「診断の報告」や「CBAuth のトークン」を HTTPS にしたとは書いていない**。

| 日付 | 版 | 記載（要旨） | 何に関するか |
|---|---|---|---|
| 2018-05-15 / 06-28 | 1804201116 / 1806051111 | 「Beta release of HTTPS connection on the bridge and SDK」 | **ローカル API** の HTTPS 化（CVE-2017-14797 対応） |
| 2019-04-02 | 1931069120 | 「For better security we slightly changed the way apps connect to your Hue Bridge」 | アプリ↔ブリッジの接続 |
| 2019-07-22 | 1933087030 | 「improved the security … by moving to a new version of the Linux-kernel」 | カーネル |
| 2020-01-13 | 1935144040 | 「a patch for a security vulnerability in the Hue Bridge v2」 | 脆弱性の修正 |
| 2020-02-24 | 19370450000 | 「HTTP/2 support; improved reliability and security」 | ローカル API |
| 2022-06-23 / 06-27 | 1952086010 / 020 | 「Moved to MQTT cloud services; improved cloud connectivity」 | クラウド接続（MQTT 化） |
| 2025-05-22 | 1971060010（※） | 「We replaced self-signed certificates with proper HTTPS certificates … with Apps and with our Cloud services」 | **自己署名→正規の HTTPS 証明書**（アプリ・クラウド）。すでに HTTPS だった接続の証明書の差し替えと読める（推測）。平文の診断には触れない |

- ※ 版番号：今日のリリースノートの取得では 2025-05-22＝1971060010。2026-11-26 の既存の調べは同じ文を 1972004020（2025-05-22）としていた。JS で描くページのため版と行の対応に揺れがある（軽微。日付と文は一致）。
- 最近（2024-2026）の行はほとんど「general reliability and performance」か新製品対応で、平文の診断・CBAuth の HTTPS 化を示す記載はない。
- 版の動き：手元のデータの約 1.60〜1.64（2023-24）→ 今は 6.x 系（6.5.1978688000 が 2026-11-12、6.6.1978753000 が 2026-11-26）。約 2 週間おきに更新が続く。

**SSTIC 2026 の論文**（Thalium／Thales、Pwn2Own Ireland、`SSTIC2026-Article-flicker_and_fall_…pdf`）：

- 解析した版は **1975170000**（リリースノートで 2026-02-16）。ハードは QCA9533（MIPS）＋ OpenWRT＋BusyBox。リッスンは 80/443（nginx）、HomeKit 8080 など。
- 内容は HomeKit と Zigbee の脆弱性で root を取る話。**診断の送信や CBAuth が平文か TLS かには触れていない**（この論文は「直ったか」の直接の材料にはならない）。価値は上の「ファームの復号手順」。

## 4. その後直ったか

| 判定 | 日付・版・資料 | 何が分かるか |
|---|---|---|
| **どちらとも言えない（続いている可能性が高い。推測）** | 2023-24、約 1.64（報告 05 の H5：Passive-Mode-Study） | 手元で**一番新しい実機の収録**。ここで**まだ**平文の HTTP の診断の報告（`POST http://diagnostics.meethue.com/v2/diagnostics/report`、`sso`・`auth` 入り、US1 15 回・FR 4 回）を観測。最新の 6.x の実機の収録は手元にない |
| まだ問題という弱い証拠（サーバー側） | 2026-11-27、当方の確認 | `diagnostics.meethue.com`（34.144.251.226、Google Cloud）は**今も平文の HTTP 専用**：`/` が HTTP 200、`/v2/diagnostics/report` への空 POST が **411 Length Required**（＝本文つき POST の口が生きている）。**HTTPS（443）は TLS が張れない**（HTTP への転送もない）。診断の報告は今も平文でしか受けられない作り |
| まだ問題という弱い証拠（サーバー側） | 2026-11-27 | CBAuth の送り先 `dcp.dc1.philips.com`（AWS eu-west-1）と `www.ecdinterface.philips.com`（別名 `dp.dc1.philips.com`）は HTTP 80 で 403（口は生きている）。HTTPS でも 403 |
| 直った可能性（弱い。インフラの撤去） | 2026-11-27 | 2016-17 年の送り先 `dcp.cpp.philips.com` と `bridge.meethue.com` は **NXDOMAIN（消滅）**。古い平文の経路の一部は無くなった（ただし後継の `dcp.dc1`・`ecdinterface` は残る） |
| 直ったとは言えない（文書側） | リリースノート 2024-2026 | 診断・CBAuth を HTTPS にした記載はなし（上の §3） |

**注意（ホスト名の区別）**：Home Assistant の利用者が「`diag.meethue.com` に毎分問い合わせる」と報告しているが、これは TLS の口（報告 05 の H6。今は `diagnostics.huedatastore.com` の別名）であって、平文の `diagnostics.meethue.com`（「diagnostics」）とは別。混同しないこと。2025-2026 年のブリッジの**診断の通信の方式（http/https）をパケットで確かめた第三者の収録は見つからなかった**。DNS のログ（`diag.meethue.com`、`www.ecdinterface.philips.com` への問い合わせが多い等）は方式を示さない。

**今の公式文書**（送信時の暗号化の書き方。2026-11-27 に取得）：

- Philips Hue／Signify プライバシー通知（**Last updated April 2023**、<https://www.philips-hue.com/en-us/support/legal/privacy-policy>）：まとめの箱に「We keep your data safe using appropriate technical and organizational measures.」。「How do we secure your personal data?」の節は「To protect your data, we will take appropriate measures … to protect the confidentiality and security of your data.」。**SSL/TLS/HTTPS・「in transit」の明記はない。**
- Hue Data Notice（**Version September 2025**、<https://www.philips-hue.com/en-us/support/legal/data-notice>）：送信時の暗号化・TLS の明記なし（「appropriate security measures」等の評価の言葉のみ）。
- 「encrypted … in transit and at rest」「end-to-end」と言っているのは **Hue Secure のカメラ**の文書（disclosure requests のページ）で、**ブリッジではない**。
- → 今の公式文書は、ブリッジの送信の方式を言い切っていないので、「宣言と違う形式」には当たらない（firmware-vs-docs の B、報告 05 の「記載なし」と同じ）。平文の診断と並びが悪いのは 2016-17 年の「using SSL」（文書 A、すでに削除）だけ。

## 5. まとめ（3 行）

- **入手**：ファーム本体は公式窓口から取れるが暗号化（6.6.1978753000 も同じ）。復号は公開ツール `unfw2` で可能だが、**root を取った実機の鍵が要る**ので、落とすだけでは中身を読めない。GPL ソースは公開だが独自アプリは含まず、診断の送り先は読めない。
- **直ったか**：**確定できない**。最新の実機の収録（2024、約 1.64）では平文の診断がまだ出ており、平文の受け口（`diagnostics.meethue.com` 80 番）は今も生き、リリースノートにも診断・CBAuth を HTTPS にした記載がない。→ **続いている可能性が高い（推測）**。一方で 2016-17 年の一部のホストは消滅。
- **論文に使えるか**：使える。「2024 年の収録でまだ平文」「今も平文の受け口が生き、文書に修正の記載なし」を根拠に「問題が残っているとみられる」と書ける。**確定には今の 6.x の実機の収録が 1 回要る**（パッシブの範囲。能動的な検査ではない）。

## 6. 未確認

- 2025-2026 年の 6.x のブリッジが、診断の報告・CBAuth を今も**平文の HTTP で送るか**（パケットで確かめた第三者の収録・自分の収録ともに無い）。サーバーが平文に答えることは機器が平文で送る証拠ではない。
- `.fw2` の中身（復号せず。鍵は root 取りが要るため扱わない）。独自アプリの送り先の文字列。
- リリースノートの 2025-05-22 の版番号（1971060010 か 1972004020 か。日付と文は一致）。
- SSTIC 2026 の論文は root 取りの話で、診断の方式には触れていない（通信方式の直接の材料ではない）。
