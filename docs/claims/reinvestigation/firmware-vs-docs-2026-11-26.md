# 最新ファームと最新文書の照合（2026-11-26）

[一覧に戻る](README.md) ・ [最新ファームの入手](firmware-2026-11-26.md)

最新のファームウェアが取れた 5 台（Hue Bridge、Sonos PLAY:1、HomePod、Triby、D-Link DCS-8300LH V2）について、次の 2 つを調べた。

- **A. 元の齟齬が直ったか**：取れたファームの中に、元の平文の送り先がまだ入っているかを静的に見る。
- **B. 最新の文書との形式の照合**：各社の今のプライバシーポリシー等を読み、**公式が宣言している方式と違う形式を使っていないか**を見る（甘い/強いの評価ではなく、宣言と違う方式を使っていないか）。

## 前提と限界

- **実機の通信は取っていない**。本当に「直った」と確かめるには、最新ファームの実機の通信をもう一度とる必要がある。今回はパッシブで、実機がない。
- **A は静的解析のみ**。ファームのファイルを公開の場所から取り、`strings` で送り先の文字列を探しただけ。**復号はしていない**（CLAUDE.md の恒久ルール）。取ったファイルは消した。
- B の文書は、収録の時点のものではなく、**今（2026-11）公開されている最新版**。日付と版を併記する。

## A. ファームの静的解析の結果

**結論：5 台とも、ファイルからは送り先が読めなかった**。各社は暗号化／固めたファームを配っており、ネットの送り先（ホスト名・URL）はファイルの中に平文で入っていない。元の齟齬が直ったかは、このやり方では分からない。

| 機器 | ファイル | 形式 | 送り先の文字列 |
|---|---|---|---|
| Hue Bridge | `BSB002_1978688000.product.RSA_prod_01.fw2` | 署名／暗号化（`data`） | 0 件 |
| Sonos PLAY:1 | `82.3-60160-1-21.upd`（別機種の例） | 固めてある。読めるのは埋め込みの CA／CRL の束だけ（`http://ca.ws.sonos.com/certs/device/crl` など。CRL の URL は規約上 HTTP で正常） | 更新・計測の送り先は読めない |
| HomePod | Apple の OTA | Apple の暗号化されたアセット | 取得・解析せず |
| Triby | `update.pup`（11.26.4） | 固めてある（ヘッダに `triby-11.26.4,build=116.da.45` だけ読める） | 0 件 |
| D-Link DCS-8300LH V2 | `DCS8300LHV2Ax_FW108B01.bin`（1.08.01） | **OpenSSL で暗号化**（`openssl enc'd data with salted password`） | 0 件 |

**補いの手がかり**（静的解析ではなく、手元の収録と第三者の観測）：

- **Hue**：手元で一番新しい収録は Passive-Mode-Study（2023-24、ファーム約 1.64）で、そこでは平文の診断の報告と CBAuth のトークンが**まだ出ていた**（[報告 05](05-philips-hue-bridge.md)）。最新のファーム（6.5.x）の収録はない。
- **Sonos**：収録で機器が使った更新のファイルの URL は、今も平文の HTTP で 200 を返す（[最新ファームの表](firmware-2026-11-26.md)）。2025-01 の第三者の掲示板では、スピーカー（ファーム 82.3-60160）が更新のファイルを平文の HTTP の GET で取りに行っていた。**その平文の経路は続いているとみられる**（第三者の観測。自分の収録ではない）。
- ほかの 3 台（HomePod、Triby、D-Link）は、手元に新しい収録も第三者の観測もない。**不明**。

## B. 最新の文書との形式の照合

**公式文書が「どの方式で送る」と言い切っていて、観測した形式がそれと違うもの**を探した。結果は **Sonos の 1 件**（と、確認できていない候補が 1 件）。

### まとめ

| # | 機器 | 最新の文書が宣言する送信時の方式 | 観測した形式 | 形式の齟齬（最新の文書に対して） |
|---|---|---|---|---|
| 5 | Hue Bridge | 一般の文書は「適切な技術的・組織的措置」だけ。送信時の暗号化の明記なし（E2E はカメラの文書で、ブリッジではない） | 平文の HTTP の診断・トークン | **なし**（文書が方式を言っていない） |
| 6 | Sonos | 「お客様のデータは、インターネットでの送信時に TLS など暗号化で保護される」 | 更新の確認（シリアル・ID 入り）、利用状況、ファームの取得が**平文の HTTP** | **あり**（下） |
| 11 | HomePod | Apple のポリシーは「管理的・技術的・物理的な保護措置」だけ。送信時の暗号化の明記なし | 平文の HTTP の音楽ファイルの取得 | **なし**（文書が方式を言っていない） |
| 19 | Triby | 方針は「合理的な手段」「最高水準のセキュリティ」（評価の言葉）だけ | 平文の SIP、平文の RTP、取引先に MAC | **なし**（方針は方式を言っていない）。ただし未確認の候補あり（下） |
| 18 | D-Link DCS-8300LH | SSL は「注文」「アカウント情報」「機器の設定とサービスのログ」に使うと明記。カメラの映像の経路の明記なし | 中継の通路の開始と最初のフレーム（トークン入り）が平文の WebSocket | **なし**（狭く読めば。広く読めば候補、下） |

### 6. Sonos ― 最新の文書と形式が食い違う

- **最新の文書**：Sonos, Inc. プライバシーに関する声明、英語（U.S.）v1.13、2026 年 9 月。
  - 「your data is protected with encryption, such as Transport Layer Security (TLS), during transmission over the Internet.」（第 8 節「Security, Storage and Retention…」）
  - 日本語版（ja-jp v1.13、最終更新 2026 年 9 月）：「お客様のデータがインターネットを介して転送される際は、TLS（トランスポート層セキュリティ）など暗号化によって保護されています。」
- **観測した形式**（[報告 06](06-sonos-play1.md)、2018 年の YourThings、「明確な矛盾」）：
  - 更新の確認 `GET http://update.sonos.com/firmware/latest/default-1-1.ups?…&serial=5CAAFD6CE0D4F&sonosid=…&householdid=…` が平文の HTTP（シリアル番号、Sonos ID、household ID 入り）。
  - 利用状況 `POST http://msmetrics.ws.sonos.com/HRMetrics/submit.aspx`（`<UsageMetrics>`、Sonos ID・household ID 入り）が平文。
  - ファームの取得が平文の HTTP。
- **照合**：最新の文書は「データはインターネットでの送信時に TLS で保護される」と言い切っている。観測では、シリアル番号・ID・利用状況が平文の HTTP で送られていた。**文書が宣言する方式（TLS）と、観測した形式（平文の HTTP）が食い違う**。
  - 文書の 2018 年版（報告 06 の文書 A）は「Any data we transmit over the internet is protected using encryption.」。最新版も「your data … during transmission over the Internet」と、範囲を言い切ったまま。
  - **限界**：最新のファームの実機の収録はない。ただし、更新のファイルの平文の HTTP の経路は今も生きていて、2025 年の第三者の観測もある（上の A）。利用状況と更新の確認が今も平文かは未確認。

### 19. Triby ― 方針では齟齬なし。未確認の候補が 1 件

- **最新の文書**：Invoxia Privacy Policy（effective 2012-01-01、last updated 2025-09-17）。
  - 「Invoxia takes reasonable steps to protect personal data…」「committed to preserving it with the highest level of security.」「no Internet or e-mail transmission is ever completely secure…」
  - どれも**評価の言葉か一般論**で、方式（TLS、平文など）を言っていない。評価の言葉だけの約束は、決まりにより「判断不能」で、矛盾にしない。
- **観測した形式**（[報告 19](19-invoxia-triby.md)）：平文の SIP（アカウントのメールアドレスをもとにしたユーザー名）、平文の RTP の通話の音声、取引先の airable に平文で MAC。
- **照合**：方針が方式を言っていないので、形式の齟齬はなし。
- **未確認の候補**：サポート記事「Data Protection and Security」が「data is transmitted via encrypted protocols」と書いているという検索結果の要約があった。もしこれが今も有効で、この文のとおりなら、平文の SIP・RTP はこの方式の宣言と食い違う。ただし**本文を読めていない**（ライブは 403、アーカイブの取得は環境で拒否）。**候補のまま**。

### 18. D-Link DCS-8300LH ― 狭く読めば齟齬なし

- **最新の文書**：D-Link Privacy Policy（effective 2020-01-01）。
  - 「When you are ordering Services via our site, we use … Secure Sockets Layer (SSL) …」「The SSL protocol is also implemented for (i) guarding your account information, and (ii) better securing all logs of settings and Services of your devices.」
  - カメラの FAQ「How does D-Link keep my videos private and secure in the cloud?」は、ログイン情報を人に教えないように、としか言っておらず、映像の暗号化の方式を言っていない。
- **観測した形式**（[報告 18](18-dlink-dcs8300lh.md)、2023-24）：中継の通路の開始 `GET http://mp-eu-sas-1.auto.mydlink.com/relay`（WebSocket、最初のフレームにトークンらしい値）が平文。CA の束の確認（HEAD）も平文。主なクラウドの接続と録画の送信は TLS。
- **照合**：SSL を使うと言っているのは「注文」「アカウント情報」「機器の設定とサービスのログ」。中継の通路の**開始**は「設定のログ」ではないので、狭く読めば齟齬なし（報告 18 の「記載なし」と同じ）。
  - 「サービスのログ」を中継の制御まで含めて広く読めば、平文の開始はこの方式と食い違う。ただしそれは広い読み方。

### 5. Hue Bridge ― 最新の文書と齟齬なし

- **最新の文書**：
  - Philips Hue／Signify プライバシー通知（Last updated April 2023）：「We keep your data safe using appropriate technical and organizational measures.」。送信時の暗号化・TLS・HTTPS の明記なし。
  - Hue Data Notice（Version September 2025）：送信時の暗号化・TLS の明記なし。
  - E2E や「encrypted in transit」と言っているのは **Hue Secure のカメラ**の文書で、ブリッジではない。
- **観測した形式**（[報告 05](05-philips-hue-bridge.md)）：ブリッジの診断の報告と CBAuth のトークンが平文の HTTP（2016〜2024）。
- **照合**：一般の文書はブリッジの送信の方式を言っていないので、形式の齟齬はなし（報告 05 の「記載なし」と同じ）。
  - 参考：2025-05-22 のブリッジのリリースノートは「自己署名の証明書を正規の HTTPS の証明書に替えた」とし、ブリッジの接続が HTTPS であることを示唆する。これと平文の診断は並びが悪いが、リリースノートは方針ではなく、最新の実機の挙動も未確認。

### 11. HomePod ― 最新の文書と齟齬なし

- **最新の文書**：Apple Privacy Policy（Updated July 30, 2025）。
  - 「We use administrative, technical, and physical safeguards to protect your personal data…」。送信時の暗号化（in transit）の明記はなく、詳細は Apple Platform Security のガイドに委ねている。
- **観測した形式**（[報告 11](11-apple-homepod.md)）：平文の HTTP の音楽ファイルの取得（`accessKey` つき）。
- **照合**：ポリシーが送信の方式を言っていないので、形式の齟齬はなし（報告 11 の「記載なし」と同じ）。Apple Platform Security のガイドや Media Services の規約は方式を言っているかもしれないが、今回は確認していない。

## 分かったこと

- **A（直ったか）**：5 台とも、ファームのファイルは暗号化／固めてあり、送り先を静的に読めない。**このやり方では直ったか分からない**。確かめるには最新ファームの実機の通信が要る。
  - 手元の材料では、Hue（2024 年の収録でまだ平文）と Sonos（更新の平文の経路が今も生きていて、2025 年の第三者の観測あり）は、**続いている可能性が高い**（推測）。
- **B（文書との形式の齟齬）**：はっきり食い違うのは **Sonos** の 1 件。最新（2026 年 9 月）の声明が「データはインターネットでの送信時に TLS で保護される」と言い切る一方、シリアル番号・ID・利用状況・ファームの取得が平文の HTTP だった。
  - **候補**：Triby のサポート記事の「encrypted protocols」の宣言（本文を読めていない）。読めたら判定する。
  - **残り 3 台**（Hue、HomePod、D-Link）：最新の公式文書は、問題の通信の送信の方式を言っていない。だから「宣言と違う形式」には当たらない（各報告の「記載なし」と同じ）。
