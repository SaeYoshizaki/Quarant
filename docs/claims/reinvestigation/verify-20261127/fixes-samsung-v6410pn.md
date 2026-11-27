# Samsung（Hanwha）SmartCam SNH-V6410PN：問題はその後直ったか（2026-11-27）

担当：Deakin のデータの機器（SNH-V6410PN、MAC 00:16:6c:d7:d5:f9、シリアル ZDZ56V2K100594B）。UNSW のデータの機器（SNH-P6410BN）とは別。下敷き：[報告 04](../../04-samsung-snh-v6410pn.md)、[報告 01](../../01-samsung-smartcam-snh-p6410bn.md)、[報告 15](../../15-samsung-https-aes.md)、[firmware-2026-11-26.md](../../firmware-2026-11-26.md) の §1・4。

- 調べ方：公式のページ（プライバシーポリシー、サポート、脆弱性報告）を直接・検索・Wayback で読んだ。サーバーが今も生きているかは、機器の識別子（シリアル・MAC・機器 ID）を一切入れない要求（DNS 解決、HEAD、TLS 握手だけ）で確かめた（2026-11-27 06:44 UTC ごろ）。ファームの本体は落としていない。機器への操作・ポートスキャンはしていない。
- APK：公開の配布元（APKPure、APKCombo、archive.org）から自動で落とす経路はどれも拒否・削除されていた（下の §2）。**ただし平文の `event.stw` は機器（ファーム）が送るもので、視聴アプリは作らない**ので、APK は今回の食い違いの主な材料にはならない。

## 1. 食い違いの要点

公式（Hanwha Vision のプライバシーポリシー、2024-）は「個人情報は暗号化通信で安全に送る」と書く。しかし Deakin 2023-24 で、SNH-V6410PN が **シリアル番号つきの通知を 12 時間おきに平文 HTTP** で送っていた（`POST http://www.samsungsmartcam.com/web/event.stw`、本文に `serial=ZDZ56V2K100594B`。報告 04 の K1）。2018 年に Hanwha が「暗号化されない遠隔の通信（CVE-2018-6295）は Resolved」としたのに、その系列の機器が 2023-24 年も平文で送っていた点が問題。

## 2. ファームウェアの入手

**結論：取れない。**firmware-2026-11-26.md（§1・4）と同じで、収録の版も最新の版も公開の場所がない。今回あらたに、旧来の配布経路そのものが消えていることを確かめた。

| 入手元の種類 | URL | 版 | 日付 | 大きさ | 素性 | 取れたか |
|---|---|---|---|---|---|---|
| 機器のクラウド配布（本来の経路） | 機器が `cloud` から取得（報告 01 の文書 C「download/update the latest firmware from the cloud」） | — | — | — | — | 取れない。SmartCam のクラウドは終了（§3 の年表） |
| Hanwha の Firmware Archive | `https://downloads.hanwhasecurity.com/firmware/` | — | — | — | — | **ホストが DNS で解決しない**（2026-11-27 に確認）。サポート記事のコメントも「2026-02-05 時点で動かない」とする |
| Hanwha Vision サポート（製品ページ／Device Manager） | support.hanwhavision.com の「How to Update Hanwha Devices Firmware」 | — | — | — | — | 取れない。業務用 Wisenet カメラ・NVR 向けの経路で、消費者向け SNH の一覧・ファイルは見当たらない |
| 第三者の掲示板 | SmartThings / Samsung community | SNH-P6410BN の `1.12_180413`（別機種、要約） | — | — | — | V6410PN のファイルは見つからない |
| APK（視聴アプリ） | APKPure・APKCombo・archive.org | — | — | — | — | 取れない。§2 末尾 |
| ARM のダンプ・GPL ソース | GitHub 等 | — | — | — | — | 見つからない |

- **ファーム本体**：SNH-V6410PN のファームのファイルは、公式・第三者・保管庫のどこにも見つからなかった。旧来の配布はクラウド経由で、そのクラウド（`downloads.hanwhasecurity.com` と samsungsmartcam のバックエンド）は今はいずれも死んでいる（§3・§4）。
- **APK（最も楽な別経路として試した結果）**：
  - 視聴アプリは 2 つ。旧「Samsung SmartCam」`com.techwin.shc`（Play ストアから削除済み）と、新「Wisenet SmartCam+」`com.techwin.wisenetsmartcam`（2024-07-08 に V6410PN の対応を終了）。
  - APKPure は Cloudflare で 403、APKCombo は両パッケージとも 404（配信停止のアプリは棚から外されている）、archive.org にも該当の APK が無かった。**楽に取れる経路では入手できず（未入手）**。
  - なお `event.stw` は機器が直接 POST する通知で、アプリ側のコードが作る URL ではない。APK を読んでも「K1 が https になったか」は決められない（決めるにはファーム本体か実機の収録が要る）。ブラウザ拡張での手動取得は親の判断に委ねる。

## 3. パッチ・更新の履歴

- **2018-03（CVE-2018-6294〜6303、Kaspersky ICS CERT 2018-03-12 / NVD 2018-03-13）**：Kaspersky が SNH-V6410PN で「ファーム更新に安全でない HTTP」「HTTP API に安全でない HTTP」などを指摘。Hanwha の脆弱性報告（2018-03-21）は CVE-2018-6295「Unencrypted way of remote control and communications」を **「Resolved」** とし、注に「fixed in the firmware updates released from March」。**直した版の番号は書いていない。対象は「All Hanwha Techwin SmartCams」**。
  - 報道（SecurityWeek、CSO、2018-03）：「Hanwha has started to release firmware updates to fix the vulnerabilities, but this work continues」「Kaspersky has only disclosed … flaws that have been fixed」。つまり 2018-03 時点で一部のみ修正、残りは後日。どの通信をどの版で直したかは公表されていない。
  - **event.stw（シリアル番号つきの平文通知）を直したという記載は、どの資料にも無い。** 事実として、同じ `event.stw` の平文通知は SNH-P6410BN が UNSW-IoTraffic（2016-17）で 13,310 回、SNH-V6410PN が Deakin（2023-24）で送り続けていた（報告 15・04）。CVE の「修正」は event.stw には及んでいない。
- **消費者向け SmartCam のリリースノート・版ごとの変更履歴**：公開されていない（Canary と同様、版の中身が出てこない）。firmware-2026-11-26.md の調べと変わらず。
- **サービス・アプリの年表**（§1「食い違いが物理的に続けられたか」を決めるうえで重要）：
  - 2020 年ごろ：ブラウザ（IE/ActiveX）の Web ビューア `www.samsungsmartcam.com/web/` の生視聴が止まる（利用者報告。firmware-2026-11-26.md が「クラウドは 2020-07-01 に終了」とした分は、この **Web ビューア** を指すとみられる＝推測。機器⇔クラウドの XMPP・event.stw・media は別で、Deakin 2023-24 でも動いていた）。
  - **2024-07-08**：Wisenet SmartCam+ アプリが SNH-V6410PN ほか 2 機種（SNH-V6414BN、SNH-C6417BN）の対応を「compatibility issues」で終了（アプリ内告知、Samsung community に写し）。
  - 2025-01-17 ごろ：サーバーへのアクセスが止まったという利用者報告が複数。
  - これで、Deakin 収録（2023-07〜2024-05）は **まだバックエンドが生きていた時期**で、2020 年の「終了」と矛盾しない（終了したのは Web ビューア）ことが整合する。

## 4. その後直ったか

| 判定 | 日付・版・資料 | URL | 何が書いてある／観測されたか |
|---|---|---|---|
| **どちらとも言えない（版の特定不能）** | Hanwha 脆弱性報告 2018-03-21 | [Wayback](https://web.archive.org/web/20210803235506/https://www.hanwha-security.com/data/tutorial/attrbt/1521604298202.pdf) / [hanwhavision.com（韓国語）](https://www.hanwhavision.com/wp-content/uploads/2021/09/보안취약점-보고서-CVE-2018-6294_6303_20180321.pdf) | CVE-2018-6295 を Resolved、「2018 年 3 月以降のファームで修正」。版番号なし。event.stw には触れていない |
| **まだ問題という証拠（当時）** | Deakin 2023-24（報告 04 の K1、報告 15） | — | 2018 の「修正」宣言の後も、同系列の機器が event.stw を平文で送り続けた（V6410PN は 7 日で 8 回、P6410BN は 2016-17 に 13,310 回） |
| **平文の口は今は到達不能（ただし暗号化したからではなく、サービスごと終了したから）** | 2026-11-27 06:44 UTC、自分で確認（識別子なし） | — | `www.samsungsmartcam.com`＝**0.0.0.0**（シンクホール、80 番に接続不可）、`xmpp.samsungsmartcam.com`＝**0.0.0.0**、`global.samsungsmartcam.com`＝**NXDOMAIN**、`media.samsungsmartcam.com`＝AWS の実 IP（54.178.136.87 ほか）だが **TLS 握手に応答せず**。バックエンド一式が死んでいる。アプリは 2024-07 終了、サーバーは 2025-01 ごろ停止（§3） |
| **今も公式は暗号化を約束（現行文書）** | Hanwha Vision プライバシーポリシー **Ver 13.1、2026-03-06 施行**（今日読んだ） | [wisenetlife.com/en-us/privacy](https://www.wisenetlife.com/en-us/privacy/) | 第 7 条 ②-2「we make sure that Personal Information can be safely transmitted over the network through encrypted communication.」**今も同じ言い切り**。収録当時（文書 A、2024-01-01 施行）と同趣旨。SmartCam web viewer は今もデータ収集の表に載る（AWS、米国、3 年保持）。サービス終了の記載は無い |

**今の公式文書の該当文（今日読んだ結果）**：現行のプライバシーポリシー（Ver 13.1）は、収録当時の版（文書 A）と同じく「個人情報は暗号化通信で安全に送る」と言い切ったまま。一方で、平文で送っていた機器のバックエンド（event.stw を含む）は、暗号化で直したのではなく **サービスごと終了**して到達できなくなった。「直った」とは言えない。

## 5. まとめ

- **入手できたか**：ファーム本体・APK とも、楽に取れる経路では **入手できなかった**（クラウド配布は終了、Firmware Archive はホストごと消滅、消費者向け SNH は業務用の配布経路に無く、アプリ APK も配信停止で棚から外れている）。
- **直ったとみられるか**：**直ったという証拠は無い。**event.stw の平文通知を直したと読める記載は一つも無く、2018 の「CVE Resolved」の後も 2023-24 年まで平文が続いた。今は平文の口（www/xmpp）が 0.0.0.0 にシンクホールされ到達不能だが、これは暗号化したのではなく **サービス終了（アプリ 2024-07、サーバー 2025-01 ごろ）** による。現行のプライバシーポリシー（2026-03）は今も「暗号化通信」を約束したまま。
- **論文に使えるか**：使える。食い違い（平文 event.stw 対「暗号化通信」）は 2023-24 のデータで確定、かつメーカーの「2018 に Resolved」宣言と突き合わせられる好例。「直ったか」への答えは **『版では直されず、機器のライフサイクル終了（サービス停止）で平文の通信そのものが消えた』** という形になり、ETSI EN 303 645 的には「脆弱性は修正されず、EOL で放置・停止された」事例として書ける。確定の限界は版の特定ができないこと（下記）。

## 6. 未確認

- 収録時（2023-24）と修正宣言時（2018-03）のファームの版番号。CVE-2018-6295 を実際に直した版の番号。
- 「2020-07-01 のクラウド終了」が Web ビューアだけを指すか（公式の一次資料は未確認。Hanwha の FAQ 記事 47319817998995 は 403 で本文を読めず、利用者報告からの推測）。
- APK の中身（楽な経路で入手できず）。入手できても event.stw の http/https は決められない（機器側の挙動のため）。
- `media.samsungsmartcam.com` の実 IP が今も Hanwha のものか、別用途に再割り当てされたか（TLS に応答しないため不明）。
- 2024-07 以降に SNH-V6410PN の実機の通信を取った第三者の観測（見つからず。サービス停止後は機器も通信できないとみられる）。
