# eufy（Anker）HomeBase 2 とドアベル：その後直ったか（2026-11-27）

担当：eufy Security（HomeBase 2 / T8010 ＋ Video Doorbell 2K）。下敷き：`03-eufy-homebase2.md`、`verify-20261127/eufy.md`、`firmware-2026-11-26.md` §3。

## 0. 食い違いの要点

- ドアベルの製品ページは「AES data encryption ensures your footage is kept private **on transmission**」、Privacy Commitment は「Data during transmission is encrypted」と書く。
- しかし 2021-10-13 の CIC 収録の WAN 録画/視聴で、HomeBase 2 はドアベルの映像（2560×1920 H.265）と音声（AAC）を AWS の中継へ UDP(PPPP/P2P) で送り、**映像の P フレームと音声は暗号化なし**（暗号化は I フレームの先頭 128 バイトずつ＝映像バイトの約 0.25% だけ）。判定は**条件付きの矛盾**（録画が機器上で行われたかが条件）。

---

## 1. APK 解析（最優先）

### 1-1. 実アプリ APK の入手は失敗（Cloudflare）

公式アプリは **eufy Security**（パッケージ `com.oceanwing.battery.cam`、v5 以降は統合アプリ「eufy」に改称）。収録期の版と最新版の両方を狙ったが、**APK 本体は 1 つも取得できなかった**。配布元がすべて Cloudflare の JS チャレンジ（`HTTP 403`、`cf-mitigated: challenge`）を返し、curl では突破できない：

| 配布元 | 結果 |
|---|---|
| apkmirror.com / www.apkmirror.com | 403 challenge |
| apkpure.com / d.apkpure.com / m.apkpure.com | 403 challenge |
| apkpure.net | TLS 証明書不一致（取得不可。`-k` は方針で使わない） |
| apkcombo.com | 403 challenge |
| apkfab.com | 403 challenge |
| archive.org | eufy の APK なし（検索 0 件） |

→ **実 APK の jadx 解析は、ブラウザを使える親のセッションに委ねる**。狙う版（版名＝表示版、`_` の後はビルド番号）：

- **収録期（2021-10-13）に近い版**：**v3.3.x**（フォーラムの更新記録で v3.3.1 が 2021.9.1）。前後の確実な版は v3.1.0_994（2021-07-12）、v3.5.0_1149 / v3.5.1_1159（2021-12）。
- **最新版**：統合アプリ「eufy」の **v6.0.41_26142（2026-06-04）**（APKMirror。より新しい版があるかは未確認）。間の節目は v4.9.3_4367（2024-12-24）、v5.0.73_12711（2025-07-18）。
- 出どころ：APKMirror の anker/eufy-security 配下（版ごとのページ多数）。

### 1-2. 代わりに読んだもの：公開実装 bropat/eufy-security-client（＝アプリの P2P を復元した公開コード）

実 APK が取れないため、**eufy アプリの P2P プロトコルを逆解析して再現した公開実装** bropat/eufy-security-client（現行 master、**v4.1.1**、リリース 2026-07-01）を読み、クライアント側が今も何を期待しているか（＝今のファームが何を送るか）を確認した。保存：`V/bropat/`（`session.ts` 211,596 B、sha256 051ea2e8…／`utils.ts` 36,699 B、sha256 38771d9f…）。

- **映像フレームの部分暗号化は今も同じ**（`src/p2p/session.ts` 2255-2311 行）。要点：
  - ヘッダのフラグ `isKeyFrame`（`data[4]==1`）と `signCode`（ヘッダ 13 バイト目、1748 行）で分岐。
  - `signCode > 0`（I フレーム）：22〜150 バイト目の **128 バイトを RSA で復号して AES 鍵**を得る（`rsaKey.decrypt`）。鍵は配信ごとにクライアントが作る RSA 鍵で包まれる。
  - 続く映像本体：`encrypted_data = data[payloadStart : payloadStart+128]`（**先頭 128 バイトだけ** AES 復号）、`unencrypted_data = data[payloadStart+128 : …]`（**残りはそのまま平文で連結**）。
  - `signCode == 0`（P フレーム）：`aesKey` は空のまま → **全体を平文として扱う**（復号なし）。
- **音声は常に平文**（`CMD_AUDIO_FRAME`、2488-2537 行）：`audio_data = data.subarray(16)` と 16 バイトのヘッダを飛ばすだけで**復号処理がない**。AAC/AAC-LC をそのままストリームへ push。
- **P2P コマンド鍵は今も「シリアル＋DID」由来**（`src/p2p/utils.ts` 100-101 行）：`getP2PCommandEncryptionKey = serial.slice(-7) + DID の一部`。WOOT 2024 の `Key = PPCS_ID[0:15] + serial[9:15]` と同じ系統で、**非秘密の識別子から作る**。
- **WebRTC/DTLS/SRTP のコードは無い**（リポジトリ全体で該当 0 件）。ECDH（`createECDH("prime256v1")`、`decryptP2PKeyECDH`、utils.ts 640 行付近）は**接続時の DSK 鍵交換**に使われ、新しめの局では接続鍵が強化されているが、**映像・音声メディアの部分暗号化と音声平文は変わっていない**。

→ CIC 2021 の観測（I フレーム先頭 128 バイトのみ暗号化、P フレームと音声は平文）は、**現行（2026-07）の公開実装でもそのまま**。つまりアプリ経由の P2P メディアの作りは直っていない。

---

## 2. ファームウェアの入手

| 入手元の種類 | URL | 版 | 日付 | 大きさ | 素性 | 取れたか |
|---|---|---|---|---|---|---|
| 公式配布（アプリ内 OTA） | なし（公開窓口なし） | HB2 v3.1.9.0h が記録上の最新 | 2022-04-26 | — | — | **取れない**（アプリから自動更新） |
| 第三者のダンプ・保管庫 | GitHub 検索（`eufy firmware` repo／`home_security eufy T8010` code） | — | — | — | — | **見つからない**（0 件） |
| ハードウェア抽出（研究） | USENIX WOOT 2024（Goeman ほか） | 版の明記なし（MIPS/Buildroot Linux、主要バイナリ `home_security`） | 解析 2022-2023、開示 2023-06 | — | 平文のバイナリ（研究者が復元） | 研究者は取得（UART 回復シェル＋CH341a フラッシュリーダ。一般公開はされていない） |
| GPL ソース | 探したが特定できず | — | — | — | — | 未確認 |
| APK | 1-1 参照 | — | — | — | — | **取れない**（Cloudflare） |

- ファームの本体はウェブで公開されておらず、第三者の公開ダンプも見当たらない。唯一の既知の入手経路は WOOT 2024 の**ハードウェア分解**（UART の回復シェルで root を取り、フラッシュをダンプ）。論文本文には版番号の記載はない。
- `firmware-2026-11-26.md` §3 の結論（公開なし、記録上の最新 HB2 v3.1.9.0h／2022-04-26）から変化なし。

---

## 3. パッチ・更新の履歴

**HomeBase 2 ファーム**（community.eufy.com「firmware-update-records-eufycam-2c-2」、2026-11-27 に閲覧）：

| 版 | 日付 | 内容 |
|---|---|---|
| v3.1.9.0h | 2022-04-26 | 「Improved the system security by fixing some issues.」（記録上の最新） |
| v3.1.7.2h | 2022-03-07 | smartDrop の通話対応、Doorbell Dual の荷物検知の最適化、バグ修正 |
| v2.1.8.5h | 2021-11-22 | 追加手順の最適化、ドアベルとの互換改善、安定性 |
| v2.1.7.8h | 2021-08-20 | バグ修正・安定性（**収録 2021-10-13 時点はこの前後とみられる＝未確認**） |
| v2.1.6.x h | 2021-03〜04 | バグ修正・HomeKit 録画改善ほか |

- **どの HB2 の変更履歴にも、暗号化・E2EE・WebRTC・P2P の記載はない**（「security improvements」という曖昧な表現のみ）。記録上 v3.1.9.0h（2022-04）より新しい HB2 ファームは無い。
- アプリ側：v3.3.1（2021-09）… v4.9.3（2024-12）… 統合アプリ v6.0.41（2026-06）。アプリの更新記録にも、P2P メディアを全文暗号化したという記載は見当たらない（未確認の部分あり）。

---

## 4. その後直ったか

| 区分 | 日付・版・資料 | 何が書いてある／観測されたか |
|---|---|---|
| **まだ問題（アプリ P2P）** | WOOT 2024（Goeman ほか、USENIX WOOT '24、pp.133-147。本文 PDF を精読） | 同じ HB2＋Doorbell 2K。§2.1「The mobile App **always** relies on the proprietary P2P protocol」。§5.4.2「暗号化画像＝平文ヘッダ＋**256 バイトの暗号化（JFIF ヘッダ）**＋残りは**未暗号**」「only the JFIF header is encrypted, leaving the rest of the image unencrypted」。「videos and images slightly differ … the encryption key is the same」。→ 開示後のファームでも**メディアは先頭だけ暗号化**（映像の P フレーム・残りは平文）という作りが続く。 |
| **まだ問題（アプリ P2P）** | bropat/eufy-security-client v4.1.1（2026-07） | 現行コードが I フレーム先頭 128 バイトのみ復号・P フレームと音声は復号なし、という**同じ部分暗号化**を実装（§1-2）。クライアントがこれを期待する＝今のファームも同じ形で送る。 |
| **直った（別経路のみ）** | Anker の声明 2023-01（The Verge が元。一次は未読、二次 MacRumors/GSMArena/AppleInsider で確認） | 問題にされた**ウェブポータル**の映像（DevTools で平文リンクが取れた件）を暗号化し、**全カメラを WebRTC（既定で暗号化）へ移す**とした。WOOT も「web viewer は WebRTC（DTLS/SRTP）」と確認。**ただしこれはウェブ経路の話**で、アプリの P2P 経路ではない。Anker は「アプリの映像は暗号化済み（傍受しても見られない）」と主張したが、CIC 2021 のデータはその映像の 99.7%＋が平文であることを示す。 |
| **どちらとも言えない（公式文言の変化）** | 現行 Privacy Commitment（www.eufy.com/privacy-commitment、2026-11-27 閲覧） | 今は「eufy encrypts your important data … **in transit by default**」。E2EE は既定ではなく**任意設定「Advanced Encryption」**（"uses end-to-end encryption … can only be decrypted by you on your authorized devices"）に格下げ。「military-grade」は**今の本文に見当たらない**。FAQ6 は「videos are stored locally and secured with AES」「protected with both TLS and SRTP」「cloud 保存時は AWS 間を暗号化」。→ 2021 年の言い切り（「Data during transmission is encrypted」「military-grade」）から**文言が後退・条件化**している。 |
| **参考（確認済み）** | WOOT 2024 §8、The Verge 二次資料 | P. Moore が示したのは「クラウドへの無認可の画像アップロード」と「**ウェブ**の映像ストリームが平文」。「これらは Eufy が修正し、今は E2EE」と論文は書くが、これもウェブ経路について。CVE-2023-37822（WPA2-PSK がシリアルから導出）も付随。 |

**今の公式文書の該当文（2026-11-27 に実際に読んだ）**

- Privacy Commitment（現行）：「eufy encrypts your important data (e.g., video footage, event lists, facial recognition data) **in transit by default**.」／「The **Advanced Encryption** option uses **end-to-end encryption** to ensure that your security videos … can only be decrypted by you on your authorized devices.」（＝任意設定）／FAQ6「Your videos are stored locally and secured with **AES** encryption by your eufy devices … protected with both **TLS** and **SRTP** … If you use cloud storage, data is encrypted in transit between your eufy devices and **AWS**.」
- ドアベル製品ページ（当時の D3/D4）にあった「AES data encryption ensures your footage is kept private on transmission」に相当する**断定**は、現行 Privacy Commitment では「in transit by default」と一般化され、E2EE は任意化されている。

---

## 5. まとめ（3 行）

- **入手**：ファーム本体も実 APK も取れなかった（公開なし／Cloudflare）。代わりに公開実装 bropat（現行）と WOOT 2024 論文、現行公式文書を確認。
- **直ったか**：アプリ経由の P2P メディアの**部分暗号化・音声平文は直っていない**（WOOT 2024 と bropat 現行コードが一致して示す）。2023 年の E2EE/WebRTC 化は**ウェブポータル経路のみ**で、CIC が捉えたアプリ P2P 経路ではない。公式文言は「in transit by default」「Advanced Encryption（任意の E2EE）」へ後退。
- **論文に使えるか**：使える。食い違い（アプリ P2P の映像・音声がほぼ平文）が**収録後も残る**ことを、第三者（WOOT 2024）と公開実装の両方で裏づけられる。ただし確定には実 APK の新旧比較（親がブラウザで取得）を 1 回足すと盤石。

---

## 6. 未確認の一覧

- 実 APK（収録期 v3.3.x／最新 v6.0.x）の jadx 解析：Cloudflare で未取得。P2P メディア処理・エンドポイント（`p2p-*.eufylife.com`、`zhixin-security-pr`、AWS 中継）が新旧でどう変わったかは**未確認**（bropat と WOOT で代替）。
- WOOT 2024 が解析した HB2 ファームの正確な版番号（論文に記載なし）。
- 収録 2021-10-13 時点の実ファーム版（v2.1.7.8h 前後と推測、未確認）。
- v3.1.9.0h（2022-04）より新しい HB2 公式ファームの有無（公開記録では無い。実機の OTA で配られたかは未確認）。
- GPL ソース公開の有無。第三者のファーム公開ダンプ（見当たらないが全数は未確認）。
- Anker 声明の一次資料（The Verge 原文）は未読。
- 現行 Privacy Commitment の「last updated」日付（ページ本文に表示なし）。
