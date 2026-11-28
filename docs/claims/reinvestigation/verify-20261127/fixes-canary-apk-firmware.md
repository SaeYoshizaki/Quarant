# Canary：Android アプリ（APK）の解析とファームの深掘り（2026-11-28）

対象：**Canary（初代 All-in-One／Pro。会社 Canary Connect、現 Smartfrog 傘下）**。
下敷き：[21-canary.md](../../21-canary.md)、[verify-20261127/fixes-sonos-canary.md](../../verify-20261127/fixes-sonos-canary.md) の Canary 節。

## 食い違いの要点（下敷きから）

- 公式 FAQ「All communication between your Canary device, the Canary Cloud, and your smartphone is encrypted over TLS/SSL (HTTPS).」（2025-10-18 の保存でも同文）に対し、**機器が `h.canaryis.com` へ TCP 80 の平文 HTTP で時刻合わせ**（htpdate、2018 年に 299 回）。送るのは見出しだけで利用者データはない。これは**機器（ファーム）側の挙動**。

---

## タスク1：APK 解析

### パッケージ名と版

- 公式アプリのパッケージ名は **`is.yranac.canary`**（「canary」の逆綴り）。確認：Play ストアの題名が「Canary - Smart Home Security」（[Play](https://play.google.com/store/apps/details?id=is.yranac.canary)、題名のみ取得できた）、2015 年のレビュー記事が同 ID を Play へリンク（[jonsuh.com 2015-03-25](https://github.com/jonsuh/jonsuh.com) の記事本文）、複数のミラーが同 ID で収録。
- 版の履歴（APKMirror、2026-11-27 取得）：最新 **9.3.0（2026-11-24）**、9.2.0（2026-10-31）… 8.18.1（2026-05）… 変種の節に 4.0.0（2019-07-29）、3.0.1（2019-03-21）。**収録時期（2018-05〜10）に一致する 2.x〜3.0 近辺**が狙いだが、APKMirror の一覧に出るのは 3.0.1（2019-03）以降。
- 旧版 **3.0.1** の素性（[ixt/ManifestDestinyDB](https://github.com/ixt/ManifestDestinyDB) の `manifests/is.yranac.canary.json`）：権限に CAMERA・RECORD_AUDIO・位置情報・Bluetooth・INTERNET など。トラッカーは **Snowplow、Google Crashlytics、Google Analytics**。エンドポイントの http/https は未記載。

### 自分での APK 取得：**未取得**（反ボット回避はしない方針）

公開ミラーはすべて Cloudflare か DNS で弾かれ、本体を落とせなかった。試したもの（2026-11-28）：

| 手段 | 結果 |
|---|---|
| curl：apkpure.com / apkmirror.com / `d.apkpure.com`（直リンク API） | 403 `cf-mitigated: challenge`（Cloudflare） |
| curl：apkcombo.com（版・DL ページ） | 404（`x-apkcombo-fast-404`、curl を弾く挙動） |
| curl：apkfab.com / m.apkpure.com | 403（Cloudflare） |
| WebFetch：apkcombo / apkpure の DL ページ | 404 / 403 |
| 軽量ミラー apksos・apkgk・apkplz・apk.tools | 当該パッケージ未収録（404） |
| ダウンロード用ホスト `download.apkcombo.com`・`api-apk.evozi.com`・apkmonk | **DNS 解決せず**（サンドボックスの外向き DNS が限定的） |
| archive.org 検索（`is.yranac.canary`／題名） | 0 件 |
| `apkeep`・`gplaycli` | 未インストール（Play 直取得は資格情報が要るので不使用） |

→ `jadx` を自分で回す材料は得られず。**自分での逆コンパイルは未実施**。代わりに下記の第三者解析を読んで引用する（信頼できないデータとして扱い、自分で未検証の旨を明記）。

### 第三者による APK 逆解析（引用。自分では未検証）

[Dicklesworthstone/franken_surveillance_system](https://github.com/Dicklesworthstone/franken_surveillance_system)（public、所有者の許可を得た機器検査の記録、2026-10〜11、`main`）。対象 APK は **`is.yranac.canary` 9.1.1**（APKPure の XAPK、base APK 92.9 MB、署名 `c816e8c989584c8a59b7ad298157d58ada4a1ccb`）。手法は `apkeep` → `unzip` → dex の `strings` →（ホットな package に）`jadx`。
- [docs/exploit/canary-outbound.md](https://github.com/Dicklesworthstone/franken_surveillance_system/blob/main/docs/exploit/canary-outbound.md)（§4〜6、commit 2026-11-03）
- [docs/research/EV-pack-H-012-app-reverse.md](https://github.com/Dicklesworthstone/franken_surveillance_system/blob/main/docs/research/EV-pack-H-012-app-reverse.md)

**アプリの `canaryis.com` 系ほかのエンドポイント（http/https の別）**

| エンドポイント | 役割 | http/https | 第三者が挙げた根拠 |
|---|---|---|---|
| `api.canaryis.com/o` | 唯一の REST API 基点 | **https** | `RetroFitAdapterFactory` が `setEndpoint("https://api.canaryis.com/o")`、ホスト一致判定 `bq/b.java:634` |
| `api.canaryis.com/o/thirdparty/safetrek/redirect` | Safetrek 連携の OAuth 戻り先 | https | `BaseConstants.java:106` |
| `canary.zendesk.com` | サポート | https | dex 文字列 |
| `firebase-settings.crashlytics.com`、`firebase.google.com` | Crashlytics／Firebase | https | dex 文字列 |

- **平文 http:// のエンドポイント：見つからない**（第三者の報告）。`wss://` も無く、独自の WebSocket クライアントも無い（okhttp ライブラリのみ）。RTSP／ONVIF／待受ソケットの文字列も無い＝アプリは**外向き HTTPS のみ**。映像も HTTPS。
- 注意：アプリが話すのは `api.canaryis.com`。機器が話す `b`／`i`／`m`／`o`／`v`／`h.canaryis.com` とは別系統。**平文の `h.canaryis.com`（htpdate）はアプリには現れない＝機器側だけの挙動**。

**証明書 pinning・独自 CA の扱い（アプリ 9.1.1、第三者 §5）**

| 確認項目 | 結果 |
|---|---|
| `res/xml/network_security_config.xml` | **空**（`<network-security-config />`。pin-set・domain-config・debug-overrides なし） |
| okhttp 外の `CertificatePinner` 生成 | 無し（`com.squareup.okhttp.*`／`okhttp3.*` のライブラリのみ） |
| dex 中の `sha256/` の pin 文字列 | 無し |
| 独自 `X509TrustManager`／`SSLSocketFactory` の差し替え | 無し |

→ アプリは**端末の標準トラストストアで検証し、pinning は一切無い**（`api.canaryis.com` の偽葉証明書で通る、と第三者は結論）。
（補足：EV-pack-H-012 は先に「OkHttp の `CertificatePinner` はあるが pin が実際に設定されているかは文字列だけでは断定できない」と書き、より詳しい §5 で「pin 無し」に確定している。自分では未検証。）

**時刻合わせの手がかり（アプリ）**：第三者の解析に htpdate／ntp／http の時刻同期の記述は無い。htpdate は機器側の C バイナリ（通信で見えた User-Agent `htpdate/1.1.2`、[21-canary.md](../../21-canary.md) C1）。**アプリ側には時刻合わせの手がかり無し**（予想どおり）。

### 自分で確かめた今の挙動（2026-11-28、識別子は送らない）

- `http://h.canaryis.com/` に HEAD（UA `htpdate/1.1.2`）→ **`301`、`Server: nginx/1.31.9`、`Date: …`、`Location: https://h.canaryis.com/`**。**平文の時刻合わせ口は今も生きている**（下敷きの観測を再確認）。
- DNS：`h.canaryis.com` と `i.canaryis.com` はどちらも `ingress-k8s-prod-edge.canaryis.com`（同じ edge）。平文の `h` と相互 TLS の `i` が同一エッジなのを再確認。

---

## タスク2：ファームのダンプ探し（深掘り）

**結論：本体は未発見（公開の配布物は無い）。** OTA 口は相互 TLS＋社内 CA で、匿名では取得できないことを今回 observed として確かめた。

### 探した場所と結果

| 入手元の種類 | URL／対象 | 結果・素性 |
|---|---|---|
| OTA 口 `o.canaryis.com` | `https://o.canaryis.com/`（CNAME `device-ota-prod.canaryis.com` → `device-ota-k8s-prod.canaryis.com`、54.156.241.154 ほか） | **相互 TLS（`Request CERT`）＋社内 CA**。サーバ証：`subject CN=*.canaryis.com, O=Canary Connect, Inc.`／`issuer O=Canary Connect, Inc., CN=Server CA 1`（自己署名連鎖）。匿名 GET は envoy の **404**。→ 本体は匿名では取れない |
| 旧 CNAME（下敷き記載） | `device-ota.prod.canaryis.com` | **NXDOMAIN**（ハイフン表記 `device-ota-prod.canaryis.com` に変わっている） |
| GitHub リポジトリ検索 | `canary camera firmware`、`canaryis` | 該当無し（Canary 諸島・stack canary 等の無関係物のみ） |
| GitHub コード検索 | `canaryis.com firmware`、`canary Ambarella A7`、`is.yranac.canary http` | ファーム本体は無し。`canaryis.com` の既存 119 件（下敷き）も HA 連携・MUD・DNS 研究・上記アプリ recon のみ |
| ファーム保管庫 firmware.center | `?q=canary` | 無し |
| ファーム保管庫 firmwarescan.com | `?s=canary` | 無し |
| ファーム保管庫 dumps.tadiphone.dev | `search=canary` | 無し |
| ファーム保管庫 vfirmware.net | — | DNS 解決せず（未確認） |
| FCC（FCC ID **2ACDL-C100**） | [fccid.io/2ACDL-C100](https://fccid.io/2ACDL-C100) | External/Internal Photos、Users Manual、Test Report のみ。**ファーム無し** |
| 分解記事 iFixit | [Teardown #63571](https://www.ifixit.com/Teardown/Canary+%28Home+Internet+Camera%29+Teardown/63571) | 物理分解のみ。フラッシュ吸い出し・ファーム無し |
| GPL ソース公開 | WebSearch | Canary の GPL 公開ページは見つからない（未発見） |
| eMMC/NAND ダンプ・Ambarella dump | GitHub／Web | 無し。SoC は Ambarella（DHCP ホスト名が一時 `Ambarella`、[21-canary.md](../../21-canary.md)）だが該当機のダンプは無し |

補足（第三者の機器観測、2026-10、franken 上記）：Canary 機（MAC `7C:70:BC:5D:4C:09`）は LAN に待受ポートを一切持たず（全ポート RST）、41 時間でクラウド通信ゼロ（DHCP NAK「wrong network」×211 で lease を取れず stranded）。**よって彼らは平文 htpdate を観測していない**（機器がクラウドに到達していないため）。機器側の TLS は社内 CA 検証で、偽の公開 CA 葉証明書は `unknown-CA` で蹴る（[FIRMWARE_ROOT_AND_DELIVERY.md](https://github.com/Dicklesworthstone/franken_surveillance_system/blob/main/docs/FIRMWARE_ROOT_AND_DELIVERY.md)）＝今回の `o.canaryis.com` の社内 CA 所見と一致。

---

## まとめ

- **APK は食い違いの補強になったか**：直接の補強にはならない。問題の平文 htpdate は**機器（ファーム）側だけ**の挙動で、アプリ（`is.yranac.canary`）は**外向き HTTPS のみ・平文エンドポイント無し**（第三者の 9.1.1 解析）。ただし「平文は機器限定」と範囲を絞れた点は前進。別件として、FAQ の「bank-level security」に関わる**新しい弱点＝アプリに証明書 pinning が一切無い**ことが分かった（これは時刻合わせの矛盾とは別の話）。すべて第三者解析に基づき、自分での jadx は未実施。
- **ファームは取れたか**：取れない。公開の配布物は無く、OTA 口は相互 TLS＋社内 CA（`Server CA 1`）で匿名 GET は 404。FCC・GPL・ダンプ・分解記事にもファーム本体は無い（今回 observed で確認）。
- **次に親がやるべきこと**：(1) Claude in Chrome で `is.yranac.canary` の APK を実際に落とす（旧版 2.x〜3.x＝2018-19 と最新 9.3.0）。自分で `jadx` を回し、第三者の「HTTPS のみ・pinning 無し」を検証し、`http://`／時刻同期の文字列が本当に無いかを新旧で比較する。(2) 今の FAQ は curl に 403 を返すので、ブラウザで本文（「all … TLS/SSL (HTTPS)」のままか）を確認。(3) pinning 無しは別立ての所見として扱う。

## 未確認

- 自分での APK 逆コンパイル（サンドボックスでダウンロードできず）。新旧版の差分比較も未実施（第三者解析は 9.1.1 の 1 版のみ）。
- 9.1.1 の OkHttp が実行時に pin を設定するか（EV-pack-H-012 の留保 vs §5 の「無し」）。自分では未検証。
- 2018-19 年に近い 2.x／3.0 の APK 本体（APKMirror の一覧は 3.0.1＝2019-03 までしか遡れず）。
- 今の Canary 機が平文 htpdate を今も送るか（2019 年以降の第三者の機器観測は無し。franken の機は lease を取れずクラウド未到達）。
- 今の公式 FAQ 本文（live は 403。下敷きの Wayback 2025-10-18 保存に依拠）。
- vfirmware.net（DNS 解決せず、未確認）。

## 親による自分での APK 検証（9.3.0、2026-11-28）

第三者解析に頼らず、**自分で APK を取得・展開して確かめた**。Claude in Chrome で APKMirror から bundle（`is.yranac.canary_9.3.0-205940_4arch`、`.apkm` 92.8 MB）を取得（`~/Downloads/`）→ base.apk（94 MB）を展開 → dex を `strings`、`network_security_config.xml` を apktool で復号。

- **Canary 自身の送り先はすべて https**：dex 文字列は `https://api.canaryis.com`、`https://api.canaryis.com/o`、`https://api.canaryis.com/o/thirdparty/safetrek/redirect`、`https://canary.zendesk.com`。**canaryis.com への平文 http は 1 つも無い**。
- dex 全体の scheme：`https://` 291、`http://` 86。ただし平文 http はすべて**第三者**：AppLovin（広告 SDK、`*.applovin.com`、`appl.vn`）、Snowplow（`iglucentral.com` のスキーマ）、XML 名前空間（`ns.adobe.com`、`dashif.org`）、`instagram.com/caughtbycanary`（会社の Instagram リンク）、`play.google.com` など。**Canary の機器・クラウド通信の平文は無い**（広告・解析の平文は FAQ の対象外だが、第三者トラッカーとして別途記録可）。
- **時刻合わせ（htpdate / h.canaryis.com）はアプリに無い**：canaryis.com は `api.` だけ。→ 平文の時刻合わせは**機器（ファーム）側だけ**、を自分でも確認。
- **証明書 pinning（訂正あり）**：`res/xml/network_security_config.xml` は **空**（`<network-security-config />`。宣言的 pinning・pin-set 無し）。ただし dex には OkHttp の `CertificatePinner`（45）・`setCertificatePinner`（3）・`HostnameVerifier`（47）の参照が**ある**。一方、ハードコードの `sha256/<base64>` の pin 文字列は**見つからない**。
  - → **実効的な pinning は無い可能性が高い**（宣言的設定が空＋pin 文字列が無い）が、`setCertificatePinner` の呼び出し箇所を jadx で読まないと断定はできない（未検証）。
  - 第三者報告の「CertificatePinner 無し」は不正確：**クラス・呼び出しの参照は存在する**。正しくは「network_security_config は空／ハードコードの pin 文字列は無い」。pinning 無しを所見にするなら、呼び出し箇所の逐語確認が要る。
- ダウンロードした `.apkm` は `~/Downloads/`（92.8 MB、私が取得）と `dl-canary/`（展開物）にある。実行していない（unzip/strings/apktool のみ）。

**結論（自己検証後）**：現行アプリ（9.3.0）は Canary の通信をすべて https で行い、平文の時刻合わせはアプリに無い＝**平文 htpdate は機器ファーム側だけ**（自己検証で確定）。pinning 無しは「宣言的設定が空・pin 文字列が無い」までで、断定には呼び出し箇所の確認が要る（保留）。
