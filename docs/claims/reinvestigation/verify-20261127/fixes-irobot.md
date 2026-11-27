# iRobot Roomba：問題はその後直ったか（2026-11-27）

担当：iRobot Roomba（CIC IoT 2022）。下敷き＝[14-irobot-roomba.md](../../14-irobot-roomba.md)、[firmware-2026-11-26.md](../../firmware-2026-11-26.md) の「14」。

## 1. 食い違いの要点

iRobot の Data Security のページ（2021-12-06、全製品対象）は「Currently, we use AES 256-bit encryption and Transport Layer Security (TLS v1.2).」「The data is encrypted both in transit and at rest.」と書く。しかし CIC 2022 の Roomba の TLS 握手 34 回はすべて **AES-128**（TLS 1.3 の `TLS_AES_128_GCM_SHA256` が 20、TLS 1.2 の `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` が 14）で、AES-256 は一度も選ばれていない。機種は収録からは特定できていない。

**結論（先に）**：食い違いは「直った／直っていない」で語れる種類ではない。**ロボットの TLS は今も AES-128**（下の第三者ソースで確認）であり、公式文書も**今も AES-256/TLS 1.2 のまま**（最新の保存版で確認）。ただし文書の「AES 256-bit」は TLS の暗号ではなく、**保存時（at rest）の暗号**を指すと読むのが最も整合的で、その読み方では矛盾そのものが成立しない。

## 2. APK 解析（最優先）

### 2.1 対象アプリ

| 項目 | 内容 |
|---|---|
| アプリ | iRobot Home（「Classic」） |
| パッケージ | `com.irobot.home`（iOS id `1012014442`） |
| 収録期の対応アプリ | このロボット（`irobotapi.com` + AWS IoT、ファーム 2.x/3.x 世代）は Classic アプリの管轄。新しい系列（V4/Matter。Combo Max 705 など）は別アプリ **Roomba Home** に分離（App Store の Classic 版の注記「For other Roomba models, please download the Roomba Home app」）。**CIC 期（2021）の機器は `com.irobot.home` が正しい** |

### 2.2 APK の入手の試み（実体は未取得）

APK の実体ファイルは**この環境では落とせなかった**。経緯：

- **版の一覧と fileID は取れた**（Uptodown、curl で到達可）。配布元 `https://irobot-home.en.uptodown.com/`。版一覧 API：`…/android/apps/1415565/versions/<page>`。
  - 収録期に近い古い版：**5.7.0-release**（2021-07-20、APKMirror の日付）。Uptodown の fileID `1172006156`、形式 apk（ユニバーサル）。ダウンロードページ `…/android/download/1172006156`。
  - 今の最新のユニバーサル apk：**7.17.4**（2025-11-06、APKMirror）。fileID `1134170255`。`…/android/download/1134170255`。（最新の 7.18.0・7.17.6・7.17.5 は xapk＝分割 APK。7.17.4 は単体 apk で解析向き。）
- **実体が落とせなかった理由**：Uptodown はダウンロードボタンの実トークン（`data-url` → `https://dw.uptodown.com/dwn/<token>`）を**ブラウザにしか埋め込まない**（curl には素のページを返す）。APKMirror・APKPure・APKCombo・APKFab は Cloudflare で 403。反ボットの回避（ブラウザ指紋の偽装やアプリ内 API の詐称）は規約外のため**していない**。
- **親への引き継ぎ**：ブラウザ（Claude in Chrome）で上の 2 つのダウンロードページを開けば実体 APK が取れる。取得後 `jadx -d <out> <apk>` で、OkHttp の `ConnectionSpec`/`CipherSuite`、`AES_256`/`AES_128` の文字列、証明書 pinning、エンドポイント（`*.iot.irobotapi.com`、AWS IoT）を読める。これは残作業。

### 2.3 APK の代わりに読めた、より強い根拠（ロボット本体の暗号）

CIC が収録したのは**ロボットの通信**（アプリではない）。そのロボットの TLS の実像は、公開のオープンソースの実装と第三者の解析から直接わかる。いずれも「ロボット側が何をしゃべるか」を示す一次に近い資料。

- **dorita980**（iRobot Roomba/Braava の非公式 SDK、koalazak）。ソースで確認：
  - ロボットのローカル制御（MQTT over TLS、ポート **8883**）：`lib/v2/local.js` 28〜31 行目で `rejectUnauthorized: false`（ロボットは自己署名証明書）、`ciphers: … || 'AES128-SHA256'`。
  - ロボットからの BLID/パスワード取得：`bin/getpassword.js` 92〜101 行目で `ciphers: … || 'AES128-SHA256,TLS_AES_256_GCM_SHA384'`、`tls.connect(8883, …)`。
  - クラウド側の口は CIC と一致：`bin/getPasswordCloud.js` が `https://disc-prod.iot.irobotapi.com/v1/discover/endpoints` と `https://unauth2.prod.iot.irobotapi.com` を叩く（CIC が見た `disc-prod`・`unauth1/3.prod.iot.irobotapi.com` と同系列）。
  - ファーム世代：1.6.x、2.x.x（900 系列が v2）、3.2.x（800 系列が v3）。V4（Matter 先行の新機種）は未対応。
- **asnowfix/home-automation `docs/irobot-local-api-research.md`**（第三者の解析）：ロボットのローカル TLS は「**TLS 1.2, `TLS_RSA_WITH_AES_128_CBC_SHA256`**, cert subject `CN=iRobot-<BLID>`」と明記（20〜21 行目）。証明書の CN が `iRobot-<BLID>` で、**CIC の DHCP ホスト名 `iRobot-<BLID>` と一致**。roombapy（Roomba980-Python）は 980 系で `set_ciphers('DEFAULT@SECLEVEL=1')` が必要（＝弱い AES-128-CBC だから、345〜346 行目）。一方、HA フォーラムの J7+ の報告（2022-06-15）では、J7+ のローカルに `ROBOT_CIPHERS='TLS_AES_256_GCM_SHA384'` を指定（348 行目）。
- **AWS IoT の口**：CIC の `a2uowfjvhio0fa.iot.us-east-1.amazonaws.com` は iRobot の AWS IoT Core のエンドポイント（複数の公開ブロックリストに iRobot のドメインとして収録）。現行ファームは ATS 版 `a2uowfjvhio0fa-ats.iot.us-east-1.amazonaws.com` を使う（irobot-explore が記録）。

**読み取れること**：
1. **ロボットの TLS は AES-128**。ローカル（8883）は `AES128-SHA256`（＝`TLS_RSA_WITH_AES_128_CBC_SHA256`）、クラウドは CIC で AES-128-GCM。**観測できるどの経路でもロボットは AES-128 を選ぶ**。これは CIC の所見（AES-128 のみ）とソースが完全に一致する。
2. したがって文書の「AES 256-bit」は、**通信路（TLS）の暗号ではない**。同じ文は「in transit **and at rest**」と言っており、AES-256 は**クラウドの保存時の暗号**（AWS の S3 などは既定が AES-256）を指すと読むのが自然。この読み方では矛盾は消える（報告の「最も限定的な読み方」と一致）。通信の暗号と広く読めば AES-128 と食い違う、という関係は変わらない。
3. **AES-256 が「使われるコード」か**：ロボット本体では、ローカルの TLS 設定は AES-128 で固定（自己署名・証明書検証なし）。新しい J7+ 系だけはローカルでも TLS 1.3 の `TLS_AES_256_GCM_SHA384` が使える（第三者報告）。つまり AES-256 の TLS は**新世代のロボットでのみ**現れうる。アプリ（phone）側の OkHttp の暗号設定と pinning は APK 未取得のため**未確認**（残作業）。

### 2.4 機種の手がかり（CIC の機器）

- 確実に言えるのは「ファーム 2.x/3.x 世代の Wi‑Fi ロボット（Classic アプリ管轄）」であること。根拠：`irobotapi.com` の discover/unauth フロー＋ AWS IoT を使い、ローカル証明書の CN が `iRobot-<BLID>`、TLS 1.3 も使える。これは 600/800/900/i/e/s 系の系列。
- **弱い手がかり（推測）**：CIC の機器は TLS 1.3 の握手でも `TLS_AES_256_GCM_SHA384` を使わず AES-128-GCM を選んでいる。J7+ 系はローカルで AES-256-GCM を扱える世代なので、CIC の機器は**J7+ より前（i/e/900 世代など）の可能性がやや高い**。ただし TLS 1.3 の暗号はサーバ（AWS IoT）側の選好でも決まるため、断定はできない。
- 収録そのものからの機種特定は依然**不可能**（TLS 1.3 で証明書が暗号化、MQTT も暗号化。機種文字列は出ない）。

## 3. ファームウェアの入手

| 入手元の種類 | URL | 版 | 日付 | 大きさ | 素性 | 取れたか |
|---|---|---|---|---|---|---|
| ロボット本体のファーム（OTA） | iRobot クラウドから TLS で配布。公開 URL なし | — | — | — | 不明 | **取れない**（外から取れない。dorita980 は「ファーム更新はルータでブロック推奨」と書くほど、更新は機器が自動で受ける） |
| GPL/LGPL のソース | [iot-content.irobot.com/notices](https://iot-content.irobot.com/notices) | 製品ごと | — | — | 平文（ソース） | **オンライン配布なし**。郵送請求（$5 の小切手）のみ。ロボットは Linux 系の GPL/LGPL 部品を含むが、ダウンロードはできない |
| アプリ APK（Classic） | Uptodown `irobot-home.en.uptodown.com`（curl 到達可） | 5.7.0（fileID 1172006156）／7.17.4（fileID 1134170255）等 | 2021-07／2025-11 | 未確認（ページ表示は大きめ） | 平文（ZIP/APK） | **ページは取れるが実体は curl では不可**（トークンがブラウザ限定）。親がブラウザで取得可 |
| アプリ APK（別ミラー） | APKMirror / APKPure / APKCombo / APKFab | 多数 | — | — | — | **403**（Cloudflare）。curl 不可 |

- ARM 機のファームのダンプ（第三者の保管庫）は見つからなかった。ロボットのファームは暗号化・自動配布で、Sonos のような第三者保管庫は無い。
- 復号は試していない。公開の復号手法も確認していない。

## 4. パッチ・更新の履歴（アプリ `com.irobot.home`）

ロボット本体の版ごとの変更履歴は公開されていない。アプリの版（APKMirror / Uptodown）は分かる範囲で：

| 版 | 日付（APKMirror） | 備考 |
|---|---|---|
| 5.2.3-release | 2020-12-16 | 収録前 |
| 5.2.4-release | 2021-03-17 | |
| 5.7.0-release | 2021-07-20 | **CIC 収録期（2021-10〜12）に最も近い** |
| 7.2.0 | 2022-12-05 | |
| 7.13.x〜7.16.x | 2024〜2025 | |
| 7.17.0〜7.17.6 | 2025-07〜2026-01 | 7.17.4（2025-11-06）が最後の単体 apk |
| 7.18.0 | 2026-06-16 | 最新（xapk/bundle、136.96 MB） |

アプリのリリースノートに TLS・暗号スイート・AES の変更に触れた記載は見つかっていない（本文未精読。APK 解析が残作業）。

## 5. その後直ったか

| 区分 | 日付・版・資料 | 何が書いてある／観測されたか |
|---|---|---|
| **まだ AES-128（＝「直っていない」とも言えるが、元から矛盾でない）** | 2026-11、dorita980 の現行 master（`lib/v2/local.js`、`bin/getpassword.js`） | ロボットのローカル TLS は今も `AES128-SHA256`、自己署名・証明書検証なし |
| 同上 | asnowfix の解析（2026 頃）、roombapy | ロボットのローカル TLS は `TLS_RSA_WITH_AES_128_CBC_SHA256`。980 系は SECLEVEL=1 が要るほど弱い |
| **公式文書は不変** | about.irobot.com/en-us/legal/data-security の **2024-05-27 の保存**（Wayback、`20240527133316`） | 「Currently, we use AES 256-bit encryption and Transport Layer Security (TLS v1.2).」「The data is encrypted both in transit and at rest.」。2021-12-06 と**一字一句同じ** |
| **新世代だけ AES-256 が可能** | HA フォーラム J7+（2022-06-15、asnowfix 経由） | J7+ はローカルで `TLS_AES_256_GCM_SHA384` を扱える。新機種ほど AES-256(TLS1.3) が現れうる |
| どちらとも言えない | 今日（2026-11-27）の公式ライブページ | JS 描画で本文が取得できず**未確認**。読めた最新は 2024-05-27 の保存で、不変 |

**今の公式文書の該当文**（2024-05-27 保存、2026-11-27 時点で読めた最新）：
> All iRobot connected products communicate with the iRobot cloud service using robust encryption. **Currently, we use AES 256-bit encryption and Transport Layer Security (TLS v1.2).** Data encryption is augmented through strong identity management. … The data is encrypted both in transit and at rest.

## 6. まとめ（3 行）

- **入手**：ロボットのファーム本体は入手不可（OTA、暗号化、GPL は郵送請求のみ）。アプリ APK は版・座標を特定したが、実体は反ボットで curl 不可（親がブラウザで取得すれば jadx 解析まで到達可能）。
- **直ったか**：ロボットの TLS は今も AES-128、公式文書も今も AES-256/TLS1.2 のまま。そもそも文書の AES-256 は「保存時」を指すと読めば矛盾ではなく、「直す対象」ではない。J7+ 等の新機種だけがローカルでも AES-256(TLS1.3) を扱える。
- **論文に使えるか**：使える。CIC の AES-128 の所見は、dorita980 のソースと第三者の解析（`TLS_RSA_WITH_AES_128_CBC_SHA256`、CN=iRobot-<BLID>）で**裏が取れる**。この件は「明確な矛盾」ではなく「最も限定的な読み方では矛盾なし／広く読めば食い違い」の典型例として、文書の『AES-256』が in transit か at rest かを切り分ける論点に使うのが筋。断定は避ける。

## 7. 未確認

- アプリ APK（5.7.0・7.17.4）の実体と、その OkHttp の `ConnectionSpec`/`CipherSuite`、`AES_256`/`AES_128` の文字列、証明書 pinning、埋め込みエンドポイント（＝本ブリーフの最優先。親のブラウザ取得待ち）。
- 今日（2026-11-27）の公式ライブページの本文（JS 描画で未取得。読めた最新は 2024-05-27 保存）。
- CIC の機器の正確な機種（収録からは特定不能。推測で「J7+ より前の世代の可能性がやや高い」どまり）。
- AWS IoT 側がどの暗号スイートを選好するか（AES-128 がロボットの選好か AWS の選好かの切り分け）。
- アプリのリリースノート本文（TLS/暗号の変更の有無）。
- iRobot のロボット向け GPL ソースに具体機種別の提供があるか（郵送請求のみで未取得）。
