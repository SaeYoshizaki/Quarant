# SimCam 1S（Simshine）：公式の発表と実際の通信の食い違いは、その後直ったか（2026-11-27）

担当：SimCam 1S。下敷き＝[02-simcam-1s.md](../../../Quarant/docs/claims/reinvestigation/02-simcam-1s.md)、[verify-20261127/simcam.md]、[firmware-2026-11-26.md](../../../Quarant/docs/claims/reinvestigation/firmware-2026-11-26.md) の §2。
調べ方：APK を落として `jadx`／`apktool` で読む（アプリは起動していない。認証情報は使っていない）。ファーム本体は先頭だけ取得。識別子（機器 ID・MAC）は送っていない。時刻は UTC。

## 1. 食い違いの要点

1S の FAQ（今日も公開、D1）は「we never have access to your data」「entirely local AI processing」と書くが、CIC IoT 2022 の `2021_11_02_Active.pcap` では、人の写った JPEG を検出ごとに **平文 HTTP で** AWS S3 バケット `elasticbeanstalk-us-east-2-793503604989`（us-east-2）へ `x-amz-acl: public-read` つきで PUT（15 回 200）。カメラは TLS を一度も使わない。**条件付きの矛盾**で、残った条件は「バケットの持ち主が Simshine か」だった。

## 2. この調べでいちばん効いた結果（APK がバケットの持ち主を示した）

**残っていた条件（持ち主＝Simshine か）は、APK の解析でほぼ埋まった。**

- Simshine の公式サポートページ（今も公開）が、公式アプリ **SimHome の APK を、まさにそのバケットから配っている**：
  `https://elasticbeanstalk-us-east-2-793503604989.s3.us-east-2.amazonaws.com/appFile/SimHome-V1.2.8.apk`（2026-11-27 に HEAD で 200、140,721,526 バイト、`Server: AmazonS3`）。
  出どころ＝[simshine.ai/support/simcam-1s-and-alloy-1s.html](https://simshine.ai/support/simcam-1s-and-alloy-1s.html)（live、2026-11-27 取得）。simcam.html / simcam-ango.html / baby-pro.html も同じ APK を指す。
- APK の中で、S3 の送り先は **サーバーから受け取る**作り。`com.simshine.baselib.bean.CloudStorageInfo` に `bucketName`・`accessKeyId`・`secretKeyId`・`roleArn`・`reqAddress` のフィールドがあり、アプリはこれを Simshine のバックエンド（luuka.fun）から得て S3 に読み書きする（`g/s/d/e/a.java`、`g/s/d/e/b.java`）。バケット名も STS の一時鍵も Simshine 側が発行している。
- アプリは S3 への PUT に **`CannedAccessControlList.PublicRead` を自分で付ける**（`g/s/d/e/a.java:98`）。カメラの `x-amz-acl: public-read` と同じ設計。
- アプリとカメラは **同じ luuka.fun バックエンドと同じエンドポイント**を使う：APK に `ota/ota/getNewVersion`、`push/push/pushMessage`、`https://www.luuka.fun/`、さらにカメラが TCP 9999 の心拍に使った同じ IP `54.202.68.76`（アプリは `http://54.202.68.76:8080/`）。

→ バケット（AWS アカウント 793503604989）と luuka.fun は **Simshine 側の設備**とほぼ断定できる（公式アプリの配布元・鍵の発行元・同じバックエンド）。カメラの長期鍵がこのアカウントに復号されること（verify-20261127/simcam.md §8）と合わせ、**条件（i）は満たされる**。FAQ の「we never have access」はこれと両立しない。

## 3. APK の解析（最優先）

| 項目 | 内容 |
|---|---|
| 新アプリ | **SimHome**、パッケージ `com.simshine.aiot`。Google Play の最新は 1.4.4（2025-12-18、versionCode 304、APKPure の一覧）。 |
| 旧アプリ | **SimCam AI**、パッケージ `com.simtoo.aicamera`（App Store `id1441938914`、Android 3.3.3／2020）。※ SimHome の中に `com/simtoo/aicamera/…` のクラスがそのまま入っていて、旧アプリは新アプリに統合されている。 |
| 落とした APK | `SimHome-V1.2.8.apk`（**ファイル名は V1.2.8 だが、中身の versionName は 1.3.0／versionCode 227**。S3 の Last-Modified 2022-10-21）。Simshine が今も公式配布している唯一の APK。収録期（2021、SimHome iOS 1.2.7）に近い。 |
| 保存先・ハッシュ | `V/dl-simcam/simhome-1.2.8/SimHome-V1.2.8.apk`、140,721,526 バイト、SHA-256 `7d04601093f0f206fe748b939eb817717790755795f859b9ee9ee9ecd23d5c38`。`jadx -d jadx-out`（4 dex、約 3,700 Java）、`apktool -s`。 |
| 最新版（1.4.4）の入手 | **未確認**。APKPure・APKMirror・d.apkpure.com は Cloudflare の challenge で 403。APKCombo/Aptoide/apkmonk は未収録。S3 の `SimHome-V1.4.4.apk` 等は 403（AccessDenied で、無いのか非公開かは区別できない）。→ 最新版の APK 取得は**親がブラウザ（Claude in Chrome）で**。 |

**探した指標**

| 指標 | 結果（SimHome V1.2.8=中身 1.3.0） |
|---|---|
| `luuka.fun` | **あり**。`g/s/d/h/c.java` が用途別に振り分け：主 API は `https://www.luuka.fun/`（TLS）、だが `http://doorbell.luuka.fun:9000/`、`http://52.38.98.219:8080/`、`http://54.202.68.76:8080/` は **平文 HTTP**。 |
| `elasticbeanstalk-us-east-2-793503604989` / `793503604989` | dex・resources・assets の**どこにも無い**。バケット名はサーバー（luuka.fun）が返す `CloudStorageInfo.bucketName` から来る（ハードコードされていない）。 |
| `s3.amazonaws.com` / AWS | **AWS Android SDK を同梱**（`com.amazonaws.*`、S3 TransferUtility、Cognito identity/idp/sync、DynamoDB、IoT）。 |
| `AKIA`（鍵の形。値は書かない） | dex に **0 件**（アプリにはアクセスキーをハードコードしていない。鍵はサーバー発行の `CloudStorageInfo` で受け取る）。※カメラ側のファームには AKIA 形の長期鍵があり、値は非公開リポジトリ `quarant-results` にある。 |
| `http://`（平文の送り先） | 上の luuka.fun 系のほか、`http://52.38.98.219:8080`、`http://54.202.68.76:8080`。`AndroidManifest` の `network_security_config.xml` は **`cleartextTrafficPermitted="true"`（全体で平文を許可）**。 |
| `iotcplatform` / TUTK / IOTC / PPPP | **ThroughTek（TUTK）Kalay の P2P SDK を同梱**：`libIOTCAPIs.so`、`libAVAPIs.so`、`libP2PTunnelAPIs.so`、`libRDTAPIs.so`、`libTUTKGlobalAPIs.so`、`libtutk_*.so`。`com.tutk.IOTC.*`、`IOTC_Connect_ByUIDEx`、`new_iotc_authkey`。→ ライブ映像（S7）は TUTK の authkey つき P2P。収録で見えた `all-master.iotcplatform.com`・UDP 10001/10240 は TUTK の登録と合う（verify の推測を裏づけ）。 |
| 画像・映像の暗号化 | **一部の画像は暗号化**。`libImageDecrypt.so`（JNI `com.simshine.baselib.filter.ImageDecrypt.decryptFile(src,dst,len,key)`、文字列 `share_key`・`No encrypt jpg !`）。復号の呼び出しは「お気に入り画像（MineLikedImage）」「ベビーの毎日クリップ（EveryDayClipsPic）」「Wonderful Moment」など、クラウドに保存して後から見る画像だけ。鍵は端末ごとの `share_key`。アプリの汎用 S3 アップロード（`a.java:98`）は **暗号化せずそのまま** `public-read` で上げる。人物検知の JPEG は PCAP でそのまま開けた（平文）＝この暗号化の対象外。 |
| `public-read` の扱い | アプリ自身が PUT に `PublicRead` を付ける（上）。カメラの public-read と同じ設計。 |
| 新旧でエンドポイント／平文は変わったか | V1.2.8（中身 1.3.0）のみ解析。最新 1.4.4 は未取得（上）。旧 SimCam AI は SimHome に統合済みで、同じ luuka.fun＋AWS＋TUTK の作り。→ **新旧の差分は未確認**（親がブラウザで 1.4.4 を取れば比較可能）。 |

## 4. ファームウェアの入手

**更新確認で返る `1.20200720.tgz`（＝V20200720、2020-07-20 ビルド）の本体が、Simshine の公式サイトで公開配布されていることを確認した。**（firmware-2026-11-26.md §2 は「見つからず」だったので、ここが前進。）

| 入手元 | URL | 版 | 日付（Last-Modified／内部） | 大きさ | 素性 | 取れたか |
|---|---|---|---|---|---|---|
| 公式サイト（手動更新） | `https://www.simshine.ai/images/simcam1s/update.tgz` | V20200720 | 2021-12-09 再掲／gzip 内部 mtime **2020-07-20** | 10,323,824 B | **gzip（平文・圧縮。暗号化ではない）**。先頭 `1f 8b 08`、`file`＝gzip、エントロピー 7.99 | **取れる**（先頭 64 KB のみ取得） |
| 公式サイト | `https://www.simshine.ai/images/simcam1s/update.tgz.pba` | V20200720 | 2021-12-09／gzip 内部 2020-06-12 | 58,362,297 B | **gzip（平文・圧縮）**。先頭 `1f 8b 08` | **取れる**（先頭 64 KB のみ） |
| 公式サイト（Alloy 1S） | `https://www.simshine.ai/images/alloy1s/update.tgz`（＋ `.tgz.pba`） | V20200720 | 2021-12-09 | 10,323,850 B／58,364,338 B | gzip | 取れる（HEAD 確認） |
| 更新確認サーバー | `http://www.luuka.fun/ota/ota/getNewVersion` | — | — | — | **JSON API（静的ファイルではない）**。識別子なしの GET は `{"msg":"api参数错误.","is_success":100101}`（中国語の「パラメータ誤り」）。どのパスも catch-all で小さな JSON。HTTP・HTTPS とも 200 | 本体は無い |
| ARM ダンプ・GPL ソース・第三者保管庫 | GitHub・検索で**見つからず** | — | — | — | — | — |

- 配布の仕組み（公式サポートページ）：**SD カードの手動更新**（「カードを FAT32 で初期化 → `update.tgz` と `update.tgz.pba` を落としてカードにコピー → 挿してカメラ起動」）。OTA の getNewVersion は版の照合で、本体の配布 URL はファーム内蔵のためカメラの通信には出ていない（verify §2 と同じ）。
- 素性：両ファイルとも **gzip 圧縮の平文**（暗号化ではない）。10 MB と小さい。中身の抽出・grep（`luuka.fun`・`http://`・`AKIA`・`public-read` が今も入っているか）で「ファームで直ったか」が直接わかる。**本体の丸ごと取得・展開・解析は親の判断**（BRIEF の決まりに従い、ここでは先頭 64 KB だけ保存：`V/dl-simcam/firmware-head/`）。

## 5. パッチ・更新の履歴

- **1S／Alloy 1S のファーム**：公式に出ている版は **V20200720 のみ**（2020-07-20 ビルド）。2026-11-27 の今も、サポートページの配布はこの 1 版だけ（ファイルは 2021-12-09 に再掲されたが**版名は据え置き**）。収録（2021-11）でカメラが報告した版も `1.20200720.tgz` で、**同じ版**。→ 2020-07 以降、公開された 1S ファームの版は上がっていない。版ごとのリリースノートは見つからない。
- **アプリ**：SimHome は Play 最新 1.4.4（2025-12-18）まで続く。ただし Simshine 公式サイトが配るのは V1.2.8（中身 1.3.0、2022）のまま。SimCam AI（旧）は 3.3.3（2020）で止まり、SimHome に統合。版ごとの変更内容は公開なし。

## 6. その後直ったか

| 区分 | 証拠 | 日付・版・出どころ | 何が書いて／見えているか |
|---|---|---|---|
| まだ問題（公式文書） | 今の 1S FAQ に食い違いの文が残る | 2026-11-27 に live を取得（`https://simshine.ai/simcam-1s/faq.html`、200） | 「…never have access to your data」「local AI processing」「P2P」が今もそのまま。主張は撤回されていない |
| まだ問題（ファーム） | 公開版が収録時と同じ V20200720 | 2026-11-27、simshine.ai | カメラの平文 S3 アップロードはファーム内の挙動。版が上がっていない以上、挙動は変わっていない可能性が高い（**推測**。確定には update.tgz を展開して grep が要る＝親の判断） |
| まだ問題（アプリ設計） | アプリも public-read＋平文を許可 | SimHome V1.2.8（中身 1.3.0）、2022 | S3 PUT に `PublicRead` を自分で付ける。`cleartextTrafficPermitted="true"`。luuka.fun の一部サービスは平文 HTTP |
| 直ったという証拠 | — | — | **見つからない**。カメラの平文 S3 アップロード／平文 luuka.fun を直したという記載・観測はなし |
| どちらとも言えない | 最新アプリ 1.4.4 とファーム本体の中身 | — | 1.4.4 の APK は Cloudflare で未取得。update.tgz の本体は未展開。この 2 つで「直った」証拠が出る可能性は残る |
| 参考（アプリ側は TLS） | アプリの主 API は HTTPS | SimHome V1.2.8 | `https://www.luuka.fun/`。カメラは同じ luuka.fun を平文 HTTP で叩く。**アプリ側は TLS だがカメラ側は平文**という非対称。これはカメラ（ファーム）の問題がアプリ更新では直らないことを示す |

**今の公式文書の該当文（2026-11-27 に live を読んだ）**：1S FAQ は「No. Because the Simshine ® Simcam 1S uses entirely local AI processing, we never have access to your data.」「The live videos are streamed … on a secured P2P … without going through a server.」をそのまま掲載。→ **主張は不変**。

## 7. まとめ（3 行）

1. **入手できた**：収録版に近い公式 APK（SimHome V1.2.8＝中身 1.3.0、140 MB）と、1S/Alloy 1S のファーム本体（update.tgz 10 MB＋.pba 58 MB、gzip の平文圧縮、版は収録時と同じ V20200720）を公開元から確認・取得（APK は丸ごと、ファームは先頭だけ）。
2. **直ったとみられるか**：直った証拠は無い。FAQ の文は今日も不変、公開ファームの版は 2020-07 のまま、アプリも public-read＋平文許可の設計。カメラの平文 S3 アップロードは続いているとみられる（**推測**。確定は update.tgz の展開か実機収録）。
3. **論文に使えるか**：**使える、しかも強くなった**。APK が、残っていた条件「バケット＝Simshine か」をほぼ埋めた（公式アプリをそのバケットから配布、バケット名と鍵は Simshine バックエンドが発行、カメラと同じ luuka.fun／同じ IP、アプリも public-read）。「条件付きの矛盾」の条件（i）は満たされ、主張「we never have access」との食い違いが明確になる。

## 8. 未確認の一覧

- **最新 SimHome 1.4.4（2025-12-18）の APK**：Cloudflare（APKPure/APKMirror 403）・S3 403 で未取得。新旧でエンドポイント／平文が変わったかは未確認（→ 親がブラウザで取得）。
- **ファーム本体の中身**：update.tgz／.pba は gzip 平文圧縮で展開できるが、BRIEF の決まりで本体は未展開。`luuka.fun`・`http://`・`AKIA`・`public-read` が今のファームに残るかは未確認（→ 展開して grep は親の判断）。
- **バケットの公開設定が実際に効いているか**（public-read でオブジェクトが第三者に読めるか）：バケットへのアクセスはしていない（バケット一覧の取得は環境の制限で実施せず）。未確認。
- **アプリの暗号化画像（share_key）が人物検知イベント画像にも及ぶか**：及ばない見込み（PCAP の JPEG は平文で開けた。復号呼び出しは baby クリップ／お気に入り／Wonderful Moment だけ）だが、イベント一覧画像の表示経路は全数確認していない。
- **ファームの配布 URL（カメラが実際に取りに行く先）**：ファーム内蔵で収録に出ず未確認（公式サイトの手動 update.tgz とは別かもしれない）。
- CVE：`CVE-2025-63667`（"SIMICAM v1.16.41" のアクセス制御）は製品名が異なり、SimCam との関係・通信の件かは未確認。

## 追加解析：ファーム本体を展開して確認（2026-11-27、親セッション）

担当が見つけた公式配布の `update.tgz` を実際に落として展開した（暗号化なし、復号していない）。置き場所＝`~/datasets/claims/verify5-20261127/fwhist/simcam-fw/`。

- **入手**：`https://www.simshine.ai/images/simcam1s/update.tgz`、HTTP 200、10,323,824 バイト、SHA-256 `3aea090f44e029d16b4c2ff9ee25e480e555d2b52afcf9b9edbff97af3c1bac7`。**平文の gzip**（内部の日時 2020-07-20 07:30 UTC＝更新確認が返す `V20200720` と一致＝収録時と同じ版）。
- **構造**：`update.tgz`（tar.gz）→ `update/APP/app.tgz`（tar.gz）→ `app/`。本体は **ARM aarch64** の ELF 群（Ambarella CV25。収録の User-Agent「Linux aarch64」と一致）。主デーモンは `app/bin/simcam_debug`。ソースのパスから `libDVStream/curl_post.c`、`libMiioIot`（Xiaomi MIIO）、`libTUTKServer`（TUTK Kalay の P2P）、`libMp4Record` を使う。
- **確定したこと（ファームの平文の文字列。復号していない）**：
  - **luuka.fun の API はすべて `http://`（平文）で直書き**：`/bind/bind/getZeroTime`、`/bind/bind/getSettings`、`/bind/bind/deviceBind`、`/event/event/saveEvents`、`/ota/ota/getNewVersion`、`/ota/ota/saveOtaResult`、`/push/push/pushMessage`、`/faceservice/deviceface/queryDeviceInTheFaceInfo`、`/faceservice/deviceface/getFeature`。収録（CIC 2021）で平文で見た送り先と一致。予備の IP `http://39.98.135.211/...`（Aliyun 北京）も同じ API を平文で持つ。
  - **問題の S3 バケットがカメラのファームに埋め込まれている**：`elasticbeanstalk-us-east-2-793503604989.s3.us-east-2.amazonaws.com`、オブジェクトのキーの書式 `SimCam/%s/%s/%lu%s`（＝収録の `/SimCam/<機器ID>/PersonDetect/<時刻>` と一致）、`x-amz-acl`、`public-read`。→ **送り先のバケットは利用者の設定ではなく、カメラのファームに固定**。条件(i)（バケットの持ち主＝Simshine 側）が、APK（担当の調べ）に加えてファーム本体でも裏づけられた。
  - 会社の手がかり：`http://simtoo.oss-cn-shenzhen.aliyuncs.com`（Aliyun OSS、Simtoo/Simshine）、Aliyun OSS の C SDK（`liboss_c_sdk`）を同梱。
- **http か https か**：文字列表には S3 バケットの `https://…` の literal もある（ACL の名前空間 `http://acs.amazonaws.com/groups/...` は S3 の XML の標準で、送り先ではない）。実際のアップロードが平文 HTTP だったことは**収録（PCAP）で確定済み**で、ファームはバケット・キー・ACL と、luuka.fun が全部 http であることを裏づける。ファームが画像の PUT を http に固定しているかまでは、文字列だけでは断定しない（aarch64 の逆コンパイルはしていない）。
- **「直ったか」への意味**：公式が今も配る版が **V20200720（収録時と同じ）** で、その中で luuka.fun は全部平文、S3 のバケットとキーと public-read もそのまま。→ **ファームの作りは収録時から変わっていない＝直っていない**（公開配布版で確認）。

### 条件のまとめ（SimCam の判定の強まり）

- 条件(i)（送り先のバケット＝Simshine 側）：**成立**。APK（Simshine が同じバケットからアプリを配布、アプリがバケットの鍵を luuka.fun から受け取る）＋ファーム本体（バケット名・キー・public-read を直書き）。
- 残る条件：バケットが実際に公開状態か（`public-read` が効いているか）は、バケットにアクセスしていないので**未確認**。ただし「we never have access to your data / everything processed locally」の主張は、カメラのファーム自体が人物検知画像を Simshine のバケットへ上げる作りである以上、**条件(i)の成立で直接ぶつかる**。

## 検証：バケットの公開読み取りは実効か（2026-11-28、利用者の許可のもと）

食い違いの残る条件「`public-read` が実際に効いて画像が取れるか」を、**実在利用者の画像には触れずに**確かめた。実オブジェクトの取得（＝他人の防犯カメラの画像の取得）は privacy の線でしていない。確かめたのは匿名アクセスの設定だけ。

| 匿名の要求（2026-11-28） | 結果 | 意味 |
|---|---|---|
| 存在しないキー `SimCam/…does-not-exist…/PersonDetect/0`（https） | 403 `AccessDenied` | バケットは存在（`NoSuchBucket` ではない）。匿名の一覧権限なし |
| 同（http、カメラが使った平文の経路） | 403 `AccessDenied` | http の口も S3 の応答（403）を返す |
| バケットのルート（`GET /`、一覧） | 403 `AccessDenied` | 匿名の列挙は不可。他人の画像を一覧で探せない |

- **言えること**：バケットは今も存在し、**匿名の列挙（ListBucket）は許していない**。
- **言えないこと**：個々の `public-read` オブジェクトが匿名で取れるか。403 vs 404 が見るのは ListBucket の権限で、オブジェクト単位の公開読み取り（GetObject の public-read）ではない。Block Public Access がオン（指定が無視される）でも、個々の public-read だけ有効で一覧だけ不可でも、同じ 403 になる。区別には実オブジェクトの取得が要り、privacy の線でしていない。AWS は 2023 以降、新規バケットで Block Public Access を既定オンにしているので、今は指定が無視されている可能性もある（推測）。
- **残る判定**：条件(i)（バケット＝Simshine 側）は成立（ファーム・アプリ）。public-read の**指定**は確定（ファーム・アプリのコード）。public-read の**実効**は未検証（privacy）。「we never have access to your data」との食い違いは、送り先が会社のバケットである時点で成立し、画像の公開読み取りの実効の有無には依存しない。
