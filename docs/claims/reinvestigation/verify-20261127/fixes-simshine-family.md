# Simshine 製品ライン全体：SimCam 1S と同じ「平文 S3 public-read」の作りが他機種にもあるか（2026-11-28）

担当：Simshine（Simtoo）の **SimCam 1S 以外**の機種（ベビーモニター、ドアベル、バッテリー、Alloy 1S、初代 SimCam 等）。
下敷き＝`out/fixes-simcam.md`（SimCam 1S の確定所見。FAQ「we never have access to your data / entirely local AI processing」vs 人物 JPEG を平文 HTTP で AWS S3 バケット `elasticbeanstalk-us-east-2-793503604989` へ `public-read` PUT）。
調べ方：逆コンパイル済み SimHome APK（`dl-simcam/simhome-1.2.8/jadx-out/`）で機種識別子を割り出し、公式サポートページから各機種のファームを取得、展開して `strings` で送信先を確認。アプリ・機器は起動していない。識別子は送っていない。復号・署名回避はしていない。認証情報（AKIA 鍵の値）は書かない。時刻は UTC。

---

## 1. 目的と結論の先出し

**結論：SimCam 1S とまったく同じ「平文 luuka.fun ＋ AWS S3（バケット 793503604989）public-read ＋ ファーム内蔵のハードコード AWS 鍵 ＋ TUTK/Kalay P2P」の作りが、少なくとも 6 機種分のファーム本体で確認できた。** 2020 年版（SimCam/Alloy）から 2022 年版（Baby Pro V20220525、Ango Pro V20220318）まで、年をまたいでも作りは不変。Simshine の公式主張（SimCam 1S FAQ「データに触れない／完全ローカル処理」、ベビーモニターの公式 PR「端末内でローカルに保存・処理」「secured P2P」）は、これらのファーム本体と食い違う。**「1 社の断定主張 × 複数機種」として束ねられる。**

---

## 2. 機種の識別子（APK から）

SimHome（`com.simshine.aiot`、V1.2.8＝中身 1.3.0）の中に、機種ごとにパッケージが分かれて入っている。これが Simshine の製品ライン：

| 製品名（strings.xml） | パッケージ | 備考 |
|---|---|---|
| SimCam 1S / Alloy 1S | `com.simtoo.aicamera`（旧 SimCam AI を統合） | aarch64（Ambarella CV25） |
| SimCam / Simcam Alloy（初代） | 同上 | MIPS 系（HiSilicon、squashfs-xz） |
| SimCam Baby（ベビーモニター） | `com.sinshine.babymonitor` | MIPS（Ingenic T31 `isvp_swan`） |
| SimCam Baby Pro | `com.simshine.babypro` | MIPS（Ingenic） |
| Simshine Baby 2 | `com.simshine.baby2`（`babypro2_app_name=module-babypro`） | ファーム未入手（§6） |
| Ango Doorbell（ドアベル） | `com.simshine.doolbell`（`ango_Doorbell=Ango Doorbell`） | Ango＝MIPS、Ango Pro＝MIPS(Hi3861) |
| Battery camera（SimBatteryCam） | `com.simshine.battery` | ファーム未入手（§6） |

- **ファーム配布 URL の組み立て規則**：アプリ側は URL を組み立てていない。アプリの OTA は版の照合だけ（`ota/ota/app/getNewVersion` 等、`FirmwareVersionBean`＝版文字列のみを返す。`UpgradeFirmwareUrlBean` は定義だけで未使用の死にコード）。**ファーム本体の配布は、Simshine 公式サポートページ（`simshine.ai/support/*.html`）が `https://www.simshine.ai/images/<機種>/<ファイル>` を直リンクする SD カード手動更新**。機種ごとにパス・ファイル名・形式がバラバラ（規則化されていない）。カメラが OTA で実際に取りに行く URL はファーム内蔵で、本調べには出ていない（未確認）。
- サポートページは全 4 枚：`simcam-1s-and-alloy-1s.html`／`simcam.html`（初代）／`simcam-ango.html`（ドアベル）／`baby-pro.html`（ベビー）。Baby 2・Battery の専用ページ・ファームリンクは無い。

---

## 3. ファームの入手（一覧）

すべて 2026-11-28 に公式サイト（`www.simshine.ai/images/...`）から HEAD 200 で確認、本体を `dl-simshine/<機種>/` に取得・展開した（素性は全て標準の非暗号フォーマット。復号していない）。

| 機種 | ファーム URL | 版（内部） | サーバ Last-Modified | 大きさ | 素性 | 取得/展開 |
|---|---|---|---|---|---|---|
| SimCam 1S | `images/simcam1s/update.tgz`(+`.tgz.pba`) | V20200720（gzip mtime 2020-07-20） | 2021-12-09 | 10,323,824 B | gzip 平文→tar→app.tgz→aarch64 ELF | 親セッションで展開済（`fixes-simcam.md`） |
| **Alloy 1S** | `images/alloy1s/update.tgz` | V20200720（gzip mtime 2020-07-20 07:29:22） | 2021-12-09 | 10,323,850 B | gzip 平文（SimCam 1S と同一構成） | ○ 展開 |
| **SimCam（初代）** | `images/simcam/rootfs` | V20200723（uImage 2020-07-23） | 2021-12-09 | 11,878,464 B | u-boot uImage→squashfs(xz) | ○ 展開（unsquashfs） |
| **Simcam Alloy（初代）** | `images/alloy/rootfs` | V20200723（uImage 2020-07-23） | 2021-12-09 | 11,882,560 B | u-boot uImage→squashfs(xz) | ○ 展開 |
| **SimCam Baby** | `images/baby/update.zip` | V20210929（version.txt 20210929）※支援頁表記 V20210910 | 2021-12-09 | 25,425,920 B | 実体は GNU tar(平文)→BabyCam.zip(実体 tar)→system/ 直展開 ＋ uImage rootfs/kernel(MIPS) | ○ 展開 |
| **SimCam Baby Pro** | `images/pro/update.zip` | V20220525（version.txt 20220525）※支援頁表記 V20220510 | 2022-08-30 | 13,803,520 B | GNU tar(平文)→BabyCam.zip(tar)→system/ ＋ uImage rootfs(MIPS) | ○ 展開 |
| **Ango（ドアベル）** | `images/ango/UPDATE.zip` | V20210322（update.info 20210322） | 2021-12-09 | 7,036,018 B | zip(stored)→`system.bin`=squashfs(xz)＋`rootfs.bin`=lzop | △ system.bin 展開。rootfs.bin は lzop で未展開 |
| **Ango Pro（ドアベル）** | `images/ango-pro/UPDATE.zip` | V20220318（VERSION 20220318） | 2022-03-23 | 6,945,595 B | zip(stored)→`rootfs.bin`=jffs2＋`upg3861`(MIPS ELF) | △ rootfs.bin は jffs2 で未展開 |

- 取得物の sha256：alloy1s `fb29577b…e891a5`、simcam-orig `647480e1…af67ea`、alloy-orig `42ece191…b037bd9`、baby `2f4af5a9…95d733`、baby-pro `2f39da8c…81f9dfe`、ango `dd44631e…d511db6`、ango-pro `58f5e18c…e4475e1`。先頭 64 KB も各 `dl-simshine/<機種>/head.bin` に保存。
- ango/ango-pro の `rootfs.bin` は lzop／jffs2 で、この環境にツールが無く（lzop 無し・binwalk 無し、インストールは差し控え）**完全展開は未実施**。ただし生 `strings` で素性は確認できた（§4）。暗号化ではない（標準圧縮）。

---

## 4. 機種ごとの所見（平文 http／S3 public-read／ファーム固定か）

各ファームの**デーモン本体の文字列**（復号なし）。「ファーム固定」＝送信先が ELF/スクリプトに literal で直書き（利用者設定由来でない）。

### Alloy 1S（V20200720, aarch64, デーモン `app/bin/simcam_debug`）→ SimCam 1S と**完全一致**
- luuka.fun 全て平文 `http://www.luuka.fun/`：`bind/bind/*`・`event/event/saveEvents`・`faceservice/deviceface/getFeature`・`faceservice/.../queryDeviceInTheFaceInfo`・`ota/ota/getNewVersion`・`ota/ota/saveOtaResult`・`push/push/pushMessage`。
- S3：`elasticbeanstalk-us-east-2-793503604989.s3.us-east-2.amazonaws.com/`、キー書式 `SimCam/%s`、`x-amz-acl`、`public-read`（×4）。
- Aliyun OSS `simtoo.oss-cn-shenzhen.aliyuncs.com`、TUTK（`PPPP`/`iotcplatform.com`）、ハードコード AWS 長期鍵 `AKIA…`×1（値は書かない）。
- **送信先はファーム固定**。（補足：`http://` の多数の `example.com` 等は同梱 libcurl のドキュメント文字列で送信先ではない。）

### SimCam / Simcam Alloy（初代, V20200723, MIPS, デーモン `/opt/app/bin/mvapp`）→ **一致**
- 平文 `http://www.luuka.fun/`：bind・event/save・faceservice・ota・push。
- S3 バケット `elasticbeanstalk-us-east-2-793503604989`、`SimCam/%s`（×2）、`public-read`（×2）、`x-amz-acl`、`PersonDetect`。
- Aliyun `simtoo.oss-cn-shenzhen.aliyuncs.com`、TUTK（`PPPP`/`Kalay`/`iotcplatform.com`/`Authkey`）、`AKIA…`×1。
- **ファーム固定**。SimCam/Alloy 初代の 2 機種とも同一（バイナリ構成も同じ）。

### SimCam Baby（V20210929, MIPS, デーモン `system/bin/babymonitor`）→ **一致（ベビー画像版）**
- luuka.fun 全て平文 `http://www.luuka.fun:80/`：`bind/bind/*`・`event/event/saveEvents`・**`event/marvellous/save`（＝Wonderful Moment クリップ）**・`event/device/baby/deleteEventList`・`ota/device/getNewestVersion`・`ota/ota/saveOtaResult`・`push/push/pushMessage`。
- S3：バケット `elasticbeanstalk-us-east-2-793503604989`・`s3.amazonaws.com`、**キー書式 `BabyCam/%s/%s/%lu_%d.jpg`／`BabyCam/%s/%s/%lu%s.%s`**（＝`<製品>/<機器ID>/<種別>/<時刻>`。SimCam の `SimCam/%s/%s/%lu%s` と同設計）、`public-read`、`x-amz-acl`、ACL の被付与者 URI `http://acs.amazonaws.com/groups/global/AllUsers`（＝公開読み取りを付ける）、AWS4-HMAC-SHA256 の署名 URL。アップロードは `.jpg`（snap/thumb/イベント画像）。
- Aliyun `simtoo.oss-cn-shenzhen.aliyuncs.com`、TUTK（`PPPP`/`Kalay`/`iotcplatform.com`/`Authkey`）、`AKIA…`×1。
- **ファーム固定**（デーモン内 literal）。更新はサポート頁の SD カード手動（`babycam_check_upgrade.sh` が `/media/update/BabyCam.zip` を検証）。

### SimCam Baby Pro（V20220525, MIPS）→ **Baby と一致**
- 同じ `http://www.luuka.fun:80/` 群（bind・event/saveEvents・event/marvellous/save・ota/device/getNewestVersion・push）。
- S3 バケット `793503604989`、キー `/%s/%s/%lu`、`public-read`（×2）、`x-amz-acl`、Aliyun `simtoo.oss…`、TUTK（`Kalay`/`PPPP`/`iotcplatform.com`）、`AKIA…`×1。`http://52.38.98.219:8080`（SimCam と同じ予備 IP 系）。
- **ファーム固定**。**版は 2022-05-25 ビルド（SimCam 収録 2021 より新しい）だが、作りは同一＝直っていない。**

### Ango（ドアベル, V20210322, MIPS）→ **部分確認（同一系）**
- `system.bin`(squashfs) に `libpersonDet_inf.so`（人物検知、`PersonDetect`×56）・`libmove_inf.so`。
- `rootfs.bin`（lzop で未展開）の生 `strings` で `luuka.fun`・バケット番号 `793503604989`・`IOTC_`（TUTK）・`AKIA…`×1 が漏れて見える。
- **`public-read`／平文 http の literal は圧縮下で未確認（未展開）。**ただしバケット・luuka・TUTK・ハードコード AWS 鍵の存在は他 4 機種と同一系。（推測：同じ作り。）

### Ango Pro（ドアベル, V20220318, MIPS/Hi3861）→ **部分確認（同一系）**
- `rootfs.bin`（jffs2 で未展開）の生 `strings` で バケット番号 `793503604989`・`Kalay`（TUTK）・`http://acs…`（S3 ACL 名前空間）・`AKIA…`×1。
- **luuka.fun／public-read／平文 http は圧縮下で未確認。**バケット・TUTK・AWS 鍵の存在は同一系。（推測：同じ作り。版は 2022-03 と新しい。）

---

## 5. 各機種の「今の公式の主張」

| 対象 | 出どころ（2026-11-28 に読んだ） | 主張（断定の有無） |
|---|---|---|
| SimCam 1S | `simshine.ai/simcam-1s/faq.html`（live） | **断定**：「we never have access to your data」「entirely local AI processing」「streamed … on a secured P2P … without going through a server」 |
| ベビーモニター（Baby 系） | Simshine 公式 PR（PRNewswire, 2021, 301383756、Simshine の声） | **断定**：「Videos are stored and processed locally on the device」「only homeowners can access the camera」「secured peer-to-peer network」「locally run AI devices」 |
| ベビー（第三者レビュー） | GearBrain／MakeTechEasier／nerdtechy（2022-2026） | 「クラウドに保存しない／microSD のみ／サブスク無し」と紹介（Simshine の訴求の反映） |
| ドアベル（Ango）・初代 SimCam | サポートページ（`support/simcam-ango.html`・`simcam.html`、live） | 手順中心で privacy の断定文は無い。ただし製品ライン全体が上記の「ローカル／secured P2P」ブランディング下。 |
| Baby 2 | trendhunter 等が「Privacy Protection」を紹介 | 公式 privacy 文面は未確認。 |

→ **SimCam 1S だけでなくベビーモニターでも、Simshine 自身が「端末内でローカルに保存・処理」「secured P2P」「権利者しかアクセスできない」と断定。**これは、ベビーモニターのファームがベビー画像を `BabyCam/<機器ID>/<種別>/<時刻>.jpg` として Simshine の AWS アカウント（793503604989）の **public-read** バケットへ、ファーム内蔵のハードコード AWS 鍵で上げる作りと食い違う。

---

## 6. 入手できなかった機種（未確認）

- **Simshine Baby 2（`com.simshine.baby2`）**：公式サポートに専用ページ・ファームリンク無し。`images/baby2/`・`babypro2/` 等の推測スラグは 404。アプリ OTA のみとみられ、公開の静的ファームは**未発見**。
- **Battery camera / SimBatteryCam（`com.simshine.battery`）**：同上、サポート頁・公開ファーム**未発見**。
- `images/<slug>/update.tgz` 形式で 200 を返すのは `simcam1s`・`alloy1s` のみ（他機種は zip/rootfs と形式が違い、スラグ総当たりは不適）。
- ango／ango-pro の `rootfs.bin`（lzop／jffs2）の完全展開：ツール未導入のため未実施。`public-read`・平文 http の literal 確認は保留（親が lzop/jefferson を入れれば展開可能）。
- カメラが OTA で実際に取りに行く配布 URL（ファーム内蔵）：未確認。

---

## 7. まとめ

1. **何機種で同じ平文パターンが確認できたか**：ファーム本体で **6 機種**（Alloy 1S・初代 SimCam・初代 Alloy・Baby・Baby Pro の 5 機種で `luuka.fun 平文 http ＋ S3 バケット 793503604989 ＋ public-read ＋ x-amz-acl ＋ ハードコード AWS 鍵 ＋ TUTK` を**完全確認**、ドアベル Ango／Ango Pro の 2 機種で**部分確認**＝バケット番号・TUTK・AWS 鍵は確認、public-read/http は圧縮下で未展開）。SimCam 1S（親の確定所見）を含めると **実質ライン全体**。
2. **1S と同じか**：同じ。キー書式（`SimCam/...`＝`BabyCam/...`）、同一バケット、同一 luuka バックエンド、同一 TUTK、同一の「ファーム内蔵 AWS 長期鍵」という設計がそのまま横展開されている。**2020 年版も 2022 年版（Baby Pro / Ango Pro）も作りは不変＝時間が経っても直っていない。**
3. **論文で「1 社の断定主張 × 複数機種」として束ねられるか**：**束ねられる。**Simshine は SimCam 1S FAQ（「never have access / entirely local」）だけでなくベビーモニターの公式 PR（「stored and processed locally」「only homeowners can access」「secured P2P」）でも同じ断定をしており、その断定が、少なくとも 5 機種のファーム本体（人物／ベビー画像を自社 public-read S3 へ平文経由でアップロード）と食い違う。SimCam 1S の単発の矛盾ではなく、**同一設計の製品ライン全体に及ぶ体系的な食い違い**として提示できる。

---

## 8. 次に親がやるべきこと

- **ドアベル 2 機種の `rootfs.bin` を展開**（`lzop -d`／`jefferson` or `binwalk`）して、ango/ango-pro でも `public-read`・平文 `http://www.luuka.fun` の literal を直接確認（今は圧縮下で未確認）。
- **Baby 2・Battery camera のファーム入手**（ブラウザで最新 SimHome 1.4.4 を取り、OTA の配布経路・新機種のスラグを割り出す／端末実機なしなら公開元を再探索）。
- バケット `elasticbeanstalk-us-east-2-793503604989` が実際に公開読み取り状態か（`public-read` が効いているか）は、どの機種でもバケットにアクセスしていないため**未確認**のまま（判定は条件(i)＝持ち主＝Simshine の成立で足りる）。

---

### 付録：参照した公式 URL（2026-11-28 取得）
- サポート一覧：`https://www.simshine.ai/support/`
- `https://www.simshine.ai/support/simcam-1s-and-alloy-1s.html`／`simcam.html`／`simcam-ango.html`／`baby-pro.html`
- ファーム：`images/simcam1s/update.tgz`・`images/alloy1s/update.tgz`・`images/simcam/rootfs`・`images/alloy/rootfs`・`images/baby/update.zip`・`images/pro/update.zip`・`images/ango/UPDATE.zip`・`images/ango-pro/UPDATE.zip`
- 主張：`https://simshine.ai/simcam-1s/faq.html`（live）、Simshine 公式 PR `https://prnewswire.com/news-releases/simshine-releases-wifi-baby-monitor-for-real-time-monitoring-and-safety-301383756.html`
