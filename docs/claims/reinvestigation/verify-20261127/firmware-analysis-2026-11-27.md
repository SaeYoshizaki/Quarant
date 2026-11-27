# Sonos PLAY:1 のファームウェアの深掘り解析（2026-11-27）

[まとめに戻る](fixes-sonos-canary.md) ・ [確かめ直し](README.md)

落とした 2 本の PLAY:1 のファーム（[fixes-sonos-canary.md](fixes-sonos-canary.md) の「落としたファームの中身」）を、中身を展開して読んだ。目的は 2 つ。

1. **元の食い違い（平文の HTTP で製造番号などを送る）が、今のファームの中にも仕組みとして残っているか**を、文字列だけでなくコードで確かめる。
2. 通信だけでは裏の取れなかった点（更新・時刻帯・使用データが http か https か）を、ファームの作りから決められるか。

- 使った道具：自作のコンテナ解析、`tar`、`unsquashfs`、`xz`、Ghidra 12.1.2（headless、PowerPC BE 32）。
- **暗号・署名は破っていない**（CLAUDE.md の恒久ルール）。暗号化された部分は開けていない。読んだのは、ファームの中にもともと平文で入っている部分だけ。
- 置き場所：ファーム本体とカタログは外付けディスクの `~/datasets/claims/verify5-20261127/fwhist/`。リポジトリには入れない。

## 1. ファームの形と、どこが暗号化されているか

`.upd` は独自のコンテナで、`49 7f 16 35` で始まる区画（section）が並ぶ。各区画＝16 バイトの見出し（マジック、種類、全体長、予備）＋本体。

**86.11-82170（今の版、2026-11-03、21,423,961 バイト）**：11 区画。

| # | 種類 | 大きさ | エントロピー | 中身 |
|---|---|---|---|---|
| 0 | 1 | 12 B | — | 版（`56 0b fa40 01`＝86.11-82170） |
| 1 | 21 | 128 B | — | パッチの名前（下） |
| 5 | 22 | 149 KB | 7.50 | カーネルとみられる（圧縮） |
| **6** | **23** | **14.3 MB** | **5.72** | **root FS（tar アーカイブ、平文）** |
| 8 | 6 | 1.5 MB | 8.00 | **暗号化**（宛先 `346ce6e3…`） |
| 9 | 4 | 5.5 MB | 8.00 | **暗号化**（宛先 `346ce6e3…`） |
| 10 | 17 | 380 B | 7.07 | 署名とみられる末尾 |

- **肝心の部分（root FS）は暗号化されていない**。区画 6 は普通の tar で、中身は 1 ファイル＝`bin/anacapad`（Sonos の本体のデーモン。ELF 32-bit **big-endian PowerPC**、14.3 MB、stripped）。更新・時刻・メトリクスの URL の処理は全部この中にあり、そのまま読める。
- 暗号化されているのは区画 8・9（高エントロピー、`88 64 99 ca` の見出しに宛先の指紋 `346ce6e38225ca8177024fbebfaad7043344b3bd`）。これは別の区画（たとえば別のファイルシステムや DSP など。中身は未確認）で、**今回の調べには要らない**。指紋は、第三者の保管庫（BookCatKid）が「鍵を回収済み」とする宛先と一致する。
- 先頭近くのパッチの名前：`2021_11_PATCHES`、`2022_02_PATCHES`、`UBI_RED_KEY_WITH_NONCE`、`2023_01_PATCHES`、`MAX_MDP_VERSION_6`、`2023_12_PATCHES`、`2024_12_PATCHES`。日付つきの印で、中身は書かれていない。

**34.16-37101（2018 年の版、8,306,684 バイト）**：区画 4・5 が高エントロピー（7.96、7.65）で、本体は暗号化／圧縮されている。root FS を平文で取り出せる区画はない。ただし **2018 年の挙動は収録（PCAP）で分かっているので、この版を開ける必要はない**。

## 2. 暗号化された部分を開けるか（公開の手法の調べ）

利用者の依頼で、暗号化を解く方法が公開されていないかを調べた（読んだだけ。試していない）。

- **blasty（bl4sty）の研究**：Sonos のファームを取得して復号する方法を公開していて、NCC Group がこれを使って Sonos One と Era 100 のファイルシステムを解析した（NCC Group の記事、Black Hat USA 2024「Listen Up: Sonos…」、[whitepaper](https://nccgroup.com/media/uzbp3ttw/bhus24_sonos_whitepaper.pdf)。本文は 403 で未読、要約による）。
- **Geissler（HITB 2023）**：機種によっては root FS が LUKS の暗号ボリュームで、鍵のファイルが平文で埋まっている、とする（[スライド](https://conference.hitb.org/hitbsecconf2023ams/materials/D2T1%20-%20Smart%20Speaker%20Shenanigans%20-%20Making%20the%20SONOS%20One%20Sing%20Its%20Secrets%20-%20Peter%20Geissler.pdf)、要約による）。
- **第三者の保管庫（BookCatKid/sonos-firmware-archive）**：宛先ごとの鍵の回収と復号の手順を公開している。今回見た区画 8・9 の宛先 `346ce6e3…` は、その「回収済み」の一覧にある。

**判断（利用者に相談）**：今の版は肝心の部分（anacapad）が平文で読めたので、**復号しなくても目的は果たせた**。残る暗号化の区画と 2018 年版の復号は、

- この研究の問い（公式の発表と通信の食い違い）には要らない（2018 年は収録がある）。
- この研究でこれまで守ってきた線（「暗号・署名は破らない」）を越える。

ので、**今回はやらない**のがよいと考える。やる意味が出るとすれば、暗号化された区画の中に、通信の方式を決める別のコードがあると分かったときだけ。やるかどうかは利用者が決める。

## 3. 元の食い違いが今のファームに残っているか（anacapad の中身）

anacapad の中の、平文で読める文字列とコードで確かめた。

### 3-1. 時刻帯の取得：http が直書き（確定）

- 文字列：`http://update-timezone.sonos.com/timezone/timezones.xml`（anacapad の中に 1 つ、`http://` の直書き）。
- これは設定値ではなく、ファームに固定の URL。**今の版でも、時刻帯の表は平文の HTTP で取りに行く作り**。2018 年（S6）と 2021 年のデータの観測と一致する。
- （Ghidra の逆コンパイルで、この文字列を使う関数を確認：下の 4）

### 3-2. 更新の確認・取得の URL：製造番号などを入れる書式が残る（確定）

- 書式の文字列：
  - `%supdate.upm?cmaj=%u&cmin=%u&cbld=%u&subm=%u&rev=%u&reg=%u&serial=%s`
  - `%s%s-%u-%u.upd?cmaj=%u&cmin=%u&cbld=%u&subm=%u&rev=%u&reg=%u&serial=%s`
  - `&sonosid=%s&householdid=%s`
- 先頭の `%s`（配布元のアドレス）は、設定か、サーバーが渡すマニフェスト（`UpdateURL`、`ManifestURL`）から来る。**scheme（http か https か）はこの `%s` の中**で、ファームには固定されていない（`%s://` という書式が別にある）。
- つまり、**更新の URL に製造番号・Sonos ID・household ID を入れる作りは今の版にも残っている**。http か https かは、機器が受け取る配布元のアドレス次第。第三者の記録では、機器が知らせる `UpdateURL`・`ManifestURL` も 2026-11 のマニフェストの `base_url` も `http://`（[fixes-thirdparty.md](fixes-thirdparty.md)）。このファーム自身も 2026-11-03 に平文の HTTP で取得されている。→ **今も平文で送っているとみられる**（推測。確定には実機の収録が要る）。
- ソースのパスの文字列：`../anacapa-1.0/oc/zone/zoneplayer/auto_update_scheduler.cxx`。

### 3-3. 使用データ（メトリクス）：送り先は設定値（http/https はファームからは不明）

- 文字列：`O_HRMETRICS_URL`、`/HRMetrics/`、`%s%s?hhid=%s`、`pollInterval.htm`、`submit.aspx`、`<UsageMetrics>`、`X-Sonos-Id-Hash: %s`。
- 送り先は設定キー `O_HRMETRICS_URL` から来るので、http か https かはファームの文字列からは決められない。2018 年のデータでは、古い版（33.15）だけ平文で、41.3 以降は TLS だった。今の版で平文に戻っている証拠はない。

### 3-4. scheme の扱い（全体）

- anacapad の URL の scheme は、ほとんどが `%s://` の変数（http/https を実行時に決める）。固定で `http://` と書いてあるのは、時刻帯のほか、LAN・ローカルの診断などの内部向けだけ。固定の `https://` は `sslauth.sonos.com`、`sonar.ws.sonos.com` など。
- **更新の配布元を `https://` で固定した文字列はない**。

## 4. Ghidra による逆コンパイル（対象の関数）

anacapad を Ghidra 12.1.2 の headless（PowerPC BE 32）で読み込み、上の文字列を使う関数を逆コンパイルした。各文字列の参照は 1 か所ずつで、関数が特定できた。

### 4-1. 更新 URL を作る関数（`FUN_106a69f8` @0x106a69f8）

3 つの更新 URL の文字列（`.upd` の書式、`update.upm` の書式、`&sonosid=…&householdid=…`）は、**すべてこの 1 つの関数**が使っていた。逆コンパイル（抜粋、整形）：

```c
void FUN_106a69f8(char *out, uint outsz, char *base /*param_3*/, char *subpath /*param_4*/,
                  int mdp /*param_5*/, uint *ver /*param_6*/, char *sonosid /*param_7*/,
                  char *householdid /*param_8*/, char append_au, char use_manifest) {
  char serial[36];
  sonosMdpSerialToString(mdp + 0x14, serial, 0x20);        // 製造番号を文字列に
  if (use_manifest == 0) {
    if (base_is_empty(subpath)) subpath = "default";
    __snprintf_chk(out, outsz, ...,
        "%s%s-%u-%u.upd?cmaj=%u&cmin=%u&cbld=%u&subm=%u&rev=%u&reg=%u&serial=%s",
        base, subpath, ver..., serial);                    // ← .upd の取得 URL
  } else {
    __snprintf_chk(out, outsz, ...,
        "%supdate.upm?cmaj=%u&cmin=%u&cbld=%u&subm=%u&rev=%u&reg=%u&serial=%s",
        base, ver..., serial);                             // ← update.upm（更新の確認）
  }
  __snprintf_chk(out+len, ..., "&sonosid=%s&householdid=%s", sonosid, householdid);
  if (append_au) snprintf(out+len, ..., "&au=1");
}
```

- **確定**：更新の確認（`update.upm`）と取得（`.upd`）の URL に、`sonosMdpSerialToString` で取った**製造番号**、**Sonos ID**、**household ID** を入れて組み立てる。2018 年（S1・S2）と 2021 年（C1）のデータで平文で観測した URL と、同じ要素・同じ順。この作りは今の版にも残っている。
- scheme とホスト（`base`、引数 `param_3`）は**この関数に渡される**。ファームの中で固定していない。呼び出し側が渡す `base` が http か https かで決まる。第三者の記録では、機器が受け取る配布元は http。
- `serial` は機器自身の MDP シリアル（`sonosMdpSerialToString`）。URL のクエリに平文で入る。

### 4-2. HTTP の見出しを作る関数（`FUN_104bad70`）

更新などの要求に付ける見出しを組み立てる。逆コンパイル（抜粋）：

```c
snprintf_append(..., "X-Sonos-SWGen: %u\r\nX-Sonos-Firmware: %s\r\nX-Sonos-Muse-Api: %s\r\n", ...);
if (FUN_104babec(idhash, 0x2d))   // 45 バイトの値を作れたら
    snprintf_append(..., "X-Sonos-Id-Hash: %s\r\n", idhash);
```

- 2021 年のデータで平文の HTTP の要求に付いていた `X-Sonos-Firmware`・`X-Sonos-Id-Hash` などの見出しは、この関数が作る。`X-Sonos-Id-Hash` は 45 バイトの値（何のハッシュかは未確認。[報告の C2 の条件](sonos.md)のまま）。

### 4-3. 使用データ（メトリクス）を作る関数（`FUN_106441e4`）

`/HRMetrics/` を使う関数。`R_CustomerID`（顧客 ID）を読んで、メトリクスの送信を組み立てる。送り先（`O_HRMETRICS_URL`）は設定値で、http か https かはコードからは決まらない（3-3 と同じ）。

### 4-4. 時刻帯の URL（`http://update-timezone.sonos.com/...`）

- 文字列は読み取り専用の区画（vaddr `0x10c157c0`）にある完全な literal。参照元 `0x1013d6dc` は関数の外（既定の設定の表とみられる）。
- **確定**：`http://` 込みの完全な URL がファームに固定で入っている。今の版でも、時刻帯の表は平文の HTTP で取りに行く作り。

## 4b. ほかの脆弱性を探したか（コマンドインジェクションなど、2026-11-27）

利用者の依頼で、暗号化の話とは別に、anacapad の中に脆弱性(コマンドインジェクションなど)らしきものがないかを**ざっと**見た。結論は「いちばん分かりやすい候補は、きちんと対策されていた」。本格的な監査ではない(下の限界）。

### 見たもの

- 危険な関数の import：`system`、`execve`、`sprintf`、`strcpy`、`sscanf` がある（大きな C/C++ では普通）。`system`・`execve` への直接の参照は Ghidra では 0（ラッパー経由とみられる）。
- コマンドらしい文字列：`/bin/ping -c 3`、`/usr/bin/traceroute`、`/bin/pcap - not (host %s and port %d)`、`/bin/upgrade_mgr`、`/bin/chronyc`、`/bin/dmesg` など。多くは固定の診断コマンド。
- `:1400` のデバッグ用 Web 画面に、**利用者が入れたホスト名で ping/traceroute/nslookup を実行する**フォームがある（`<form action="/ping"> … <input name="host" size="64">`）。これがコマンドインジェクションの古典的な候補。

### ping の処理を追った（`/ping` → `FUN_100c7294` → `FUN_100c709c`）

- POST の `host` を取り出し、コマンドを `"%s %s"`（＝`"/bin/ping -c 3 " + host`）の**1 本の文字列**に組み立てて実行関数へ渡す。文字列を組むので、本来はインジェクションの危険がある形。
- **しかし、実行前に 3 つの対策がある**：
  1. **ホストの検証**（`FUN_104d62cc(host, ".-")`）：host の各文字を調べ、**英数字でも `.` でも `-` でもない文字が 1 つでもあれば拒否**する（拒否されると host は保存されず、コマンドは実行されない）。スペース、`;`、`|`、`` ` ``、`$`、`&`、`(`、`)`、改行、`/` などの**シェルの特殊文字はすべて弾かれる**。→ 実行側がシェルかどうかに関わらず、注入する手段がない。
  2. **CSRF トークンの検証**（`FUN_104b7410`）：正しいトークンがないと実行しない。
  3. **ゲート**（`FUN_104be238` → `FUN_104c10a4`）：デバッグ機能が有効でなければ 403 を返す。
- traceroute・nslookup も同じ `host` の検証を通る。
- pcap（`/bin/pcap - not (host %s and port %d)`）の `%s` は、利用者の入力ではなく**接続相手の IP アドレス**（機器が整形した値）。これも注入には使えない。

### いま見た範囲の所見

- 見たコードは、文字列操作に境界つきの関数（`__snprintf_chk`、`strlcpy`）を使っていて、作りは丁寧。
- いちばん分かりやすいコマンド実行の経路（デバッグの ping など）は、**厳しい文字の許可リスト＋CSRF＋ゲート**で守られていて、**コマンドインジェクションは成立しない**。
- 参考（脆弱性ではない）：機器は dropbear の SSH サーバーを持ち、鍵が `/jffs/persist/ssh/…` にある。`:1400` には `/jobs?job=…` でジョブを起動する口もある（未解析）。これらが外から届くか・認証があるかは、静的解析だけでは分からない。

### 限界（大事）

- 見たのは平文の区画（anacapad 1 本）だけ。ファームの**暗号化された区画は開けていない**ので、そこにあるコードは見ていない。
- `sprintf`・`strcpy` の全呼び出しを追ってバッファあふれを探す、といった**本格的な監査はしていない**。「候補をいくつか見て、分かりやすいものは対策済みだった」という段階。
- **到達性は未確認**：フォームや口に、外から（または LAN から認証なしで）実際に届くかは、実機で確かめないと分からない。

### 論文に書けるか

- **コマンドインジェクションは見つかっていない**（候補は対策済み）。だから「ついでにお得に書ける脆弱性」にはならない。
- 仮に本物の脆弱性（リモートでコードが動くなど）を見つけた場合は、注意が要る：
  - 実機で**到達性と再現を確かめる**必要がある（能動的な検査。今の研究のパッシブの範囲の外）。
  - 実在の製品の未修正の脆弱性は、**論文に載せる前に製造者へ報告**するのが筋（Sonos は届け出の窓口と PGP 鍵を公開している）。公表の調整なしに論文へ出すのは避ける。
  - これは「公式の発表と通信の食い違い」という今回の研究とは**別の種類の貢献**で、別の手順と倫理が要る。

## 5. 「元の脆弱性」の状態（参考）

公式のセキュリティの勧告（[fixes-sonos-canary.md](fixes-sonos-canary.md)）の CVE（U-Boot、Wi-Fi ドライバ、AirPlay、SMB、UPnP のトークン漏れ）は、今回の食い違い（平文の送信）とは別の話で、どれも今の版より前の版で直ったとされている。今回のファーム解析では、これらは追っていない（本研究の対象は、公式の発表と通信の食い違い）。

## 6. まとめ

- 今の版の root FS（anacapad）は暗号化されておらず、読めた。暗号化は別の区画だけ。
- **時刻帯の取得は、今の版でも http が直書き**（確定）。
- **更新の URL に製造番号・Sonos ID・household ID を入れる作りは、今の版にも残る**（確定）。scheme は配布元のアドレス次第で、ファームは https を強制していない。第三者の記録と合わせると、今も平文で送っているとみられる（推測）。
- 使用データの http/https は、ファームからは決められない（設定値）。
- 暗号化された部分と 2018 年版の復号は、公開の手法はあるが、今回の目的には要らず、この研究の線を越えるので、やらない（利用者の判断）。
- **確定の一歩**：今の PLAY:1 の実機の通信を 1 回取れば、更新と時刻帯が今も平文かを、推測でなく観測で言える（パッシブの範囲）。
