# 引き継ぎ：製造者の暗号化の主張と通信の食い違い（YourThings 2018）

**2026-11-10 に方針を変えた（[../DECISIONS.md](../DECISIONS.md) の D41）。次の会話は [sweep-handoff.md](sweep-handoff.md) から始める（残りの作業と手順）。** 5 つのデータセットの自動の洗い出しの結果、先行研究での振り分け、パケットでの確認がある。道具は `scripts/claims/sweep/`、出力は `~/datasets/claims/sweep/<データセット>/`（記録ごとの JSONL。値は鍵付きのハッシュだけ。鍵は `~/datasets/claims/sweep/.key`）。以下は 2026-11-02 時点の YourThings の内容。

2026-11-02。次の会話はここから始める。全体の結果は [results-yourthings.md](results-yourthings.md)、人が確かめる 23 件は [review-yourthings.md](review-yourthings.md)、決めたことは [../DECISIONS.md](../DECISIONS.md) の D31〜D39。Ring の先行研究との比較と検証のやり直しは [ring-prior-work.md](ring-prior-work.md)（下の 2 節の 1 行目と 3 節はこの結果で直した）。

## 1. ここまでの状態

- YourThings の 44 製品、公開されている 13 日分（2018-03-20、21、28、04-10〜19）すべてで、製造者の公開文書の主張（687 件）と通信を突き合わせた。暗号化の主張は 153 件。
- 判定はすべて 1 人（Claude）によるもの。人の確認は項目 1（Ring）の途中。
- 作成者の検査（ポートスキャン、偽の証明書による中間者の検査）は集計から外している（D35、D38）。

## 2. 指摘できうる候補（強い順）

「食い違いの候補」は、主張と食い違う観測があるという意味で、主張が誤りという意味ではない。

| # | 製品 | 主張（出典） | 観測（13 日分） | 強さと注意 |
|---|---|---|---|---|
| 2 | Philips Hue Bridge | 「transfers data securely (using SSL)」（プライバシーポリシー 2017-08） | 平文の HTTP で中身があるもの 3,208 回、うち Authorization つき 1,905 回（Philips のホストへ） | 強い。直前に送るデータ（ブリッジの ID など）を挙げている |
| 3 | Sonos PLAY:1 | 「Any data we transmit over the internet is protected using encryption」ほか 2 文（2018-02） | `update.sonos.com` の URL に householdid・serial・sonosid。ファームウェアを平文の HTTP で 3 回取得（03-20 に 2 回、04-13 に 1 回）し、そのたびに版が上がった | 強い |
| 4 | TP-Link HS105・LB130 | 「measures, including encryption and SSL technology, designed to secure your personal information」（プライバシーポリシー 2018-01） | アプリからの LAN の制御（tcp/9999）が公開鍵の XOR だけ。プラグはアカウント名・緯度・経度、電球はアカウント名を返す | 中。LAN 内だけ。キー名だけ確認（値は未記録） |
| 5 | Apple HomePod | 「name, contacts, music you listen to, and searches is sent to Apple servers using encrypted protocols」 | 03-21 に `streamingaudio.itunes.apple.com` から平文の HTTP で音声を 3 回取得（accesskey というパラメータ） | 中。音声自体はファイル内で暗号化されている可能性。文は Apple TV／Siri の文脈で、HomePod への当てはめは推定 |
| 6 | Withings Home | 「Communication via SSL」「AES-256 …」（製品ページ 2018-04） | 平文の POST 4 回。TLS は 5,259 回中 5,248 回が AES-128 | 中。AES-256 は保存時の意味かもしれない |
| 7 | Wink Hub 2 | 「certificate pinning」（FAQ 2017-07） | 作成者の偽の証明書の接続 42 回中 21 回で、握手のあとにデータを送った | 中。アプリの話か機器の話か不明。データセットの能動的な検査に依存 |
| 8 | Logi Circle | 「AES 256 Bit Dual Layer Encryption to protect and store your audio and video」（FAQ 2018-03） | TLS は 19 回すべて AES-128 | 弱〜中。内側の暗号（Dual Layer）は見えない |
| 9 | iRobot Roomba | 「AES 256-bit encryption and TLS v1.2」（2018-11、キャプチャの 7 か月後） | iRobot 自身のサーバーとの TLS は 17 回すべて AES-128 | 弱。文書の時期 |
| 10 | Harman Kardon Invoke | 「encryption technologies」（曖昧） | Spotify の SDK へ平文の GET 15 回 | 弱。宛先が第三者 |
| 11 | Canary | 「AES 256-bit data encryption」 | 26,334 回中 4 回だけ AES-128 | 弱 |
| 12 | 文言の上で食い違い | Canary（HEAD のみ 158 回）、Piper（中身のない GET 5 回） | | 弱 |
| 13 | 確かめが要る一致 | Nest「2048-bit RSA private keys for key exchange」 | Nest Cam IQ 自身の鍵は ECDSA P-224 | 読み方次第 |

**除外（2026-11-07、一次ふるい）：Philips Hue Bridge、Harman Kardon Invoke、Canary、Logi Circle、iRobot Roomba、Piper nv**（[triage.md](triage.md)）。上の表の 2、6〜12 行目のうち、これらの製品の行は候補ではない。

**除外：Ring Video Doorbell**（2026-11-02、利用者の判断）。平文の通信は確かめられたが、「Encryption: Bank-grade」は対象が書かれておらず、2017-11-15 以降の販売ページの仕様の欄にもないので、食い違いを証明できなかった。観測の多くも既知の問題だった（[ring-prior-work.md](ring-prior-work.md)）。

主張がない（または判定できない）が目立つ観測：VeraLite がログを平文の FTP で送る（470 回）、偽の証明書を受け入れた疑い（August、VeraLite、WeMo Crock-Pot、Harmony Hub、Harman、Samsung TV）、SmartThings のサーバー証明書が RSA 1,024 ビット、WeMo は TLS 1.0 のみで前方秘匿性なし。

## 3. Ring の再確認（2026-11-02、パケット単位。除外した製品の記録）

元の PCAP（`/Volumes/QuarantData/yt-extract/20180320/2018/03/20/`、03-21 は `usb-yourthings/iot_traffic20180321.tgz`）で確かめた。

- **機種**：要求の `X-RingDeviceType: doorbell`（03-20、ヘッダーがそろう 8,356 回すべて）。Ring の API を扱う公開のライブラリでは、後継機は doorbell_v4 などを名乗る（API の `kind` の値で、このヘッダーとの対応は未確認）。MAC の先頭 00:1d:c9 は GainSpan。YourThings の評価の型番は Video Doorbell、版は N/A。本体は確かめていない（未確認）。
- **ファームウェアの版は SIP の User-Agent に出ている**：03-21 は `Device/dpdv2/1.10.70`、04-11 は `1.19.217`、04-13 は `1.10.70` のあと `1.19.217`。Ring の版の表（2017-10-22）は Ring Video Doorbell を 1.10.71 としている。
- **平文の HTTP**：`eth1-20180320.1200.1521565200` の TCP ストリーム 21。フレーム 2450 `GET /doorbots_api/vod/ready HTTP/1.1`、2452 `Host: vod.ring.com`、2454 `Authorization: Basic …`、2456 `Content-Length: 0`、2458 `X-RingDeviceType: doorbell`、2460 空行。応答 2478 `HTTP/1.1 404 Not Found`（nginx）。復号した表示ではなく、元の TCP の中身。要求は行ごとに別のセグメントで送られる。**どのパケットも 2 回ずつ入っている**（同じシーケンス番号。キャプチャの重複）。
- **キャプチャの位置**：YourThings のゲートウェイの eth1（ドアベルの送信元 MAC が見える LAN 側）。この位置では平文。**ゲートウェイより外で VPN などがあったかは分からない（未確認）**。
- **認証情報の構造**（値は記録していない）：Base64 を戻すと「ユーザー名:パスワード」。ユーザー名は 12 桁の 16 進で、機器の MAC と一致。パスワードは 32 桁の 16 進のあとに NUL が 1 バイト。**03-20、03-21、04-11 の全要求で同じ値で、04-13 は別の値**（同じ構造。04-13 の前に約 2 日通信がない）。何から作られたかは不明（MD5 かどうかも不明）。利用者のアカウント情報ではない（ユーザー名がメールアドレスではなく MAC）。
- **件数**：要求の行を（宛先、送信元ポート、TCP の絶対シーケンス番号）で数え、重複を除くと 03-20 が 8,364 件、03-21 が 8,363 件、04-11 が 1 件、04-13 が 12 件。Zeek は 03-20 が 8,372 件、03-21 が 8,364 件。tshark の `http.request` だけで数えると、分割された要求を組み立てられず少なく出る（6,972 件など）ので使わない。
- **平文のポーリングは版で消える**：`GET /doorbots_api/vod/ready` は 03-20、03-21 と 04-13 の更新前（1.10.70）にだけあり、04-10、04-11、04-13 の更新後、04-14〜19 にはない。代わりに tcp/9998 への接続が約 15 秒ごとに始まる（04-13 は 15:51:09 から）。接続の目的は TLS の中なので未確認。
- **/vod/ready の応答**：約 10 秒（中央値 10.15 秒）ごとで、応答はほぼ 404（03-20：404 が 8,083 件、408 が 3 件）。先行の実機調査（Kidder 2017）は「映像の開始要求がない」意味と説明している。**映像の前には 200 が返り、直後に POST が続く**（`eth1-20180321.1750` のフレーム 7456→7515、`eth1-20180413.1545` の 239450→239687）。
- **fw.ring.com の POST はセッションの要求で、ファームウェアではない**：`/doorbots_api/vod` が 2 回、`/doorbots_api/dings` が 3 回（`?api_version=4`、本文 `protocol=sip`）。応答は 200 で Base64。
- **ただし fw.ring.com からのファームウェアの取得も平文**：04-13 15:49:50 と 15:50:15 に `GET /doorbots_api/v2_firmwares/1550/download`（`component=flash`、`app`。`eth1-20180413.1545` のフレーム 359841、`eth1-20180413.1550` の 14465）。応答は `1550_flash.bin` と `1550_app.bin`。**Quarant の Ring への `I4_INSECURE_FIRMWARE_UPDATE_HTTP`（2 回）はこの 2 回と一致し、正しかった**（前の記録の「ホスト名による誤検出」は誤り）。署名の有無は未確認。
- **映像と音声**：全 5 セッションの SIP は udp/15063 の平文で、SDP は `RTP/AVP`、`a=crypto` などはない。ドアベルの udp/51506 からの音声は 5 回とも見えない。
  - **1.10.70**（03-21 17:50、04-13 15:41、15:48）：RTP の中身は H.264 の構造どおりで、**暗号化されていない**。例：`eth1-20180321.1750.1521672600` の INVITE はフレーム 7667、最初の RTP は 8209。映像そのものは戻していない。
  - **1.19.217**（04-11 20:04、04-13 15:55）：先頭バイトは一様でエントロピーは 8.000。**中身は不透明**（暗号化の可能性が高いが方式は不明）。INVITE に `X-Session-Hash` が増える。
  - サーバー→スマートフォン（192.168.0.159）は、どちらの版のときも H.264 の構造が見える。スマートフォンの SIP は tcp/15064 の TLS 1.2。
- **時計**：パケットの時計がずれている。03-20 は 8 台のサーバーの Date と NTP の応答に対して約 1,028 秒進み、04-11 は約 11 秒、04-13 は約 21 秒。

詳しい根拠（ファイル、フレーム、フィールド）は [ring-prior-work.md](ring-prior-work.md) の 3 節。

## 4. 未完了の作業

0. **深掘り 1〜4 は済み**（[sonos-check.md](sonos-check.md)、[deep-checks.md](deep-checks.md)）。強い候補は Sonos だけ。Withings Home、TP-Link、Wink Hub 2 の扱いは利用者の判断待ち。
   Sonos は論文に向けて整理した（[sonos-paper.md](sonos-paper.md)）。2021 年の CIC IoT 2022 の Sonos One でも、ファームウェアの取得の URL に同じ識別子が平文で出ていた。URL の形は Geissler（HITB 2023）が公開済み。
   ほかの製品の文書と先行研究はクラウドのセッションで調べる（[cloud-research-brief.md](cloud-research-brief.md)、結果は `research/`）。
1. **先行研究との比較（Ring）**：済み（[ring-prior-work.md](ring-prior-work.md)）。4 本を読み、表にした。暫定の見立ては誤りで、平文の HTTP・Basic・SIP・1.10.70 の RTP は既知。残りは同じ文書の 5 節（更新の転送の報告の追加の検索、UNSW 2018 と Deakin の Ring で版と挙動を確かめる）。利用者の判断で候補から除外した（判定の列は not assessable）。
2. **ほかの 11 製品の文書の探し直し**：Ring と同じ深さで（全ドメインの PDF、サポート記事の題名、ブログ）。
3. **人の確認**：[review-yourthings.md](review-yourthings.md) の 23 件。
4. ほかのデータセット（UNSW、CIC、Deakin）への展開。

## 5. データと道具の場所

- 外付けディスク QuarantData（`~/datasets` はここへのリンク）。13 日分の元データは `usb-yourthings/`（tgz）、03-20 と 04-10 は `yt-extract/` に展開済み。
- 集計の出力：`~/datasets/claims/`（`flows-yt/`、`gt-yt/`、`obs-yourthings.json`、`flows-yourthings.json`、`mitm-yourthings.tsv`、`versions-yt/`、`entropy-yt/`、保存した文書 `snapshots/`）。
- リポジトリの外の道具：`~/datasets/claims/jobs/`（`wb.py`：Wayback の取得、間隔を空ける。`ocr.sh`、`tplink_keys.py`、`ring_http.sh`、`ring_auth_summary.py`、`launch.py`：Claude Code を閉じても止まらない起動）。
- Ring だけを取り出した 13 日分の PCAP と集計：`~/datasets/claims/ring13/`（`<日>/` に PCAP と元のフレーム番号の `.frames`、`out/` に集計、`phone-<日>/` にスマートフォンとサーバーの通信）。スクリプトは `scripts/claims/ring/`。`out/cred-labels.json` は資格情報の SHA-256 なので外に出さない。
- Mac は 16GB。ほかのアプリでスワップが増えると Quarant が止まる。長い処理は `launch.py` で切り離し、スクリプトの中でログを開く。
