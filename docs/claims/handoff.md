# 引き継ぎ：製造者の暗号化の主張と通信の食い違い（YourThings 2018）

2026-11-02。次の会話はここから始める。全体の結果は [results-yourthings.md](results-yourthings.md)、人が確かめる 23 件は [review-yourthings.md](review-yourthings.md)、決めたことは [../DECISIONS.md](../DECISIONS.md) の D31〜D38。

## 1. ここまでの状態

- YourThings の 44 製品、公開されている 13 日分（2018-03-20、21、28、04-10〜19）すべてで、製造者の公開文書の主張（687 件）と通信を突き合わせた。暗号化の主張は 153 件。
- 判定はすべて 1 人（Claude）によるもの。人の確認は項目 1（Ring）の途中。
- 作成者の検査（ポートスキャン、偽の証明書による中間者の検査）は集計から外している（D35、D38）。

## 2. 指摘できうる候補（強い順）

「食い違いの候補」は、主張と食い違う観測があるという意味で、主張が誤りという意味ではない。

| # | 製品 | 主張（出典） | 観測（13 日分） | 強さと注意 |
|---|---|---|---|---|
| 1 | Ring Video Doorbell（初代とみられる） | 仕様の欄の「Encryption: Bank-grade」（製品ページ 2017-04、How it works 2016-04）。Ring の 2016〜2018 年の公開文書で、機器の通信の暗号化に触れたのはこれだけ | 下の 3 節。平文の HTTP に固定の認証情報、平文の SIP、暗号化されていない RTP の映像 | 強い。ただし先行の実機調査が多い（4 節）。新規性は「公開データでの再現・定量化」と「主張との照合」 |
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

主張がない（または判定できない）が目立つ観測：VeraLite がログを平文の FTP で送る（470 回）、偽の証明書を受け入れた疑い（August、VeraLite、WeMo Crock-Pot、Harmony Hub、Harman、Samsung TV）、SmartThings のサーバー証明書が RSA 1,024 ビット、WeMo は TLS 1.0 のみで前方秘匿性なし。

## 3. Ring の再確認（2026-11-02、パケット単位）

元の PCAP（`/Volumes/QuarantData/yt-extract/20180320/2018/03/20/`、03-21 は `usb-yourthings/iot_traffic20180321.tgz`）で確かめた。

- **機種**：要求の `X-RingDeviceType: doorbell`（03-20、1,163 回すべて）。Ring の API を扱う公開のライブラリでは、後継機は doorbell_v4 などを名乗る。MAC の先頭 00:1d:c9 は GainSpan（初代の Wi-Fi モジュール）。YourThings の評価の型番は N/A。**ファームウェアの版は通信に出ていない（未確認）**。
- **平文の HTTP**：`eth1-20180320.1200.1521565200` の TCP ストリーム 21。フレーム 2450 `GET /doorbots_api/vod/ready HTTP/1.1`、2452 `Host: vod.ring.com`、2454 `Authorization: Basic …`、2456 `Content-Length: 0`、2458 `X-RingDeviceType: doorbell`、2460 空行。応答 2478 `HTTP/1.1 404 Not Found`（nginx）。復号した表示ではなく、元の TCP の中身。要求は行ごとに別のセグメントで送られる。**どのパケットも 2 回ずつ入っている**（同じシーケンス番号。キャプチャの重複）。
- **キャプチャの位置**：YourThings のゲートウェイの eth1（ドアベルの送信元 MAC が見える LAN 側）。この位置では平文。**ゲートウェイより外で VPN などがあったかは分からない（未確認）**。
- **認証情報の構造**（値は記録していない）：Base64 を戻すと「ユーザー名:パスワード」。ユーザー名は 12 桁の 16 進で、機器の MAC と一致。パスワードは 32 桁の 16 進のあとに NUL が 1 バイト。**03-20 と 03-21 の全要求（約 16,700 回）で同じ値**（要求ごと・日ごとに変わらない）。機器固有の値とみられるが、何から作られたかは不明（MD5 かどうかも不明）。利用者のアカウント情報ではない（ユーザー名がメールアドレスではなく MAC）。
- **件数**：要求の行を（宛先、送信元ポート、TCP の絶対シーケンス番号）で数え、重複を除くと 03-20 が 8,364 件、03-21 が 8,363 件。Zeek は 8,372 件と 8,364 件（差 8 件と 1 件）。tshark の `http.request` だけで数えると、分割された要求を組み立てられず少なく出る（6,972 件など）ので使わない。コマンドは `~/datasets/claims/jobs/ring_http.sh`、`ring_auth_summary.py`。
- **/vod/ready の 404**：約 10 秒ごとのポーリングで、応答はほぼ 404（03-20：404 が 8,083 件、408 が 3 件）。先行の実機調査（Kidder 2017）は「映像の開始要求がない」意味と説明している。**こちらでは、映像のセッションの直前に 404 以外の応答があるかを確かめていない（未確認）**。
- **fw.ring.com の POST はファームウェアではない**：`POST /doorbots_api/vod?api_version=4`、本文 `protocol=sip`（12 バイト）。応答は 200、本文は Base64 で 1,040 バイト、偏りなし（7.83 ビット／バイト）。映像のセッションの情報をアプリの層で暗号化（または圧縮）して返しているとみられる。前の記録で「ファームウェア」としたのは誤りで、claims.tsv を直した。Quarant の Ring への `I4_INSECURE_FIRMWARE_UPDATE_HTTP`（2 回）も、ホスト名による誤検出の可能性が高い。
- **映像と音声**：03-21 17:50（キャプチャの時刻）のセッション（`eth1-20180321.1750.1521672600`）。
  - SIP は udp/15063 の平文（INVITE はフレーム 133 から、100、183、200、ACK、BYE）。SDP は音声 `m=audio … RTP/AVP 0`（PCMU）、映像 `m=video … RTP/AVP 97`（H.264）。`RTP/SAVP`、`a=crypto`、`a=fingerprint`、`a=key-mgmt` はない。
  - 映像の RTP（udp/51504 → 52.206.247.65:39700、12 秒で重複を除いて 1,085 パケット）は版 2、種類 97。中身の先頭の 1 バイトは H.264 の構造どおり（FU-A 1,060、SPS 12、PPS 12）。SPS は Baseline、レベル 4.0（フレーム 143 など）。**暗号化されていない H.264**。映像そのものは戻していない。
  - ドアベルからの音声の RTP は、このセッションでは見えなかった。
  - 調べたのは 03-21 の 1 セッションだけ。13 日分のほかの 4 回の POST の後も同じかは未確認。
- **時計**：サーバーの Date ヘッダー（11:43:00 GMT）とパケットの時刻（12:00:08 UTC）が約 17 分ずれる。どちらが正しいかは未確認。

## 4. 未完了の作業

1. **先行研究との比較（Ring）**：利用者が挙げた 4 本（Nick「Ring Doorbell Security」2016-07-24、Scott Kidder「The Ring Smart Doorbell API」2017-07-04、Alharbi & Aspinall 2018、Paracha ほか IoTLS、IMC 2021）を**まだ読んでいない**。読んで、機種・時期・ファームウェア・通信先・認証方式・暗号化の対象・今回との差分を表にし、「既知の挙動の再確認／既知の問題への追加証拠／未報告の可能性／証拠不足」に分ける。暫定の見立ては「平文 HTTP と Basic 認証は既知に近い。平文の SIP と暗号化されていない RTP の映像、主張との照合が追加の価値になりうる」。
2. **ほかの 11 製品の文書の探し直し**：Ring と同じ深さで（全ドメインの PDF、サポート記事の題名、ブログ）。
3. **人の確認**：[review-yourthings.md](review-yourthings.md) の 23 件。
4. ほかのデータセット（UNSW、CIC、Deakin）への展開。

## 5. データと道具の場所

- 外付けディスク QuarantData（`~/datasets` はここへのリンク）。13 日分の元データは `usb-yourthings/`（tgz）、03-20 と 04-10 は `yt-extract/` に展開済み。
- 集計の出力：`~/datasets/claims/`（`flows-yt/`、`gt-yt/`、`obs-yourthings.json`、`flows-yourthings.json`、`mitm-yourthings.tsv`、`versions-yt/`、`entropy-yt/`、保存した文書 `snapshots/`）。
- リポジトリの外の道具：`~/datasets/claims/jobs/`（`wb.py`：Wayback の取得、間隔を空ける。`ocr.sh`、`tplink_keys.py`、`ring_http.sh`、`ring_auth_summary.py`、`launch.py`：Claude Code を閉じても止まらない起動）。
- Ring だけを取り出した PCAP（一時）：`~/yt-tmp/ring/0320/`、`0321/`（各 35MB）。
- Mac は 16GB。ほかのアプリでスワップが増えると Quarant が止まる。長い処理は `launch.py` で切り離し、スクリプトの中でログを開く。
