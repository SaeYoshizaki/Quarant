# Ring Video Doorbell：先行研究との比較と検証のやり直し

2026-11-02。[handoff.md](handoff.md) の 4 節の 1 の結果。候補の一覧は [results-yourthings.md](results-yourthings.md)、スクリプトは `scripts/claims/ring/`、Ring だけを取り出した PCAP と集計は `~/datasets/claims/ring13/`（リポジトリの外）。

## 1. 結論

- **handoff の見立ては修正が必要**。「平文の SIP と暗号化されていない RTP の映像が追加の価値」としていたが、平文の HTTP・Basic 認証は Nick 2016、平文の SIP は Kidder 2017、RTP の映像が暗号化されていないことは Alharbi & Aspinall 2018 がすでに報告している。
- **「暗号化されていない映像」はファームウェアの版による**。1.10.70 では H.264 の構造がそのまま見える。1.19.217 では RTP のヘッダーだけが平文で、中身は不透明になる。
- **収録の中で版が変わっていた**。04-13 に 1.10.70 の機器が平文の HTTP でファームウェアを取得し、以後 1.19.217 になった。同じ機器の更新前後を比べられる。
- **追加検証する価値があるのは主に 3 点**（5 節）。平文の HTTP でのファームウェアの取得、版の境目と更新前後の差、ドアベル→サーバーとサーバー→スマートフォンの非対称の実データ。どれも、資料が見つからなかっただけでは新規とは言えない。
- **製造者の説明との食い違いは「未確認」**。「Encryption: Bank-grade」は何を暗号化するか書いておらず、確認できる最後の版は 2017-04-20。収録に最も近い販売ページ（2017-12-24）の仕様の欄にはない（4 節）。

## 2. 比較表

根拠の記号：**[P]** は今回 PCAP で自分で確認した（3 節に file・frame・field）。**[H]** は handoff などの既存の解析からの引用で、今回確かめ直したものは [P] にした。文献の主張は著者の報告であり、今回の PCAP の事実としては扱わない。

| | Nick「Ring Doorbell Security」2016 | Scott Kidder「The Ring Smart Doorbell API」2017 | Alharbi & Aspinall, IET 2018 | Paracha ほか「IoTLS」IMC 2021 |
|---|---|---|---|---|
| **書誌と読んだ箇所** | geekyschmidt.com、Nick（サイトの表記は Nicholas Schmidt）、2016-07-24。[Wayback 2016-10-27](https://web.archive.org/web/20161027140455/http://geekyschmidt.com/2016/07/24/ring-doorbell-security) の本文全体。サポートの回答は画像で、取得できず未確認。直接の取得は TLS の検証に失敗（Cisco Umbrella の証明書）で、検証は切っていない | [kidder.io](https://kidder.io/2017/07/04/ring-doorbell-api/)、2017-07-04。本文全体（節：Polling、Initiating Session、SIP、Comparison to Earlier Protocol Versions、Suggestions） | R. Alharbi, D. Aspinall。[Edinburgh の査読版 PDF](https://www.pure.ed.ac.uk/ws/portalfiles/portal/66693053/An_IoT_Analysis_Framework_An_Investigation_of_IoT_Smart.pdf)（doi:10.1049/cp.2018.0047）、全文。Table 2 は PDF の p.5–7、Table 3 は p.8。元の修士論文（2017、[SDL](https://drepo.sdl.edu.sa/handle/20.500.14154/49660)）は 401 で読めず未確認 | M.T. Paracha, D.J. Dubois, N. Vallina-Rodriguez, D. Choffnes。doi:10.1145/3487552.3487830。[著者版 PDF](https://dspace.networks.imdea.org/handle/20.500.12761/1516) の Table 1（p.3）、§4.1（p.3–4）、Fig.2・Fig.3（p.7）、§5.1（p.8）、§5.2（p.8–9） |
| **1. 対象機器と調査時期** | 「Ring Doorbell」。型番・版の記載なし。MAC の先頭は 00:1d:c9（本文に記載）。2016-07 以前 | 2015-12 購入の初代。Device/dpdv2/1.8.90（SIP の User-Agent）。2016-11 と 2017-07 に取得 | 「Ring Doorbell」と 4 機種。型番・版・調査日の記載なし。修士論文は 2017、会議は 2018-03-28 | 「Ring Doorbell」。型番・版の記載なし。受動的な実験のみの機器（Table 1 の *）。2018-01〜2020-03 |
| **2. 観測・検証した内容** | 機器とファイアウォールの間の PCAP。port 80 の Basic、イベントの JSON（`sip_server_tls` は false、`sip_server_tls_port` は 15064）、SIP、G.711 と H.264（種類 97）の指定。Base64 を戻し、MAC と 32 桁の値と報告。API は試していない | ハブでの PCAP。vod.ring.com への平文のポーリング（17 秒）と 404／200、`POST /doorbots_api/vod?api_version=3`、dings、motions、平文の SIP と SDP、2016 年の平文の JSON と 2017 年の Base64 の比較。RTP の中身は調べていない | 能動的な検査を含む枠組み。Camera-Server は暗号化なしの RTP、Server-Phone は鍵の管理が悪い SRTP、Registration サーバーへの中間者は更新前のみ成立。方法の詳細は本文になし | 受動の TLS の統計だけ（Ring は中間者の検査の対象外）。Fig.2 は弱い暗号の提示、Fig.3 は前方秘匿性のある暗号での確立。§5.1 で Ring は 2018-04 に前方秘匿性を採用とする。平文の通信は対象外 |
| **3. 今回と一致する点** | [P] OUI 00:1d:c9。tcp/80 の Basic。認証情報の構造（MAC 12 桁＋16 進 32 桁＋NUL。Nick の掲載値も同じ構造で、値は記録していない）。SIP の From のユーザーが MAC。SDP の種類 | [P] パス、ヘッダー（`X-RingDeviceType: doorbell`）、404／200 の意味、200 の直後の POST、`protocol=sip`、Base64 の応答、SIP の User-Agent の文字列、udp/15063、SDP の 51504／51506、`RTP/AVP`、X-SSRC-A／V | [P] 1.10.70 のドアベル→サーバーの RTP は平文の H.264。更新が自動で起きること（04-13 の取得。ただし利用者の操作の有無は未確認） | [P] TLS 1.2。ClientHello は全 13 日で RC4 と 3DES を含む 4 種のみ（Fig.2 の Ring の行が常に 1.0 であることと同じ向き） |
| **3. 異なる点** | [P] 応答は JSON ではなく Base64（api_version=4）。`sip_server_tls` などは見えない。Nick はポート 80 の JSON を見たが、今回は dings の応答も不透明 | [P] ポーリングは 10.15 秒（中央値）で 17 秒ではない。api_version=4。版は 1.10.70／1.19.217。**認証情報は 03-20〜04-11 で同じで、04-13 に 1 回だけ変わった**（Kidder は 2 日で異なると報告）。Kidder の「digest」「RTSP」の語は、Kidder 自身の掲載ヘッダー（Basic）と SDP（RTP/AVP）と合わない | [P] 1.19.217 の RTP は不透明。Server-Phone は **iOS のアプリと思われる端末で平文の RTP**（種類 96、H.264 の構造）。`a=crypto` などの有無は SIP が TLS のため見えない | [P] **前方秘匿性なし**。全 13 日で 0 回（4 種とも RSA 鍵交換）。IoTLS の Fig.3 の Ring の行は 2018-01〜03 に部分的（色から約 0.75、0.45、0.75。読み取りの概算）、2018-04 以降は 1.0。同じ月に結果が違うので、同じ個体・同じ設定とは言えない |
| **4. 比較できない点と理由** | 版と型番（記載なし）。映像の中身（Nick は SDP まで）。サポートの回答（画像を取得できず）。平文の JSON の中身（今回は api_version=4 で不透明） | 2016 年の平文の JSON の値（今回は見えない）。Kidder の RTP（中身を調べていない）。motions の経路（今回は観測なし） | 型番・版・調査日（記載なし）。Android のアプリの検査、Web の検査、物理の検査（通信からは判定できない）。Registration サーバーへの中間者（Ring の TLS への中間者の検査は今回のデータにない：`mitm-yourthings.tsv` に Ring の行がなく、[P] 証明書はすべて DigiCert の `*.ring.com`） | 型番・版（記載なし）。Ring の生データ（TLS の握手のデータはデータ共有の申請が必要で未取得。`device_fingerprints.txt` に Ring はない）。平文の通信（対象外）。Fig.3 の数値（色の概算のみ） |
| **5. 判定** | **同一の既知問題**：平文の HTTP と MAC を使う Basic 認証、TLS を使わない SIP。根拠は上の一致。ただし版は未確認 | **同一の既知問題**：平文のポーリング、Basic、平文の SIP。版は 1.8.90 と 1.10.70 で別だが同じ系列。認証情報の変化は**異なる観測**で、追加の知見の候補としては弱い（観測の範囲が違う） | RTP は**同一の既知問題**（ただし同じ型番・版かは未確認）。Server-Phone は**関連する別の問題**で、結果も異なる。Registration は**未確認** | **関連する別の問題**（TLS の質だけ）。前方秘匿性の差は**未確認**（型番・版が不明で、個体の差か時期の差か判断できない） |

## 3. 今回の観測（自分で確認した分）

ファイル名は `eth1-` で始まる元の 5 分のキャプチャ。フレーム番号は元のファイルの番号（`*.frames` の対応表で確かめた）。時刻はパケットの時刻（UTC 表記）。元のファイルは `usb-yourthings/iot_traffic<日>.tgz`。

### 3.1 版と更新

機器：MAC は 00:1d:c9 で始まる（Wireshark の OUI で GainSpan。Basic のユーザー名でもあるので全体はここに書かない。[devices.tsv](devices.tsv) の RingDoorbell の行）。通信のある日の IP は 192.168.0.19。DHCP のホスト名は RingDoorbell。

| 時刻 | ファイル | フレーム | フィールドと値 |
|---|---|---|---|
| 03-21 17:50:12 | `20180321.1750.1521672600` | 7667 | SIP INVITE、User-Agent `Device/dpdv2/1.10.70`、ヘッダーに `X-Session-Hash` なし |
| 04-11 20:04:20 | `20180411.2000.1523494800` | 143287 | SIP INVITE、`Device/dpdv2/1.19.217`、`X-Session-Hash`（49 文字、値は記録しない） |
| 04-13 15:41:22 | `20180413.1540.1523652000` | 38257 | SIP INVITE、`Device/dpdv2/1.10.70`（**04-11 より古い版に戻っている**） |
| 04-13 15:49:50 | `20180413.1545.1523652300` | 359841 | `GET /doorbots_api/v2_firmwares/1550/download?component=flash`、Host fw.ring.com、Basic |
| 同 | 同 | 359933 | 200、`application/octet-stream`、`filename="1550_flash.bin"`、本文 438,937 バイト（`20180413.1550` のフレーム 14240 まで、欠けなし） |
| 04-13 15:50:15 | `20180413.1550.1523652600` | 14465 | 同じパスで `component=app` |
| 同 | 同 | 14774 | 200、`filename="1550_app.bin"`、本文 430,301 バイト（フレーム 18863 まで、欠けなし） |
| 04-13 15:55:14 | `20180413.1555.1523652900` | 8047 | SIP INVITE、`Device/dpdv2/1.19.217`、`X-Session-Hash` あり |

- 本文の統計（中身は保存も表示もしていない）：エントロピーは 6.548 と 6.320 ビット／バイト。4 KiB ごとに 7.9 以上のブロックは 0。全体を暗号化または圧縮した形ではない。`app` の本文には `dpdv2`、`/doorbots_api/`、`protocol=sip`、`gainspan`、`GS2000`、`srtp` などの文字列がある（数だけ確認）。
- **署名や完全性の検証があるかは通信からは分からない（未確認）**。
- なぜ 04-13 に古い版に戻っていたかは未確認。04-11 20:19 から 04-13 15:25 まで Ring の通信がなく（04-12 は 0 パケット）、戻ったあとは認証情報が変わっている。

### 3.2 日ごとの変化

Ring だけを取り出した PCAP を日ごとに自分で数えた。要求は、ヘッダーが最後までそろうものの数（欠けのある要求を入れた行数は 03-20 が 8,364、03-21 が 8,363 で handoff と一致）。Basic の値は同一性だけを記号で示す。

| 日 | SIP の User-Agent の版 | 平文 `GET /vod/ready` | 平文の POST | ファームウェアの取得 | TLS の ClientHello（tcp/443＋9998） | Basic の値 | RTP の映像 |
|---|---|---|---|---|---|---|---|
| 03-20 | SIP なし | 8,356 | 0 | 0 | 0 | A | なし |
| 03-21 | 1.10.70 | 8,357 | vod 1 | 0 | 2＋0 | A | 平文の H.264 |
| 03-28 | SIP なし | 0 | 0 | 0 | 0 | なし | なし（DHCP を繰り返し、DNS の応答が 1 つも見えない） |
| 04-10 | SIP なし | 0 | 0 | 0 | 0＋853 | なし | なし |
| 04-11 | 1.19.217 | 0 | dings 1 | 0 | 0＋712 | A | 不透明 |
| 04-12 | Ring のパケット 0 | | | | | | |
| 04-13 | 1.10.70、15:55 から 1.19.217 | 7 | dings 2、vod 1 | 2 | 5＋282（9998 の最初は `20180413.1550` 47412、15:51:09） | B | 15:41、15:48 は平文、15:55 は不透明 |
| 04-14 | SIP なし | 0 | 0 | 0 | 2＋825 | なし | なし |
| 04-15 | SIP なし | 0 | 0 | 0 | 0＋825 | なし | なし |
| 04-16 | SIP なし | 0 | 0 | 0 | 0＋820 | なし | なし |
| 04-17 | SIP なし | 0 | 0 | 0 | 0＋832 | なし | なし |
| 04-18 | SIP なし | 0 | 0 | 0 | 0＋857 | なし | なし |
| 04-19 | SIP なし | 0 | 0 | 0 | 1＋838 | なし | なし |

- **平文の Basic は版が変わっても残る**。ただし 1.10.70 では約 10 秒ごと、1.19.217 では ding のときだけになる。
- ポーリングの間隔の中央値は 10.15 秒（03-20、03-21、04-13）。tcp/9998 への接続の間隔の中央値は 15.10 秒（Zeek の conn.log）。多くは TLS まで進まず（04-10 は 6,034 接続のうち TLS は 854 回）、目的は中が見えないので未確認。
- TLS は全日で ClientHello が同じ 4 種（`0x002f, 0x000a, 0x0005, 0x0004`）、SNI なし、TLS 1.2。サーバーの選択はすべて `0x002f`（`TLS_RSA_WITH_AES_128_CBC_SHA`）。**前方秘匿性のある暗号は提示もしていない**。証明書はすべて DigiCert の `*.ring.com`。Zeek の 6,855 回と、自分で数えた ServerHello の 6,855 回は一致する。
- 1550 が 1.19.217 に当たるというのは、取得の前後の User-Agent からの推定で、本文の中に `1.19.217` の文字列は見つかっていない。
- 03-20 と 04-10、04-14〜19 の版は SIP がないので分からない。挙動からは、それぞれ 1.10.70 と 1.19.217 と同じに見える。

### 3.3 映像：版で変わる

RTP の中身の先頭バイトを比べた。H.264 の NAL ユニットは先頭ビットが必ず 0 で、種類も限られる。映像そのものは戻していない。

| セッション（開始、INVITE のフレーム） | 版 | RTP（種類 97） | 先頭バイトの種類 | 先頭ビットが 1 | 一様分布との χ²（df=255、0.1% の棄却値は約 330） | 中身全体のエントロピー |
|---|---|---|---|---|---|---|
| 03-21 17:50（`20180321.1750` 7667） | 1.10.70 | 1,079 | 4（0x5c、0x7c、0x67、0x68） | 0 | 158,017 | 7.843 |
| 04-13 15:41（`20180413.1540` 38257） | 1.10.70 | 37,439 | 4（同） | 0 | 4,983,305 | 7.894 |
| 04-13 15:48（`20180413.1545` 240781） | 1.10.70 | 9,805 | 4（同） | 0 | 1,306,962 | 7.889 |
| 04-11 20:04（`20180411.2000` 143287） | 1.19.217 | 36,792 | 256 | 50.2% | 266 | 8.0000 |
| 04-13 15:55（`20180413.1555` 8047） | 1.19.217 | 46,185 | 256 | 50.2% | 280 | 8.0000 |

- 1.10.70 は FU-A の開始と終了もほぼ整合する（03-21 は 177 組で不整合 6、04-13 15:41 は 5,078 組で不整合 29）。SPS は Baseline、レベル 4.0（`profile=66, level=40`。03-21 は 12 個）。**暗号化されていない H.264**。
- 1.19.217 は先頭バイトが一様で、H.264 の構造がない。**中身は暗号化されている可能性が高い**が、方式は不明。パケット長の分布は版で変わらない（1294、1289 が最多）ので、長さを変えない変換とみられる。SDP は `RTP/AVP` のままで、`RTP/SAVP`、`a=crypto`、`a=fingerprint`、`a=key-mgmt` はない。鍵がどこで渡るかは未確認（POST の応答の Base64 の中身は読めない）。
- 平文のまま残るもの（1.19.217 でも）：SIP（udp/15063）、SDP、`POST /doorbots_api/dings` の `Authorization: Basic`（04-11 の `20180411.2000` 143044、04-13 の `20180413.1555` 7850）。
- POST の応答の本文は 5 回とも Base64 で、戻すと 960〜1,040 バイト、すべて 16 の倍数、約 7.8 ビット／バイトで、JSON ではない。ブロック暗号の形と合うが、確かめていない。2016 年の平文の JSON（Nick、Kidder）とは異なる。
- ドアベルの udp/51506 からの音声の RTP は、5 セッションすべてで見えない。
- `X-SSRC-V` と RTP の SSRC は 5 セッションすべてで一致した。

### 3.4 サーバー→スマートフォン

ドアベルと同じ時刻に、スマートフォン（192.168.0.159、Apple の OUI。YourThings の評価では iOS のアプリ 4.1.13。**収録時の版は未確認**）が同じサーバーと通信している。

| セッション | SIP | サーバー→スマートフォンの映像（最初のフレーム） | 先頭バイト |
|---|---|---|---|
| 03-21 17:50（ドアベル 1.10.70） | tcp/15064、TLS 1.2、0xc030（`20180321.1750` 8048、8052） | 52.206.247.65:22166→:49853、1,047 パケット、種類 96（8327） | 0x5c、0x7c、0x67、0x68 の 4 種 |
| 04-13 15:55（ドアベル 1.19.217） | tcp/15064、TLS 1.2、0xc030（`20180413.1555` 34710、34728） | 35.174.122.92:29844→:59772、20,938 パケット、種類 96（35065） | 同じ 4 種 |

ドアベルからサーバーが不透明な 04-13 15:55 でも、**サーバーからスマートフォンは H.264 の構造が見える**。音声（種類 0）も両方向にあるが、中身は戻していない。

### 3.5 BYE のあとも映像を送り続ける

| セッション | 種類 | INVITE→BYE | BYE のあとの RTP |
|---|---|---|---|
| 03-21 17:50 | vod | 12.5 秒 | 4 パケット |
| 04-13 15:48 | vod | 91.4 秒 | 5 パケット |
| 04-11 20:04 | ding | 29.5 秒 | 33,709 パケット（300.1 秒） |
| 04-13 15:41 | ding | 30.2 秒 | 34,406 パケット（309.4 秒） |
| 04-13 15:55 | ding | 300.4 秒 | 22,778 パケット（308.4 秒） |

ding のセッションでは、サーバーが BYE を送ったあと約 5 分、ドアベルは映像を送り続ける。サーバーは ICMP の到達不能を返している。理由は未確認。

### 3.6 時計

パケットの時刻はサーバーの時刻より進んでいる。03-20 の `20180320.1200` では、8 台のサーバーの `Date` がすべて約 1,028 秒遅く、NTP の応答も同じ差だった。04-11 は約 11 秒、04-13 は約 21 秒。**パケットの時計がずれていて、ずれは日によって変わる**。時刻は ±20 分の幅で読む。

## 4. 製造者の文書（食い違いの判断の前に）

比較の基準は「収録（2018-03-20〜04-19）までに公開され、この機器に当てはまる説明」。公開日が書かれていない文書は、アーカイブの取得日しか分からない。

### 確認した文書

| 文書 | 公開・改訂の日 | アーカイブの日 | 機器の通信の暗号化について |
|---|---|---|---|
| [How it works](https://web.archive.org/web/20160407063030/https://ring.com/how-it-works) | 記載なし | 2016-04-07 | 仕様の欄に「Encryption: Bank-grade」。対象の説明なし |
| [製品ページ ring.com/video-doorbell](https://web.archive.org/web/20170420084549/https://ring.com/video-doorbell) | 記載なし | 2017-04-20 | Tech Specs に Encryption の行。対象の説明なし。**確認できる最後の版** |
| [販売ページ shop.ring.com/products/video-doorbell](https://web.archive.org/web/20171224064350/https://shop.ring.com/products/video-doorbell) | 記載なし | 2017-11-15、**2017-12-24**、2018-07-25 | **Tech Specs に Encryption の行がない**（ほかの行はほぼ同じ）。`ring.com/video-doorbell` は 2018-05-01 の取得でここへ 301 |
| 同じ販売ページの VD2、Pro | 記載なし | 2018-03-08、2018-01-06 | 記載なし |
| [FAQ](https://web.archive.org/web/20170128123919/https://ring.com/faq) | 記載なし | 2017-01-28 | Wi-Fi の WEP／WPA、支払いの HTTPS、録画の保存先のみ |
| [ポートの記事](https://web.archive.org/web/20161020225254/https://support.ring.com/hc/en-us/articles/205385394-What-Ports-do-I-need-to-open-in-my-firewall-for-Ring-Doorbells-and-Chimes-) | 2016-10-04 | 2016-10-20 | TCP 80、443、TCP/UDP 15063、UDP 51504／51506 を列挙。暗号化の記述なし。tcp/9998 はない |
| [プライバシーポリシー](https://web.archive.org/web/20170128130642/https://ring.com/privacy) | 2016-11-25 | 2017-01-28 | 口座のパスワードと一般的な保護のみ。暗号化なし |
| [Privacy Notice](https://web.archive.org/web/20180725110729/https://shop.ring.com/pages/privacy) | 発効 2018-03-27（収録中） | 2018-07-25 | 管理・技術・物理の保護措置という一般的な記述のみ。暗号化なし |
| [ファームウェアの記事](https://web.archive.org/web/20170802101755/https://support.ring.com/hc/en-us/articles/115001773886-Updating-The-Firmware-for-Ring-Video-Doorbell-Ring-Doorbell-Pro-and-Stick-Up-Cam-) | 2017-08-02 | 2017-08-02 | 自動で更新する。Ring Video Doorbell は 1.8.90。転送の保護の記述なし |
| [版の確認の記事](https://web.archive.org/web/20171022193809/https://support.ring.com/hc/en-us/articles/115004599926-Checking-and-Updating-Your-Firmware) | 2017-09-07 | 2017-10-22 | Ring Video Doorbell は 1.10.71、VD2 は 1.9.72、Pro は 1.9.3。転送の保護の記述なし |
| [Terms](https://web.archive.org/web/20170128113221/https://ring.com/terms) | 2016-11-25 | 2017-01-28 | 利用者の禁止事項としてのみ |
| [ブログ（Wi-Fi パスワード）](https://web.archive.org/web/20160116013109/http://blog.ring.com:80/index.php/2016/01/13/100-of-active-ring-video-doorbells-keep-your-wi-fi-password-secure/) | 2016-01-13 | 2016-01-16（claims.tsv の 2016-01-13 は投稿日で、取得日はこれ） | 毎日更新を確認する、当時の版は 1.6.39。通信の暗号化の記述なし |
| メディアキット PDF（2017-01-30）、ユーザーマニュアル PDF（2018-10-19、**PDF の作成日 2016-03**） | | | 暗号化の記述なし（マニュアルは収録後の取得） |

収録の後の文書（基準には使わない。参考）：[ポートの記事 2019-01-23](https://web.archive.org/web/20190123144421/https://support.ring.com/hc/en-us/articles/205385394-What-Ports-Do-I-Need-to-Open-in-My-Firewall-for-Ring-Doorbells-and-Chimes-) は tcp/9998 を列挙。[プロトコルの記事 2019-08-21](https://web.archive.org/web/20190821005614/https://support.ring.com/hc/en-us/articles/205385394-The-Protocols-and-Ports-Used-by-Ring-Devices) は 9998／9999 を Ring Socket Service、15063／15064 を SIP、RTP を UDP と説明。一般の FAQ（2018-10-19）、販売サイトの FAQ（2018-07-13）、Terms（2018-08-01）に機器の通信の暗号化の記述なし。

### 取得できなかった文書

- Nick の記事のサポートの回答（画像）。直接は i0.wp.com が 403、Wayback は 404。これ以上は試していない。
- VD2 のマニュアル PDF（2019-10-14、アーカイブ自体が 1 MB で切れている。[unreadable.md](unreadable.md)）。

### 探したが見つからなかった文書

- 2016〜2018 年の Ring のセキュリティのページ（`ring.com/*` の 1,193 行の URL、`support.ring.com/hc/en-us/articles/*` の 1,681 行の URL の題名を検索。題名で分かる範囲）。
- ファームウェアのリリースノート。1.10.70 と 1.19.217 の説明。
- 2017-10-22 と 2019-01-23 の間の版の表、2016-10-20 と 2019-01-23 の間のポートの記事。
- 初代のマニュアルの、2018-03 以前の取得。

### 判定

**食い違いは「未確認」**。理由は 2 つ。

1. 対象が書かれていない。機器の通信、録画の保存、アカウントのどれを指すか、文書からは決められない。
2. 収録の時点で有効だったか分からない。確認できる最後は 2017-04-20 で、遅くとも 2017-11-15 には販売ページに行がなく、収録に最も近い 2017-12-24 にもない。

「2017-04 時点の文言と、2018-03 の 1.10.70 の通信に差がある」とは言える。これを製造者の誤りとは言わない。

## 5. まとめ

### 既知問題の再確認にとどまる点

- 平文の HTTP、MAC を使う Basic の認証情報、平文の SIP、SDP の形：Nick 2016、Kidder 2017 と同じ。
- 1.10.70 の暗号化されていない RTP：Alharbi & Aspinall 2018 と同じ（型番・版は未確認）。
- 1.19.217 の RTP の不透明な中身と `X-Session-Hash`、平文の RTP のスマートフォン側：[Dojo by BullGuard 2019](https://web.archive.org/web/20190411195308/https://dojo.bullguard.com/dojo-by-bullguard/blog/ring/)（CVE-2019-9483）と同じ構造。依頼の 4 本には入っていないが、**handoff の見立てを崩す報告**なので読んだ。
- 弱い暗号の提示：IoTLS の Fig.2 と同じ向き。

### 追加検証する価値がある点

新規と判断したものではない。どれも、4 本と下の資料には見つからなかったという段階。

1. **平文の HTTP でのファームウェアの取得**（3.1）。4 本には記述がない。Alharbi は自動更新と書くだけ。追加で、更新の転送を扱う報告を探す必要がある。署名の有無が分からないので、危険の大きさは言えない。
2. **版の境目と、同じ機器の更新前後の差**（3.1〜3.3）。Alharbi は平文、Dojo は暗号化と報告するが、どちらも版を書いていない。今回は 1.10.70 と 1.19.217 で分かれる。ほかのデータセット（UNSW 2018、Deakin の Ring）で版と挙動を確かめられる。
3. **ドアベル→サーバーが不透明で、サーバー→スマートフォンが平文の H.264**（3.4）。Dojo と同じ構造だが、2018-04 の公開データで再現できる。Alharbi の「SRTP」との違いは、アプリの種類（Android／iOS）か時期の差かもしれない。
4. **ding のセッションで BYE のあと約 5 分送り続ける**（3.5）。報告は見つけていない。録画の仕様か不具合か、判断の材料がない。
5. **認証情報が日ごとに変わらない**（03-20〜04-11 で同じ）。Kidder の「2 日で変わった」と異なる。ただし比較の範囲が違う。

### 判断に不足する証拠

- **機種**：YourThings の評価は Model: Video Doorbell、版は N/A。通信の証拠（`X-RingDeviceType: doorbell`、OUI、DHCP のホスト名、Ring の版の表の 1.10.71 に近い 1.10.70、本文の GS2000）は初代を指すが、本体を確かめてはいない。
- **ファームウェアの版**：SIP がない日は分からない。03-20 と 04-10、04-14〜19 の版は挙動からの推定。
- **更新の経緯**：03-21 と 04-10 の間（収録なし）、04-13 に古い版に戻っていた理由、更新が自動か手動か（SoK の Table VI は Manual、Alharbi は Automated、Ring は自動と説明）。
- **4 本の版と調査日**：Nick、Alharbi、IoTLS は版を書いていない。Alharbi の修士論文、Nick のサポートの回答、IoTLS の生データは未取得。
- **署名、鍵の受け渡し、平文の Base64 の中身**：通信からは分からない。
- **YourThings の評価との差**：評価のページは HTTP 0/1、Cleartext Authentication 0/13 で、平文の Basic の観測と合わないように読める。指標の定義の違いか、未確認。
- **製造者の説明**：上の 4 節。

### 4 本以外で確認した資料

| 資料 | 読んだ範囲 | 関係 |
|---|---|---|
| [Dojo by BullGuard, Or Cyngiser, 2019-02-27](https://web.archive.org/web/20190411195308/https://dojo.bullguard.com/dojo-by-bullguard/blog/ring/) | 全文（Wayback 2019-04-11） | 3.3、3.4 と同じ構造。型番・版の記載なし |
| [Alrawi et al., SoK, IEEE S&P 2019](https://coeus.ece.gatech.edu/articles/sok_sp19.pdf) | Ring の行のみ（Table II〜VII、p.10、16–18） | データセットの出典。Ring の更新は M（Manual） |
| [Ren et al., IMC 2019](https://moniotrlab.khoury.northeastern.edu/wp-content/uploads/2019/09/ren-imc19.pdf) | Ring の行のみ（p.4、11–13） | 動きで録画する挙動の話。Ring の平文の記述は見当たらない（全文は未読） |
| [YourThings の評価](https://yourthings.info/devices/ring_doorbell) | ページ全体 | 3 節、上の差 |
| Bitdefender 2019、Pen Test Partners 2016（Wi-Fi の設定） | 検索の要約のみ。**本文は未読** | 関連する別の問題（設定時）とみられるが、未確認 |
| GTVHacker の wiki、KTH の修士論文（2023）、Boing Boing、BetaNews、Tripwire | **取得できず（526、403、途中で切断）** | 未確認 |

## 6. handoff.md と既存の解析の訂正

| 箇所 | 元の記述 | 確認の結果 |
|---|---|---|
| 3 節「機種」 | ファームウェアの版は通信に出ていない | **誤り**。SIP の User-Agent にある（3.1） |
| 3 節「機種」 | `X-RingDeviceType` は 03-20 に 1,163 回 | 8,356 回すべて（ヘッダーがそろう要求）。1,163 の出所は不明 |
| 3 節「fw.ring.com」 | Quarant の `I4_INSECURE_FIRMWARE_UPDATE_HTTP`（2 回）はホスト名による誤検出の可能性が高い | **誤り**。2 回は 04-13 15:49:50 と 15:50:15 で、実際のファームウェアの取得と一致する。Quarant は正しかった |
| 3 節、claims.tsv | POST 5 回はすべて `vod` で、それぞれ平文の SIP と暗号化されていない RTP が続く | vod 2 回、dings 3 回。うち 1.19.217 の 2 回は RTP が不透明 |
| claims.tsv | 更新の確認は見つからない | 04-13 に取得を確認 |
| 3 節「映像と音声」 | INVITE はフレーム 133、SPS はフレーム 143 | Ring だけを取り出した PCAP の番号。元のファイルでは 7667、8209 が映像の最初 |
| 3 節 | 映像のセッションの直前の 404 以外の応答は未確認 | **確認した**。`20180321.1750` 7456、`20180413.1545` 239450 が 200 で、直後に POST |
| 3 節「時計」 | どちらが正しいか未確認 | パケットの時計がずれている（3.6） |
| 2 節の表の 1 行目 | 強い | 食い違いの判定は未確認（4 節） |
| 4 節の暫定の見立て | 平文の SIP と RTP が追加の価値 | 既知（1 節） |
| 確認して合っていたもの | | 03-20 の `20180320.1200` のフレーム 2450〜2460、2478。要求の行の数 8,364／8,363（8,362＋POST 1）。404 が 8,083 件、408 が 3 件。認証情報の構造。Zeek の TLS 6,855 回（確立 6,824、未確立 31）がすべて `TLS_RSA_WITH_AES_128_CBC_SHA` |

## 7. 再現

```bash
export RING13=~/datasets/claims/ring13
export RING_MAC=...   # devices.tsv の RingDoorbell の行の MAC を、コロンなしの小文字で
python3 -I scripts/claims/ring/extract_mac.py /Volumes/QuarantData/usb-yourthings/iot_traffic20180413.tgz $RING13/20180413 $RING_MAC
python3 -I scripts/claims/ring/http_scan.py $RING13/20180413 $RING13/out/http-20180413.tsv $RING13/out/cred-labels.json
python3 -I scripts/claims/ring/sip_scan.py  $RING13/20180413 $RING13/out/sip-20180413.tsv
python3 -I scripts/claims/ring/rtp_test.py     # 3.3 の表
python3 -I scripts/claims/ring/fw_body.py      # 3.1 の本文の統計
python3 -I scripts/claims/ring/after_bye.py    # 3.5 の表
python3 -I scripts/claims/ring/summary.py      # 3.2 の表
```

`cred-labels.json` は認証情報の SHA-256 と番号の対応で、外に出さない。出力の TSV には認証情報も本文もない。
