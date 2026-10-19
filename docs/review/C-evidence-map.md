# 確認 C：要件と検出の対応、精度の監査

出現率の表（evidence-rates.md）は、「どの要件の証拠に、Quarant のどの検出を、どんな条件で数えるか」を決めた対応表（`docs/assessment/evidence-map.json`）で数えている。この対応表と、「確定（違反として数える）か、候補止まりか」の線引きは、Claude が決め、抜き取りの監査（precision-audit.md、E4〜E14）で直してきた。基準の確認（human-review-accuracy.md）で一部は確認済みだが、要件ごとの全体はまだなので、ここで確認してもらう。

## 確認のしかた

- 各要件について、数え方と、確定か候補止まりかを読んで、**容認する**か**変更する**にチェックを付ける。
- 「未実装」は、Quarant に対応する検出がないもの。出現率の表では「—」になる。
- 監査の記録（英語）は、各要件の「監査の記録」を開くと見られる。

---

### 5.1-1　初期パスワードが共通でないか

- 数え方：平文で見えたパスワード（HTTP の Basic、Telnet、MQTT、FTP）を候補として数える。公開の初期パスワードの一覧との照合はしていない
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Values are masked by design; no comparison against published default-credential lists.
- 監査：Tokens are not passwords; only password-bearing evidence counts.

</details>

### 5.1-2　初期パスワードが推測しやすくないか

- 数え方：5.1-1 と同じ検出を候補として数える。強さは評価していない
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Same as 5.1-1; password strength is not assessed.

</details>

### 5.1-2A　機器同士の認証にパスワードを使っていないか

- 数え方：機器がクライアントで、相手が外部のサーバーのとき、平文のパスワード（MQTT、HTTP の Basic、FTP）を違反として数える
- 扱い：**違反として数える**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 監査：E4 sample: 0/15 INSECURE_HTTP_AUTH events were M2M password logins (13 x-token headers, 2 user Basic logins to the device).

</details>

### 5.1-3　認証の暗号がベストプラクティスか

- 数え方：TLS 1.0／1.1 の使用と、壊れた暗号スイート（RC4、3DES、DES、NULL、EXPORT、匿名、MD5）の選択を違反として数える。CBC は数えない（厳しい読み方では数える）。前提：その通信路で認証が行われている
- 扱い：**違反として数える**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 前提：the weak channel carries authentication
- 監査：E4 sample: weak version 15/15 correct; all 15 'weak cipher selected' were CBC suites, which are not violation evidence by themselves, so only broken suites count. E6 (CIC 2022 power-on): 4/4 devices correct. Nest Cam, Netatmo camera and Hue bridge offered at most TLS 1.0 themselves; Echo Spot offered TLS 1.2 and a video-service server selected TLS 1.0. E11/E12: two 2016 misses fixed: a camera serving TLS that chose TLS 1.0 for a phone offering 1.2 (finding now goes to the server), and a blood-pressure meter on port 8777 whose first segment held only the record header.

</details>

### 5.1-5　総当たりへの対策があるか

- 数え方：RTSP で、多数の失敗した認証の試行に応答し続けたことを候補として数える。締め出し中でも 401 を返す実装と区別できないので、失敗のあとに成功した場合だけ確定できる
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Only RTSP is examined. Continued 401 answers cannot be told apart from a lockout that also answers 401, so a run of failures is a candidate; only success_after_failures=true shows the failures did not lock the client out. Reporting marks runs beyond the NIST SP 800-63B limit of 100 consecutive failures.
- 監査：E9 (CIC 2022 RTSP brute force): SimCam answered ~3,500 Hydra attempts per run (~23/s) with 401 and no refusal; Amcrest answered 36 with 401. No run ended in success, so neither is confirmed.

</details>

### 5.2-2　脆弱性に期限内に対処しているか

- 数え方：未実装（版と CVE の公開日の照合をしていない）
- 扱い：**未実装**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：I5 matches device families, not versions against CVE timelines.

</details>

### 5.3-4A　更新を自動で行えるか（適合だけ示せる）

- 数え方：利用者の操作なしの更新のダウンロードを候補として数える
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Whether the user triggered the update is not known.

</details>

### 5.3-7　更新の暗号がベストプラクティスか

- 数え方：平文の HTTP でのファームウェアらしい取得を候補として数える（キーワードで判断。署名の有無は分からない）
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Cleartext transport of an update does not show weak update cryptography: the package may be signed (TS 5.3-7 concerns the update mechanism's cryptography).
- 前提：the HTTP transfer is a software update (keyword-based)
- 監査：E4 sample: transfers were plausibly updates (path contains 'ota'); signature status unknown.

</details>

### 5.3-8　セキュリティ更新を適時に配布しているか

- 数え方：未実装
- 扱い：**未実装**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：As 5.2-2.

</details>

### 5.5-1　すべての通信の暗号がベストプラクティスか

- 数え方：5.1-3 と同じ（TLS 1.0／1.1、壊れた暗号スイート）
- 扱い：**違反として数える**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 監査：E4 sample: weak version 15/15 correct; all 15 'weak cipher selected' were CBC suites, which are not violation evidence by themselves, so only broken suites count. E6 (CIC 2022 power-on): 4/4 devices correct. Nest Cam, Netatmo camera and Hue bridge offered at most TLS 1.0 themselves; Echo Spot offered TLS 1.2 and a video-service server selected TLS 1.0. E11/E12: two 2016 misses fixed: a camera serving TLS that chose TLS 1.0 for a phone offering 1.2 (finding now goes to the server), and a blood-pressure meter on port 8777 whose first segment held only the record header.

</details>

### 5.5-4　ネットワークから使える機能に認証があるか

- 数え方：認証情報なしの要求に、機器が成功で応じた操作（設定の書き込み、家の情報の取得、映像の配信）を違反として数える。DLNA の再生関係の操作は、規格自身の例外なので除く
- 扱い：**違反として数える**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Authentication outside the request (earlier pairing, host allow-lists, a physical button) is not visible; whether the function was carried out is not known.
- 前提：the function is not meant as open access inside the home network (EN 303 645 5.5-4 itself allows services made available without authentication within a restricted network, e.g. DLNA)
- 監査：E5: IoT devices with evidence: 2016 HP printer (status queries on 3910/3911 and IPP printing from a PC answered without credentials; one unauthenticated PUT of /DevMgmt/ProductConfigDyn.xml), 2018 Belkin WeMo (GetHomeInfo SOAP answered 200 without credentials). Printer status and printing may fall under the restricted-network exception; the configuration write and the WeMo call do not obviously. Most matches overall were the gateway's UPnP IGD (non-IoT, excluded). E6 (CIC 2022 power-on): the only match was a DLNA GetProtocolInfo to a Sonos MediaRenderer, which EN 303 645 5.5-4 itself cites as an allowed restricted-network service; DLNA/UPnP AV services are excluded.

</details>

### 5.5-5　設定の変更に認証があるか

- 数え方：未実装（5.5-4 の検出の一部が当てはまるが、分けていない）
- 扱い：**未実装**
- [ ] 容認する
- [ ] 変更する
- メモ：

### 5.5-6　秘密情報を通信中に暗号化しているか

- 数え方：平文の Authorization（Basic など）、トークンや API キーを名乗るヘッダ・URL・本文のキー、Cookie、MQTT・Telnet・FTP のパスワード、UDP の `user=…&pwd=…`、応答の本文の秘密を違反として数える。要求ごとの署名（AWS、OSS、WSSE、Digest）、識別子（`serial`、`device_id`）、正体不明の `sid=` は除く（厳しい読み方では数える）
- 扱い：**違反として数える**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 監査：E4 sample: HTTP auth/token headers 15/15 and session IDs in URLs 4/4 correct; 4/4 'token' events were device serial numbers (identifiers, not CSPs) and are excluded; cookies may be non-session (probable). IoT-23: a Philips Hue sent Authorization headers and auth= URL parameters in cleartext to its cloud (correct). E6 (CIC 2022 power-on): Hue bridge (Authorization headers, auth= in URL) and Home Eye camera (Authorization header) to cloud over HTTP, both correct. E8 (CIC 2022 interactions/scenarios): Hue bridge again (correct); a Sonos One sent sid= in cleartext URLs to opml.radiotime.com (TuneIn radio session ID; whether it is a critical security parameter is unclear, undecided). E9 (CIC 2022 active): SimCam's Authorization headers to S3 were AWS SigV4 signatures (per-request, not reusable), now named in the evidence and excluded; the same requests uploaded JPEG snapshots in cleartext, which is 5.8-1 evidence Quarant does not yet detect. E11 (miss measurement): INSECURE_HTTP_BODY_SECRET was missing from this list; across all data its IoT events outside the serial=/device_id= exclusion were Withings sessionid= (4 devices) and an iHome evrythng.api_key= (all correct), so it is now included. INSECURE_MQTT_PAYLOAD_SECRET and INSECURE_TELNET_PAYLOAD_SECRET never occurred and stay out (unaudited). Home Eye's Authorization was an Alibaba OSS per-request signature (false positive); OSS and WSSE are now named in the evidence and excluded like AWS SigV4. E14 (YourThings 2018, unseen devices): two misses, a VeraLite hub logging into an external FTP server in cleartext and a Harmony Hub receiving an API key in a cleartext HTTP response; INSECURE_FTP_CREDENTIALS and INSECURE_HTTP_RESPONSE_SECRET were added afterwards.

</details>

### 5.5-7　遠隔から到達できるインターフェースで秘密情報を守っているか

- 数え方：5.5-6 と同じ検出のうち、送信元か宛先が外部（インターネット側）のものを数える
- 扱い：**違反として数える**
- [ ] 容認する
- [ ] 変更する
- メモ：

### 5.6-2　認証なしで不要な情報を公開していないか

- 数え方：機器探索（SSDP の SERVER、mDNS の TXT）の中の版の文字列を候補として数える。監査では 22 件すべてプロトコルが求めるものだった
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Most visible version strings are mandated by the protocol (UPnP SERVER header) or are protocol versions (mDNS pv=, vers=); TS 5.6-2 itself notes that standard protocols may require such disclosure.
- 前提：the disclosed version is security-relevant and not needed for operation
- 監査：E4 sample: 0/22 discovery version strings were evidence of a violation.

</details>

### 5.8-1　個人データを暗号で守っているか

- 数え方：平文の個人データ（利用者の ID など）と、平文の画像・映像・音声の送信（HTTP と、HTTP 以外の TCP）を違反として数える
- 扱い：**違反として数える**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 監査：E4 sample: 10/10 correct (user identifier in cleartext body); all from one device. E10 (I6_MEDIA_UPLOAD_CLEARTEXT): all matches checked. Home Eye camera PUT JPEG snapshots to Alibaba Cloud OSS (Hong Kong) over HTTP at power-on (3/3), on 14/30 idle nights and in the active day; SimCam PUT JPEGs to S3 over HTTP. Both correct. No match in UNSW 2016/2018 or IoT-23; a direct search of the raw traffic of three UNSW days found no media upload either. E11/E12: the rule read only the first multipart part and missed a 2016 TP-Link camera streaming h264 video and AAC audio to tplinkcloud.com over HTTP (now every part is read); a Borun camera (CIC 2022 power-on) sent JPEGs inside a proprietary TCP protocol to port 8899 (now detected by file signature, device to public address only). E4's 2018 match was a MacBook Pro, not an IoT device.

</details>

### 5.8-2　機微な個人データを暗号で守っているか

- 数え方：5.8-1 の個人データの検出を候補として数える（機微かどうかは区別していない）
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：No distinction between personal and sensitive personal data.

</details>

### 5.9-2　停止のあとに接続が戻るか

- 数え方：未実装
- 扱い：**未実装**
- [ ] 容認する
- [ ] 変更する
- メモ：

### 5.9-3　再接続が秩序立っているか

- 数え方：大半が無応答の相手への接続の繰り返しを候補として数える（バックオフは確かめていない。厳しい読み方では、応答のある繰り返しも数える）
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Backoff and protocol conformance are not checked.
- 監査：E4 sample: 0/12 PERSISTENT_CONNECTION_ATTEMPTS were reconnect storms (all answered, regular sessions); only mostly-unanswered retry loops count. IoT-23: the 3 mostly-unanswered loops were malware C2/scan loops, i.e. infection behaviour rather than the product's reconnection design; traffic alone cannot separate the two. E7 (CIC 2022 idle): Borun camera retried logreport.nvcam.net:80 about 40 times an hour, mostly unanswered, on many nights (a retry loop against an unresponsive logging server: plausible, backoff not checked); SimCam once.

</details>

### 5.11-1　利用者のデータを消去できるか

- 数え方：未実装
- 扱い：**未実装**
- [ ] 容認する
- [ ] 変更する
- メモ：

### 5.12-1　初期設定が安全か

- 数え方：Telnet・FTP のサービスと、UPnP でのポート開放を候補として数える（初期設定のままかは分からない）
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Default vs user-enabled is not known (applies to listening services and to UPnP port mappings alike).
- 監査：E5: one IoT device (2018 Belkin NetCam) repeatedly mapped external TCP 9031 to itself through UPnP and the gateway accepted; the other mappings came from a PC and an Android phone (excluded).

</details>

### 5.13-1B　ネットワークからの入力を検証しているか

- 数え方：未実装
- 扱い：**未実装**
- [ ] 容認する
- [ ] 変更する
- メモ：

### 6-8　匿名化すべきデータを匿名化しているか

- 数え方：平文の個人データのアップロードを候補として数える（何を匿名化すべきかは分からない）
- 扱い：**候補止まり**
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>監査の記録（英語）</summary>

- 足りないところ：Which data should be anonymised is not known under Model N.

</details>
