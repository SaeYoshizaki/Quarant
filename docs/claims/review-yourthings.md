# 確認用の表：YourThings の暗号化の主張（人が確かめるもの）

判定は 1 人で行った。ここにある 23 件（食い違いの候補、文言の上で食い違い、確かめが要る一致）を、人が確かめる。表は claims.tsv から作った（2026-11-02）。

## 確かめること

1. **引用**：アーカイブの URL を開き、引用がその文書にあるか。前後を読んで、主張の範囲（機器とクラウドの間か、アプリか、保存時か）の読み方が妥当か。手元の保存した版は `~/datasets/claims/snapshots/` の下（表のファイル名）。
2. **観測**：根拠の数と宛先が、主張の範囲に入るか（第三者の宛先、接続確認、LAN 内だけ、などは注意の欄を見る）。
3. **判定**：食い違いの条件（method.md の 3）に当たるか。当たらないと思ったら、その理由を書く。

結果は、各項目の「確認」の行に「同意」「不同意（理由）」「保留（理由）」のどれかを書く。

## 1. Ring Video Doorbell：食い違いの候補（contradiction candidate (T1a)）

- **主張**："Encryption Bank-Grade"
- **文書**：D1、アーカイブ 2017-04-20（キャプチャとのずれ -11.0 か月）。https://web.archive.org/web/20170420084549/https://ring.com/video-doorbell
- **保存した版**：`ring_com_video_doorbell-20170420.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：plaintext GET to vod.ring.com with Authorization: Basic about every 10 s on 03-20 (8372) and 03-21 (8364), mostly 404, and 13 more on 04-11 and 04-13 (16,749 in all); plaintext POST to fw.ring.com with Authorization: Basic (5) (Zeek); Quarant INSECURE_HTTP_AUTH 16,633; TLS 6855, none with forward secrecy (TLS_RSA_WITH_AES_128_CBC_SHA) (13 days: 03-20, 03-21, 03-28, 04-10..19; 03-20 and 03-21 analysed by Quarant without the dataset's scanner host)
- **注意**：vague claim: only "encryption is used" is judged; "bank-grade" is not
- **2026-11-02 の再確認**：[ring-prior-work.md](ring-prior-work.md)。上の根拠のうち POST 5 回の内訳は vod 2 回、dings 3 回。映像は 1.10.70 で平文、1.19.217 で不透明。平文の HTTP でのファームウェアの取得（04-13）を確認。文言には対象の説明がなく、2017-11-15 以降の販売ページの仕様の欄にはないので、当時の説明としての適用は未確認。**判定の案：食い違いは未確認**。
- **調べた文書（2026-11-02 に探し直した）**：2016〜2018 年にアーカイブされた Ring の公開文書を、ring.com、support.ring.com、static.ring.com、blog.ring.com のすべての PDF を含めて探した。
  - 製品ページ（2017-04-20）と「How it works」のページ（2016-04-07）：仕様の欄に「Encryption: Bank-grade」だけ（同じ文言。後者は claims.tsv に別の行で入れた）。
  - ring.com の FAQ（2017-01-28）：支払いのページが HTTPS、Wi-Fi は WPA2、録画は「secure cloud servers」に保存。機器の通信の暗号化には触れていない。
  - サポート記事「必要なポート」（2016-10-20）：機器が使うポートとして TCP 80 と TCP 443 などを列挙。80 の通信を暗号化するかは書いていない。
  - サポート記事（Protect の FAQ 2018-01-27、ファームウェアの記事 2017）、公式ブログ（Wi-Fi パスワードの件、2016-01-13）、ユーザーマニュアルの PDF（2018-10-19）、メディアキットの PDF（2017-01-30）、プライバシーポリシー（2017-01-28）：機器の通信の暗号化の記述なし。
  - セキュリティのページ：2016〜2018 年には見つからない。
  - まとめ：機器の通信の暗号化について書いてあるのは、仕様の欄の一言だけ。それを限定・説明する文書はない。
- **claims.tsv の行**：2（見出しを 1 行目とした行番号）
- **確認**：

## 2. Canary：食い違いの候補（contradiction candidate (T2)）

- **主張**："All parts of our system—from the device to the cloud to the app—employ extensive security measures to protect private data, such as AES 256-bit symmetric-key encryption, Virtual Private Cloud (VPC), secure HTTP access (HTTPS) using TLS/SSL, and more."
- **文書**：D2、アーカイブ 2018-02-27（キャプチャとのずれ -0.7 か月）。https://web.archive.org/web/20180227160118/https://canary.is/uk/security/
- **保存した版**：`canary-uk-security-20180227.txt`
- **型・範囲**：T2、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：4 of 26334 TLS handshakes with Canary's servers used AES-128 (ECDHE_RSA_WITH_AES_128_GCM_SHA256, o.canaryis.com and v.canaryis.com, 03-20); the rest AES-256; also 158 plaintext HEAD to h.canaryis.com:80, no body or parameters (Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19); the dataset's man-in-the-middle test sessions excluded
- **注意**：UK page; US page 2017-05-13 not compared yet; weak candidate: 4 of 8010 handshakes; the plaintext HEADs alone would make it wording-only (T1b)
- **claims.tsv の行**：3（見出しを 1 行目とした行番号）
- **確認**：

## 3. Canary：文言の上で食い違い（wording-only contradiction）

- **主張**："When a customer streams video through the Canary app, all video and data is securely encrypted between the device, the cloud, and the smartphone."
- **文書**：D2、アーカイブ 2018-02-27（キャプチャとのずれ -0.7 か月）。https://web.archive.org/web/20180227160118/https://canary.is/uk/security/
- **保存した版**：`canary-uk-security-20180227.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：same 158 HEAD requests; TLS 26324/26334 ECDHE_RSA_WITH_AES_256_GCM_SHA384, 6 ECDHE_RSA_WITH_AES_256_CBC_SHA384, 4 ECDHE_RSA_WITH_AES_128_GCM_SHA256 (the AES-128 ones to o.canaryis.com and v.canaryis.com on 03-20 only; Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19, the dataset's man-in-the-middle test sessions excluded)
- **注意**：no video or data seen in plaintext
- **claims.tsv の行**：4（見出しを 1 行目とした行番号）
- **確認**：

## 4. TP-Link HS105：食い違いの候補（contradiction candidate (T1a)）

- **主張**："We have implemented measures, including encryption and SSL technology, designed to secure your personal information from accidental loss and from unauthorized access, use, alteration, and disclosure."
- **文書**：D3、アーカイブ 2018-01-31（キャプチャとのずれ -1.6 か月）。https://web.archive.org/web/20180131001047/http://www.tp-link.com:80/us/privacy
- **保存した版**：`tplink_us_privacy-20180131.txt`
- **型・範囲**：T1、主張の範囲 all、観測の範囲 external+lan
- **根拠**：on 04-13 and 04-15 the phone app controlled the plug over the LAN (tcp/9999, 46 flows): the plug's replies carried the cloud account user name (cnCloud.get_info.username), its location (latitude_i, longitude_i), deviceId, MAC and alias, readable after undoing the XOR (key names only checked, values not recorded); to the internet only TLS (48 flows) and 1 plaintext GET without content to download.tplinkcloud.com (flowscan.py, Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：names SSL; scope is 'personal information'; the LAN control protocol (tcp/udp 9999) is JSON hidden with a public XOR autokey, which anyone on the network can undo; that is obfuscation, not encryption; the observation is LAN only
- **claims.tsv の行**：61（見出しを 1 行目とした行番号）
- **確認**：

## 5. TP-Link LB130：食い違いの候補（contradiction candidate (T1a)）

- **主張**："We have implemented measures, including encryption and SSL technology, designed to secure your personal information from accidental loss and from unauthorized access, use, alteration, and disclosure."
- **文書**：D3、アーカイブ 2018-01-31（キャプチャとのずれ -1.6 か月）。https://web.archive.org/web/20180131001047/http://www.tp-link.com:80/us/privacy
- **保存した版**：`tplink_us_privacy-20180131.txt`
- **型・範囲**：T1、主張の範囲 all、観測の範囲 external+lan
- **根拠**：on 04-13 and 04-15 the phone app controlled the bulb over the LAN (tcp/9999 and udp/9999, 71 flows): the bulb's replies carried the cloud account user name (smartlife.iot.common.cloud.get_info.username), deviceId, MAC and alias, readable after undoing the XOR (key names only checked); to the internet only TLS (74 flows; 44 TLS1.2 handshakes with the real servers, all with forward secrecy; 20 more were the dataset's man-in-the-middle test) (flowscan.py, Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：names SSL; scope is 'personal information'; the LAN control protocol (tcp/udp 9999) is JSON hidden with a public XOR autokey, which anyone on the network can undo; that is obfuscation, not encryption; the observation is LAN only
- **claims.tsv の行**：71（見出しを 1 行目とした行番号）
- **確認**：

## 6. Apple HomePod：食い違いの候補（contradiction candidate (T1a)）

- **主張**："certain information such as your name, contacts, music you listen to, and searches is sent to Apple servers using encrypted protocols."
- **文書**：D2、アーカイブ 2018-04-12（キャプチャとのずれ 0.0 か月）。https://web.archive.org/web/20180412230006/https://www.apple.com/privacy/approach-to-privacy/
- **保存した版**：`www_apple_com_privacy_approach_to_privacy-20180412.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：on 03-21 the HomePod fetched audio from streamingaudio.itunes.apple.com over plaintext HTTP 3 times, with a URL parameter named accesskey and an x-playback-session-id header (Zeek; Quarant INSECURE_HTTP_AUTH and INSECURE_HTTP_TOKEN 3 each); otherwise plaintext only to OCSP, push/config (init.ess.apple.com 'ix') and one software download with a cookie (appldnld.apple.com, 03-28); 2430 TLS1.2 (13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：Siri section of Apple privacy site, written for iOS; product not named; the audio itself may be encrypted inside the file (not visible); the request shows which audio was fetched; the sentence is from Apple's TV/Siri privacy text, applied to the HomePod
- **claims.tsv の行**：146（見出しを 1 行目とした行番号）
- **確認**：

## 7. Sonos PLAY:1：食い違いの候補（contradiction candidate (T1a)）

- **主張**："When we transmit data over the Internet, we protect it through the use of encryption."
- **文書**：D3、アーカイブ 2018-02-02（キャプチャとのずれ -1.5 か月）。https://web.archive.org/web/20180202085145/https://www.sonos.com/en-us/legal/privacy
- **保存した版**：`sonos_privacy-20180202.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external+lan
- **根拠**：plaintext GET to update.sonos.com with URL parameters named householdid, serial, sonosid and version fields; Quarant INSECURE_HTTP_TOKEN 51, I4_INSECURE_FIRMWARE_UPDATE_HTTP 31 (13 days: 03-20, 03-21, 03-28, 04-10..19); plaintext requests with content to the internet 165 in all, many to third parties (legato.radiotime.com, streamtheworld.com); the speaker updated twice during the capture, each time downloading its firmware in plaintext HTTP from update-firmware.sonos.com: on 03-20 (8.3 MB at 21:42 and 8.8 MB at 21:43 UTC; 33.15 → 34.16 → 41.3) and on 04-13 (8.8 MB at 16:34 UTC; 41.3 → 42.2), rebooting after each (Zeek conn and http, versions.py; Quarant I4_INSECURE_FIRMWARE_UPDATE_HTTP at the same minutes)
- **注意**：scope: all data over the Internet (device and app); not LAN; vendor-wide privacy statement; the update check carries device and household identifiers, not necessarily personal data
- **claims.tsv の行**：217（見出しを 1 行目とした行番号）
- **確認**：

## 8. Sonos PLAY:1：食い違いの候補（contradiction candidate (T1a)）

- **主張**："In addition, your data is protected with encryption, such as Transport Layer Security (TLS), during transition over the Internet."
- **文書**：D3、アーカイブ 2018-02-02（キャプチャとのずれ -1.5 か月）。https://web.archive.org/web/20180202085145/https://www.sonos.com/en-us/legal/privacy
- **保存した版**：`sonos_privacy-20180202.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external+lan
- **根拠**：same as above (plaintext update.sonos.com requests and three plaintext firmware downloads on 03-20 and 04-13)
- **注意**：scope: over the Internet (device and app); not LAN; vendor-wide privacy statement
- **claims.tsv の行**：218（見出しを 1 行目とした行番号）
- **確認**：

## 9. Sonos PLAY:1：食い違いの候補（contradiction candidate (T1a)）

- **主張**："Any data we transmit over the internet is protected using encryption."
- **文書**：D3、アーカイブ 2018-02-02（キャプチャとのずれ -1.5 か月）。https://web.archive.org/web/20180202085145/https://www.sonos.com/en-us/legal/privacy
- **保存した版**：`sonos_privacy-20180202.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external+lan
- **根拠**：same as above (plaintext update.sonos.com requests and three plaintext firmware downloads on 03-20 and 04-13)
- **注意**：FAQ part of the statement; same claim as above; vendor-wide privacy statement; the strongest wording of the three
- **claims.tsv の行**：219（見出しを 1 行目とした行番号）
- **確認**：

## 10. Withings Home：食い違いの候補（contradiction candidate (T2)）

- **主張**："Nokia Home uses bank level technologies such as AES-256 and secure HTTP (HTTPS) to protect your data at the device, cloud and app level so that all your data is stored safely."
- **文書**：D1、アーカイブ 2018-04-04（キャプチャとのずれ 0.0 か月）。https://web.archive.org/web/20180404154334/https://health.nokia.com/us/en/home
- **保存した版**：`withings_home_product-20180404.txt`
- **型・範囲**：T2、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：5248 of 5259 TLS handshakes with the real servers negotiated AES-128 (ECDHE_RSA_WITH_AES_128_GCM_SHA256); 11 used AES-256; on the LAN, 3 DTLS 1.0 sessions with the phone used AES-256 (Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19, the dataset's man-in-the-middle test sessions excluded)
- **注意**：names AES-256 and HTTPS at device, cloud and app level; also T1; 'bank level' not judged; 'stored safely' is storage; sold as Nokia Home at capture time; sentence ends with 'stored safely', so AES-256 may refer to storage; also 3 plaintext POST, see next rows
- **claims.tsv の行**：250（見出しを 1 行目とした行番号）
- **確認**：

## 11. Withings Home：食い違いの候補（contradiction candidate (T1a)）

- **主張**："Communication via Secure Socket Layer (SSL)"
- **文書**：D1、アーカイブ 2018-04-04（キャプチャとのずれ 0.0 か月）。https://web.archive.org/web/20180404154334/https://health.nokia.com/us/en/home
- **保存した版**：`withings_home_product-20180404.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：4 plaintext POST to scalews.withings.net with URL parameter named action and a text body (Zeek); 5259 TLS otherwise (13 days: 03-20, 03-21, 03-28, 04-10..19, test sessions excluded)
- **注意**：spec table, Security row; sold as Nokia Home at capture time
- **claims.tsv の行**：251（見出しを 1 行目とした行番号）
- **確認**：

## 12. Harman Kardon Invoke：食い違いの候補（contradiction candidate (T1a)）

- **主張**："Harman engages the use of numerous technological security measures to preserve the security of your information, including without limitation, encryption technologies and authentication tools."
- **文書**：D3、アーカイブ 2018-03-15（キャプチャとのずれ -0.2 か月）。https://web.archive.org/web/20180315093228/http://www.harman.com:80/privacy-policy
- **保存した版**：`harman_privacy-20180315.txt`
- **型・範囲**：T1、主張の範囲 all、観測の範囲 external
- **根拠**：15 plaintext GET to esdk-ffl.spotify.com with URL parameters named key_id, value (Zeek); 2212 TLS otherwise (13 days: 03-20, 03-21, 03-28, 04-10..19, test sessions excluded)
- **注意**：only 'encryption is used' could be judged; scope not stated (website and products); same text on harmankardon.com/privacy-policy.html 2018-01-23; policy last updated 2016-03-31; vague claim: only 'encryption is used' judged; destination is the third-party Spotify SDK and the content of the parameters is unknown
- **claims.tsv の行**：268（見出しを 1 行目とした行番号）
- **確認**：

## 13. Canary：文言の上で食い違い（wording-only contradiction）

- **主張**："Secure web transfer (SSL/TLS)"
- **文書**：D1、アーカイブ 2018-03-23（キャプチャとのずれ 0.0 か月）。https://web.archive.org/web/20180323133427/https://canary.is/canary/
- **保存した版**：`canary_product-20180323.txt`
- **型・範囲**：T1、主張の範囲 all、観測の範囲 external
- **根拠**：158 plaintext HEAD to h.canaryis.com:80, no body or parameters (Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19); TLS 26324/26334 ECDHE_RSA_WITH_AES_256_GCM_SHA384, 6 ECDHE_RSA_WITH_AES_256_CBC_SHA384, 4 ECDHE_RSA_WITH_AES_128_GCM_SHA256 (the AES-128 ones to o.canaryis.com and v.canaryis.com on 03-20 only; Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19, the dataset's man-in-the-middle test sessions excluded)
- **注意**：spec section 'Security & Data Protection'; range not stated
- **claims.tsv の行**：288（見出しを 1 行目とした行番号）
- **確認**：

## 14. Canary：食い違いの候補（contradiction candidate (T2)）

- **主張**："AES 256-bit data encryption"
- **文書**：D1、アーカイブ 2018-03-23（キャプチャとのずれ 0.0 か月）。https://web.archive.org/web/20180323133427/https://canary.is/canary/
- **保存した版**：`canary_product-20180323.txt`
- **型・範囲**：T2、主張の範囲 all、観測の範囲 external
- **根拠**：TLS 26324/26334 ECDHE_RSA_WITH_AES_256_GCM_SHA384, 6 ECDHE_RSA_WITH_AES_256_CBC_SHA384, 4 ECDHE_RSA_WITH_AES_128_GCM_SHA256 (the AES-128 ones to o.canaryis.com and v.canaryis.com on 03-20 only; Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19, the dataset's man-in-the-middle test sessions excluded)
- **注意**：spec section; unclear whether transport or storage; weak candidate: 4 of 8010 handshakes used AES-128
- **claims.tsv の行**：289（見出しを 1 行目とした行番号）
- **確認**：

## 15. Canary：文言の上で食い違い（wording-only contradiction）

- **主張**："If a customer uses an open or insecure Wi-Fi network (or in the event their home network is ever compromised), they can feel comfortable knowing their video and data connection to the Canary Cloud is securely encrypted."
- **文書**：D2、アーカイブ 2018-02-27（キャプチャとのずれ -0.7 か月）。https://web.archive.org/web/20180227160118/https://canary.is/uk/security/
- **保存した版**：`canary-uk-security-20180227.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：158 plaintext HEAD to h.canaryis.com:80, no body or parameters (Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：video and data connection to the cloud
- **claims.tsv の行**：292（見出しを 1 行目とした行番号）
- **確認**：

## 16. Canary：文言の上で食い違い（wording-only contradiction）

- **主張**："Canary connects directly to Canary Services through authenticated and encrypted channels."
- **文書**：D4、アーカイブ 2019-07-16（キャプチャとのずれ 14.9 か月）。https://web.archive.org/web/20190716202759/https://help.canary.is/hc/en-us/articles/115005468648-How-do-I-know-my-Canary-s-connection-is-secure-
- **保存した版**：`canary_help_conn_secure-20190716.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：158 plaintext HEAD to h.canaryis.com:80, no body or parameters (Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：after capture; claim archived after capture
- **claims.tsv の行**：309（見出しを 1 行目とした行番号）
- **確認**：

## 17. Piper nv：文言の上で食い違い（wording-only contradiction）

- **主張**："All connections to and from Piper (including Live video, 2-way audio, cloud communications and video clips) are encrypted and authenticated."
- **文書**：D4、アーカイブ 2019-07-21（キャプチャとのずれ 15.0 か月）。https://web.archive.org/web/20190721215820/https://getpiper.zendesk.com/hc/en-us/articles/200684304-How-secure-is-Piper-How-can-I-be-sure-it-won-t-be-hacked-
- **保存した版**：`piper_zd_how_secure-20190721.txt`
- **型・範囲**：T1、主張の範囲 all、観測の範囲 external
- **根拠**：5 plaintext GET without content to static.getPiper.com on 04-16; everything else TLS (17865 TLS1.2 handshakes, all with forward secrecy) (Zeek, flowscan.py, 13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：after capture; revised wording of the same article; claim archived after capture
- **claims.tsv の行**：349（見出しを 1 行目とした行番号）
- **確認**：

## 18. Piper nv：文言の上で食い違い（wording-only contradiction）

- **主張**："Piper encrypts all outbound communication to its secure cloud using AES-128 and AES-256 algorithms."
- **文書**：D2、アーカイブ 2019-07-21（キャプチャとのずれ 15.0 か月）。https://web.archive.org/web/20190721211821/https://getpiper.zendesk.com/hc/en-us/articles/219256067-Security-and-Privacy-Details
- **保存した版**：`piper_zd_secpriv-20190721.txt`
- **型・範囲**：T2、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：16115 AES_256_GCM and 1750 AES_128 handshakes, as claimed; but 5 plaintext GET without content to static.getPiper.com on 04-16 (Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19, the dataset's man-in-the-middle test sessions excluded)
- **注意**：after capture (article dated January 27, 2019); claim archived after capture; the algorithms match; only the 'all outbound' part fails, with content-less requests
- **claims.tsv の行**：351（見出しを 1 行目とした行番号）
- **確認**：

## 19. Philips Hue Bridge：食い違いの候補（contradiction candidate (T1a)）

- **主張**："Philips Lighting, transfers data securely (using SSL) and will encrypt some data, such as your MAC address when it is stored."
- **文書**：D3、アーカイブ 2017-08-18（キャプチャとのずれ -7.0 か月）。https://web.archive.org/web/20170818072006/http://www2.meethue.com/en-us/privacy-policy
- **保存した版**：`hue_privacy-20170818.txt`
- **型・範囲**：T1、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：3208 plaintext HTTP requests with content from the bridge to Philips hosts (dcp.cpp.philips.com 968, www.ecdinterface.philips.com 916, bridge.meethue.com with URL parameters named auth and sso), 1905 with an Authorization header (Zeek); Quarant INSECURE_HTTP_AUTH 1873; TLS with the real servers only 6 times (7 more were the dataset's MITM test) (13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：in the section on data collected via the Website and the App; 'using SSL' is the transfer claim, storage encryption is not assessable; the sentence follows the list of bridge data (bridge ID, serial number, usage and crash data), so it covers data sent by the bridge; claim_scope corrected to device-cloud
- **claims.tsv の行**：526（見出しを 1 行目とした行番号）
- **確認**：

## 20. Wink Hub 2：食い違いの候補（contradiction candidate (T2: certificate validation)）

- **主張**："We adopt security measures that include certificate pinning, encryption, two-factor authentication for all system administrators, and regular security audits."
- **文書**：D4、アーカイブ 2017-07-08（キャプチャとのずれ -8.4 か月）。https://web.archive.org/web/20170708204125/https://www.wink.com/help/faq/
- **保存した版**：`wink_help_faq-20170708.txt`
- **型・範囲**：T1、主張の範囲 all、観測の範囲 external
- **根拠**：in the dataset authors' man-in-the-middle test (04-12, forged certificate issued by thing-catcher.gtisc.gatech.edu), the hub sent application data after the handshake in 21 of 42 sessions to hub-api.wink.com (mitm_sessions.py, tls_records.zeek); the other 21 ended with a client alert. Encryption itself: 103 TLS1.2 handshakes with the real servers, no plaintext HTTP to the internet (Zeek, test sessions excluded, 13 days: 03-20, 03-21, 03-28, 04-10..19). YourThings scorecard: MITM device-to-cloud 4/4
- **注意**：vendor-wide help FAQ; scope (app or hub) not stated; the pinning part is judged from the dataset's own active test (D35), which a strictly passive observer cannot run; encryption part consistent as observed
- **claims.tsv の行**：586（見出しを 1 行目とした行番号）
- **確認**：

## 21. iRobot Roomba：食い違いの候補（contradiction candidate (T2)）

- **主張**："Currently, we use AES 256-bit encryption and Transport Layer Security (TLS v1.2)."
- **文書**：D2、アーカイブ 2018-11-10（キャプチャとのずれ 6.7 か月）。https://web.archive.org/web/20181110041231/https://webapi.irobot.com//Legal/Documents/North-America/United-States/Legal-Documents/Data-Security.aspx?sc_lang=en
- **保存した版**：`irobot-datasecurity-body-20181110041231.txt`
- **型・範囲**：T2、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：TLS with iRobot's own server disc-prod.iot.irobotapi.com used AES-128 (TLS_RSA_WITH_AES_128_CBC_SHA256, 17 handshakes), as did cloudfront downloads (17); only the MQTT connections on tcp/8883 used AES-256 (21 TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 1 TLS_RSA_WITH_AES_256_CBC_SHA256; 6 more without a visible handshake); all TLS 1.2 (Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：read in a browser (body is an embedded page, earliest capture after the capture period); the sentence before says 'All iRobot connected products communicate with the iRobot cloud service using robust encryption'; weak on timing (7 months after)
- **claims.tsv の行**：788（見出しを 1 行目とした行番号）
- **確認**：

## 22. Logi Circle：食い違いの候補（contradiction candidate (T2)）

- **主張**："Logitech uses unique, random and automatically rotating AES 256 Bit Dual Layer Encryption to protect and store your audio and video content."
- **文書**：D4、アーカイブ 2018-03-13（キャプチャとのずれ -0.2 か月）。https://web.archive.org/web/20180313165545/http://support.logitech.com:80/en_us/product/circle/faq
- **保存した版**：`logi_sup_circle_faq-20180313.txt`
- **型・範囲**：T2、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：all 19 TLS handshakes with the real servers (including api.video.logi.com) used AES-128 (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); 6 more were the dataset's man-in-the-middle test and are excluded (Zeek, 13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：'Dual Layer' may mean an inner encryption layer inside TLS, which is not visible; 'store' is storage
- **claims.tsv の行**：798（見出しを 1 行目とした行番号）
- **確認**：

## 23. Nest Cam IQ：一致（確かめが要る）（consistent (as observed)）

- **主張**："Dropcams and Nest Cams connect to the Nest cloud service using 2048-bit RSA private keys for key exchange, implement perfect forward secrecy and encrypt data between Dropcam/Nest Cam and the Nest cloud service using AES 128-bit encryption and Transport Layer Security (TLS)."
- **文書**：D2、アーカイブ 2018-04-10（キャプチャとのずれ 0.0 か月）。https://web.archive.org/web/20180410151638/https://nest.com/privacy/data/
- **保存した版**：`nest_com_privacy_data-20180410.txt`
- **型・範囲**：T2、主張の範囲 device-cloud、観測の範囲 external
- **根拠**：350/389 handshakes TLS1.0 ECDHE_RSA_WITH_AES_128_CBC_SHA (forward secrecy), 39 without a visible handshake; server certificates RSA 2048 (350); the Nest Cam IQ's own (client) certificate is ECDSA P-224 in all 336 handshakes where it was visible, not RSA (Zeek x509, 13 days: 03-20, 03-21, 03-28, 04-10..19)
- **注意**：needs review: if '2048-bit RSA private keys' means the camera's own key, the Nest Cam IQ contradicts it (ECDSA P-224); if it means the server's key used to sign the ECDHE exchange, it is consistent. The sentence names Dropcams and Nest Cams, possibly written before the IQ
- **claims.tsv の行**：6（見出しを 1 行目とした行番号）
- **確認**：
