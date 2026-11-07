# 候補の一次ふるい（2026-11-07）

候補を 1 件ずつ深く調べる前に、Ring と Hue で結論を変えた 3 点で全候補をふるった。深掘りは残ったものだけにする。

- **時期**：収録（2018-03-20〜04-19）の直前と直後の版に、同じ文があるか。`scripts/claims/triage_docs.py`（Wayback、出力は `~/datasets/claims/triage/docs.tsv`）。
- **範囲**：その文が機器の通信を指すか。claims.tsv の note と前後の文脈から。
- **観測**：「平文」の中身が、URL のパラメータや本文の構造として読めるか。`scripts/claims/triage_http.py`（既存の `gt.log` のキー名だけを集計）。

○は確かめられた、△は弱いか未確認、×は満たさない。観測の欄は既存の解析からの集計で、PCAP は読み直していない。

| 製品（claims.tsv の行） | 時期 | 範囲 | 観測 | 案 |
|---|---|---|---|---|
| **Sonos PLAY:1**（217〜219） | ○ 直前 2018-02-02 にあり。直後 2018-04-24 は 219 のみ残る | ○ インターネット上で送るデータすべて | ○ Sonos の更新サーバーへの平文の要求の URL に householdid、serial、sonosid。ファームウェアも平文の HTTP | **深掘り 1** |
| **Withings Home**（251、250） | ○ 直前 2018-03-16、直後 2018-04-25 ともにあり | ○ 製品の仕様の欄（251） | △ 平文の POST 4 回、本文あり（JSON でもフォームでもない。中身が読めるかは未確認）。250 の AES-256 は保存の意味かもしれない | **深掘り 2** |
| **Wink Hub 2**（586） | ○ 2017-07-08、2018-07-16 ともにあり | △ アプリかハブか書いていない | ○ 作成者の偽の証明書の接続 42 回中 21 回で、握手のあとにデータを送った | **深掘り 3** |
| **TP-Link HS105、LB130**（61、71） | ○ 直前 2018-01-31、直後 2018-06-23 ともにあり | △ 個人情報の保護全般 | ○ LAN の制御が公開鍵の XOR だけで、アカウント名と緯度経度が読める（LAN 内だけ） | 深掘り 4 |
| August Doorbell Cam（213） | ○ | × 業界標準で PII を守る（曖昧） | △ 第三者（PubNub）への GET 3 回、本文なし | 保留 |
| Apple HomePod（146） | ○ | × Siri と iOS の文書で、HomePod の名前がない | △ 音声の取得 3 回（中身は暗号化の可能性） | 保留 |
| Harman Kardon Invoke（268） | ○ 直前にあり、直後の版にはない | × 曖昧 | × 第三者（Spotify の SDK）への GET 15 回、本文なし | 除外（2026-11-07） |
| Canary（3、4、288、289、292、309） | ○ | ○ | × 平文は HEAD 158 回だけで中身なし。AES-128 は 26,334 回中 4 回 | 除外（2026-11-07） |
| Logi Circle（798） | △ 照合できず（読んだ版でも文が機械的に見つからない） | △ 保存と内側の暗号 | × TLS の暗号の強さだけの差 | 除外（2026-11-07） |
| iRobot Roomba（788） | × 収録後（2018-11）の版しかない | | | 除外（2026-11-07） |
| Piper nv（349、351） | × 収録後（2019-07）の版しかない | | × 中身のない GET 5 回 | 除外（2026-11-07） |
| Philips Hue Bridge（526） | × 「using SSL」は 2017-09-18 の版まで、2017-09-24 以降の版にない | △ ウェブサイトとアプリで集めるデータ | × インターネット側の本文は 13 日分すべて不透明（`CB-Encrypted; cipher=AES` か 16 進で 16 バイト単位） | 除外（2026-11-07） |
| Ring Video Doorbell | | | | 除外済み（[ring-prior-work.md](ring-prior-work.md)） |

## Hue の 13 日分（`~/datasets/claims/hue13/`、スクリプトは `scripts/claims/hue/`）

- 型番は BSB002（`description.xml`、`eth1-20180321.0000.1521608400` のフレーム 582）。版は SSDP で 1.15.0 → 1.23.0（04-11）→ 1.24.0（04-13）。
- Philips のサーバーへの平文の HTTP は 1 日 220〜811 回（1.24.0 からは約 60 回）。要求の本文は 13 日分すべて不透明で、平文に見えたのはエラー応答の HTML だけ。`Authorization: CBAuth` は要求ごとに値が変わる。先行の報告（AV-TEST, M. Morgenstern, 2017-06-19, [Hue! Let there be light!](https://web.archive.org/web/20220703112515/https://www.iot-tests.org/2017/06/hue-let-there-be-light/)、Online communication の節）の「HTTP の上で AES」と一致する。
- ファームウェアは平文の HTTP で取得していた（`GET fds.cpp.philips.com/firmware/...`、04-11 19:45 と 04-12 01:25 に 256,632 バイト、04-12 02:10 に 7,632,617 バイト、エントロピー 8.00）。handoff の「大きな取得は見えない」は誤り。
- 1.23.0 から `ws.meethue.com` への TLS が始まる。作成者の偽の証明書の接続は 7 回とも Hue が拒否した（`mitm-yourthings.tsv`）。
- 未取得：Ferreira の CVE-2017-14797 の記事、Dhanjani の 2013 年の論文（本人のサイトは期限切れの証明書、Wayback に読める版なし）、Notra ほか 2014。

## 次

深掘りの結果：Sonos は候補を維持（[sonos-check.md](sonos-check.md)）。Withings Home と TP-Link は既知の問題の再確認、Wink Hub 2 は主張の範囲が未確認（[deep-checks.md](deep-checks.md)）。除外は利用者の判断で claims.tsv に反映した（判定の列は not assessable）。
