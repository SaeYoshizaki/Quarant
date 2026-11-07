# 深掘り 2〜4：Withings Home、Wink Hub 2、TP-Link（2026-11-07）

[triage.md](triage.md) の続き。深掘り 1（Sonos）は [sonos-check.md](sonos-check.md)。どれも短く確かめた。

## まとめ

| 製品 | 判定の案 | 理由 |
|---|---|---|
| Sonos PLAY:1 | **候補を維持（強い）** | [sonos-check.md](sonos-check.md) |
| Withings Home | 弱い（既知の問題の再確認） | 平文は 13 日で 4 回の証明書の取得だけ。MAC アドレスを送る。AV-TEST 2017 が同じことを報告している |
| Wink Hub 2 | 未確認（主張の範囲） | 「certificate pinning」がハブに当てはまるか、文書から決められない。同じ社のセキュリティのページは「アプリが送るデータ」と書く |
| TP-Link HS105、LB130 | 弱い（既知の問題の再確認） | LAN の XOR は softScheck 2016 が公開している。主張は個人情報の保護一般 |

## Withings Home（claims.tsv 250、251）

- **主張**：製品ページの仕様の欄「Communication via Secure Socket Layer (SSL)」（[2018-04-04 の版](https://web.archive.org/web/20180404154334/https://health.nokia.com/us/en/home)。直前 2018-03-16、直後 2018-04-25 の版にもある）。250 の AES-256 は、同じ文が保存の話で終わるので、通信の暗号の強さの主張かは未確認。
- **観測**（PCAP で確認したのは 03-20。`~/datasets/claims/withings13/`）：`eth1-20180320.2235.1521603300` のフレーム 35540 が `POST scalews.withings.net/cgi-bin/v2/certificate?action=…`。本文はフォーム形式で、キーは `mac_address`、`service`、`challenge`、`key_type`、`method`。`mac_address` の値は機器の MAC と一致（値は記録していない）。応答（フレーム 35572）は証明書の一覧の JSON（キー `body`、`certificates`、`date`、`digest`、`status`、6,341 バイト）。
- **13 日の数**（既存の gt.log）：平文の要求はこの形の POST だけで、03-20、04-11（2 回）、04-18 の計 4 回。本文はどれも 101 バイト。ほかはすべて TLS（5,259 回）。
- **先行研究**：E. Clausing（AV-TEST）, [Testing Withings Home](https://web.archive.org/web/20220519012211/https://www.iot-tests.org/2017/01/testing-withings-home/), 2017-01-06。ほとんどの接続は TLS 1.2 か DTLS 1.0。証明書の一覧を平文で取得し、MAC アドレスを平文で送り、MP3 とファームウェアも平文で取得すると報告。**同一の既知問題**。今回の 13 日では、MP3 とファームウェアの平文の取得は見えなかった（版の違いか、更新がなかったためかは未確認。YourThings の評価の版は 409）。

## Wink Hub 2（claims.tsv 586）

- **主張**：ヘルプの FAQ「Is Wink secure?」の「certificate pinning」（[2017-07-08 の版](https://web.archive.org/web/20170708204125/https://www.wink.com/help/faq/)、2018-07-16 の版にもある）。対象を書いていない。同じ社の [Security のページ](https://web.archive.org/web/20170423174149/https://www.wink.com/security/)（2017-04-23、収録までにほかの版なし）は、証明書による暗号化を「アプリが送る個人のデータ」について書いている。
- **観測**（既存の解析、`mitm-yourthings.tsv`）：04-12 の作成者の偽の証明書の接続 42 回（`hub-api.wink.com`）のうち 21 回で、ハブが握手のあとにデータを送った。残り 21 回は拒否した。
- **先行研究**：Paracha ほか, IoTLS, IMC 2021 の Table 7（p.8）で、Wink Hub 2 は 2 つの宛先のうち 1 つで偽の証明書を受け入れた。時期は 2021-03 で、今回より後。**関連する既知の問題**。
- **未確認**：ハブが送ったデータの中身（偽の証明書の接続の中は見えない）。主張がハブに当てはまるか。

## TP-Link HS105、LB130（claims.tsv 61、71）

- **主張**：プライバシーポリシー（2018-01-31、2018-06-23 の版にもある）の「encryption and SSL technology … to secure your personal information」。個人情報の保護一般で、通信の種類を書いていない。
- **観測**（既存の解析）：04-13 と 04-15 にアプリが LAN で操作したとき、応答に XOR を戻すとアカウント名、緯度経度（プラグ）が読める。インターネットへの通信は TLS。
- **先行研究**：softScheck の [tplink-smartplug](https://github.com/softScheck/tplink-smartplug)（2016-07〜10 のコミット）が、tcp/9999 の XOR の自己鍵（初期値 171）と認証のなさを公開している（本文は README のみ確認。元の記事は未取得）。**同一の既知問題**。
