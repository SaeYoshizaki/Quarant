# 試し：YourThings 2018 の 5 製品で、製造者の主張と通信を突き合わせる

2026-10-30。D31 の進め方を、少数の機器で最初から最後まで通して確かめるためのもの。

## 方法

- **主張**：Wayback Machine で、キャプチャ（2018-04-10〜12）より前のいちばん近い版を取った。製品ページ、セキュリティのページ、プライバシーポリシー。引用は原文のまま。
- **通信**：YourThings の 2018-04-10〜12。Zeek の記録（`~/datasets/gt-yt/`、Quarant とは独立。TLS の版・暗号スイート・SNI、HTTP は要求の形だけで値は含まない）と、Quarant の解析結果（`~/datasets/runs-yt5/`）。機器は MAC で特定した（[devices.tsv](devices.tsv)）。
- **判定**：主張ごとに「どんな通信が見えたら食い違いか」を決めてから数えた。判定は 4 つ：食い違いの候補／主張どおり／主張が曖昧で判定できない／主張が見つからない。食い違いの候補は、主張が誤りだという意味ではない。

## 結果

| 製品 | 主張（出典） | 観測（3 日） | 判定 |
|---|---|---|---|
| Ring Video Doorbell | "Encryption: Bank-Grade"（製品ページ、2017-04-20） | `fw.ring.com` への平文の HTTP の POST が 1 回。`Authorization: Basic` ヘッダーつき（Zeek と Quarant の `INSECURE_HTTP_AUTH` が一致。値は見ていない）。TLS は 1,566 回すべて TLS 1.2、`TLS_RSA_WITH_AES_128_CBC_SHA`（前方秘匿性なし） | **食い違いの候補**：暗号化をうたう機器が、認証情報を平文で送っている。「Bank-Grade」の中身は定義されていないので、暗号スイートの選び方は判定に使わない |
| Canary | "all video and data is securely encrypted between the device, the cloud, and the smartphone"、"All parts of our system—from the device to the cloud to the app—employ … secure HTTP access (HTTPS) using TLS/SSL"（セキュリティのページ、英国版 2018-02-27） | `h.canaryis.com` への平文の HTTP の HEAD が 34 回（本文なし、パラメータなし、応答は 301）。TLS は 5,954 回中 5,936 回が `ECDHE_RSA_WITH_AES_256_GCM_SHA384` | **文言の上では食い違い（中身はほぼない）**：「すべての部分が HTTPS」に対して平文の通信がある。ただし送っているのはヘッダーだけで、データや映像は平文では見えない |
| Nest Cam IQ | "connect to the Nest cloud service using 2048-bit RSA private keys for key exchange, implement perfect forward secrecy and encrypt data … using AES 128-bit encryption and Transport Layer Security (TLS)"（セキュリティのページ、2018-04-10）。"AES 128-bit encryption, TLS/SSL"（製品ページ、2018-04-10） | TLS の 157 回中 118 回が TLS 1.0、`ECDHE_RSA_WITH_AES_128_CBC_SHA`（前方秘匿性あり、AES-128）。39 回は握手が見えない。`ipv4.connman.net`（接続確認、第三者）への平文の GET が 5 回（本文なし） | **主張どおり**（見えた範囲で）。TLS 1.0 は主張に版が書かれていないので食い違いではない。接続確認は Nest への送信ではない |
| Nest Cam | 同上 | TLS の 93 回中 18 回が上と同じ。75 回は握手が見えない | **主張どおり**（見えた範囲で。見えない接続が多い） |
| Belkin NetCam HD | 製品ページ（2018-03-07）にセキュリティの主張なし。プライバシーポリシー（2018-04-08）は "the transmission of information via the Internet is not 100% secure" と保証しない書き方 | TLS の 585 回中 584 回が `TLS_RSA_WITH_AES_256_CBC_SHA`（前方秘匿性なし）。LAN 内の平文の HTTP の GET が 310 回 | **主張が見つからない** |
| Philips Hue Bridge | "developing and deploying best practice security features for our products and services"（製品セキュリティのページ、2017-12-23） | クラウド（`bridge.meethue.com` など）への平文の HTTP の POST が 3 日で 1,615 回。URL に `auth`、`sso` という名前のパラメータがある（値は見ていない）。TLS は 8 回だけ | **主張が曖昧で判定できない**（「ベストプラクティス」に対して平文の送信は目立つが、主張の中身が定義されていない） |

## 分かったこと

- **通信だけで確かめられる主張は、製造者によって書き方が大きく違う**。Nest は暗号スイートの性質（前方秘匿性、AES-128、TLS）まで書いていて、通信で確かめられた。Ring は「Bank-Grade」、Hue は「ベストプラクティス」のように中身のない言葉で、確かめられる部分が少ない。
- **主張がない製品もある**（Belkin NetCam HD）。食い違いは数えられないが、「主張なし」も結果になる。
- **観測が目立つ機器と、食い違いが出る機器は一致しない**。Hue は平文の送信がいちばん多いが、具体的な主張がない。Canary は主張が強いぶん、少しの平文で食い違いになる。
- **Zeek の記録で足りた**。TLS の暗号スイートと HTTP の要求の形が分かれば、今回の主張はすべて判定できた。Quarant は、Ring の認証ヘッダーの検出で一致を確かめるのに使った。

## 限界

- 当時のページは 1 つずつ探したので、見落とした文書がある。とくに Ring はセキュリティのページがアーカイブにない。マニュアルやアプリの中の説明は見ていない。
- 3 日間の通信だけ。ファームウェアの版は確かめていない。
- 握手が見えない TLS の接続（Nest）は、判定に入れていない。

## 次に決めること

1. 主張の書き方を分ける（具体的／曖昧／保証しない／なし）。数えるときの分母になる。
2. 主張の型ごとに「食い違いの条件」を決めて、表にする（暗号化、前方秘匿性、更新、認証情報）。
3. 集める文書の範囲（製品ページ、セキュリティのページ、プライバシーポリシー、マニュアル）をそろえる。
