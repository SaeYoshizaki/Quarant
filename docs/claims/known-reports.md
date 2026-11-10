# 先に報告されていた観測（2026-11-10）

食い違いの候補ごとに、同じ観測を先に報告していた資料をまとめた。詳しい比較は [ring-prior-work.md](ring-prior-work.md)、[deep-checks.md](deep-checks.md)、[sonos-paper.md](sonos-paper.md)。

- **種類**：論文は査読つきの会議・論文誌。発表、ブログ、試験報告は論文ではない。
- **最後の列**は、その資料がメーカーの説明との食い違いとして指摘していたか。
- Alrawi ほかの Table VII は、2026-11-10 に PDF の 18 ページを拡大して読んだ。Subahi ほかは同じ日に本文を読んだ。ほかは上の文書からの引用。

| 製品 | 見つけた食い違い（主張／観測） | 先に報告していた資料 | 種類 | 報告していたこと | 説明との食い違いとしての指摘 |
|---|---|---|---|---|---|
| Ring Video Doorbell（除外） | 「Encryption: Bank-grade」／平文の HTTP と MAC を使う Basic 認証、平文の SIP、暗号化していない映像の RTP（版 1.10.70） | Nick, geekyschmidt.com, 2016-07-24 | ブログ | 平文の HTTP、MAC を使う Basic、TLS を使わない SIP | なし |
| | | S. Kidder, kidder.io, 2017-07-04 | ブログ | 平文のポーリング、Basic、平文の SIP | なし |
| | | R. Alharbi, D. Aspinall, IET 2018, doi:10.1049/cp.2018.0047（Table 2、3） | 論文 | カメラからサーバーへの RTP が暗号化されていない。型番と版の記載なし | なし |
| | | Dojo by BullGuard, 2019-02-27（CVE-2019-9483） | ブログ | 新しい版の映像の構造、スマートフォン側の平文の RTP | なし |
| | | M. T. Paracha ほか, IMC 2021（Fig.2、§5.1） | 論文 | 弱い暗号の提示。TLS の質だけ | なし |
| | | O. Alrawi ほか, IEEE S&P 2019（Table VII, p.18） | 論文 | 指摘していない。機器とクラウドの間は「すべて暗号化」、HTTP の欄は空 | ― |
| Wink Hub 2 | 「certificate pinning」／作成者の偽の証明書の接続 42 回中 21 回で、ハブがデータを送った | Alrawi ほか, S&P 2019（Table VII, p.18） | 論文 | 機器とクラウドの間の中間者が成功（✓）。同じデータセットの作成者 | なし |
| | | Paracha ほか, IMC 2021（Table 7, p.8） | 論文 | 2 つの宛先の 1 つで偽の証明書を受け入れた（2021-03） | なし |
| TP-Link HS105、LB130 | 「encryption and SSL technology … to secure your personal information」／LAN の制御が公開の鍵の XOR だけで、アカウント名と緯度経度が読める | A. Subahi, G. Theodorakopoulos, IEEE FiCloud 2018, doi:10.1109/FiCloud.2018.00022（§IV-D-2, p.105。[ORCA の受理版](https://web.archive.org/web/20220709115639/https://orca.cardiff.ac.uk/id/eprint/123089/1/Ensuring%20compliance%20of%20IoT%20devices%20with%20their%20Privacy%20Policy%20Agreement.pdf)） | 論文 | 型番は HS110 で別。アプリとプラグの LAN の通信を、アプリの暗号の関数で戻して平文で読めた | なし。逆に、ポリシーは暗号化に触れていないとし、暗号化している側に数えた。どの版のポリシーかは書いていない（未確認） |
| | | softScheck, tplink-smartplug, 2016 | GitHub | XOR の自己鍵（初期値 171）、認証がない | なし |
| | | Alrawi ほか, S&P 2019（Table VII, p.18） | 論文 | 指摘していない。アプリと機器の間は「すべて暗号化」 | ― |
| Withings Home | 「Communication via Secure Socket Layer (SSL)」／平文の POST 4 回（証明書の一覧の取得、MAC アドレスを送る） | E. Clausing, AV-TEST, 2017-01-06 | 試験報告 | 同じ。MP3 とファームウェアの平文の取得も | なし |
| | | Alrawi ほか, S&P 2019（Table VII, p.18） | 論文 | 指摘していない。すべて暗号化 | ― |
| Sonos PLAY:1 | 「Any data we transmit over the internet is protected using encryption.」ほか／識別子を入れた更新の確認を平文の HTTP で送る | P. Geissler, HITB Amsterdam 2023（p.58） | 発表 | 同じ URL の形と識別子。ただし示す URL は HTTPS | なし |
| | | Alrawi ほか, S&P 2019（Table VII, p.18） | 論文 | 機器とクラウドの間は「部分的に暗号化」（◐）。何が平文かは書いていない | なし |
| | | S. Hilt, Trend Micro, 2017-12。S. P. Kavalaris, E. Serrelis, ISDF 2014 | 報告、論文 | LAN 側の問題（状態ページ、認証のないサービス） | なし |
| Philips Hue（除外） | 「using SSL」（2017-09 の版まで）／平文の HTTP（本文は AES で不透明） | M. Morgenstern, AV-TEST, 2017-06-19 | 試験報告 | HTTP の上で AES | なし |
| | | Alrawi ほか, S&P 2019（Table VII, p.18） | 論文 | 指摘していない。すべて暗号化 | ― |

- **先行資料を調べていない候補**：Apple HomePod、August Doorbell Cam（どちらも保留）。一次ふるいで外した Canary、Harman Kardon Invoke、Logi Circle、iRobot Roomba、Piper nv。
- **方法の先行研究**：Subahi ほか 2018 は、プライバシーポリシーと通信を比べている（11 社のポリシー、2 機器）。説明と通信を比べること自体は新しくない。

## まとめ

- **論文がすでに報告していた観測**：Ring の暗号化されていない映像（Alharbi & Aspinall 2018）、Wink Hub 2 の中間者（Alrawi ほか 2019、Paracha ほか 2021）、TP-Link の LAN の通信が読めること（Subahi ほか 2018、型番は別）。
- **メーカーの説明との食い違いとして指摘した資料は、読んだ範囲にはなかった。** Subahi ほかは説明と通信を比べたが、TP-Link のポリシーは暗号化に触れていないとした。資料が見つからないことは新規性の根拠にしない。
- Sonos は、URL の形（Geissler 2023）と「部分的に暗号化」（Alrawi ほか 2019）だけが先にある。
