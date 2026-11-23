# 18. D-Link DCS-8300LH（Passive-Mode-Study、フランス）

[一覧に戻る](README.md)

## 不足している情報（分析の前に）

- ハードウェアの版（A1 か v2 か）とファームウェアの版：通信に平文で出ていない。**未確認**。
- アプリ（mydlink）の版：アプリの通信は収録にない。**未確認**。
- 利用者の操作（遠隔での視聴、録画の設定）：データセットに操作の記録がない。中継の通路（下の D3）が利用者の視聴によるものかは**未確認**。

## 調査対象と前提条件

| 項目 | 内容 |
|---|---|
| 製品名・型番 | D-Link DCS-8300LH（mydlink Full HD Wi-Fi カメラ）。DHCP のホスト名 `DCS-8300LH`、vendor class `D-Link IP Camera`、mDNS `DCS-8300LH-30B0._dcp._tcp.local`、WebSocket の見出し `MD-MODEL: DCS-8300LH` |
| MAC・IP | b0:c5:54:4a:30:b0、192.168.231.181 |
| ハードウェア／ファームウェア／アプリ | 未確認（上） |
| 収録日時（UTC） | FR-Capture1：2023-11-24 15:00〜11-27 13:59。FR-Capture2：2024-05-03 17:00〜05-07 12:59（機器の通信があったのは 8 日） |
| データセット | Passive-Mode-Study（Badolato ほか、IEEE PerCom 2025）`Percom116Dataset/FR/FR-Capture1`、`FR-Capture2`。フランスの家庭。OpenWrt のルーターで tcpdump |
| 観測できた通信フェーズ | 待機中のクラウドとの常時接続、DNS、DHCP（NTP は見えない）、CA の証明書の束の確認、クラウドへの大きな上り（録画とみられる）、中継の通路（WebSocket）と P2P の試み（STUN）。初期設定・ペアリングは収録にない |
| 使用した公式文書 | 下の表 |
| 時点の不足 | 英語のグローバル版のポリシーは 2024-04-07 の保存しかない（施行日 2020-05-25 なので収録時点で有効）。フランス語版は収録前の保存がある |

**使用した公式文書**

| # | 文書 | 発行元 | 公開・更新 | 保存（Wayback） | 収録との関係 |
|---|---|---|---|---|---|
| A | Charte de protection des données à caractère personnel（フランス語のプライバシーポリシー）§11「Comment sont conservées en sécurité vos données personnelles?」 | D-Link（eu.dlink.com/fr/fr） | 更新 2021-05-28 | [2023-10-14](https://web.archive.org/web/20231014221441/https://eu.dlink.com/fr/fr/privacy) | 収録前。収録地の版 |
| B | Privacy Policy（英語、グローバル）§6「How do we keep your personal information secure?」 | D-Link（www.dlink.com/en） | 施行 2020-05-25 | [2024-04-07](https://web.archive.org/web/20240407160737/https://www.dlink.com/en/privacy) | 保存は収録後。施行日から収録時点で有効 |
| C | DCS-8300LH の製品ページ（フランス語） | D-Link（eu.dlink.com/fr/fr） | 不明 | [2023-09-21](https://web.archive.org/web/20230921101651/https://eu.dlink.com/fr/fr/products/dcs-8300lh-mydlink-full-hd-indoor-camera) | 収録前 |
| D | 同（英語、英国） | D-Link（eu.dlink.com/uk/en） | 不明 | [2023-12-10](https://web.archive.org/web/20231210132259/https://eu.dlink.com/uk/en/products/dcs-8300lh-mydlink-full-hd-indoor-camera) | 収録の直後（参考） |

文書 A の該当部分（§11）：「Lorsque vous commandez des services via notre site, nous utilisons le protocole de cryptage SSL (Internet Secure Sockets layer) pour protéger les données personnelles de nos clients. Ce protocole est également mis en place pour protéger les informations de votre compte, sécuriser les « journaux » de paramètre et services de vos appareils.」
文書 B（§6）は同じ内容の英語：「The SSL protocol is also implemented for (i) guarding your account information, and (ii) securing all logs of settings and Services of your devices.」
文書 C：「sécurité WPA3」「Enregistrez des vidéos dans le cloud sécurisé mydlink.」

**最も限定的な読み方**：文書 A・B の SSL の文は「サイトでの注文」「アカウントの情報」「機器の設定とサービスの『ログ（journaux）』」の 3 つにだけ SSL を使うと言っている。機器の通信全体を暗号化するとは書いていない。

## 比較結果

| ID | 通信フェーズ | PCAPで観測された事実 | 公式文書の記載 | 判定 | PCAP側の証拠 | 文書側の証拠 | 確信度 | 補足 |
|---|---|---|---|---|---|---|---|---|
| D1 | 待機中のクラウド接続 | `mp-eu-dcdda.auto.mydlink.com:443` へ TLS 1.2（131 接続、約 576 秒おき、8 日）。サーバーが選んだのは `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`。サーバー証明書は `*.auto.mydlink.com`（GlobalSign RSA OV SSL CA 2018、2023-08-31〜2024-10-01、名前は一致）。カメラも自分の証明書（主体 `37858745`、発行者 `mydlink Device CA`、SHA-1 署名、2018-02-09〜2037-10-27）を出す相互認証 | SSL を「機器の設定とサービスのログ」に使う | 一致 | `FR-Capture1.pcap` 2023-11-24 15:00:27.337042（最初の接続） | 文書 A §11、B §6 | 中 | 中身は暗号化されていて、ログかどうかは見えない |
| D2 | 証明書の更新の確認 | `HEAD http://ca-mgr.auto.mydlink.com/default/ca-bundle.crt` を平文の HTTP で 1 回。応答は 200、`application/x-x509-ca-cert`、6,015 バイト。取得（GET）はなかった | 記載なし（CA の束の扱いについての文はない） | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-24 15:40:00.596675（元のフレーム 42843） | 文書 A・B に該当なし | 高 | 証明書の確認はログではないので、限定的な読み方では SSL の文の対象外 |
| D3 | 中継の通路（遠隔の視聴とみられる） | `GET http://mp-eu-sas-1.auto.mydlink.com/relay`（`Upgrade: websocket`、`Sec-WebSocket-Protocol: stream-proxy`、`MD-MODEL: DCS-8300LH`）を平文で 3 回、応答 101。最初の WebSocket のフレーム（バイナリ、71 バイト）にトークンらしい値が平文で入る（値は quarant-results）。その後のフレームの中は RTP（PT 96・98）で、中身の先頭のビットはランダム（暗号化されているとみられる、推測） | 記載なし（中継の通路についての文はない） | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-26 22:28:19.349691（GET、元のフレーム 3204027）、22:28:19.377736（最初のフレーム、元のフレーム 3204034） | 文書 A・B に該当なし | 高 | 「services de vos appareils」を機器のサービス全体と広く読めば食い違いになるが、その読み方はとらない |
| D4 | クラウドへの大きな上り | 2023-11-27 に `mp-eu-rcdda-2〜12.auto.mydlink.com:443` へ TLS 1.2 で 1 接続あたり 5〜18 MB を送った（合わせて約 110 MB）。録画のアップロードとみられる（推測） | 「cloud sécurisé mydlink」に録画を保存 | 一致（送る経路は TLS） | `FR-Capture1.pcap` 2023-11-27 08:54:42.182077 ほか | 文書 C | 中 | 保存時の扱いは観測不能 |
| D5 | P2P の試み | `52.212.170.9:3478` に STUN、別の私設アドレス `192.168.1.100`（この家の LAN ではない）へ UDP。中身は `$` で始まるバイナリ | 記載なし | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-26 22:28:19.452617（STUN）、22:28:19.041592（UDP） | 該当なし | 中 | 相手の私設アドレスは、スマートフォンの側の LAN のアドレスとみられる（推測） |
| D6 | 名前解決 | DNS を平文でルーター（192.168.231.1）へ 6,131 回。名前は `*.auto.mydlink.com` の 16 種だけ | 記載なし | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-24 15:40:00.332468 | 該当なし | 高 | |
| D7 | 暗号の提示 | カメラは ClientHello で 86 種の暗号を出し、3DES など古い暗号も含む。選ばれたのは AES の GCM／CBC だけ | 記載なし | 公式文書に記載なし | `FR-Capture1.pcap` 2023-11-24 15:00:27 以降のすべての ClientHello | 該当なし | 高 | 弱い暗号の提示は食い違いではない |
| D8 | Wi-Fi | — | 「sécurité WPA3」 | 観測不能 | 有線側の収録なので無線の暗号は見えない | 文書 C | — | |
| D9 | 保存時の暗号化 | — | 「cloud sécurisé」 | 観測不能 | | 文書 C | — | |

## 1. 明確な矛盾

なし。

## 2. 条件付きの矛盾

なし。D3 は、文書の「services de vos appareils」を「機器のサービス全体」と読む場合だけ食い違いになる。プロンプトの決まり（最も限定的な読み方）に従い、とらない。

## 3. 公式文書に記載のない観測事項

- D3：中継の通路の開始（WebSocket の要求と最初のフレーム）が平文。最初のフレームにトークンらしい値。
- D2：CA の証明書の束の確認が平文の HTTP（HEAD だけ）。
- D5：STUN と、別の私設アドレスへの UDP。
- D6、D7。

## 4. 公式文書と一致した事項

- D1：待機中のクラウドとの接続は TLS 1.2（相互認証）。
- D4：大きな上りは TLS。

## 5. 観測不能・判断不能な事項

- D8（Wi-Fi の WPA3）、D9（クラウドでの保存）。
- TLS の中身（ログかどうか、映像かどうか）。
- 中継の通路の RTP の中身が暗号化されているか（ランダムに見えるという観測だけ。推測）。

## 6. 追加調査に必要なデータ

- 利用者の操作の記録（遠隔の視聴をした時刻）。
- ファームウェアの版（機器のウェブの画面、アプリの表示）。
- mydlink アプリ側の通信（スマートフォンの収録）。
- mydlink の技術文書（中継の通路の暗号化についての説明）。今回は見つからなかった。

## 断定できる範囲／できない範囲

- **断定できる**：中継の通路の開始と最初のフレームが平文の HTTP／WebSocket だったこと。CA の束の確認が平文だったこと。ほかのクラウドとの通信が TLS 1.2 だったこと（証明書、暗号）。
- **断定できない**：中継の中身が暗号化されているか。トークンの役割。それらが D-Link の言う「ログ」に当たるか。

## 前回（2026-11-22）との違い

- 前回は英語の 2024 年保存の版で「弱い候補（T1a）」とした。今回は収録前のフランス語版を見つけた（同じ内容）。
- プロンプトの決まり（最も限定的な読み方）で、D3 を「公式文書に記載なし」に下げた。
