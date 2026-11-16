# 論文になく、ブログや報道にだけある食い違い（2026-11-16）

教授の方針（2026-11-16、利用者から）：ブログ程度で述べられていて、論文になっていないものは、論文に入れてよい。

この方針に当たるものを、手元のデータで確かめた。

- **新しく確かめたもの**：Eufy（CIC IoT 2022）。報道で知られた製品で、同じ種類の食い違いを通信で確かめられた。
- **これまでの候補**：A〜E（[report-2026-11-15.md](report-2026-11-15.md)）の、先に書いていた資料の種類を下の 2 節にまとめた。

## 1. Eufy HomeBase 2 とドアベル（CIC IoT 2022、2021-10-13）

### 要点

- 公式の説明（収録の 18 日前の版）：「Data during transmission is encrypted.」
- **確認済み**：外からアプリで見た映像と音声は、ほとんど暗号化されずにインターネットへ出ていた。
  - 音声（AAC）は全部が平文で、普通の道具（ffmpeg）でそのまま復号できた。
  - 映像（H.265）で暗号化されていたのは、一部のフレームの先頭 128 バイトだけで、多くても全体の 0.21%。
- 報道（2022 年）が「暗号化されていない」としたのは、ウェブポータルの映像だった。アプリの映像について、Anker は「ずっと端から端まで暗号化していた」と答えていた。
- 同じ機器を調べた論文（USENIX WOOT 2024、ワークショップ）は、アプリの映像を「暗号化されている」と書いている。こちらの観測とは逆。

### 機器と機種

- 機器の一覧の名前は「Eufy Homebase」。MAC は 8c:85:80:6c:b6:47、IP は 192.168.137.182。
- HomeBase の型番 T8010（HomeBase 2）は、mDNS の TXT の md による（[sweep-results.md](sweep-results.md)）。
- ドアベルの機種は**未確認**。映像は 2560×1920 の H.265 だった。Video Doorbell 2K（電池式）の解像度と同じで、WOOT 2024 が調べた組み合わせ（HomeBase 2 と Video Doorbell 2K）と同じとみられる（推測）。
- ファームウェアの版は**未確認**。

### 根拠の通信（確認済み）

ファイルは `~/datasets/raw/cic-iot-2022/3-Interactions/Home Automation/Eufy Homebase/` の下。CIC の Readme は、WAN を「別のネットワークにつないだスマートフォンのアプリでの操作」としている。Watch は「録画せずにドアベルの映像を見る」、Recording は「ドアベルの映像を録画する」。

| ファイル | 送り先（HomeBase から） | 映像のフレーム（鍵つき／ほか） | ほかのフレームのうち、平文の H.265 で始まるもの | 音声のフレーム（AAC） |
|---|---|---|---|---|
| WAN_WATCH/eufyhomebaseWANWATCH_1.pcap | 3.16.202.62:11197 | 10／197 | 196 | 215（13.8 秒） |
| WAN_WATCH/eufyhomebaseWANWATCH_2.pcap | 3.16.202.62:11463 | 3／2 | 1 | 1 |
| WAN_RECORDING/eufyhomebaseWANRECORDING_2.pcap | 54.219.251.168:11392 | 30／459 | 459 | 505（32.3 秒） |
| WAN_RECORDING/eufyhomebaseWANRECORDING_3.pcap | 35.162.187.157:11159 | 32／483 | 483 | 531（34.0 秒） |

- **送り先**：3 つとも LAN の外の Amazon のアドレス（WHOIS は Amazon Technologies Inc.）。スマートフォンへ直接ではなく、中継を通っているとみられる（推測。WOOT 2024 p.135 も、遠隔ではクラウドの中継サーバーを通ると書く）。
- **通信の形**：UDP の PPPP（`f1 d0` で始まる DRW）の中に、`XZYH` で始まるメッセージが入っている。命令 1300 が映像、1301 が音声。TLS や DTLS ではない。
- **映像**：
  - 例：WANWATCH_1 のフレーム 213 に、映像のフレームの先頭 `00 00 00 01 02 01 d0 09` が平文で見える。H.265 の開始コードと、キーフレームではない普通のスライス（NAL の種類 1）の見出し。
  - 128 バイトの鍵（RSA で包んだもの）を持つフレームは 75 個。暗号化されているのは、それぞれの先頭 128 バイトとみられる。
  - ほかの 1,141 個のうち 1,139 個は、平文の開始コードで始まる。
  - 暗号化されうるのは、多くても 9,600 バイト。映像 4.67 MB の 0.21%。
  - ほかの 1,141 フレームの末尾のバイトは、H.265 の終わり方と合う。偶数が 87%（平文なら約 88%、乱数なら 50%）、下位 4 ビット以上が 0 のものが 50%（平文なら約 50%、乱数なら 6%）。
- **音声**：
  - 例：WANWATCH_1 のフレーム 275 に、ADTS の見出し `ff f1 60 40` が平文で見える。
  - 4 本で 1,252 フレーム。すべて AAC-LC（16 kHz、モノラル）としてエラーなく復号でき、合わせて 80 秒になった。
  - 音は小さい（WANWATCH_1 の RMS は −58 dB）。耳で聞いて中身を確かめてはいない（**未確認**）。
  - 取り出した音声は `~/datasets/claims/dig/eufy/` に置いた（リポジトリには入れない）。
- **ドアベルを押したとき**（LOCAL_RING の 3 本、フレーム 88、70、70）：
  - 毎回、`zhixin-security-pr.s3.us-west-2.amazonaws.com` へ TLS で約 24 KB を送った。中身は見えない（**未確認**）。
  - 待機中の 30 日分（2-Idle）には、この送り先への接続はなかった。
- **映像を画として見られるかは未確認**。先頭が暗号化されたフレームに、復号に要る設定（VPS、SPS、PPS）が入っているとみられるため。音声は確認済み。

### 公式文書（収録の 18 日前）

eufy の「Privacy Commitment」（カナダのストア、[Wayback 2021-09-25](https://web.archive.org/web/20210925012802/https://ca.eufylife.com/pages/privacy-commitment)）。同じ文が 2021-12-08 の米国のページにもある。eufy 全体のページで、HomeBase 2 の名前が出る。

> **End-to-End Encryption** / Peeking Prohibited
> All recorded footage is encrypted on-device and sent straight to your phone—and only you have the key to decrypt and watch the footage. Data during transmission is encrypted.

> **Local Storage** / For Your Eyes Only
> Home is where your data belongs. With secure local storage, your private data never leaves the safety of your home, and is accessible by you alone.

- **食い違いの候補（T1a）**：「Data during transmission is encrypted.」と、平文の音声とほぼ平文の映像。claims.tsv の 1621 行目を直した。前の判定（一致）は、エントロピーが高いことだけを根拠にしていた。
- **判定しない**：「All recorded footage is … sent straight to your phone」は録画の話。CIC の Recording は、見ている映像を録画する操作なので、保存した録画を送る通信かは分からない。
- **判定しない**：「never leaves the safety of your home」は、ドアベルを押したときの約 24 KB の中身が見えない。

### 似た資料

| 資料 | 種類 | 書いていること | こちらとの違い |
|---|---|---|---|
| S. Hollister, "Anker's Eufy lied to us about the security of its security cameras", The Verge, 2022-11-30（[Wayback](http://web.archive.org/web/20261113124652/https://www.theverge.com/2022/11/30/23486753/anker-eufy-security-camera-cloud-private-encryption-authentication-storage)） | 報道 | Paul Moore と Wasabi が、カメラの映像をクラウド経由で暗号化なしに VLC で見られると指摘した。The Verge も確かめた。eufy の「never leaves the safety of your home」「end-to-end」の説明を引いている。顔の写ったサムネイルをクラウドに上げていたことも書く | 同じ種類の食い違い（説明は暗号化、実際は平文）。ただし経路はウェブポータルの映像で、アプリの映像ではない。Moore の元の投稿は読んでいない（**未確認**） |
| S. Hollister, "Anker finally comes clean about its Eufy security cameras", The Verge, 2023-01-31（[Wayback](http://web.archive.org/web/20261021193311/https://www.theverge.com/23573362/anker-eufy-security-camera-answers-encryption)） | 報道（Anker の回答） | 暗号化されていなかったのはウェブポータルの映像だけとする。アプリの映像は「These streams have always used end-to-end encryption.」 | こちらの 2021 年のアプリの映像は、ほとんど平文。回答は収録より後なので、比べる主な文書は上の 2021 年の版 |
| V. Goeman ほか, "Reverse Engineering the Eufy Ecosystem", USENIX WOOT 2024（[PDF](https://www.usenix.org/system/files/woot24-goeman.pdf)） | 論文（ワークショップ。トップ 4 ではない） | 同じ HomeBase 2 と Video Doorbell 2K を 2023 年に調べた。アプリの映像は「The JFIF stream is encrypted with a symmetric P2P AES key」（§2.1.2、p.135）。保存した画像は、見出しの 256 バイトだけが暗号化され、残りは平文（§5.4.2、p.140）。鍵は通信に平文で出る値から作れる。「military-grade encryption」の説明と比べている | アプリの映像を「暗号化されている」とし、こちらとは逆。版が新しいためかもしれない（**未確認**）。部分的な暗号化は、保存した画像についてだけ。関連研究で Moore の結果に触れている（p.144） |
| eufy-security-client（GitHub、bropat。最初のコミット fa68546、2021-02-06）`src/p2p/session.ts` | 公開のコード | 鍵つきの映像のフレームだけ、先頭 128 バイトを復号し、残りはそのまま使う。音声は復号しない | こちらの観測と同じ作り。ただし、問題としては書いていない |

- **論文での扱い**：アプリの映像がほとんど平文だという報告は、論文にはない（読んだ範囲）。唯一の論文（WOOT 2024）は逆のことを書いている。
- **ブログや報道での扱い**：同じ種類の食い違いが報じられたのは、別の経路（ウェブポータル）とサムネイル。
- 先行研究の表：[sweep/prior-claims.tsv](sweep/prior-claims.tsv) の最後の行。

### 別の読みと弱い点

- 鍵つきのフレームの先頭を暗号化すると、普通の再生ソフトでは映像を再生できない。製造者は、これで「暗号化」と呼んでいる可能性がある。ただし、音声は全部平文で復号できる。
- 中継のアドレスの持ち主は Amazon で、eufy が使うサーバーかは**未確認**。
- クラウドの有料プランを使っていたかは**未確認**。
- この 4 本は、どれも 2021-10-13 の 14:35〜14:42（UTC）の、25〜43 秒の操作。

### 確かめ方

```bash
D="$HOME/datasets/raw/cic-iot-2022/3-Interactions/Home Automation/Eufy Homebase"
python3 scripts/claims/sweep/eufy_p2p.py --audio-dir ~/datasets/claims/dig/eufy "$D"/WAN_WATCH/*.pcap "$D"/WAN_RECORDING/*.pcap
tshark -r "$D/WAN_WATCH/eufyhomebaseWANWATCH_1.pcap" -Y "frame.number==213 || frame.number==275" -x
tshark -r "$D/LOCAL_RING/eufyhomebaseLCLRING_1.pcap" -Y "tls.handshake.type==1" -T fields -e frame.number -e tls.handshake.extensions_server_name
```

## 2. これまでの候補で、先に書いていた資料の種類

食い違い（説明と通信の違い）として書いた資料は、A〜E のどれにもなかった。下の表は、通信の問題そのものを書いていた資料の種類。分類は [sweep/prior-claims.tsv](sweep/prior-claims.tsv) による。

| 候補 | 通信の問題を書いていた資料 | 論文 |
|---|---|---|
| A. SmartCam SNH-P6410BN の平文の映像（UNSW 2018） | Kaspersky 2018（ブログ、クラウドの作りの問題） | 逆の記述だけ。Loi ほか 2017（CCS のワークショップ）は、同じ機器のサーバーとの通信を、エントロピーから平文ではないとした |
| B. SimCam 1S の画像のアップロード（CIC） | なし（似た例は別の会社の Eufy の報道だけ） | なし |
| C. 「AES 256」で AES-128：Somfy、Withings Home | Somfy は DEF CON 2016 の発表（Bluetooth の側、前の製品）。Withings Home は AV-TEST 2017（試験報告、同じ暗号スイート） | なし |
| C. 「AES 256」で AES-128：iRobot | AV-TEST 2019（ブログ、暗号スイートはなし） | 別の面だけ。Alrawi ほか S&P 2019 は iRobot のサーバーの TLS を能動的に調べた。暗号スイートと説明の比較はない |
| C. 「AES 256」で AES-128：Awair、Samsung（HTTPS） | Wannigama ほか WoWMoM 2024 が同じ暗号スイートを報告。IoTLS（IMC 2021）は全体の傾向 | あり（トップ 4 ではない） |
| D. SNH-V6410PN の平文のイベント通知（Deakin） | Kaspersky 2018（ブログ）、CVE-2018-6295 | なし |
| E. Hue Bridge の平文の HTTP | AV-TEST 2017（試験報告）、Mandalari ほか PoPETs 2021 | あり（トップ 4 ではない） |

- **論文にないもの**：A、B、D、C のうち Somfy と Withings Home、新しい Eufy。iRobot は、論文には別の面だけ。
- **除外した Ring（YourThings）**：平文の HTTP と SIP はブログ（2016、2017）にだけある。暗号化されていない映像は Alharbi と Aspinall（IET 2018）が報告している。除外の主な理由は「Bank-grade」の対象が書かれていないことで、今回の方針では変わらない。

## 3. 記録の訂正：エントロピーだけで「暗号化」とした判定

- Eufy の判定は、エントロピーが高いことから暗号化と推定していた。圧縮した音声や映像も、エントロピーは高い。
- 同じ根拠の判定が、ほかに 18 行ある：
  - Nest Protect と Nest Guard（YourThings、UNSW 2016-17、UNSW 2018）
  - Ring Video Doorbell（Deakin、3 行）
- Ring は映像を送るので、同じ確かめ方をするのが次の作業（**未検証**）。

## 4. 判断が要ること

1. Eufy を候補に入れるか。報道と同じ種類の食い違いだが、経路が違う。論文（WOOT 2024）は逆のことを書いている。
2. 取り出した音声（80 秒）を見せてよいか。
3. Deakin の Ring を同じ方法で確かめるか。
