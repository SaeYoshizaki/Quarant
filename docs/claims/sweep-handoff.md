# 引き継ぎ：5 つのデータセットの洗い出し（2026-11-11）

次の会話はここから始める。結果の全体は [sweep-results.md](sweep-results.md)、決めたことは [../DECISIONS.md](../DECISIONS.md) の D41、実験の記録は [../EXPERIMENTS.md](../EXPERIMENTS.md) の E16。利用者は、下の「残りの作業」を最後まで任せている（2026-11-11）。

## 1. 済んだこと

- **洗い出し**：UNSW 2016、UNSW-IoTraffic、YourThings 2018、CIC IoT 2022、Deakin 2023。74 製品・166 件の候補（[sweep/candidates.tsv](sweep/candidates.tsv)）。記録は `~/datasets/claims/sweep/<データセット>/*.jsonl`（値は鍵付きのハッシュ。鍵は `~/datasets/claims/sweep/.key`）。
- **先行研究の振り分け**：[sweep/prior-ids.tsv](sweep/prior-ids.tsv)（識別子など 61 件）、[sweep/prior-tls.tsv](sweep/prior-tls.tsv)（TLS 105 件）、[sweep/prior-images.tsv](sweep/prior-images.tsv)（カメラの画像）。
- **パケットでの確認**：「見つからず」と「ブログ等のみ」の 20 件（16 件確認、1 件弱い、3 件外す）。いちばん重いのは、Home Eye と SimCam のカメラが画像を平文の HTTP でクラウドに送っていたこと。

## 2. 残りの作業（この順で、最後まで）

### 2-1. 「論文で一部」の 40 件をパケットで確かめる

1. 外付けディスクがつながっているか確かめる（`ls /Volumes/QuarantData`）。つながっていなければ利用者に頼んで待つ。
2. 洗い出しの記録を手元にコピーする（ディスクから直接読むと遅い）。作業用のフォルダに `cp -R ~/datasets/claims/sweep/<データセット>` を 5 つ。
3. 実行する：
   ```
   python3 scripts/claims/sweep/verify_all.py docs/claims/devices.tsv docs/claims/sweep/prior-ids.tsv PAPER-PARTIAL <記録のコピー> <出力.txt> \
     ~/datasets/raw/unsw-iotraffic/pcaps ~/datasets/raw/cic-iot-2022 ~/datasets/raw/deakin-iot/pcapFull <取り出し先> /Volumes/QuarantData/yt-extract
   ```
   `verify_all.py` は、記録から「その項目と宛先が入っているキャプチャ」を選ぶ。手元にないものは skipped になる。
4. skipped を減らす。記録（`field` の file と frame）から必要なファイルを決めて取り出し、やり直す。
   - YourThings：`/Volumes/QuarantData/usb-yourthings/iot_traffic2018MMDD.tgz`。**tgz の中のパスは日によって違う**（03-20、03-21、04-15 は `2018/MM/DD/eth1-…`、04-11 は `11/eth1-…`、04-12 は `12/eth1-…`）。分からなければ `tar tzf … | grep` で調べる（数分かかる）。03-20 と 04-10 は `/Volumes/QuarantData/yt-extract/` に展開済み。
   - UNSW 2016：`~/datasets/raw/unsw-iot-traces/16-MM-DD.tar.gz`（1 日 1 ファイル）。
5. 判定する（確認、弱い、外す）。LAN の値（UPnP、mDNS）との一致は、名乗ったキャプチャが別なら `verify.py http … <kind>@<そのキャプチャ>` で比べる。
6. [sweep-results.md](sweep-results.md) に「論文で一部の確認」の表を足し、「数」と「次」を直す。PR を作ってマージする。

**1 回目（途中で止めたもの）で分かったこと**：
- 確認：Withings Smart Baby Monitor（`auth` が 544 回すべて MAC）、Withings Aura（`auth` の 2 種類の値の片方が MAC、約 1,500 回）、Withings Home と Smart Scale（`mac_address` が MAC）、D-Link DCH-S161（`/fw-upgrade` の `device_id` が MAC）、Belkin NetCam（ログのアップロードのパスが UPnP の MAC と一致、8 回）、Sonos 2 機種（ファームウェア 8 MB と 47 MB を HTTP で取得、エントロピー約 8）。
- 識別子とは言えないもの：Bose の `q:mac` は 32 文字で MAC ではない（ハッシュかは未確認）、`q:token` は 1 文字。Amazon Echo の `q:sid` は 4 文字。Samsung TV の「ファームウェア」は 4 KB のヘッダーのファイル。
- やり直しが要るもの：根拠のファイルの選び方を誤っていた Harmony、Hue、Ring、Sonos の識別子、TP-Link NC220、Insteon Camera。LAN の値を別のファイルから読む必要がある Belkin WeMo の 4 製品と Roku の 2 製品。

### 2-2. SimCam の説明と通信の食い違いを確かめる

SimCam は、記事や App Store で「映像は機器の中で処理する」と紹介されている（[sweep/prior-images.tsv](sweep/prior-images.tsv)）。一方、CIC の 2021-11-02 の収録では、人物検知の画像を平文の HTTP で S3 に送っていた。
- 収録（2021-11）より前の版の説明を、Wayback で探す（`scripts/claims/wb.py`。間隔を空ける）。メーカーのページ、App Store、製品の説明書。公開日、改訂日、取得日を分けて書く。
- 説明が検知の画像も含むかを確かめる。時期と範囲を確かめられなければ、食い違いは「未確認」。
- 結果を sweep-results.md に書き、PR を作ってマージする。

### 2-3. 利用者に報告する

日本語で、確認済み、未検証、未確認を分けて報告する。

## 3. 利用者の判断が要るもの（勝手に進めない）

- 分類（先行研究の区分）の、人による確認。
- メーカーへの連絡。リポジトリの公開設定（今は公開）。
- 実機を使う能動的な検証。

## 4. 守ること

- 値は伏せない（2026-11-11 に変更）。ツールの出力と利用者への報告には、値をそのまま出す。識別子（MAC、シリアル番号、機器 ID）は、このリポジトリの文書に書いてよい。認証情報（パスワード、トークン、セッション ID、アクセスキー ID、署名）は、非公開のリポジトリ `SaeYoshizaki/quarant-results` の `claims/`（手元は `~/Desktop/quarant-results`。`claims/` だけを取り出してある）に書く。洗い出しの記録には値がない（鍵付きのハッシュだけ）ので、値は根拠のフレームを tshark で開いて読む。
- PCAP の根拠には、ファイル名、フレーム番号、フィールドを付ける。文献には、資料名、著者、年、URL、ページか節を付ける。読めないものは「未確認」と書く。
- ホスト名やポートだけで目的を決めない（中身で決める）。先行研究が見つからないことを新規性の根拠にしない。
- git：ブランチ → PR → `gh pr merge --merge`（利用者の確認は要らない）。利用者は GitHub の Pull Shark（マージした PR の数）を増やしたいので、PR はできるだけ小さく分ける（スクリプト、文書、結果は別の PR に。区切りごとに出す）。quarant-results でも同じ。main への直接の push はしない。中身のない PR は作らない。マージされたかは `gh pr view --json state` で確かめる。コミットと PR に Claude の署名を入れない。PCAP は入れない。
- 文書は短く平易に。教授が読む文書に「Claude がやった」と書かない。

## 5. はまりどころ

- 外付けディスクから同時に読むのは 3 本まで。多いとディスクが詰まる。
- `tarfile` に大きな bufsize を渡さない（遅くなる）。gzip は別のプロセスで展開する（`expose.py` のやり方）。
- Deakin は Linux cooked の形式。送信元の MAC は `sll.src.eth`（`verify.py` の `src()` で対応済み）。
- devices.tsv で製品を探すときは label で引く。名前の一部で探すと取り違える（TP-Link Tapo と Samsung の Pan/Tilt）。
- tshark は CRLF を `\r\n` の文字で出す（`verify.py` で対応済み）。非標準のポートの HTTP は `VERIFY_DECODE="tcp.port==8802,http"` のように指定する。
- YourThings は全パケットが 2 回ずつ入っている。作成者の中間者の検査の証明書（発行者 `thing-catcher.gtisc.gatech.edu`、04-10〜13）は除く。作成者のポートスキャン（03-20、21、28）も機器の挙動に入れない。
- 作業用の一時フォルダ（`/private/tmp/…`）は、Mac を再起動すると消える。
- Mac のメモリは 16 GB。大きなキャプチャ（Deakin の 1 日分は約 700 MB、IoTraffic の August は 6 GB）は 1 本ずつ扱う。
