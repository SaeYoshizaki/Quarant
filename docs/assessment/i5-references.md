# I5 の知識ベース：CVE の確認（2026-10-17）

`knowledge/i5_vulnerable_components.json` の 21 項目について、記載されていた CVE を NVD（`services.nvd.nist.gov` の CVE API）で一つずつ確かめた。

- **確かめたこと**：NVD に載っている対象製品（CPE）と説明が、項目の製品ファミリーと一致するか。
- **問い合わせた内容**：公開されている CVE の番号だけ。キャプチャのデータは送っていない。

## 結果

| 項目 | CVE | NVD の対象製品 | 攻撃の経路 | 判定 |
|---|---|---|---|---|
| nest_cam | CVE-2019-5043 | Google Nest Cam IQ Indoor（ファームウェア 4620002） | ネットワーク | 残す |
| hikvision_camera | CVE-2021-36260 | Hikvision のカメラ（DS-2CD、DS-2DF など） | ネットワーク | 残す |
| smartthings_hub | CVE-2025-2233 | Samsung SmartThings 0.55.5 未満（NVD ではアプリケーションとして登録） | 隣接ネットワーク | 残す（製品の種類があいまい） |
| philips_hue_hub | CVE-2018-7580 | Philips Hue のファームウェア | ネットワーク | 残す |
| aqara_hub | CVE-2025-65292 | Aqara Camera Hub G3、Hub M2、Hub M3 | ネットワーク | 残す |
| amazon_echo | CVE-2021-37436 | Amazon Echo Dot（2021-07-02 までのファームウェア） | 物理アクセス | 残す（通信からは悪用の可否が分からない） |
| apple_watch | CVE-2023-32417 | Apple watchOS 9.5 未満 | 物理アクセス | 残す（同上） |
| samsung_galaxy_watch | CVE-2025-20945、CVE-2025-20997 | Galaxy Watch シリーズ | ローカル | 残す（同上） |
| tplink_controller | CVE-2023-1389 | **TP-Link Archer AX21（ルーター）** | — | **外す**。Kasa や Tapo のスマート機器ではない |
| tuya_controller | CVE-2025-56400 | **Tuya の SDK と、スマートフォンのアプリ（Tuya Smart、Smart Life）** | — | **外す**。機器ではない |
| switchbot_controller | CVE-2024-48786 | **SwitchBot の Android アプリ**（com.theswitchbot.switchbot 5.0.4） | — | **外す** |
| switchbot_controller | CVE-2025-53649 | **SwitchBot の iOS／Android アプリ** | — | **外す** |
| lg_thinq_appliance | CVE-2023-44121 | **LG V60 ThinQ（スマートフォン）の LG ThinQ サービス** | — | **外す**。家電ではない |

- 記載されていた CVE 14 件のうち、5 件は項目の製品に当てはまらなかった。残った CVE は 9 件。
- CVE がもともとなかった 9 項目と、CVE がなくなった 4 項目、合わせて 13 項目は、データとして残したうえで照合しないようにした（`status: inactive_no_verified_reference`）。
  - もともとなかった項目：ring_camera、aqara_sensor、eve_sensor、switchbot_sensor、apple_homepod、google_nest_audio、google_pixel_watch、irobot_roomba、samsung_family_hub
  - CVE がなくなった項目：tplink_controller、tuya_controller、switchbot_controller、lg_thinq_appliance
- 照合する項目は 8 つになった。

## あわせて直したこと

| 問題 | 例 | 対応 |
|---|---|---|
| キーワードを部分文字列で照合していた | `lg` が algolia に、`eve` が events に、`hue` が hue を含むあらゆるホスト名に一致した | 単語やドメインのラベルの単位で照合する |
| ベンダー名のキーワードを、接続先にも照合していた | google.com や amazonaws.com に接続するすべての機器が、そのベンダーの製品の候補になった | 推定したベンダー名とファミリー名にだけ照合する |
| 多くの機器が使う共有クラウドの名前が、接続先のキーワードに入っていた | `google`、`amazon`、`apple`、`icloud`、`samsung`、`galaxy`、`pixel`、`watch`、`echo`、`lg`、`lge`、`eve`、`siri`、`homekit` | 接続先のキーワードから外した |

## 限界

- 確かめたのは、CVE と製品ファミリーの対応だけ。観測した機器が、その CVE の影響を受ける版かどうかは、パッシブな観測では分からない。イベントの根拠の種類は、引き続き `reference_match`（適用できるかは未確認）とする。
- 項目ごとの代表的な CVE は、その製品ファミリーの脆弱性を網羅したものではない。

## 実データでの変化（S2 と同じ PCAP。UNSW 2016 の 3 日分、UNSW 2018 の 6 日分、IoT-23 の 8 シナリオ）

| | 変更前 | 変更後 |
|---|---|---|
| I5 の一致（機器 × 項目） | 9 件 | 6 件 |

- **なくなった 3 件（どちらも誤り）**：
  - TP-Link のクラウド対応カメラに、ルーターの CVE（CVE-2023-1389）を付けていた。2 件。
  - ノート PC を SwitchBot の機器と推定し、アプリの CVE を付けていた。
- **残った一致**：
  - 正しい：Amazon Echo（UNSW 2018、IoT-23 Honeypot-5）、Philips Hue（UNSW 2018 の攻撃データの機器、IoT-23 Honeypot-4）。
  - 誤り：Samsung Galaxy Tab（タブレット）が SmartThings ハブとして一致した。タブレットのカテゴリを「ハブ」と推定したためで、原因はカテゴリ推定にある（ROADMAP Step 1-2）。
- 合成シナリオのラベル評価は変わらなかった（L09 は引き続き `reference_match` で一致）。
