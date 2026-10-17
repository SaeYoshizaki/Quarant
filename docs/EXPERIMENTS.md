# 実験記録

実験ごとに、データ、Quarant のコミット、手順、結果、解釈、限界を記録する。
データはリポジトリの外（`~/datasets/`）に置き、出力は `~/datasets/runs/` に保存する。データセットの詳細は [DATASETS.md](DATASETS.md) を参照。

## E1：公開データセットによる最初の検証（2026-10-17）

- **Quarant**：branch `dataset-eval`（評価コードは `internal/dataseteval`、コマンドは `quarant dataset-eval`）
- **環境**：Apple Silicon（macOS）、単一プロセス

### E1-1：IoT-23（実マルウェア、フロー単位のラベル）

**対象**：悪性 6 シナリオ、正常 2 シナリオ。各シナリオは、PCAP と、ラベル付きの Zeek conn ログ。

```bash
quarant analyze <scenario>.pcap --out runs/<s>/events.jsonl
quarant dataset-eval iot23 --run runs/<s> --labels <s>/conn.log.labeled --scenario <s>
```

| シナリオ | マルウェア | ラベルの種類（フロー数） | 結果 | 検出したイベント |
|---|---|---|---|---|
| 34-1 | Mirai | C&C（6706）、IRC 6667番、宛先 1 | ✅ 検出 | `PERSISTENT_CONNECTION_ATTEMPTS` |
| | | DDoS（14394） | ⬜ 検出器なし | |
| | | PartOfAHorizontalPortScan（122） | ❌ 見逃し ※1 | |
| 3-1 | Muhstik | PartOfAHorizontalPortScan（145,597、宛先 61,766、SSH 22番） | ✅ 検出 | `OUTBOUND_SCAN_SUSPECTED` |
| | | Attack（5961、SSH のブルートフォース、宛先 221） | ✅ 検出 ※2 | `PERSISTENT_CONNECTION_ATTEMPTS` ×75 |
| | | C&C（8、2407番、宛先 5） | ❌ 見逃し ※3 | |
| 8-1 | Hakai | C&C（8222、50番、宛先 2、すべて無応答） | ✅ 検出 | `PERSISTENT_CONNECTION_ATTEMPTS` ×2（宛先ごと） |
| 20-1 | Torii | C&C-Torii（16、443番） | ❌ 見逃し ※3 | |
| 21-1 | Torii | C&C-Torii（14、443番） | ❌ 見逃し ※3 | |
| 42-1 | Trojan | C&C-FileDownload（3）と FileDownload（3） | ❌ 見逃しと ⬜ 検出器なし | |
| 4-1 | 正常（Philips Hue） | — | 振る舞いの WARNING は 0 件。周期通信の INFO が 1 件 | |
| 5-1 | 正常（Amazon Echo） | — | 振る舞いの WARNING は 0 件。INFO は、周期通信 4 件と、example.com への接続確認 1 件 | |

**集計**（検出器があるラベル種別を単位に数える）

- 検出：5 / 10。内訳は、Mirai と Hakai の C&C、Muhstik のスキャンとブルートフォース。
- 見逃し：5 / 10。
- 検出器なし：DDoS、FileDownload。
- 正常機器で振る舞いの WARNING：0 件。

**解釈と限界**

- ※1：Mirai の「PartOfAHorizontalPortScan」は、実際には**1 つの IP の 1 ポートへの 121 回の試行**で、多数の宛先を探す横方向のスキャンではない。ラベルの付け方の問題なので、Quarant の見逃しとして扱うのは適切ではない。
- ※2：ブルートフォースを専用に検出する機能はない。標的ごとの「執拗な接続試行」として表面化した。
- ※3：少量で低頻度の C&C は、通信の振る舞いだけではほぼ区別できない。
  - 例：Torii は 1 日に約 15 回、443 番で TLS 通信をしていた。
  - 脅威情報（IOC との照合）がないと検出は難しい。Phase 2 の脅威情報連携の根拠になる。
- **しきい値の決め方**：`PERSISTENT_CONNECTION_ATTEMPTS` のしきい値（30 回／時）は、UNSW の 1 日目（正常）の分布と、このシナリオ 8-1 を見て決めた。そのため、8-1 での検出は**評価データでの調整の結果**であり、汎化の根拠にはならない。
  - 汎化の確認として、UNSW の残り 19 日（正常）での誤検知を E1-2 で測った。
- **データの性質**：感染した機器は主に Raspberry Pi で、1 シナリオにつき 1 台。LAN 内の文脈はほとんどない。

### E1-2：UNSW IoT traces（正常、20 日、MAC の正解あり）

**対象**：2016-09-23〜10-12 の 20 日分の PCAP（圧縮時 6.4GB）と、正解の機器一覧（MAC と機器名、31 件）。

- **開発用**：16-09-23。しきい値の調整に使った。
- **ホールドアウト**：残りの 19 日。調整に使っていない検証用データ。

```bash
quarant analyze <day>.pcap --out runs/unsw-<day>/events.jsonl
quarant dataset-eval unsw --run runs/unsw-<day> --devices List_Of_Devices.txt
```

**機器識別**（20 日分を合算）

| 項目 | 結果 |
|---|---|
| 一覧の機器を 1 日以上観測できた | 31 / 31 |
| OUI からベンダーが分かった | 31 / 31。うち 7 台は、Wi-Fi モジュールや OEM の製造元で、製品ブランドとは異なる ※ |
| DHCP を観測できた | 31 / 31 |
| ホスト名が分かった（DHCP または mDNS） | 19 / 31 |
| mDNS を観測できた | 13 / 31 |
| SSDP を観測できた | 7 / 31 |

※ ブランドと OUI のベンダーが異なる例：

- iHome → AzureWave
- PIX-STAR → AMPAK
- Android → Murata
- Blipcare → Rezolt
- Insteon カメラ → TP-Link（OEM）
- 名前のない機器 → Reecam
- ノート PC → AzureWave

OUI から分かるのは「NIC の製造元」であり、製品ブランドとは限らない。Quarant が `mac_vendor` を `reference_match` として扱い、カテゴリの推定に直接使っていないのはこのため。

**正常データでの振る舞い検知**（ホールドアウト 19 日）

| 検出 | INFO | WARNING 以上 | 内容 |
|---|---|---|---|
| `PERIODIC_COMMUNICATION_OBSERVED` | 201 | 8 | WARNING の内訳：Galaxy Tab→北京の IP の 5222 番（XMPP、DNS なしの直接接続）が 6 件、ノート PC→IP 直指定の HTTP（毎時）が 2 件。悪性ではなく、設計どおりの「要確認」 |
| `PERSISTENT_CONNECTION_ATTEMPTS` | 150 | 4 | 無応答の宛先への再試行など。悪性ではない |
| `IP_MAC_BINDING_CHANGED` | — | 3 | ゲートウェイによる中継、ランダム化 MAC。機器構成による誤検知 |
| `LATERAL_SCAN_SUSPECTED` | — | 1 | **実際のスキャン**：MacBook（.243）が Insteon カメラ（.192）の 2.7 万以上のポートに、1 分間で接続を試みていた（ポート 1、2、3… の連番）。データセットではラベルが付いていないが、正しい検出 |

**解釈**

- 誤検知候補の WARNING は、19 日 × 31 台で 15 件だった（1 日あたり約 0.8 件）。
- INFO は「正常なテレメトリでも起こる観測」として出しており、これは設計どおり。
- 「正常」とされているデータの中にも、ラベルのない実際のスキャンが含まれていた。**正常データの誤検知率を測るときは、検出結果を人が確認する手順が欠かせない**。
- WARNING 以上の検出の大部分は、2016 年の機器による平文 HTTP と古い TLS（`INSECURE_HTTP` 30,086 件、`I7_TLS_WEAK_VERSION_OBSERVED` 4,515 件）。これは実在する弱点の観測であり、誤検知ではない。ただしイベントの冗長性が高く、相関によるまとめ（Phase 2）が必要。
- **性能**：
  - 1 日（約 15〜40 万フロー）あたり、20 秒〜2 分。
  - 当初は、接続先の多い機器がいる日に 21 分かかっていた。I5 照合をフローごとにやり直していたためで、キャッシュで解消した（同じ日で 128 秒、出力は同一）。

### E1 のまとめ（研究の問いに対して）

| 観点 | 結果 |
|---|---|
| 機器識別 | DHCP と OUI で全台を捕捉できた。ホスト名は 6 割。ブランドの特定は OUI だけでは不確実 |
| L2 の攻撃（ARP スプーフィング） | 27/27 を検出（低いレートでも検出できた） |
| マルウェアの振る舞い | スキャン、ブルートフォース、執拗な C2 再接続は検出できた。少量の TLS による C2（Torii）は振る舞いだけでは検出できなかった |
| 量で押す攻撃（DoS、リフレクション） | 検出器がなく未評価 |
| 正常データでの誤検知 | 1 日あたり約 0.8 件の WARNING。すべて人が確認できる根拠つき |
| パッシブ監視の限界（見えないこと） | TLS の中身、少量の C2、ファームウェアと CVE の正解、ハブ配下の機器 |

### E1-3：UNSW IoT attack traces（ARP スプーフィングなど、攻撃の時間窓の注釈あり）

**対象**：攻撃と正常通信を含む 5 日分の PCAP（2018-06-01、06-02、10-22、10-23、10-24。約 9.5GB）。

- 正解は、被害機器の MAC ごとの攻撃時間窓（開始と終了の Unix 時刻、攻撃名）。
- 18-10-24 のファイルは途中で切れていた。Quarant は読めた部分（約 5 時間）を解析し、警告を出した。

```bash
quarant analyze <day>.pcap --out runs/unswatk-<day>/events.jsonl
quarant dataset-eval unsw-attacks --run runs/unswatk-<day> --annotations annotations/   # 許容誤差 ±2 分
```

| 攻撃の種類 | キャプチャ内の時間窓 | 検出 | 備考 |
|---|---|---|---|
| ArpSpoof（1・10・100 pps、LAN 内の攻撃者） | 27 | **27（100%）** | レート別でも 9/9、9/9、9/9。検出は `IP_MAC_BINDING_CHANGED` |
| TcpSynDevice（SYN flood） | 36 | — | 検出器なし |
| TcpSynReflection | 36 | — | 検出器なし |
| UdpDevice（UDP flood） | 21 | — | 検出器なし |
| PingOfDeath | 15 | — | 検出器なし |
| Ssdp、Snmp、Smurf（リフレクション） | 12、6、9 | — | 検出器なし |

**誤検知の候補**：攻撃時間窓の外で、`IP_MAC_BINDING_CHANGED` が 107 件出た。

- そのほとんどは、正解の機器一覧にない MAC がゲートウェイ（.1）や機器（.175）の IP を名乗ったもの。該当する MAC は次の 3 つ。
  - `2c:27:d7`（OUI は Hewlett Packard）
  - `8c:85:90`（Apple）
  - `08:00:27`（VirtualBox の仮想 NIC）
- これらは攻撃側の機材と考えられる。ただし、注釈のない区間でも攻撃していたのか、正規の機器なのかは、データからは確認できない。そのため誤検知候補として扱う。

**解釈と限界**

- 機器自身がアドレスと MAC の対応を宣言する L2 の攻撃は、パッシブ観測と相性がよく、低いレートでも見逃さなかった。
- 量で押す攻撃（フラッド、リフレクション）は、検出器がないため評価していない。Phase 2 の候補。
  - これらは、宛先あたりのパケットレートや反射応答の比率を使えば、説明可能な方法で検出できる見込みがある。
- 攻撃は、ラボで動かした攻撃ツールによるもの。

## E2：TLS ClientHello パーサの差分ファジング（2026-10-17、測定装置の妥当性検証として補助的に実施）

**目的**：監視装置が読み取った内容（Quarant のパーサ）が、標準的な実装（Go `crypto/tls`）の解釈と一致するかを確かめる。食い違いがあると、誤検知や見逃しの原因になるだけでなく、すり抜け（evasion）にも使われ得る。

**方法**（`internal/parserdiff`。オフラインで、どの機器にも何も送らない）

```bash
go test ./internal/parserdiff -fuzz FuzzClientHelloDifferential -fuzztime 10m
quarant parser-diff --pcap <capture>
```

**分類**

| 分類 | 意味 |
|---|---|
| `agree` | 一致 |
| `quarant_only` | 比較相手が拒否する入力を、Quarant が ClientHello と判定した。存在しないものを報告し得る |
| `reference_only` | Quarant が正常な ClientHello を見落とした |
| `field_mismatch` | 両方とも受け入れたが、読み取った項目が食い違った |
| `lenient_unparsed_extension` | Quarant が中身を解釈しない拡張だけが不正。報告する項目は影響を受けないので許容する |
| `reference_lenient_rfc_invalid` | 比較相手が RFC 違反（セッション ID が 32 バイト超、暗号スイートが空など）を受け入れた。Quarant の拒否が正しい |

**ファジングで見つかり、修正した読み違い**（それぞれ回帰用のテスト入力として保存した）

1. 拡張ブロックが壊れていても、途中までの結果を正常として返していた。後ろにある `supported_versions` を読み落とすと、TLS 1.3 のクライアントが旧バージョンを使っているように見える。
2. データの途中にある 0x16 から ClientHello を探していた。TLS ではないデータから、存在しない ClientHello を作り出し得る。
3. 拡張ブロックの終わりと ClientHello の終わりが一致しているかを確認していなかった。圧縮方式が欠けた ClientHello も受け入れていた。
4. 中身が空の SNI 拡張を受け入れていた。SNI の構造の検証を `crypto/tls` と同じ厳しさにした。
5. （コードを読んで見つけたもの）失敗した候補位置で読み取った値が、結果に持ち越されていた。

**実データでの測定**

| データ | ClientHello | 一致（修正前／修正後） | 複数セグメントにまたがる | 届いた順と並べ直した順で結果が変わる | 解析対象外のポートで見落とし |
|---|---|---|---|---|---|
| UNSW 2016（16-10-11） | 2,792 | 100% ／ 100% | 0 | 0 | **102（3.7%）**。993、5228、80、56700、1119 番 |
| UNSW 2018（18-10-24） | 969 | 100% ／ 100% | 0 | 0 | **17（1.8%）** |
| 2026 年の実通信（手元の PCAP） | 87 | 100% ／ 100% | **86（99%）** | 0 | 0 |

**解釈**

- **ファジングで見つけた読み違い**：正常な機器の通信では起きなかった（修正前でも一致率 100%）。効果は、異常な入力や細工された入力への頑健さ、つまりパッシブ監視を欺かれにくくすることにあり、正常時の精度には効いていない。
- **ポート番号に頼った判定による見落とし**：実データでは 1.8〜3.7% あった。内容から TLS を判定するように変えた結果、UNSW の 1 日分で解析できた ClientHello は 2,693 件から 2,794 件に増え、弱い TLS の検出も新たに見つかった。
- **2026 年の通信**：ClientHello が複数の TCP セグメントにまたがるのが普通になっていた（量子耐性の鍵交換 X25519MLKEM768 で大きくなったため）。今回は並べ替えの影響はなかったが、TCP の再組み立てをしていないことは、現代の通信では危険が大きい。並べ替えや再送を起こした合成 PCAP で評価する必要がある（次の課題）。
