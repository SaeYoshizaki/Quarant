# 先行研究：製造者の主張・ポリシーと実際の通信

2026-10-30 に調べた。論文は、出版元、arXiv、著者の研究室のページのどれかで存在を確かめた。規模や機器名などの細かい数字は、引用する前に本文で確かめ直す（下の「要確認」）。

## いちばん近い研究

**Subahi & Theodorakopoulos, "Ensuring Compliance of IoT Devices with Their Privacy Policy Agreement", IEEE FiCloud 2018, pp.100–107, doi:10.1109/FiCloud.2018.00022**（Crossref で書誌を確認）

- IoT 機器の**プライバシーポリシー**と、自前のテストベッドで取った通信（機器とクラウド、アプリとクラウド）を比べた。
- 対象は 11 社のポリシーと 2 機器（TP-Link のプラグ、Belkin NetCam）。2 機器とも、ポリシーと通信が食い違っていたとしている。（要確認：機器名と件数）
- 博士論文（Cardiff University, 2020, https://orca.cardiff.ac.uk/140023/ ）で、GDPR から作った基準と、暗号化された通信から送ったデータの種類を推定する方法に広げている。
- 本研究との違い：対象はプライバシーで、セキュリティの主張ではない。機器を操作しながら計測していて、公開データセットもアーカイブの文書も使っていない。

**「IoT のポリシー × 通信」という組み合わせ自体には先行研究がある。「初めて」とは書かない。**

## 宣言と観測を比べる研究（IoT 以外、または能動的）

| 研究 | 比べたもの | 方法 | 本研究との違い |
|---|---|---|---|
| Andow et al., PoliCheck, USENIX Security 2020 | Android アプリ 13,796 本のプライバシーポリシーとデータフロー | 動的解析（アプリを動かす） | モバイル、プライバシー、能動的 |
| Koch et al., "Keeping Privacy Labels Honest", PoPETs 2022 | iOS アプリ 1,687 本のプライバシーラベルと通信 | ダミーの個人データを入れて送信を見る | モバイル、能動的 |
| Iqbal et al., "Your Echos are Heard", IMC 2023 | Echo とスキルの通信・広告と、ポリシーの記載 | 架空の利用者を作って監査 | 1 つのエコシステム、能動的 |
| Young et al., SkillDetective, USENIX Security 2022 | Alexa スキル 54,055 個、Google のアクション 5,583 個と、プラットフォームの規約 | 対話で動かす | 通信ではなく音声のやり取り |
| Ahmad, Li, Luo, IoTPrivComp, ESORICS 2022（会議名は要確認） | IoT のアプリ約 1,500〜1,950 本のポリシーとアプリのコード | 静的解析 | 機器の通信ではない |
| Mandalari et al., "Protected or Porous", IEEE S&P 2023 | IoT の防御製品がうたう検知能力と、実際の挙動 | 79 機器への 4,000 回超の攻撃 | 「セキュリティの主張 × 挙動」は近いが、対象は防御製品で能動的 |

## 主張を集める側、通信を測る側

| 研究 | 内容 | 本研究との関係 |
|---|---|---|
| Blythe, Sombatruang, Johnson, J. Cybersecurity 2019, doi:10.1093/cybsec/tyz005 | 270 機器・220 社のマニュアルとサポートページから、書かれたセキュリティ機能を集め、英国の行動規範に当てはめた | 主張を集める部分の先行研究。通信とは比べていない |
| Ren et al., "Information Exposure from Consumer IoT Devices", IMC 2019 | 81 機器で、暗号化、平文の中身、第三者への送信を測った | 測る項目はほぼ同じ。主張とは比べていない |
| Huang et al., IoT Inspector, IMWUT 2020 | 家庭から集めた通信で、古い TLS、平文、広告への通信を測った | 同上 |
| Alrawi et al., SoK, IEEE S&P 2019 | 45 機器を、機器・アプリ・クラウド・通信の 4 つの面で評価した（能動的な検査を含む） | YourThings の出典。主張とは比べていない。結果の照らし合わせに使える |

周辺：Hamid et al.（arXiv 2308.05890、IoT のプライバシーポリシーの分析。通信とは比べていない）、MUD プロファイル（製造者が宣言した通信）と観測の照合（arXiv 1902.02484）。

## 見つからなかったもの

- IoT 機器の**セキュリティの主張**（暗号化、更新、認証）を、通信と比べた研究。
- 公開データセットを後から解析し直して、主張と比べた研究。
- キャプチャした時期のアーカイブの文書を使った研究。
- 米国の Cyber Trust Mark や Singapore の CLS を取った機器の通信を調べた研究。
- LLM で IoT の製造者の文書から主張を取り出す研究（モバイルのデータセーフティ欄を扱ったものはある）。

検索で見つからなかったという意味で、ないことの証明ではない。Google Scholar で、Subahi らと Blythe らを引用している論文をたどって確かめる。

## 本研究の位置づけ（案）

新しさは、次の組み合わせとして書く。

1. プライバシーではなく、**セキュリティの主張**を対象にする。
2. **厳密にパッシブ**で、**公開データセットを解析し直す**。新しく計測しないので再現でき、複数のデータセットにまたがる。
3. キャプチャした時期の**アーカイブの文書**と比べる。
4. 通信で判定できる主張とできない主張を分ける（ETSI EN 303 645 の分類、[assessment/ts103701-final.md](../assessment/ts103701-final.md)）。

必ず引用するもの：Subahi & Theodorakopoulos 2018（と博士論文）、PoliCheck、Koch et al. 2022、Blythe et al. 2019、Ren et al. 2019、IoT Inspector、Alrawi et al. 2019、Iqbal et al. 2023、Mandalari et al. 2023。

## 要確認

- Subahi らの機器名（TP-Link のプラグ、Belkin NetCam）と、食い違いの件数。本研究の試しの機器と重なるので、本文で確かめる。
- IoTPrivComp の会議名と年。
- 各論文の規模の数字。
