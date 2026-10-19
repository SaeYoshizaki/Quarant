# 確認 A：要件の分類（E3、ETSI TS 103 701）

通信を見るだけの観測者（モデル N）が、ETSI EN 303 645 の各要件について、公式の試験仕様 TS 103 701 の手順に沿って何を判定できるかを、Claude が分類した。2 回の独立した分類と、食い違いの裁定まで Claude が行っている。論文の「判定できない要件が 71%」の元になる表なので、全件を確認してもらう。

## 確認のしかた

- 各要件について、Claude の判定と理由を読んで、**容認する**か**変更する**にチェックを付ける。
- 変更する場合は、メモ欄にどう変えるか（例：「判定できない」にする、理由）を書く。迷ったものは、チェックを付けずにメモ欄に「？」と書けばよい。
- 英語の原文（試験の内容と、分類の理由）は、各要件の「原文」を開くと見られる。
- 2026-10-17 に確認済みの 10 件は、あらかじめ「容認する」にチェックしてある。

## 言葉

- **違反だけ示せる**：通信に、違反の証拠が現れることがある。ただし、証拠がなくても適合とは言えない。
- **判定できない**：試験の手順が、製造者の文書（IXIT、ICS）の確認や、機器の操作、物理的な確認、試験者による攻撃などを必要としていて、通信を見るだけでは合否のどちらにも届かない。
- **適合だけ示せる**：通信に、適合の証拠が現れることがある。
- **IXIT／ICS**：製造者が試験所に出す、実装の情報や申告書。通信の観測者には手に入らない。
- **裁定 P-a**：2 回の分類が食い違ったときの原則の 1 つ。機器ごとの一意性、必要性、安全な初期値、秩序立った再接続のような「性質」は、試験の手順が文書の確認であっても、観測と第三者の参照（公開の一覧、標準など）で違反を示せる、とした。
- **裁定 P-b〜P-e**：製造者の文書の項目との比較になるもの（P-b）、「すべての部品が」のような全称の適合（P-c）、試験者自身の攻撃の結果（P-d）、処理の目的や同意の根拠（P-e）は、観測者には判定できない、とした。

## 集計（Claude の判定）

| 判定           | 要件の数 |
| -------------- | -------- |
| 違反だけ示せる | 22       |
| 判定できない   | 55       |
| 適合だけ示せる | 1        |

---

### 5.0-1 　適用しない・満たさない推奨事項に、正当な理由が示されているか

- Claude の判定：**判定できない**
- 理由：製造者の申告書（ICS）の確認だけで、通信には何も現れない
- [x] 容認する
- [ ] 変更する
- メモ：これは、LLM を導入して、それに調べさせる形を将来的に導入するという考えでどうでしょうか？（2026-10-19：通信だけの分類としては容認。公開文書を LLM で読む案は、モデル ND の将来の拡張として記録）

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.0-1-1**（判定できない、2 回の分類が一致）：Check that the ICS justifies every recommendation declared not applicable or not met.  
  理由：Unit a reviews SO-supplied ICS only.

</details>

### 5.1-1 　初期パスワードを使う場合、機器ごとに異なるか

- Claude の判定：**違反だけ示せる**
- 理由：平文のパスワードが公開の初期パスワードの一覧と一致すれば、違反を示せる。機器ごとに異なるかは、1 台の通信からは分からないので、適合は示せない
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.1-1-1**（違反だけ示せる、裁定 (P-a)）：Assess from IXIT whether non-user-defined passwords used outside factory default are generated unique per device.  
  理由：Unit a is IXIT review; per-device uniqueness cannot be judged from one device's traffic.
- **5.1-1-2**（判定できない、2 回の分類が一致）：Look for undocumented password mechanisms, check user-defined passwords are enforced, and check generated passwords match the documented mechanism.  
  理由：Verdict compares discovered mechanisms and password generation with the IXIT (a, c) and needs setup interaction (b); per v2.1 not reachable passively.

</details>

### 5.1-2 　あらかじめ設定されたパスワードが、推測しやすくないか（規則性、MAC や SSID との関係など）

- Claude の判定：**違反だけ示せる**
- 理由：平文で見えたパスワードが MAC や SSID から作られている、または辞書にあれば違反を示せる。適合を示すには生成方法の文書が要る
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.1-2-1**（違反だけ示せる、2 回の分類が一致）：Judge whether the documented generation of pre-installed passwords avoids regularities, common strings, links to public data, and low complexity.  
  理由：Substitution: a pre-installed password seen in cleartext can be checked against the MAC/SSID (b, c) and the dictionary named by the TS; FAIL only, PASS needs the IXIT mechanism.
- **5.1-2-2**（判定できない、2 回の分類が一致）：Check that actual pre-installed passwords plausibly follow the documented generation mechanism.  
  理由：Verdict is deviation from the IXIT generation description (unit a); per v2.1 assuming IXIT content is not allowed.

</details>

### 5.1-2A 　機器同士の認証にパスワードを使っていないか

- Claude の判定：**違反だけ示せる**
- 理由：平文の機器同士のログイン（MQTT の CONNECT、クラウドへの Basic 認証など）が見えれば違反を示せる。すべての通信路が見えないので、適合は示せない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.1-2A-1**（違反だけ示せる、2 回の分類が一致）：Determine from IXIT whether any machine-to-machine authentication relies on passwords.  
  理由：Substitution: a cleartext M2M login carrying a password (e.g. MQTT CONNECT) shows passwords in use (unit a); PASS would need all M2M channels visible.
- **5.1-2A-2**（違反だけ示せる、2 回の分類が一致）：Search for undocumented mechanisms and check whether M2M authentication accepts passwords.  
  理由：Unit b: a cleartext M2M login with password (e.g. MQTT CONNECT, HTTP Basic to cloud) is observable FAIL evidence; PASS rests on absence, and encrypted M2M is invisible.

</details>

### 5.1-3 　認証に使う暗号が、ベストプラクティスに沿っているか

- Claude の判定：**違反だけ示せる**
- 理由：見えた TLS の版や暗号スイートを公的な一覧（TR 103 621 など）と照らせば違反を示せる。適合を示すには、文書での説明の確認が要る
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.1-3-1**（違反だけ示せる、2 回の分類が一致）：Assess documented security guarantees, mechanism fitness, best-practice status and known attacks for authentication cryptography.  
  理由：Per v2 conceptual-crypto rule: observed TLS versions/suites judged against TR 103 621 or SOGIS can show non-best-practice (units c, d); units a, b and PASS need IXIT.
- **5.1-3-2**（判定できない、2 回の分類が一致）：Check that the authentication cryptography actually used matches the documented cryptographic details.  
  理由：Verdict is deviation of used crypto from IXIT (unit a); per v2.1 not reachable. Catalogue-based judgement of observed TLS is captured in 5.1-3-1.

</details>

### 5.1-4 　利用者が認証の値を変更でき、その方法が分かりやすく説明されているか

- Claude の判定：**判定できない**
- 理由：機器を操作して確かめる必要がある。通信には現れない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.1-4-1**（判定できない、2 回の分類が一致）：Assess whether user authentication values can be changed and whether user information explains how, plainly.  
  理由：Substitution: a public manual explaining value changes can support PASS for units a, b; missing public text cannot show FAIL since guidance may be in the app.
- **5.1-4-2**（判定できない、2 回の分類が一致）：Perform the documented change of user authentication values and verify old values fail and new ones work.  
  理由：Units a, b require operating the DUT.

</details>

### 5.1-5 　総当たり攻撃への対策（遅延、締め出しなど）があるか

- Claude の判定：**違反だけ示せる**
- 理由：裁定 P-a。試験の手順は文書の確認と試験者による総当たりだが、第三者による総当たりに、遅延も締め出しもなく応答し続けたのが見えれば、標準（NIST SP 800-63B の上限）と照らして違反を示せる。適合は示せない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.1-5-1**（違反だけ示せる、裁定 (P-a)）：Assess whether documented brute-force countermeasures on network-addressable authentication make attacks impracticable.  
  理由：Unit a is IXIT review only.
- **5.1-5-2**（判定できない、2 回の分類が一致）：Discover undocumented network authentication mechanisms and attempt brute force against documented ones.  
  理由：Verdict compares discovered network authentication with IXIT (a) and needs brute-force attempts (b); per v2.1 not reachable passively.

</details>

### 5.2-1 　脆弱性の届け出の方針が、誰でも見られる形で公開されているか

- Claude の判定：**判定できない**
- 理由：通信ではなく、製造者の公開ページで決まる
- [x] 容認する
- [ ] 変更する
- メモ：これは、LLM を導入して、それに調べさせる形を将来的に導入するという考えでどうでしょうか？（2026-10-19：通信だけの分類としては容認。公開文書を LLM で読む案は、モデル ND の将来の拡張として記録）

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.2-1-1**（判定できない、2 回の分類が一致）：Assess whether the vulnerability disclosure policy is accessible to anyone without accounts or similar barriers.  
  理由：Substitution: unit a judged from the openly reachable vendor VDP; PASS reachable, FAIL would rest on not finding it.
- **5.2-1-2**（判定できない、2 回の分類が一致）：Verify the VDP is public and contains contact details plus acknowledgement and status-update timelines.  
  理由：Units a, b are decidable from the published VDP; failing to find it is absence and needs care.

</details>

### 5.2-2 　届け出られた脆弱性が、期限内に対処されているか

- Claude の判定：**違反だけ示せる**
- 理由：裁定 P-a。試験の手順は製造者の内部の手順の確認だが、修正が公開されてから長く経った CVE に当たる版が通信で見えれば、公開の脆弱性情報と照らして違反を示せる（Quarant は版の照合を実装していない）
- [x] 容認する
- [ ] 変更する
- メモ：これも LLM を使うと良さそう（2026-10-19：通信だけの分類としては容認。公開文書を LLM で読む案は、モデル ND の将来の拡張として記録）

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.2-2-1**（違反だけ示せる、裁定 (P-a)）：Assess whether documented actions and time frames ensure timely handling of disclosed vulnerabilities, plus SO confirmation.  
  理由：Units a, b depend on SO process documentation.

</details>

### 5.2-3 　製造者が脆弱性を監視し、特定し、修正する手順を持っているか

- Claude の判定：**判定できない**
- 理由：製造者の内部の手順の確認で、通信には現れない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.2-3-1**（判定できない、2 回の分類が一致）：Assess documented processes for monitoring, identifying and rectifying vulnerabilities, plus SO confirmation.  
  理由：Units a-d review internal manufacturer processes.

</details>

### 5.3-1 　すべてのソフトウェア部品を安全に更新できるか

- Claude の判定：**判定できない**
- 理由：部品の一覧は製造者の内部の情報。平文の更新は悪用の可能性を示すが、機器が改ざんを受け入れるかは確かめられない
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-1-1**（判定できない、2 回の分類が一致）：Assess justifications for non-updatable components and apply the update-mechanism design review of 5.3-2-1.  
  理由：Units a, b are IXIT reviews; component inventory is internal.
- **5.3-1-2**（判定できない、裁定 (P-d)）：Apply the functional update-misuse attacks of 5.3-2-2 to each referenced update mechanism.  
  理由：Unit a is attack-based; passively, plaintext or unexpected-source update downloads indicate misuse potential, but on-device verification must be assumed.

</details>

### 5.3-2 　更新の仕組みが、攻撃者に悪用されないようになっているか

- Claude の判定：**判定できない**
- 理由：試験は文書の確認と、試験者による攻撃（なりすまし、巻き戻しなど）。パッシブには、平文での配布のような「さらされている」ことしか分からない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-2-1**（判定できない、2 回の分類が一致）：Assess whether the documented design of each update mechanism prevents attacker misuse.  
  理由：Unit a is IXIT design review.
- **5.3-2-2**（判定できない、裁定 (P-d)）：Devise and execute attacks (MITM, rollback, tampered packages) to test whether update misuse is prevented.  
  理由：Units a, b are active; NET-OBS only indicates exposure (e.g. firmware over HTTP) without showing the DUT would accept a manipulated update.

</details>

### 5.3-3 　更新が、利用者にとって簡単に適用できるか

- Claude の判定：**判定できない**
- 理由：文書の確認。通信に更新が見えても、試験の手順には使われない
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-3-1**（判定できない、裁定 (P-c)）：Assess whether each software component has at least one update mechanism simple for users to apply.  
  理由：Unit a is IXIT review; unattended update traffic is not part of the TS method. Under ND, a public manual may stand in for the IXIT description.

</details>

### 5.3-4A 　更新を自動で行えるように設定できるか

- Claude の判定：**適合だけ示せる**
- 理由：利用者の操作なしに更新のダウンロードが見えれば、自動の可能性を示せる（適合だけ示せる）。利用者が手で始めた更新とは区別できない
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-4A-1**（判定できない、裁定 (P-c)）：Assess from IXIT whether at least one update mechanism can be configured to run automatically.  
  理由：Unit a is IXIT review. Under ND, a public manual may stand in for the IXIT description.
- **5.3-4A-2**（適合だけ示せる、2 回の分類が一致）：Check in the DUT configuration that at least one update mechanism can be automated.  
  理由：Unit a needs settings; observed update downloads without user action suggest automation, but user-triggered updates cannot be excluded passively.

</details>

### 5.3-4B 　初期設定のときに、自動更新を有効にするかの同意を求めているか

- Claude の判定：**判定できない**
- 理由：初期設定の画面での確認で、通信から利用者の選択は分からない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-4B-1**（判定できない、2 回の分類が一致）：Identify automatic update mechanisms and check that consent to enable them is queried and honoured at initialisation.  
  理由：Units a-c are IXIT reviews.
- **5.3-4B-2**（判定できない、2 回の分類が一致）：During setup, verify consent is requested and the automatic update state follows the user's choice.  
  理由：Units a-c require running initialisation and choosing consent; traffic alone cannot link update behaviour to the user's choice.

</details>

### 5.3-5 　初期化のときや、その後に、セキュリティ更新を確認しているか

- Claude の判定：**判定できない**
- 理由：文書の確認。定期的な更新の確認の通信は、試験の手順には使われない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-5-1**（判定できない、裁定 (P-c)）：Assess from IXIT whether update mechanisms check for security updates during or after initialisation.  
  理由：Unit a is IXIT review; periodic update-check traffic is not used by the TS. Under ND, a public manual may stand in for the IXIT description.

</details>

### 5.3-6A 　利用者が自動更新を有効・無効・延期にできるか

- Claude の判定：**判定できない**
- 理由：文書と設定画面の確認
- [x] 容認する
- [ ] 変更する
- メモ：文書まで LLM に読ませられないかな。.. トークン消費がやばいかな（2026-10-19：通信だけの分類としては容認。公開文書を LLM で読む案は、モデル ND の将来の拡張として記録）

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-6A-1**（判定できない、2 回の分類が一致）：For automatic update mechanisms, check documented user ability to enable, disable and postpone them.  
  理由：Units a, b are IXIT reviews. Under ND, a public manual may stand in for the IXIT description.
- **5.3-6A-2**（判定できない、2 回の分類が一致）：Verify in the DUT configuration that users can enable, disable and postpone automatic updates.  
  理由：Unit a requires UI access.

</details>

### 5.3-6B 　利用者が更新の通知を有効・無効にできるか

- Claude の判定：**判定できない**
- 理由：文書と設定画面の確認
- [x] 容認する
- [ ] 変更する
- メモ：文書まで LLM に読ませられないかな。.. トークン消費がやばいかな（2026-10-19：通信だけの分類としては容認。公開文書を LLM で読む案は、モデル ND の将来の拡張として記録）

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-6B-1**（判定できない、2 回の分類が一致）：For mechanisms with update notifications, check documented user ability to enable and disable them.  
  理由：Unit a is IXIT review. Under ND, a public manual may stand in for the IXIT description.
- **5.3-6B-2**（判定できない、2 回の分類が一致）：Verify in the DUT configuration that users can enable and disable update notifications.  
  理由：Unit a requires UI access.

</details>

### 5.3-7 　更新の仕組みに、ベストプラクティスの暗号を使っているか

- Claude の判定：**違反だけ示せる**
- 理由：更新の通信の TLS の版や暗号スイートを公的な一覧と照らせば、違反を示せる。署名の検証などは見えないので、適合は示せない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-7-1**（違反だけ示せる、2 回の分類が一致）：Assess documented guarantees, fitness, best-practice status and known attacks for update cryptography.  
  理由：Per v2 conceptual-crypto rule: TLS versions/suites seen on update connections judged against TR 103 621 or SOGIS can show non-best-practice (c, d); signatures and units a, b need IXIT.

</details>

### 5.3-8 　セキュリティ更新を、適時に配布しているか

- Claude の判定：**違反だけ示せる**
- 理由：裁定 P-a。5.2-2 と同じく、修正が公開されてから長く経った CVE に当たる版が見えれば、違反を示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-8-1**（違反だけ示せる、裁定 (P-a)）：Assess whether documented security-update procedures and time frames enable timely deployment, plus confirmation.  
  理由：Units a, b are internal process documentation.

</details>

### 5.3-9 　更新の真正性と完全性を、機器が確かめているか

- Claude の判定：**判定できない**
- 理由：機器の中での検証は、通信には現れない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-9-1**（判定できない、2 回の分類が一致）：Assess whether updates are checked for authenticity and integrity, and whether the DUT itself performs the checks.  
  理由：Units a-d review IXIT; on-device verification is internal.

</details>

### 5.3-10 　ネットワーク経由の更新を、信頼できる仕組みで確かめているか

- Claude の判定：**判定できない**
- 理由：設計の文書の確認と、文書にない更新経路の発見。後者も文書との比較が要る
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-10-1**（判定できない、2 回の分類が一致）：Mixed case: review update verification via a trust relationship and discover undocumented network update mechanisms.  
  理由：TS labels it conceptual/functional. Bullets on verification and trust relationship review IXIT design (a, b); unit c compares discovered update paths with IXIT; per v2.1 none reachable.

</details>

### 5.3-11 　必要なセキュリティ更新を、利用者に分かりやすく知らせているか

- Claude の判定：**判定できない**
- 理由：利用者への通知（画面）の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-11-1**（判定できない、2 回の分類が一致）：Assess whether users are informed recognisably about required security updates, including risks mitigated.  
  理由：Units a, b are IXIT reviews of user notifications. Under ND, a public manual may stand in for the IXIT description.

</details>

### 5.3-12 　更新で基本機能が止まる場合に、利用者に知らせているか

- Claude の判定：**判定できない**
- 理由：利用者への通知（画面）の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-12-1**（判定できない、2 回の分類が一致）：Check whether users are notified when an update will disrupt basic functioning.  
  理由：Unit a is IXIT review. Under ND, a public manual may stand in for the IXIT description.

</details>

### 5.3-13 　サポート期間を公開しているか

- Claude の判定：**判定できない**
- 理由：製造者の公開ページで決まる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-13-1**（判定できない、2 回の分類が一致）：Assess whether the published support period can be found and understood by a non-expert user.  
  理由：Substitution: unit a judged from the vendor's public support-period page; findable and clear gives PASS, findable but unclear gives FAIL; not finding it proves nothing.
- **5.3-13-2**（判定できない、2 回の分類が一致）：Verify the access route to the support period works as documented, is unrestricted, and actually defines the period.  
  理由：Unit b and publication existence decidable from PUBLIC; units a, c compare with IXIT and remain open.

</details>

### 5.3-14 　更新できない機器について、理由と交換の方法を公開しているか

- Claude の判定：**判定できない**
- 理由：製造者の公開ページで決まる
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-14-1**（判定できない、2 回の分類が一致）：Checks that the published explanation of why a device receives no updates, and how hardware replacement is supported, is clear to non-experts.  
  理由：Substitution: unit a judged from public rationale and replacement pages; clarity decides PASS or FAIL once found. Applicability (not updatable) cannot be shown passively.
- **5.3-14-2**（判定できない、2 回の分類が一致）：Verify access to rationale and replacement plan works as documented, is unrestricted, and covers period and method.  
  理由：Units b-d decidable from PUBLIC; unit a needs IXIT.

</details>

### 5.3-15A 　更新できない機器を、ネットワークから切り離せるか

- Claude の判定：**判定できない**
- 理由：機器を操作して確かめる必要がある
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-15A-1**（判定できない、2 回の分類が一致）：Assess whether the documented isolation method can remove the DUT from its network or place it in a closed environment.  
  理由：Unit a is IXIT review. Under ND, a public manual may stand in for the IXIT description.
- **5.3-15A-2**（判定できない、2 回の分類が一致）：Isolate the DUT as documented and check that only connectivity-related functions are lost.  
  理由：Units a-c require performing isolation and checking device function; reconnect loops after outages say nothing about main function.

</details>

### 5.3-15B 　更新できない機器のハードウェアを交換できるか

- Claude の判定：**判定できない**
- 理由：物理的な作業が必要
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-15B-1**（判定できない、2 回の分類が一致）：Assess whether the documented hardware replacement method is suitable.  
  理由：Unit a is IXIT review. Under ND, a public manual may stand in for the IXIT description.
- **5.3-15B-2**（判定できない、2 回の分類が一致）：Replace the hardware as documented and verify connectivity and functions are regained.  
  理由：Units a, b need physical action.

</details>

### 5.3-16 　型番が、ラベルや画面で分かるか

- Claude の判定：**判定できない**
- 理由：ラベルや画面の確認。通信で流れる型番は、ラベルや画面には当たらない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.3-16-1**（判定できない、2 回の分類が一致）：Assess whether the model designation is clearly recognisable by label or user interface.  
  理由：Unit a concerns label or UI; network-advertised model names are not label/UI.
- **5.3-16-2**（判定できない、2 回の分類が一致）：Obtain the model designation as documented and check it is plain text and matches IXIT.  
  理由：Units a, b require physical/UI access and IXIT.

</details>

### 5.4-1 　機器に保存する秘密の値（鍵など）を安全に守っているか

- Claude の判定：**判定できない**
- 理由：機器の内部の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.4-1-1**（判定できない、2 回の分類が一致）：Assess consistency of SSP types, adequacy of guarantees and protection schemes, and completeness of the SSP list.  
  理由：Units a-d are IXIT reviews.
- **5.4-1-2**（判定できない、2 回の分類が一致）：Check that documented storage protection schemes for SSPs are actually implemented.  
  理由：Unit a requires internal access or active probing.

</details>

### 5.4-2 　機器に埋め込んだ識別情報を、改ざんから守っているか

- Claude の判定：**判定できない**
- 理由：機器の内部の確認。通信に見える識別子が、埋め込みのものかは分からない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.4-2-1**（判定できない、2 回の分類が一致）：Check hard-coded identities are declared and that their documented protection provides tamper resistance.  
  理由：Units a-c are IXIT reviews; identifiers seen on the wire cannot be shown to be hard-coded security identities.
- **5.4-2-2**（判定できない、2 回の分類が一致）：Check that tamper-resistance protection of hard-coded identities is implemented as documented.  
  理由：Unit a is physical/internal inspection.

</details>

### 5.4-3 　ソフトウェアに埋め込んだ秘密の値を、そのまま使っていないか

- Claude の判定：**判定できない**
- 理由：文書の確認。公開の CVE（埋め込みのパスワードなど）は、試験の手順には使われない
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.4-3-1**（判定できない、裁定 (P-b)）：Check hard-coded CSPs are documented and that their provisioning prevents their use in operation.  
  理由：Units a, b are IXIT reviews; public hard-coded-credential CVEs are not part of the TS method.
- **5.4-3-2**（判定できない、2 回の分類が一致）：Check that the documented provisioning replacing hard-coded CSPs is really applied during operation.  
  理由：Unit a needs operating setup; traffic cannot reveal that a credential is hard-coded.

</details>

### 5.4-4 　更新の検証や通信に使う秘密の値が、機器ごとに異なるか

- Claude の判定：**判定できない**
- 理由：文書の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.4-4-1**（判定できない、裁定 (P-b)）：Check CSPs for update verification and service communication are documented and generated unique per device with sound mechanisms.  
  理由：Unit a is IXIT only; unit b judges IXIT generation description, public catalogues are only aids.

</details>

### 5.5-1 　すべての通信を、ベストプラクティスの暗号で守っているか

- Claude の判定：**違反だけ示せる**
- 理由：見えた TLS の版や暗号スイートを公的な一覧と照らせば、違反を示せる。適合を示すには、すべての通信路と文書が要る
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.5-1-1**（違反だけ示せる、2 回の分類が一致）：Desk review of documented secure channels for all secure communication: guarantees, mechanism fit, best-practice crypto per catalogue, no known feasible attack.  
  理由：Substituting observed TLS parameters for IXIT crypto details and judging them against TR 103 621/SOGIS can show FAIL; guarantee/mechanism fit and full PASS need IXIT.
- **5.5-1-2**（判定できない、2 回の分類が一致）：Check on the device that the crypto actually used on channels for all secure communication matches what the IXIT documents.  
  理由：Unit a: handshakes are observable, but FAIL means a difference from IXIT, which cannot be established without IXIT; reach none.

</details>

### 5.5-2 　ネットワークとセキュリティの実装が、審査済みか

- Claude の判定：**判定できない**
- 理由：審査の報告書と、実装の一覧（文書）が要る
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.5-2-1**（判定できない、2 回の分類が一致）：Desk check that each listed network/security implementation was reviewed or evaluated and that the review covers its scope.  
  理由：Units a,b operate on IXIT 12 and SO reports; even if a certificate is public, knowing which implementations exist requires IXIT.
- **5.5-2-2**（判定できない、2 回の分類が一致）：Check that name and version of each reviewed implementation on the device match those in its review report.  
  理由：Unit a: the comparison target is the SO report (IXIT); the no-information PASS branch needs interaction to establish. Reach none.

</details>

### 5.5-3 　暗号の部品を更新できるか

- Claude の判定：**判定できない**
- 理由：製造者の文書の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.5-3-1**（判定できない、2 回の分類が一致）：Desk check that crypto-using components have a referenced update mechanism and that replacement side effects were considered.  
  理由：Units a,b are purely about SO documentation (IXIT 6); observed update traffic does not show crypto replaceability.

</details>

### 5.5-4 　ネットワークから使える機能に、認証を必要としているか

- Claude の判定：**違反だけ示せる**
- 理由：認証なしの要求に機器が応じたことが見えれば、違反を示せる（家庭内に限った公開サービスの例外を除く）。すべての機能は試せないので、適合は示せない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.5-4-1**（判定できない、裁定 (P-d)）：Desk review that network-reachable functions need authentication, that it distinguishes subjects, is protected, and authorization works.  
  理由：All units a-d assess IXIT 13/IXIT 1 descriptions; nothing is decidable from public sources. ND: a published manual documenting an unauthenticated function shows FAIL.
- **5.5-4-2**（違反だけ示せる、2 回の分類が一致）：Try accessing network functions unauthenticated, with bad credentials, and with proper rights; check authentication protection against IXIT.  
  理由：Units a,b active; an opportunistically observed unauthenticated plaintext request served by the device establishes FAIL under stated assumptions; PASS needs interaction.

</details>

### 5.5-5 　セキュリティに関わる設定の変更に、認証を必要としているか

- Claude の判定：**違反だけ示せる**
- 理由：認証なしの設定の変更が受け付けられたのが見えれば、違反を示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.5-5-1**（判定できない、裁定 (P-d)）：Same desk review as 5.5-4-1, in all device states, limited to functions permitting security-relevant configuration changes.  
  理由：Unit a inherits the IXIT-only units of 5.5-4-1. ND: a published manual documenting an unauthenticated function shows FAIL.
- **5.5-5-2**（違反だけ示せる、2 回の分類が一致）：Active authentication tests from 5.5-4-2 for configuration-changing functions, plus search for undocumented network logical interfaces.  
  理由：Unit a as 5.5-4-2: observed unauthenticated configuration change gives FAIL under assumptions; unit b needs IXIT; PASS unreachable.

</details>

### 5.5-6 　重要なセキュリティパラメータ（パスワード、鍵、トークン）を、通信中に暗号化しているか

- Claude の判定：**違反だけ示せる**
- 理由：平文で流れているのが見えれば、違反を示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.5-6-1**（違反だけ示せる、2 回の分類が一致）：Desk review of documented secure channels carrying critical security parameters: guarantees, mechanism fit, best-practice crypto per catalogue, no known feasible attack.  
  理由：Substituting observed TLS parameters for IXIT crypto details and judging them against TR 103 621/SOGIS can show FAIL; guarantee/mechanism fit and full PASS need IXIT.
- **5.5-6-2**（判定できない、2 回の分類が一致）：Check on the device that the crypto actually used on channels carrying critical security parameters matches what the IXIT documents.  
  理由：Inherits 5.5-1-2: verdict is a difference from IXIT, unreachable without IXIT.

</details>

### 5.5-7 　遠隔から到達できるインターフェースで、重要なセキュリティパラメータを守っているか

- Claude の判定：**違反だけ示せる**
- 理由：平文で流れているのが見えれば、違反を示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.5-7-1**（違反だけ示せる、2 回の分類が一致）：Desk review of documented secure channels carrying critical security parameters over remotely accessible interfaces: guarantees, mechanism fit, best-practice crypto per catalogue, no known feasible attack.  
  理由：Substituting observed TLS parameters for IXIT crypto details and judging them against TR 103 621/SOGIS can show FAIL; guarantee/mechanism fit and full PASS need IXIT.
- **5.5-7-2**（判定できない、2 回の分類が一致）：Check on the device that the crypto actually used on channels carrying critical security parameters over remote interfaces matches what the IXIT documents.  
  理由：Inherits 5.5-1-2: verdict is a difference from IXIT, unreachable without IXIT.

</details>

### 5.5-8 　重要なセキュリティパラメータを、一生を通じて管理しているか

- Claude の判定：**判定できない**
- 理由：製造者の手順の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.5-8-1**（判定できない、2 回の分類が一致）：Desk review that CSP management processes span the full lifecycle and that the SO confirms implementing them.  
  理由：Units a,b concern manufacturer processes and a confirmation in IXIT; no traffic or public route.

</details>

### 5.6-1 　使っていないネットワークや論理インターフェースを無効にしているか

- Claude の判定：**判定できない**
- 理由：文書の確認と、試験者による探索。文書にないインターフェースかは、文書なしには言えない
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-1-1**（判定できない、2 回の分類が一致）：Desk check that every enabled network interface and network-reachable logical interface has a valid documented purpose.  
  理由：Units a,b judge IXIT 15/28 justifications.
- **5.6-1-2**（判定できない、2 回の分類が一致）：Check device interface status against documentation and look for undocumented network and logical interfaces.  
  理由：Units a,b active/physical; unit c FAIL means an interface absent from IXIT 28, unprovable without IXIT. Reach none.

</details>

### 5.6-2 　認証なしで、不要な情報（セキュリティに関わるソフトウェアの版など）を公開していないか

- Claude の判定：**違反だけ示せる**
- 理由：裁定 P-a。「必要か」は性質なので、認証なしで流れるセキュリティに関わる版の情報が、プロトコルの仕様で必要とされないものなら、違反を示せる（E4 の監査では、見えた版の文字列は 22 件すべてプロトコルが求めるものだった）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-2-1**（違反だけ示せる、裁定 (P-a)）：Desk review of what each network logical interface reveals without authentication: correctly labelled and necessary.  
  理由：Units a,b judge IXIT 28 'Disclosed Information'.
- **5.6-2-2**（判定できない、2 回の分類が一致）：Observe whether interfaces leak security-relevant information without authentication beyond what is documented.  
  理由：Unit a: disclosures are visible, but FAIL means not described in IXIT; unreachable without IXIT. Reach none.

</details>

### 5.6-3 　不要な物理インターフェースを、外から触れられないようにしているか

- Claude の判定：**判定できない**
- 理由：物理的な確認。通信の観測者からは見えない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-3-1**（判定できない、2 回の分類が一致）：Desk check that physical interfaces not needing exposure are casing-protected and disabled per documentation.  
  理由：Units a,b read IXIT 15 only.
- **5.6-3-2**（判定できない、2 回の分類が一致）：Inspect device for exposed physical interfaces, casing protection and enabled status, against documentation.  
  理由：Units a-c need physical inspection; a gateway observer cannot see non-IP air or wired ports.

</details>

### 5.6-4A 　デバッグ用のインターフェースを、無効にするか保護しているか

- Claude の判定：**判定できない**
- 理由：物理的な確認。Telnet のサービスが見えても、物理的なデバッグの口の証拠にはならない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-4A-1**（判定できない、2 回の分類が一致）：Desk check that debug interfaces have best-practice access control or a disable mechanism and correct default status.  
  理由：Units a-d read IXIT 15 only.
- **5.6-4A-2**（判定できない、2 回の分類が一致）：On the device, verify debug interfaces are disabled or protected and find undeclared interfaces usable for debugging.  
  理由：Units a,b require attempting to use physical interfaces; an observed Telnet service is not evidence about physical debug ports.

</details>

### 5.6-4B 　デバッグ用の物理ポートを、機器が保護しているか

- Claude の判定：**判定できない**
- 理由：物理的な確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-4B-1**（判定できない、2 回の分類が一致）：Desk check that physical-port debug interfaces are documented as physically protected by the device.  
  理由：Unit a reads IXIT 15 only.
- **5.6-4B-2**（判定できない、2 回の分類が一致）：Physically verify that debug ports are protected by the device.  
  理由：Unit a needs physical access.

</details>

### 5.6-5 　初期設定で有効なサービスが、必要なものだけか

- Claude の判定：**判定できない**
- 理由：文書の確認。見えたサービスは手がかりになるが、試験の手順にはない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-5-1**（判定できない、2 回の分類が一致）：Desk check that each default-enabled software service is necessary for intended use per its description and justification.  
  理由：Unit a judges IXIT 13 justifications; observed services could hint at extra services but the case defines no such route.

</details>

### 5.6-6 　コードを、必要な機能だけに絞っているか

- Claude の判定：**判定できない**
- 理由：文書の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-6-1**（判定できない、2 回の分類が一致）：Desk judgement of whether documented code minimization techniques suitably reduce code to needed functionality.  
  理由：Unit a is IXIT-only.

</details>

### 5.6-7 　最小権限の原則などで、権限を分けているか

- Claude の判定：**判定できない**
- 理由：文書の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-7-1**（判定できない、2 回の分類が一致）：Desk judgement of whether documented privilege controls support separation of duty, need to know and least privilege.  
  理由：Unit a is IXIT-only.

</details>

### 5.6-8 　ハードウェアでメモリへのアクセスを制御しているか

- Claude の判定：**判定できない**
- 理由：文書（と基板）の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-8-1**（判定できない、2 回の分類が一致）：Desk check that documented memory access control mechanisms are hardware-level and actually control memory access.  
  理由：Units a,b are IXIT-only (possibly board inspection).

</details>

### 5.6-9 　安全な開発の手順を持っているか

- Claude の判定：**判定できない**
- 理由：製造者の手順の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.6-9-1**（判定できない、2 回の分類が一致）：Desk review that secure development processes cover the listed lifecycle topics and that the SO confirms them.  
  理由：Units a,b concern SO processes and confirmation.

</details>

### 5.7-1 　起動時にソフトウェアの正しさを確かめているか（セキュアブート）

- Claude の判定：**判定できない**
- 理由：機器の内部の確認。起動時の検証は通信には現れない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.7-1-1**（判定できない、2 回の分類が一致）：Desk check that secure boot provides integrity and authenticity and that its detection mechanisms suit those guarantees.  
  理由：Units a,b read IXIT 20.
- **5.7-1-2**（判定できない、2 回の分類が一致）：Verify on the device that software verification at boot works as documented, possibly by tampering firmware.  
  理由：Unit a needs firmware access and manipulation; boot-time checks are not visible in traffic.

</details>

### 5.7-2 　不正なソフトウェアの変更を検知したとき、警告し、通信を絞るか

- Claude の判定：**判定できない**
- 理由：試験者が改ざんを起こす必要がある。観測者には、検知が起きたかが分からない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.7-2-1**（判定できない、2 回の分類が一致）：Desk check that the documented alert on unauthorized software change suffices and allowed communications are only those needed.  
  理由：Units a,b read IXIT 20.
- **5.7-2-2**（判定できない、2 回の分類が一致）：After provoking an unauthorized software change, check alerting and that outbound communication is limited to alerting.  
  理由：Unit b's measurement is passive traffic inspection, but both units require the TL to induce the tamper event; a passive observer cannot know detection occurred.

</details>

### 5.8-1 　関連するサービスとの間の個人データを、暗号で守っているか

- Claude の判定：**違反だけ示せる**
- 理由：平文の個人データや、古い暗号が見えれば、違反を示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.8-1-1**（違反だけ示せる、2 回の分類が一致）：Desk review of documented secure channels carrying personal data to associated services: guarantees, mechanism fit, best-practice crypto per catalogue, no known feasible attack.  
  理由：Substituting observed TLS parameters for IXIT crypto details and judging them against TR 103 621/SOGIS can show FAIL; guarantee/mechanism fit and full PASS need IXIT.
- **5.8-1-2**（判定できない、2 回の分類が一致）：Check on the device that the crypto actually used on channels carrying personal data to associated services matches what the IXIT documents.  
  理由：Inherits 5.5-1-2: verdict is a difference from IXIT, unreachable without IXIT.

</details>

### 5.8-2 　機微な個人データを、暗号で守っているか

- Claude の判定：**違反だけ示せる**
- 理由：平文の機微な個人データが見えれば、違反を示せる
- [ ] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.8-2-1**（違反だけ示せる、2 回の分類が一致）：Desk review of documented secure channels carrying sensitive personal data to associated services: guarantees, mechanism fit, best-practice crypto per catalogue, no known feasible attack.  
  理由：Substituting observed TLS parameters for IXIT crypto details and judging them against TR 103 621/SOGIS can show FAIL; guarantee/mechanism fit and full PASS need IXIT.
- **5.8-2-2**（判定できない、2 回の分類が一致）：Check on the device that the crypto actually used on channels carrying sensitive personal data to associated services matches what the IXIT documents.  
  理由：Inherits 5.5-1-2: verdict is a difference from IXIT, unreachable without IXIT.

</details>

### 5.8-3 　外部を感知するセンサー（カメラ、マイクなど）を、利用者に分かりやすく説明しているか

- Claude の判定：**判定できない**
- 理由：製造者の文書で決まり、通信の観測者には判断できない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.8-3-1**（判定できない、2 回の分類が一致）：Check sensor documentation is reachable and understandable for lay users, and that all obvious sensors are documented.  
  理由：N: the subject is the manufacturer's documentation, not allowed under N. ND: published docs can show FAIL (missing/unclear sensor info); unit c needs inspection, so PASS unreachable.

</details>

### 5.9-1 　ネットワークや電源の停止に対して、回復力があるか

- Claude の判定：**判定できない**
- 理由：文書の確認と、試験者による停止の実施
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.9-1-1**（判定できない、2 回の分類が一致）：Judge whether the SO-declared resilience mechanisms suit network and power outages and meet their stated guarantees.  
  理由：Both a and b judge IXIT 23 content only; nothing visible in traffic or public sources decides them.
- **5.9-1-2**（判定できない、2 回の分類が一致）：Cut network and power to the device and check resilience behaviour matches the SO description.  
  理由：Verdict is solely a mismatch with IXIT 23; passive path cannot reach it.

</details>

### 5.9-2 　ネットワークが切れても、ローカルで動き続け、復旧後に戻るか

- Claude の判定：**違反だけ示せる**
- 理由：自然に起きた停止のあとに、接続が戻らないことが見えれば、違反を示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.9-2-1**（判定できない、2 回の分類が一致）：Judge declared resilience mechanisms, including continued local operation without network and clean recovery after power loss.  
  理由：Units a-c evaluate only declared mechanisms in IXIT 23.
- **5.9-2-2**（違反だけ示せる、2 回の分類が一致）：Induce network and power loss; check the device keeps working locally and restores connectivity and function as documented.  
  理由：IXIT bullet unreachable, but resuming connectivity is a property: no reconnection after a naturally occurring outage (b) shows FAIL. Local functionality (a) blocks PASS.

</details>

### 5.9-3 　再接続を秩序立てて行うか（再接続の嵐を起こさないか）

- Claude の判定：**違反だけ示せる**
- 理由：裁定 P-a。試験の手順は文書の確認だが、「秩序立った再接続」は性質なので、無応答の相手への間隔を空けない再試行の繰り返しが見えれば、違反を示せる
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.9-3-1**（違反だけ示せる、裁定 (P-a)）：Judge whether declared per-interface resilience measures give orderly connection and avoid mass reconnection.  
  理由：a and b assess IXIT 28 'Resilience Measures' only.
- **5.9-3-2**（判定できない、2 回の分類が一致）：Verify the declared resilience measures, especially against simultaneous mass reconnection, e.g. by sniffing connection setup and teardown.  
  理由：Verdict is solely a mismatch with IXIT 28 resilience measures; not reachable passively.

</details>

### 5.10-1 　テレメトリを、セキュリティ上の異常の検知に使っているか

- Claude の判定：**判定できない**
- 理由：製造者の側の分析は、通信には現れない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.10-1-1**（判定できない、2 回の分類が一致）：Check at least one security examination of telemetry is declared and that the telemetry suits detecting security anomalies.  
  理由：a and b concern manufacturer-side analysis described only in IXIT 24; telemetry upload may be visible but its examination is not.

</details>

### 5.11-1 　利用者のデータを、簡単に消去できるか

- Claude の判定：**違反だけ示せる**
- 理由：裁定 P-a。試験の手順は機器の操作が必要だが、消去（初期化）のあとも、前の利用者のデータや識別子を送り続けているのが見えれば、消えていないことを示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.11-1-1**（判定できない、2 回の分類が一致）：Judge whether a simple user-data erasure function exists, is adequate, and covers personal data, configuration and user keys.  
  理由：Units a-c rely entirely on IXIT 25/21/10 declarations.
- **5.11-1-2**（違反だけ示せる、裁定 (P-a)）：Create user data, run each erase function, check interaction matches and data is gone; check users cannot delete others' data.  
  理由：All units need operating the device (a-d) and inspecting its state (c).

</details>

### 5.11-2 　関連するサービスにある個人データを、消去できるか

- Claude の判定：**判定できない**
- 理由：機器やアプリの操作が要る。削除の要求は暗号化されている
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.11-2-1**（判定できない、2 回の分類が一致）：Judge whether a simple function deletes personal data held by associated services and covers all such services.  
  理由：a and b compare IXIT 25 against IXIT 21 only.
- **5.11-2-2**（判定できない、2 回の分類が一致）：Create personal data on associated services, run deletion, check interaction and that the service no longer holds it.  
  理由：Units a-c need device/app operation; deletion requests are TLS-encrypted so traffic cannot show them.

</details>

### 5.11-3 　データの消去の方法を、分かりやすく説明しているか

- Claude の判定：**判定できない**
- 理由：文書の確認と、実際の消去の操作
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.11-3-1**（判定できない、2 回の分類が一致）：Check the user documentation covers every deletion function concisely with all steps, by following it.  
  理由：b needs the IXIT 25 inventory and c needs executing deletions; public manuals alone cannot decide coverage or step completeness.

</details>

### 5.11-4 　データの消去が終わったことを、利用者に知らせるか

- Claude の判定：**判定できない**
- 理由：画面の通知の確認で、通信には現れない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.11-4-1**（判定できない、2 回の分類が一致）：Run each deletion function per documentation and check the user receives a clear confirmation of deletion.  
  理由：Confirmation is a UI message (c) after lab-triggered deletion (a,b); not visible in traffic.

</details>

### 5.12-1 　初期設定が安全か

- Claude の判定：**違反だけ示せる**
- 理由：裁定 P-a。「安全な初期値」は性質なので、初期状態で安全でない設定（平文の管理サービスが応答する、UPnP でポートを開けるなど）が見えれば、違反を示せる。初期状態のままかは分からないので、Quarant では候補止まり
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.12-1-1**（違反だけ示せる、裁定 (P-a)）：Judge whether each declared user decision during setup/maintenance is necessary and has a secure default.  
  理由：a and b assess IXIT 26 contents.
- **5.12-1-2**（判定できない、2 回の分類が一致）：Trigger each user decision and check it is prominent, understandable, and as declared.  
  理由：All units require running setup/maintenance flows on the device or app.

</details>

### 5.12-2 　安全な設定の方法を、案内しているか

- Claude の判定：**判定できない**
- 理由：設定の操作と文書が要る
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.12-2-1**（判定できない、2 回の分類が一致）：Set up the device following secure-setup documentation; check every security-relevant decision is covered with a recommendation.  
  理由：Public docs can show recommendations exist (c), but completeness needs IXIT 26 (b) and a needs setup; no passive path to the verdict.

</details>

### 5.12-3 　安全に設定できているかを、確認する方法を案内しているか

- Claude の判定：**判定できない**
- 理由：機器の設定を変えて確かめる必要がある
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.12-3-1**（判定できない、2 回の分類が一致）：Judge whether setup-check and maintenance-check documentation covers every needed step and parameter.  
  理由：Documentation may be published, but which steps are needed depends on device knowledge from IXIT; a/b not fully decidable from PUBLIC.
- **5.12-3-2**（判定できない、2 回の分類が一致）：Configure the device securely then insecurely and check the documented checks correctly tell the two apart.  
  理由：Every unit requires reconfiguring the device.

</details>

### 5.13-1A 　利用者の入力を検証しているか（画面などから）

- Claude の判定：**判定できない**
- 理由：文書の確認と、試験者による不正な入力の試行
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.13-1A-1**（判定できない、2 回の分類が一致）：Check each user interface has a declared input validation method and that it is effective.  
  理由：a and b judge IXIT 27/29 only.
- **5.13-1A-2**（判定できない、2 回の分類が一致）：Check all user interfaces are declared and try malformed input (fuzzing, web scanning) to see validation holds.  
  理由：b is active misuse testing; a needs IXIT; both are verdict conditions.

</details>

### 5.13-1B 　ネットワークからの入力を検証しているか

- Claude の判定：**違反だけ示せる**
- 理由：裁定 P-a。試験の手順は試験者によるファジングやスキャンだが、第三者の不正な入力による攻撃（インジェクションなど）が成功したのが見えれば、違反を示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **5.13-1B-1**（判定できない、2 回の分類が一致）：Check each network-accessible logical interface has a declared input validation method that is effective.  
  理由：a and b judge IXIT 28/29 only.
- **5.13-1B-2**（違反だけ示せる、裁定 (P-a)）：Fuzz or scan network interfaces to test validation; check all network interfaces are declared.  
  理由：Verdict needs both bullets; a is active probing, so no passive path even though b could be partly indicated by observed interfaces/services.

</details>

### 6-1 　個人データの扱いを、分かりやすく説明しているか

- Claude の判定：**判定できない**
- 理由：製造者の文書（プライバシーポリシー）で決まる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-1-1**（判定できない、2 回の分類が一致）：Judge whether the way personal data processing is documented gives clear information on what, why, who and how long.  
  理由：Conceptual subject (consumer information) substitutable by the public privacy policy: a missing purpose, recipient or retention element establishes FAIL; completeness per IXIT category blocks PASS.
- **6-1-2**（判定できない、2 回の分類が一致）：Check consumer-facing information on personal data processing is clear and matches the declared data categories, purposes, parties and retention.  
  理由：Bullet 1 (clarity/transparency) is a property of the public policy; recipients seen in DNS/SNI but undisclosed show FAIL. Bullet 2 (IXIT match) blocks PASS.

</details>

### 6-2 　同意に基づく処理で、明確な同意を得ているか

- Claude の判定：**判定できない**
- 理由：文書の確認と、同意の画面の操作
- （2026-10-17 に確認済み：納得）
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-2-1**（判定できない、裁定 (P-e)）：Judge whether opt-in consent for consent-based processing is described as free, obvious and explicit.  
  理由：a evaluates IXIT 21 descriptions only.
- **6-2-2**（判定できない、2 回の分類が一致）：Check consent is actually obtained as the SO describes for each consent-based data category.  
  理由：a needs operating the consent UI and IXIT comparison.

</details>

### 6-3A 　同意をいつでも取り消せるか

- Claude の判定：**判定できない**
- 理由：文書の確認と、取り消しの操作
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-3A-1**（判定できない、2 回の分類が一致）：Judge whether the SO describes how consent can be withdrawn at any time via device/service settings.  
  理由：a evaluates IXIT only.
- **6-3A-2**（判定できない、2 回の分類が一致）：Check consent can be withdrawn as described for each consent-based data category.  
  理由：a requires performing withdrawal; checking that flows stop afterwards would still need the withdrawal to be triggered.

</details>

### 6-3B 　同意の情報を保存しているか

- Claude の判定：**判定できない**
- 理由：文書と保存された記録の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-3B-1**（判定できない、2 回の分類が一致）：Judge whether the device provides a means to store consent information as declared.  
  理由：a evaluates IXIT only.
- **6-3B-2**（判定できない、2 回の分類が一致）：Check stored consent information is as described for each consent-based data category.  
  理由：a needs access to stored consent records and IXIT.

</details>

### 6-4 　テレメトリの個人データが、目的に必要なものだけか

- Claude の判定：**判定できない**
- 理由：文書の確認。平文のテレメトリに目的を超える個人データがあれば、手がかりになる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-4-1**（判定できない、2 回の分類が一致）：Judge whether personal data within declared telemetry is necessary for the stated purpose.  
  理由：Conceptual subject substitutable by observed plaintext telemetry: personal data clearly beyond the published purpose would show FAIL. Encrypted telemetry and IXIT block PASS.

</details>

### 6-5 　テレメトリについて、利用者に説明しているか

- Claude の判定：**判定できない**
- 理由：文書の確認
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-5-1**（判定できない、2 回の分類が一致）：Judge whether the telemetry documentation lets consumers learn about telemetry processing.  
  理由：If telemetry is observed but public documentation gives no telemetry information, unsuitability (FAIL) follows; PASS needs IXIT 24 to judge suitability.
- **6-5-2**（判定できない、2 回の分類が一致）：Obtain the telemetry information and check it matches the declared purposes and describes what is collected, use, recipients and purposes.  
  理由：c,d: missing description of collected telemetry or recipients in public docs, contrasted with observed endpoints, shows FAIL; a,b need IXIT so PASS unreachable.

</details>

### 6-6 　個人データを、必要なものだけ集め、必要な期間だけ保存しているか

- Claude の判定：**判定できない**
- 理由：文書の確認。平文で見えた不要な個人データは手がかりになるが、削除は見えない
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-6-1**（判定できない、2 回の分類が一致）：Judge necessity of each personal data category, reasonableness of its retention, and suitability of its disposal process.  
  理由：Substituting observed plaintext personal data for declared categories, data unnecessary for the published purpose fails bullet 1; b,c and PASS need IXIT.
- **6-6-2**（判定できない、裁定 (P-e)）：Create personal data, find data collected not created by the user, judge its necessity, and check deletion when no longer needed.  
  理由：Bullet 1 is breached when plaintext PII unnecessary for the stated purpose is seen (b,c). Deletion (d) is invisible, so PASS is unreachable.

</details>

### 6-7 　集計に使うデータを、最小限に集めているか

- Claude の判定：**判定できない**
- 理由：文書の確認。集計前の生のデータの平文の送信は手がかりになる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-7-1**（判定できない、2 回の分類が一致）：For data used only for aggregation, judge minimal collection, early aggregation and minimal retention.  
  理由：Substituting observed uploads: raw per-event records sent in plaintext where only aggregates are documented shows non-minimal collection/late aggregation. Retention and PASS need IXIT.
- **6-7-2**（判定できない、2 回の分類が一致）：Create data meant for aggregation and check the aggregation mechanism behaves as declared.  
  理由：Verdict is a mismatch with IXIT 21 aggregation description; not reachable passively.

</details>

### 6-8 　匿名化すべきデータを、匿名化しているか

- Claude の判定：**違反だけ示せる**
- 理由：識別できる個人データが平文で送られていれば、集めるときに匿名化していないことを示せる
- [x] 容認する
- [ ] 変更する
- メモ：

<details><summary>原文（試験の内容と、分類の理由）</summary>

- **6-8-1**（違反だけ示せる、2 回の分類が一致）：Judge whether declared anonymization technologies are used and appropriate across collection, processing and storage.  
  理由：Identifiable personal data seen in plaintext uploads shows anonymization is not applied at collection; appropriateness overall and PASS need IXIT.
- **6-8-2**（判定できない、2 回の分類が一致）：Create data meant for anonymization and check anonymization works as declared.  
  理由：Verdict is a mismatch with IXIT 21 anonymization description; not reachable passively.

</details>
