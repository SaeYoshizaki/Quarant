# 「AES 256」の候補（C）の先行研究：機器ごと（2026-11-16）

[report-2026-11-15.md](report-2026-11-15.md) の C 節（「AES 256」と書いた製品で、サーバーが AES-128 を選ぶ）について、5 本の論文の本文を読んだ。PDF は利用者が用意したもので、リポジトリには入れない。

| 略称 | 論文 | 読んだ版 |
|---|---|---|
| IoTLS | M. T. Paracha, D. J. Dubois, N. Vallina-Rodriguez, D. Choffnes, "IoTLS: Understanding TLS Usage in Consumer IoT Devices", ACM IMC 2021, doi:10.1145/3487552.3487830 | 出版版（pp.165〜） |
| SoK | O. Alrawi, C. Lever, M. Antonakakis, F. Monrose, "SoK: Security Evaluation of Home-Based IoT Deployments", IEEE S&P 2019, doi:10.1109/SP.2019.00013 | IEEE Xplore の版（ページは印刷の番号。PDF の 17 ページ目が p.1378） |
| Wannigama | S. Wannigama, A. Sivanathan, A. Hamza, H. Habibi Gharakheili, "Unveiling Behavioral Transparency of Protocols Communicated by IoT Networked Assets", IEEE WoWMoM 2024, pp.39-44 | 出版版。比べるため arXiv:2404.07408v1（著者が「full version」とする版）も読んだ |
| IoTLS 2.0 | C. Gupta, N. Guldali, M. Damie, "IoTLS 2.0: How Far Has IoT Industry Come in Securing Communications with TLS?", EuroSec 2026, doi:10.1145/3803525.3804979 | 出版版（pp.53〜59） |
| Akgul | O. Akgul, R. Abu-Salma, W. Bai, E. M. Redmiles, M. L. Mazurek, B. Ur, "From 'Secure' to 'Military-Grade': Exploring the Effect of App Descriptions on User Perceptions of Secure Messaging", ACM WPES 2021, doi:10.1145/3463676.3485602 | King's Research Portal の出版版 |

## 要点

- **5 本とも、製造者の「AES 256」の説明と、通信で選ばれた暗号を比べていない。**
- 機器の名前が出るのは、C の 6 製品のうち 4 製品だけ。
  - Awair と Samsung のカメラ：Wannigama。同じ UNSW 2016 の通信を使っている。
  - Roomba と Withings Home：SoK。2018 年の機器。
- SNH-V6410PN（Deakin）と Somfy（IoT-23）は、5 本のどれにもない。
- 鍵の長さ（AES-128 か 256 か）を問題にしている論文はない。IoTLS 2.0 は、どちらも NIST の推奨に沿うとしている。

## 機器ごと

| 製品（こちらのデータ） | IoTLS | SoK | Wannigama | IoTLS 2.0 | Akgul |
|---|---|---|---|---|---|
| Awair（UNSW-IoTraffic 2016-17） | なし（40 機器にない。Table 1, p.167） | なし | **あり**（下） | なし | なし |
| iRobot Roomba（CIC 2021） | なし | **あり**。ただし 2018 年の別の個体（下） | なし | なし（ロボット掃除機は iLife 10s だけ） | なし |
| SmartCam SNH-P6410BN（UNSW-IoTraffic、UNSW 2018） | なし | なし | **あり**（「Samsung camera」。機種名はない。下） | なし（Samsung は冷蔵庫だけ） | なし |
| SNH-V6410PN（Deakin 2023-24） | なし | なし | なし | なし | なし |
| Somfy のゲートウェイ（IoT-23 2019） | なし | なし | なし | なし | なし |
| Withings Home（YourThings 2018） | なし | **あり**（下） | なし（Withings はほかの製品だけ） | なし | なし |
| 対照：Canary（UNSW） | なし | あり（下） | なし | なし | なし |
| 対照：Nest Cam（CIC 2021） | なし（Nest は Thermostat だけ） | あり（2018 年の Nest Camera） | なし | あり（Nest Camera Indoor、2025 年） | なし |

### Awair：Wannigama

- 同じ UNSW 2016 の通信。TLS は tcp/443 で 647 本、ほかに tcp/8883 で 179 本（Table I、p.40）。合わせて 826 本で、こちらの数と同じ。
- サーバーが選んだ暗号として、0x003c と 0x003d を挙げる（p.40）。AES-128 と AES-256 の CBC_SHA256 で、どちらも RSA の鍵交換。
- 書いていないこと：
  - 割合（こちらは 744 本が AES-128、82 本が AES-256）
  - 機器が AES-256 を先に出していること
  - 前方秘匿性がないこと
  - 「AES 256 bit encryption」の説明
- arXiv 版だけにある文：Awair、Samsung のカメラ、Ring などのサーバーが「consistently chose a weak code from the client-suggested ciphersuite」（p.3）。出版版にはこの段落がない。

### Samsung のカメラ（SNH-P6410BN）：Wannigama

- 同じ UNSW 2016 の通信。名前は「Samsung camera」で、機種は書いていない。
- 書いていること：
  - TLS は tcp/443 で 65 本。HTTP は 13,396 本で、ほかに tcp/49152 で 19,801 本（Table I、p.40）。
  - サーバーが選んだ暗号は 0xc013（ECDHE_RSA_AES_128_CBC_SHA、p.40）。
  - 機器は、相手によって TLS 1.2 と 1.0 を出し分ける（p.40）。
- arXiv 版だけにあること：TLS 1.0 を使う「most vulnerable cluster」に入れている。弱い暗号の文も同じ（p.3）。
- 書いていないこと：
  - XMPP（tcp/5222、STARTTLS のあとの TLS）。こちらでは、ここで AES-256 が選ばれていた。
  - 映像
  - 「SSL (AES 256bit)」の説明

### iRobot Roomba：SoK

- SoK の Roomba は 2018 年の機器（YourThings と同じ研究室）。こちらの C の行は CIC 2021 の Roomba で、個体も時期も違う。
- Table VII（p.1379）：
  - 機器とクラウドの間は「完全に暗号化」（●）、アプリとクラウドの間も ●、アプリと機器の間は ○。
  - 中間者の検査は 3 つとも ✗（成功しなかった）。
- Table V（p.1378）：クラウドのサーバーを能動的に調べた結果で、「Vuln SSL」に ✓。本文（§IV-F, p.1372）は、自己署名の証明書、名前の不一致、古い TLS/SSL の版への対応などをまとめて「TLS/SSL configuration issues」と呼ぶ。Roomba の中身は書いていない。
- 暗号スイートの記述はない。

### Withings Home：SoK

- YourThings と同じ研究室の 2018 年の機器（同じ個体かは未確認）。
- Table VII（p.1379）：機器とクラウド、アプリとクラウド、アプリと機器が、すべて「完全に暗号化」（● ● ●）。中間者の検査は 3 つとも ✗。
- 付録 B「A. Good: Withings Home」（p.1380）：
  - 「The network communication between device-to-cloud, app-to-cloud, and app-to-device uses full encryption and is not susceptible to MITM attacks.」
  - 「The device did authenticate in clear-text … to … an XMPP server」。注に xmpp.withings.net:5222 とある。Table V（p.1378）の「Cleartext Auth」も ✓。
- 暗号スイートと「AES-256」の説明はない。

### 対照：Canary、Nest Cam

- **Canary（SoK、2018）**：Table VII で機器とクラウド、アプリとクラウドが ●。Table V でクラウドに自己署名の証明書（✓）。暗号スイートの記述はない。
- **Nest Camera（SoK、2018）**：
  - Table VII で ● ●。Table V で自己署名の証明書と Vuln SSL に ✓。
  - 付録 B「B. Satisfactory: Nest Cam」（p.1380）は、証明書のピンニングを使うとする。
- **Nest Camera Indoor（IoTLS 2.0、2025）**：
  - TLS 1.3 に対応し、TLS 1.3 で接続した（§4.2, p.56）。3DES を提示していた（§4.3, p.56）。
  - CIC 2021 の Nest Cam が TLS 1.0 だけだったこととは、時期も機種も違う（機種が同じかは未確認）。

## 全体の傾向として引けること

- **IoTLS**：
  - 「Devices tend to have better support for perfect forward secrecy than the servers they connect to.」（§5.1, p.172）。前方秘匿性を提示した 33 機器のうち 22 機器で、多くの接続が前方秘匿性なしだった。
  - 考察（§6, p.175）：「some devices support the latest secure TLS features but still negotiate weak connections due to lack of server support」。
  - AES の鍵の長さは扱っていない。
- **IoTLS 2.0**：
  - 2025 年の 22 機器では、前方秘匿性なしで接続した機器は 1 つだけ（Table 4, p.58）。
  - AES-GCM の 128 ビットと 256 ビットは、どちらも NIST の推奨に沿うとする（§4.3, p.56）。
  - 7 機器が AES-128-CBC で接続した。
- **Wannigama**：サーバーが機器の提示から弱い暗号を選ぶ（arXiv 版 p.3）。
  - arXiv 版の注 3（p.2）は、Ring が 0xc014（AES-256）を 1 番目に出すと書く。
  - 本文では、Ring のサーバーが 0xc027（AES-128）を選んだとある（p.40）。ただし、鍵の長さの違いには触れていない。
- **Akgul**：IoT ではなく、メッセージアプリの説明文についての利用者の調査（357 人）。
  - 「military-grade encrypted」を「seemingly technical, widely used to describe encryption, but ultimately meaningless」とする（§3.1, p.121）。
  - 説明を「encrypted」「military-grade encrypted」にすると、秘密の用途に向くと受け取られやすくなった（要旨）。
  - 具体的な暗号（AES256 など）に触れた参加者は 1% 未満（p.128）。
  - 製品の検証はしていない。「説明の言葉が受け止め方を変える」という動機づけに使える。

## こちらの記録への影響

- **区分は変わらない**：「AES 256」の説明と、選ばれた暗号を比べた資料は、この 5 本にもない。サーバーが弱い方を選ぶこと自体は、IoTLS と Wannigama（arXiv 版）にある。どちらもトップ 4 の会議ではない。SoK（S&P）は暗号スイートを扱っていない。
- **Wannigama の引用は版を書く**：「consistently chose a weak code」と Ring の注 3 は、arXiv 版だけにある。報告で引くときは arXiv 版と書く。
- **確かめること（未確認）**：SoK は、Withings Home が xmpp.withings.net:5222 へ平文で認証したと書く。こちらの記録には、Withings Home の 5222 の通信が出てこない。
  - 平文の XMPP なら、Withings Home は平文の通信がもう 1 つあることになる。
  - STARTTLS のあとの TLS なら、Samsung と同じく洗い出しが数えていない接続になり、「Withings Home はすべての接続で AES-128」が崩れるかもしれない。
  - 外付けディスクがつながったら、YourThings の通信で確かめる。
