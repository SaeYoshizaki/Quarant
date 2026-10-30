# データセットの機器の一覧

製造者の主張と通信を突き合わせる（D31）ための一覧。元の表は [devices.tsv](devices.tsv)（手で作成）、観測の期間は `scripts/claims/build_catalog.py` が Quarant の解析結果（`device_inventory.json`）から付ける。

機器の特定の仕方：UNSW 2016 は `List_Of_Devices.txt`、UNSW-IoTraffic はファイル名、YourThings は `device_mapping.csv`（IP の対応）、Deakin は `macAddresses.csv`。UNSW 2018 には機器の一覧がないので、MAC アドレスを UNSW 2016 と UNSW-IoTraffic の一覧と照らした（どちらにもない 3 台と、名乗りだけで分かった 2 台は note に書いた）。CIC IoT 2022 は、機器ごとに 1 台ずつ電源を入れた Power の 3 回のキャプチャすべてに現れ、他の機器のキャプチャにはほぼ現れない MAC アドレスを、その機器とした。IoT-23 は正常な 3 シナリオだけを載せた（感染させた機器は主に Raspberry Pi で、製造者の主張がない）。スマートフォン、PC、ゲートウェイ、ゲーム機は載せていない。

限界：YourThings で解析したのは 2018-04-10〜12 だけ。型番が空の製品は、主張を集めるときに製品のページから型番を絞る必要がある。

## データセットごとの台数

| データセット | 一覧の行 | 解析結果で見えた | 製品が分からない |
|---|---|---|---|
| UNSW IoT traces 2016 | 23 | 23 | 0 |
| UNSW-IoTraffic 2016-17 | 27 | 27 | 0 |
| UNSW attacks 2018 | 28 | 28 | 3 |
| IoT-23 (benign) | 3 | 2 | 0 |
| YourThings 2018 | 57 | 45 | 1 |
| CIC IoT 2022 | 40 | 40 | 1 |
| Deakin 2023 | 24 | 19 | 0 |

製品（製造者 × 製品名 × 型番）：116 件。そのうち解析結果で見えたもの：102 件、2 つ以上のデータセットで見えたもの：30 件。

## 製品の一覧

期間は解析結果で機器が見えた日（キャプチャ時刻。2000 年より前の時刻は、機器の時計が戻ったものとして除く）。型番は、データセットのラベルか機器の名乗りで分かったものだけ書く（根拠は devices.tsv の model_basis）。

| 製造者 | 製品 | 型番 | 種類 | UNSW IoT traces 2016 | UNSW-IoTraffic 2016-17 | UNSW attacks 2018 | IoT-23 (benign) | YourThings 2018 | CIC IoT 2022 | Deakin 2023 |
|---|---|---|---|---|---|---|---|---|---|---|
| Aeotec | Smart Home Hub (SmartThings) |  | hub |  |  |  |  |  |  | 2024-04-08〜2024-05-19 |
| Amazon | Echo |  | voice-assistant | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-03-24 | 2018-06-01〜2018-10-25 | 2018-09-21〜2018-09-21 |  |  |  |
| Amazon | Echo (1st gen) | Echo (1st gen) | voice-assistant |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Amazon | Echo Dot |  | voice-assistant |  |  |  |  |  | 2021-09-28〜2021-12-24（2 台） |  |
| Amazon | Echo Dot (3rd gen) |  | voice-assistant |  |  |  |  |  |  |  |
| Amazon | Echo Dot (4th gen) | Echo Dot (4th gen) | voice-assistant |  |  |  |  |  |  | 2023-07-25〜2023-08-01 |
| Amazon | Echo Show 8 | Echo Show 8 | voice-assistant |  |  |  |  |  |  | 2023-07-25〜2024-05-19（2 台） |
| Amazon | Echo Spot |  | voice-assistant |  |  |  |  |  | 2021-09-28〜2021-12-24 |  |
| Amazon | Echo Studio |  | speaker |  |  |  |  |  | 2021-09-28〜2021-12-24 |  |
| Amazon | Fire TV |  | tv-streaming |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Amazon | Smart Plug |  | plug |  |  |  |  |  | 2021-09-23〜2021-12-24 |  |
| Amcrest | camera |  | camera |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| Apple | Apple TV (4th gen) | Apple TV (4th gen) | tv-streaming |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Apple | HomePod |  | speaker |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Arlo (Netgear) | Arlo base station | VMB3010 | camera |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Arlo (Netgear) | Arlo base station | VMB5000 | camera |  |  |  |  |  | 2021-09-28〜2021-12-24 |  |
| Arlo (Netgear) | Arlo Q |  | camera |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| Atomi | Smart Coffee Maker |  | appliance |  |  |  |  |  | 2021-09-28〜2021-12-24 |  |
| August | Doorbell Cam |  | doorbell |  | 2016-12-02〜2017-04-13 | 2018-06-01〜2018-10-25 |  | 2018-04-10〜2018-04-12 |  |  |
| AVTech | IP Camera |  | camera |  |  |  |  |  |  |  |
| Awair | Air Quality Monitor |  | sensor |  | 2016-11-10〜2017-03-07 | 2018-06-01〜2018-06-02 |  |  |  |  |
| Axis | Network Camera |  | camera |  |  |  |  |  |  |  |
| Belkin | NetCam HD |  | camera |  | 2017-02-21〜2017-03-16 | 2018-10-21〜2018-10-25 |  | 2018-04-10〜2018-04-12 |  |  |
| Belkin | WeMo Link |  | hub |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Belkin | WeMo Motion Sensor |  | sensor | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-03-07 | 2018-06-01〜2018-10-25 |  | 2018-04-10〜2018-04-12 |  |  |
| Belkin | WeMo Switch |  | plug | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-03-23 | 2018-06-01〜2018-06-02 |  | 2018-04-10〜2018-04-12 |  |  |
| Belkin (Crock-Pot) | WeMo Crock-Pot |  | appliance |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| BlipCare | Blood Pressure Meter |  | health | 2016-09-23〜2016-10-04 | 2016-10-04〜2017-04-10 |  |  |  |  |  |
| Borun | camera |  | camera |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| Bose | SoundTouch 10 | SoundTouch 10 | speaker |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Canary | Canary |  | camera |  | 2016-11-22〜2017-03-05 | 2018-06-01〜2018-10-25 |  | 2018-04-10〜2018-04-12 |  |  |
| Chamberlain | myQ Garage |  | appliance |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| D-Link | DCS-5009L | DCS-5009L | camera |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| D-Link | DCS-8000LH | DCS-8000LH | camera |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| D-Link | Water Sensor | DCH-S161 | sensor |  |  |  |  |  | 2021-09-29〜2021-12-24 |  |
| Dropcam (Nest) | Dropcam |  | camera | 2016-09-22〜2016-10-12（2 台） | 2017-01-01〜2017-04-13 | 2018-06-01〜2018-10-25 |  |  |  |  |
| Eufy (Anker) | HomeBase |  | hub |  |  |  |  |  | 2021-09-23〜2021-12-24 |  |
| EZVIZ | Security Camera |  | camera |  |  |  |  |  |  |  |
| Facebook | Portal |  | voice-assistant |  |  |  |  |  |  |  |
| Globe | Smart Lamp |  | bulb |  |  |  |  |  | 2021-09-28〜2021-12-24 |  |
| Google | Chromecast Ultra |  | tv-streaming |  |  | 2018-10-21〜2018-10-25 |  |  |  |  |
| Google | Google Home |  | voice-assistant |  |  | 2018-06-01〜2018-10-25 |  | 2018-04-10〜2018-04-12 |  |  |
| Google | Google Home Mini |  | voice-assistant |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Google | Home Hub |  | voice-assistant |  |  |  |  |  |  |  |
| Google | Nest Mini |  | voice-assistant |  |  |  |  |  | 2021-09-23〜2021-12-24 |  |
| Gosund | Smart Plug |  | plug |  |  |  |  |  | 2021-09-23〜2021-12-24（7 台） |  |
| Harman Kardon | Invoke | Invoke | voice-assistant |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| HeimVision | camera |  | camera |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| HeimVision | Smart Lamp |  | bulb |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| Home Eye | camera |  | camera |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| HP | Printer (ENVY) |  | printer | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-04-13 | 2018-06-01〜2018-10-25 |  |  |  | 2023-07-25〜2024-05-19 |
| iHome | Smart Plug |  | plug | 2016-09-28〜2016-10-07 | 2016-10-05〜2017-02-24 | 2018-06-01〜2018-10-25 |  |  |  |  |
| Insteon | Camera |  | camera | 2016-09-28〜2016-10-12（2 台） |  |  |  |  |  |  |
| Insteon | Hub Pro | Hub Pro | hub |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Invoxia | Triby |  | speaker | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-04-07 | 2018-10-21〜2018-10-25 |  |  |  |  |
| iRobot | Roomba |  | appliance |  |  |  |  | 2018-04-10〜2018-04-12 | 2021-09-29〜2021-12-24 |  |
| Koogeek | Smart Bulb | LB1 | bulb |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| LG | webOS TV |  | tv-streaming |  |  |  |  |  | 2021-09-28〜2021-11-03 |  |
| LIFX | Color 1000 | Color 1000 | bulb |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| LIFX | Smart Bulb |  | bulb | 2016-09-28〜2016-10-12 | 2016-09-30〜2017-04-13 | 2018-10-21〜2018-10-25 |  |  |  |  |
| Logitech | Harmony Hub |  | hub |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Logitech | Logi Circle |  | camera |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Luohe | camera |  | camera |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| Lutron | Caseta Smart Bridge |  | hub |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Mattel | Hello Barbie |  | toy |  | 2017-03-02〜2017-04-13 | 2018-06-01〜2018-06-02 |  |  |  |  |
| MiCasaVerde | VeraLite | VeraLite | hub |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Nest (Google) | Hello (doorbell) |  | doorbell |  |  |  |  |  |  |  |
| Nest (Google) | Nest Cam |  | camera |  |  |  |  | 2018-04-10〜2018-04-12 | 2021-09-22〜2021-12-24 |  |
| Nest (Google) | Nest Cam IQ |  | camera |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Nest (Google) | Nest Guard (Secure) |  | hub |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Nest (Google) | Protect |  | sensor | 2016-09-23〜2016-10-11 | 2016-09-30〜2017-04-13 | 2018-06-01〜2018-10-25 |  | 2018-04-10〜2018-04-12 |  |  |
| Nest (Google) | Thermostat |  | appliance |  |  |  |  |  |  |  |
| Netatmo | Smart Indoor Camera (Welcome) |  | camera |  |  |  |  |  |  | 2023-07-25〜2024-05-19 |
| Netatmo | Weather Station |  | sensor | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-04-13 | 2018-10-21〜2018-10-25 |  |  | 2021-09-22〜2021-12-24 | 2023-07-25〜2024-05-19 |
| Netatmo | Welcome |  | camera | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-03-26 | 2018-06-01〜2018-06-02 |  |  | 2021-09-22〜2021-12-24 |  |
| NVIDIA | Shield TV |  | tv-streaming |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Perfk | Motion Sensor |  | sensor |  |  |  |  |  |  | 2023-07-25〜2024-05-19（2 台） |
| Philips | Hue Bridge |  | hub |  | 2016-11-14〜2017-04-13 | 2018-10-21〜2018-10-25 | 2018-10-25〜2018-10-26 | 2018-04-10〜2018-04-12 | 2021-09-23〜2021-12-24 |  |
| Piper | Piper nv | Piper nv | camera |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Pix-Star | Easy Digital Photo Frame |  | photo-frame |  |  |  |  |  |  | 2023-07-25〜2024-05-19 |
| Pix-Star | Photo Frame |  | photo-frame | 2016-09-22〜2016-10-05 | 2016-09-30〜2017-04-06 | 2018-06-01〜2018-10-25 |  |  |  |  |
| Rachio | Rachio 3 |  | appliance |  |  |  |  |  |  |  |
| Ring | Alarm Base Station |  | hub |  |  |  |  |  | 2021-09-29〜2021-12-24 |  |
| Ring | Video Doorbell |  | doorbell |  | 2017-03-07〜2017-04-13 | 2018-06-01〜2018-10-25 |  | 2018-04-10〜2018-04-11 |  | 2023-07-25〜2023-09-06 |
| Roku | Roku 4 | Roku 4 | tv-streaming |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Samsung | Galaxy Watch5 Pro | Galaxy Watch5 Pro | wearable |  |  |  |  |  |  | 2024-05-13〜2024-05-19 |
| Samsung | Pan/Tilt 1080P Wi-Fi Camera |  | camera |  |  |  |  |  |  | 2023-07-25〜2024-05-19 |
| Samsung | Smart Monitor M80B | M80B | tv-streaming |  |  |  |  |  |  | 2023-07-26〜2024-05-19 |
| Samsung | Smart TV |  | tv-streaming |  |  |  |  | 2018-04-10〜2018-04-10 |  |  |
| Samsung | SmartCam |  | camera | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-04-13 | 2018-06-01〜2018-10-25 |  |  |  |  |
| Samsung | SmartThings Hub |  | hub | 2016-09-22〜2016-10-12 | 2016-09-30〜2017-04-13 | 2018-06-01〜2018-10-25 |  | 2018-04-10〜2018-04-12 |  |  |
| Securifi | Almond |  | hub |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| SimCam | camera |  | camera |  |  |  |  |  | 2021-09-22〜2021-12-24 |  |
| Somfy | Door Lock |  | lock |  |  |  |  |  |  |  |
| Sonos | Beam |  | speaker |  |  |  |  |  |  |  |
| Sonos | Sonos One | ZPS18 | speaker |  |  |  |  |  | 2021-09-28〜2021-12-24 |  |
| Sonos | Sonos speaker | ZPS1 (PLAY:1) | speaker |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| TCL / Roku | Roku TV |  | tv-streaming |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Teckin | Smart Plug |  | plug |  |  |  |  |  | 2021-09-23〜2021-12-24（2 台） |  |
| TOPERSUN | Smart Plug |  | plug |  |  |  |  |  |  | 2023-07-25〜2024-05-19（2 台） |
| TP-Link | Day/Night Cloud Camera | NC220 | camera | 2016-09-22〜2016-10-05 | 2016-09-30〜2017-04-13 | 2018-10-21〜2018-10-25 |  |  |  |  |
| TP-Link | Smart Plug | HS110(US) | plug | 2016-09-22〜2016-10-07 | 2016-09-30〜2017-03-07 | 2018-06-01〜2018-10-25 |  |  |  |  |
| TP-Link | Smart Plug | HS105 | plug |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| TP-Link | Smart Wi-Fi LED Bulb | LB130 | bulb |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| TP-Link | Tapo Pan/Tilt Camera | C210 | camera |  |  |  |  |  |  | 2023-07-25〜2024-05-19 |
| Tuya | Smart Doorbell |  | doorbell |  |  |  |  |  |  |  |
| Western Digital | My Cloud EX2 Ultra |  | nas |  |  |  |  |  |  |  |
| Wink | Hub |  | hub |  |  |  |  |  |  |  |
| Wink | Hub 2 |  | hub |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Withings | Aura Sleep Sensor |  | health | 2016-09-28〜2016-10-12 | 〜2017-03-24 |  |  |  |  |  |
| Withings | Body+ | Body+ | health |  |  |  |  |  |  | 2024-04-08〜2024-05-18 |
| Withings | BPM Connect | BPM Connect | health |  |  |  |  |  |  | 2024-04-09〜2024-05-17 |
| Withings | Home |  | camera |  |  |  |  | 2018-04-10〜2018-04-12 |  |  |
| Withings | Smart Baby Monitor |  | camera | 2016-09-22〜2016-10-07 | 2016-09-22〜2016-10-07 |  |  |  |  |  |
| Withings | Smart Scale |  | health | 2016-09-22〜2016-10-11 | 2016-09-30〜2017-04-13 |  |  |  |  |  |
| Yutron | Smart Plug |  | plug |  |  |  |  |  | 2021-09-23〜2021-12-24（2 台） |  |

## 製品が分からない機器（主張を集められない）

- UNSW attacks 2018：(no list; Withings OUI)（not in any list; product unknown）
- UNSW attacks 2018：(no list; Espressif OUI)（ESP_ hostname only; product unknown）
- UNSW attacks 2018：(no list; Belkin OUI)（not in any list; product unknown）
- YourThings 2018：ChineseWebcam（maker unknown; claims cannot be collected）
- CIC IoT 2022：Smart Board（maker unknown）

## 一覧にはあるが、解析結果では見えなかった機器

- IoT-23 (benign)：CTU-Honeypot-Capture-7-1 (Somfy door lock)（not analysed by Quarant yet; MAC not taken）
- YourThings 2018：WinkHub（not seen in the analysed captures）
- YourThings 2018：NestBell（not seen in the analysed captures）
- YourThings 2018：Rachio3（not seen in the analysed captures）
- YourThings 2018：AmazonEchoDotGen3（not seen in the analysed captures）
- YourThings 2018：NestThermostat（not seen in the analysed captures）
- YourThings 2018：GoogleHomeHub（not seen in the analysed captures）
- YourThings 2018：FacebookPortal（not seen in the analysed captures）
- YourThings 2018：SonosBeam（not seen in the analysed captures）
- YourThings 2018：LGWebOSTV（not seen in the analysed captures）
- YourThings 2018：MyCloudEX2Ultra（not seen in the analysed captures）
- YourThings 2018：AxisNetworkCamera（not seen in the analysed captures）
- YourThings 2018：AVTechIPCam（not seen in the analysed captures）
- Deakin 2023：EZVIZ Security Camera（model not named）
- Deakin 2023：NEST Protect smoke alarm
- Deakin 2023：Withings Body+ (Scales)
- Deakin 2023：Withings Connect (Blood Pressure)
- Deakin 2023：TUYA Smartdoor Bell（model not named）
