# 5 つのデータセットの洗い出し（2026-11-10）

教授との面談（2026-11-10、[DECISIONS.md](../DECISIONS.md) の D41）を受けて、1 製品の深掘りをやめ、手元のデータセットすべてで識別子と暗号化の問題を自動で洗い出した。先行研究で振り分けたうえで、残る候補を並べる。

## やったこと

- **対象**：UNSW 2016（20 日）、UNSW-IoTraffic（27 機器、2016-09〜2017-04）、YourThings 2018（13 日）、CIC IoT 2022（攻撃以外の 1,033 ファイル）、Deakin 2023（34 日）。機器は [devices.tsv](devices.tsv) の 5 データセット分。
- **道具**：`scripts/claims/sweep/`。PCAP を 1 回読み（`expose.py`）、製品ごとの表にし（`report.py`）、候補を 1 行ずつにまとめ（`candidates.py`）、先行研究と結ぶ（`merge_prior.py`）。値は書き出さず、鍵付きのハッシュ、形、長さだけを残す。
- **見るもの**：
  - 機器が LAN で名乗る値（UPnP のシリアル、SSDP・mDNS の ID、DHCP のホスト名）や MAC アドレスが、インターネットへの平文の通信に出ているか。
  - 認証情報らしい値（Authorization、auth、token、sessionid）が平文で出ているか。
  - HTTP でのファームウェアの取得。
  - TLS の版、暗号、前方秘匿性、サーバー証明書。YourThings の作成者の中間者の検査（発行者 `thing-catcher.gtisc.gatech.edu`、04-10〜13）は除いた。
- **先行研究**：論文 11 本の機器ごとの対応表と、候補ごとの検索（CVE、ブログ、論文）。本文を読めたものだけを根拠にした。結果は [sweep/prior-ids.tsv](sweep/prior-ids.tsv) と [sweep/prior-tls.tsv](sweep/prior-tls.tsv)。
- **確かめ方**：Sonos の既知の結果（YourThings 2018-03-20 のフレーム 60977 の serial と householdid、フレーム 4429 の UPnP のシリアル）を自動で再現した。「見つからず」と「ブログ等のみ」の 20 件（2026-11-10）と「論文で一部」の 41 件（2026-11-11）は、パケットで確かめた（下）。TLS の 105 件も、根拠の握手をパケットで確かめた（2026-11-11、TLS の節）。

## 数

- 候補：85 製品、194 件（[sweep/candidates.tsv](sweep/candidates.tsv)）。2026-11-11 に、取りこぼしていたダウンロードの 11 件、Deakin のやり直しで出た TLS の 4 件、UNSW 2018 の 12 件、IoT-23 の 1 件を足した。
- 識別子など 61 件：除く 0、論文で一部 42、ブログ等のみ 9、見つからず 10。
- TLS 110 件：除く 7、論文で一部 59、ブログ等のみ 2、見つからず 1、対応表の論文にない 33、未確認 8（2026-11-11 に Deakin の 4 件と IoT-23 の Somfy を候補ごとに探した）。
- 2026-11-11 の追加：Wannigama ほか（IEEE WoWMoM 2024、arXiv:2404.07408 の Table I p.2、§II）が UNSW のデータで Awair と Samsung SmartCam の TLS、Triby の Basic 認証を扱っていたので、この 3 件を「論文で一部」に移した。
- 公式文書との食い違いの候補と、取りこぼしていたダウンロードの先行研究は [sweep/prior-claims.tsv](sweep/prior-claims.tsv)。

区分（2026-11-11 に基準を変えた。以前は IMC と PETS も「除く」にしていて、識別子 1 件と TLS 13 件がそれで除かれていた）。

- **除く**：IEEE S&P、USENIX Security、ACM CCS、NDSS の論文が、同じ機器（または同じ系列）の同じ問題を詳しく示している。除いたものには理由（論文、表か節、ページ）を書く。
- **論文で一部**：IMC、PETS、ほかの会議の論文、集計だけ、同じメーカーの別の機種、または問題の別の面。
- **ブログ等のみ**：ブログ、勧告、CVE、講演、GitHub。
- **見つからず**：探した範囲で報告がない。**新しいという意味ではない。**

## 識別子・認証情報・ファームウェア（61 件）

「最初の根拠」はデータセット、ファイル、フレーム番号。中身の項目名と宛先は [sweep/candidates.tsv](sweep/candidates.tsv) の detail、先行研究の書誌と違いは [sweep/prior-ids.tsv](sweep/prior-ids.tsv)。

| 製品 | 種類 | データ | 回数 | 平文で送っていたもの（項目 → 宛先） | 最初の根拠 | 先行研究 | 区分 |
|---|---|---|---|---|---|---|---|
| August Doorbell Cam | MAC（HTTP 以外） | iotraffic | 2 | raw bytes in tcp/443 payload; raw bytes in tcp/68 payload | iotraffic:pcaps__AugustDoorBell_e076d03f00ae.pcap フレーム 5122643 | ― | 見つからず |
| HeimVision camera | 識別子（平文の HTTP） | cic2022 | 28 | form:device_id=MAC -> esd.closeli.com:80 | cic2022:1-Power__Cameras__HeimVision Camera__POWER__heimvisioncamPOWER_1.pcap フレーム 62 | ― | 見つからず |
| Home Eye camera | 認証情報らしい値（平文） | cic2022 | 82 | h:authorization:oss -> xyxcamera.oss-cn-hongkong.aliyuncs.com:80 | cic2022:1-Power__Cameras__Home Eye Camera__POWER__homeeyecamPOWER_1.pcap フレーム 25 | ― | 見つからず |
| Invoxia Triby | HTTP でのファームウェア取得 | iotraffic | 22 | developer.invoxia.com/update/triby/update.pup (4064478 B); developer.invoxia.com/update/triby/update.pup (4064439 B) | iotraffic:pcaps__TribySpeaker_18B79E022044.pcap フレーム 514528 | ― | 見つからず |
| Invoxia Triby | MAC（HTTP 以外） | iotraffic,unsw2016 | 27442 | aa:bb:cc:dd:ee:ff in tcp/5228 payload; aabbccddeeff in tcp/8090 payload | iotraffic:pcaps__TribySpeaker_18B79E022044.pcap フレーム 10 | ― | 見つからず |
| Invoxia Triby | 識別子（平文の HTTP） | iotraffic,unsw2016 | 561 | text=MAC -> 46.105.38.79:5228; q:mac=MAC -> developer.invoxia.com:80 | iotraffic:pcaps__TribySpeaker_18B79E022044.pcap フレーム 2 | ― | 見つからず |
| Nest (Google) Guard (Secure) | MAC（HTTP 以外） | yourthings | 449 | raw bytes in tcp/11095 payload | yourthings:eth1-20180410.0045.1523339100 フレーム 49432 | ― | 見つからず |
| SimCam camera | 認証情報らしい値（平文） | cic2022 | 16 | h:authorization:aws4-hmac-sha256 -> elasticbeanstalk-us-east-2-793503604989.s3.amazonaws.com:80 | cic2022:2021_11_02_Active.pcap フレーム 1122 | ― | 見つからず |
| TP-Link Day/Night Cloud Camera NC220 | MAC（HTTP 以外） | unsw2016 | 8 | aabbccddeeff in udp/40043 payload; aabbccddeeff in udp/42730 payload | unsw2016:16-09-30.pcap フレーム 493236 | ― | 見つからず |
| unknown Smart Board | HTTP でのファームウェア取得 | cic2022 | 1 | edgedl.me.gvt1.com/edgedl/delta-update/jflookgnkcckhobaglndicnbbgbone/{id}/{id}/{id} (4136 B) | cic2022:2-Idle__2021_12_20_Idle.pcap フレーム 9926 | ― | 見つからず |
| Amcrest camera | 識別子（平文の HTTP） | cic2022 | 64 | path[2]=mdns_name -> 54.205.158.199:8802; text=mdns_name -> 34.238.41.119:8800 | cic2022:1-Power__Cameras__Amcrest__POWER__amcrestcamPOWER_1.pcap フレーム 137 | dh-p2p README（2023） | ブログ等のみ |
| Apple HomePod | 認証情報らしい値（平文） | yourthings | 3 | h:x-playback-session-id -> streamingaudio.itunes.apple.com:80 | yourthings:eth1-20180321.2015.1521681300 フレーム 61634 | Apple Doesn't Encrypt Downloads, Exposes More than 1Billion iPhones an（2018） | ブログ等のみ |
| Borun camera | MAC（HTTP 以外） | cic2022 | 28317 | aabbccddeeff in udp/8877 payload | cic2022:1-Power__Cameras__Borun Camera__POWER__boruncamPOWER_1.pcap フレーム 91 | Critical vulnerability in v380 cameras: how plaintext credentials expo（2025） | ブログ等のみ |
| Borun camera | 識別子（平文の HTTP） | cic2022 | 227 | json:deviceid=named json:deviceid -> rapi.av380.net:8002; json:deviceid=named json:deviceid -> 120.24.217.232:8002 | cic2022:1-Power__Cameras__Borun Camera__POWER__boruncamPOWER_1.pcap フレーム 107 | Same as Borun id-other: Shamagin 2025 (dev.to) and darkisdark 2025 (Ha（2025） | ブログ等のみ |
| Netatmo Weather Station | MAC（HTTP 以外） | cic2022,iotraffic,unsw2016 | 18388 | aa:bb:cc:dd:ee:ff in tcp/25050 payload | cic2022:1-Power__Other__Netatmo Weather Station__POWER__netatmoweatherPOWER_1.pcap フレーム 29 | Did You Remove That Debug Code? Netatmo Weather Station Sending WPA Pa（2015） | ブログ等のみ |
| Pix-Star Easy Digital Photo Frame | 識別子（平文の HTTP） | deakin | 34 | q:usr=MAC -> iptime.pix-star.com:80 | deakin:pcapFull__2023-07-26.pcap フレーム 630490 | PrivacyCon 2016 slides (home IoT case studies)（2016） | ブログ等のみ |
| Pix-Star Photo Frame | 識別子（平文の HTTP） | iotraffic,unsw2016 | 36 | q:usr=MAC -> iptime.pix-star.com:80 | iotraffic:pcaps__PixStarPhotoFrame_e076d033bb85.pcap フレーム 814 | PrivacyCon 2016 slides (home IoT case studies)（2016） | ブログ等のみ |
| Samsung Pan/Tilt 1080P Wi-Fi Camera | 識別子（平文の HTTP） | deakin | 68 | form:serial=mdns_txt:sn -> www.samsungsmartcam.com:80 | deakin:pcapFull__2023-07-26.pcap フレーム 278764 | Somebody's watching! When cameras are more than just 'smart（2018） | ブログ等のみ |
| Samsung SmartCam | 識別子（平文の HTTP） | iotraffic,unsw2016 | 22293 | form:serial=upnp:serialNumber -> www.samsungsmartcam.com:80 | iotraffic:pcaps__SamsungCamera_00166cab6b88.pcap フレーム 17830 | Somebody's watching! When cameras are more than just 'smart（2018） | ブログ等のみ |
| Amazon Echo | 認証情報らしい値（平文） | iotraffic,unsw2016 | 3 | q:sid -> opml.radiotime.com:80 | iotraffic:pcaps__AmazonEcho_44650d56ccd3.pcap フレーム 4526692 | Information Exposure From Consumer IoT Devices（2019） | 論文で一部 |
| Amazon Echo | 識別子（平文の HTTP） | iotraffic,unsw2016 | 4 | q:serial=named q:serial -> opml.radiotime.com:80 | iotraffic:pcaps__AmazonEcho_44650d56ccd3.pcap フレーム 3450200 | Information Exposure From Consumer IoT Devices（2019） | 論文で一部 |
| August Doorbell Cam | 認証情報らしい値（平文） | yourthings | 2 | q:auth -> august.pubnub.com:80 | yourthings:eth1-20180411.2025.1523496300 フレーム 138769 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| August Doorbell Cam | 識別子（平文の HTTP） | iotraffic,yourthings | 13 | q:uuid=named q:uuid -> pubsub.pubnub.com:80; q:uuid=named q:uuid -> august.pubnub.com:80 | iotraffic:pcaps__AugustDoorBell_e076d03f00ae.pcap フレーム 374 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| Belkin NetCam HD | 識別子（平文の HTTP） | iotraffic,yourthings | 13 | path[3]=upnp:macAddress -> devices.xbcs.net:8899; body=MAC -> devices.xbcs.net:8899 | iotraffic:pcaps__BelkinCamera_b4750eece5a9.pcap フレーム 38218 | Ensuring Compliance of IoT Devices with Their Privacy Policy Agreement（2018） | 論文で一部 |
| Belkin WeMo Link | 識別子（平文の HTTP） | yourthings | 1 | q:mac=upnp:macAddress -> fw.xbcs.net:80 | yourthings:eth1-20180321.1855.1521676500 フレーム 10293 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| Belkin WeMo Motion Sensor | 識別子（平文の HTTP） | yourthings | 3 | q:mac=upnp:macAddress -> fw.xbcs.net:80 | yourthings:eth1-20180321.1855.1521676500 フレーム 6908 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| Belkin WeMo Switch | 識別子（平文の HTTP） | yourthings | 3 | q:mac=upnp:macAddress -> fw.xbcs.net:80 | yourthings:eth1-20180321.1855.1521676500 フレーム 6614 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| Belkin (Crock-Pot) WeMo Crock-Pot | 識別子（平文の HTTP） | yourthings | 8 | path[3]=upnp:macAddress -> devices.xbcs.net:8899; q:mac=upnp:macAddress -> fw.xbcs.net:80 | yourthings:eth1-20180320.0155.1521528900 フレーム 86249 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| Bose SoundTouch 10 | 認証情報らしい値（平文） | yourthings | 3 | q:token -> bose.vtuner.com:80 | yourthings:eth1-20180320.2155.1521600900 フレーム 86457 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| Bose SoundTouch 10 | 識別子（平文の HTTP） | yourthings | 37 | q:mac=named q:mac -> bose.vtuner.com:80; q:lat=named q:lat -> api2.iheart.com:80 | yourthings:eth1-20180320.2155.1521600900 フレーム 86524 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| D-Link Water Sensor DCH-S161 | 識別子（平文の HTTP） | cic2022 | 32 | q:device_id=MAC -> mp-us-fwd.auto.mydlink.com:80 | cic2022:2-Idle__2021_11_24_Idle.pcap フレーム 470005 | Bradley & Barrera, 'Towards Characterizing IoT Software Update Practic（2022） | 論文で一部 |
| Insteon Camera | 識別子（平文の HTTP） | unsw2016 | 8112 | q:mac=MAC -> connect.insteon.com:80; q:sn=MAC -> connect.insteon.com:80 | unsw2016:16-09-28.pcap フレーム 1005362 | Information Exposure From Consumer IoT Devices（2019） | 論文で一部 |
| Insteon Hub Pro | 識別子（平文の HTTP） | yourthings | 197 | q:mac=named q:mac -> connect.insteon.com:80 | yourthings:eth1-20180411.1935.1523493300 フレーム 52663 | Information Exposure From Consumer IoT Devices（2019） | 論文で一部 |
| Invoxia Triby | 認証情報らしい値（平文） | iotraffic,unsw2016 | 23 | h:authorization:basic -> 8937406324.airable.io:80 | iotraffic:pcaps__TribySpeaker_18B79E022044.pcap フレーム 60097 | Unveiling Behavioral Transparency of Protocols Communicated by IoT Net（2024） | 論文で一部 |
| Logitech Harmony Hub | 識別子（平文の HTTP） | yourthings | 5647 | q:uuid=named q:uuid -> pubsub.pubnub.com:80; q:uuid=named q:uuid -> ps-145.pubnub.com:80 | yourthings:eth1-20180320.0000.1521522000 フレーム 63191 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| NVIDIA Shield TV | HTTP でのファームウェア取得 | yourthings | 3 | ota-downloads.nvidia.com/ota/data/posted-roms_romuploader/external/{id} (1191918991 B); ota-downloads.nvidia.com/ota/data/posted-roms_romuploader/external/{id} (1166754831 B) | yourthings:eth1-20180411.2015.1523495700 フレーム 148952 | Alrawi et al., 'SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| Philips Hue Bridge | 認証情報らしい値（平文） | cic2022,iotraffic,yourthings | 19584 | q:auth -> 130.211.93.93:80; h:authorization:cbauth -> dcp.cpp.philips.com:80 | cic2022:1-Power__Home Automation__Philips Hue Bridge__POWER__philipshuePOWER_1.pcap フレーム 133 | Blocking Without Breaking（2021） | 論文で一部 |
| Philips Hue Bridge | HTTP でのファームウェア取得 | yourthings | 1 | fds.cpp.philips.com:80/firmware/{id}/{id}/{id} (7632617 B) | yourthings:eth1-20180412.0210.1523517000 フレーム 9326 | Towards Characterizing IoT Software Update Practices（2022） | 論文で一部 |
| Philips Hue Bridge | 識別子（平文の HTTP） | cic2022,yourthings | 2568 | h:authorization:cbauth=mdns_txt:bridgeid -> dcp.cpp.philips.com:80; h:authorization:cbauth=mdns_txt:bridgeid -> www.ecdinterface.philips.com:80 | cic2022:1-Power__Home Automation__Philips Hue Bridge__POWER__philipshuePOWER_1.pcap フレーム 133 | In the Room Where It Happens（2023） | 論文で一部 |
| Ring Video Doorbell | 認証情報らしい値（平文） | iotraffic,yourthings | 14063 | h:authorization:basic -> vod.ring.com:80; h:authorization:basic -> 52.202.14.79:80 | iotraffic:pcaps__RingDoorBell_884aea31669d.pcap フレーム 4483 | Ring Doorbell Security（2016） | 論文で一部 |
| Ring Video Doorbell | MAC（HTTP 以外） | iotraffic,yourthings | 62 | aabbccddeeff in udp/15063 payload | iotraffic:pcaps__RingDoorBell_884aea31669d.pcap フレーム 34254 | Ring Doorbell Security（2016） | 論文で一部 |
| Roku 4 | 識別子（平文の HTTP） | yourthings | 2 | h:x-roku-reserved-serial-number=upnp:serialNumber -> cloudservices.roku.com:80 | yourthings:eth1-20180415.1640.1523828400 フレーム 21849 | Watching You Watch: The Tracking Ecosystem of Over-the-Top TV Streamin（2019） | 論文で一部 |
| Samsung Smart TV | 認証情報らしい値（平文） | yourthings | 1 | q:mboxSession -> nflenterprises.tt.omtrdc.net:80 | yourthings:eth1-20180410.0025.1523337900 フレーム 118613 | Information Exposure From Consumer IoT Devices（2019） | 論文で一部 |
| Samsung Smart TV | HTTP でのファームウェア取得 | yourthings | 12 | otn.samsungcloudcdn.com/firmware/tv/487/{id}/OUITHeaders.dat (4224 B) | yourthings:eth1-20180410.1855.1523404500 フレーム 203105 | Towards Characterizing IoT Software Update Practices（2022） | 論文で一部 |
| Samsung Smart TV | 識別子（平文の HTTP） | yourthings | 2 | q:d_uuid=named q:d_uuid -> cm.everesttech.net:80; q:location=named q:location -> nflenterprises.tt.omtrdc.net:80 | yourthings:eth1-20180410.0025.1523337900 フレーム 118613 | Information Exposure From Consumer IoT Devices（2019） | 論文で一部 |
| Sonos One ZPS18 | 認証情報らしい値（平文） | cic2022 | 2 | q:sid -> opml.radiotime.com:80 | cic2022:4-Scenarios__6-IoT and Non-IoT__IoTNonIoT_1.pcap フレーム 39444 | Smart Speaker Shenanigans: Making the SONOS One Sing Its Secrets（2023） | 論文で一部 |
| Sonos One ZPS18 | HTTP でのファームウェア取得 | cic2022 | 2 | update-firmware.sonos.com/firmware/Prod/{id}/{id} (47489420 B); update-firmware.sonos.com/firmware/Prod/{id}/{id} (49815981 B) | cic2022:2-Idle__2021_11_17_Idle.pcap フレーム 592027 | Smart Speaker Shenanigans: Making the SONOS One Sing Its Secrets（2023） | 論文で一部 |
| Sonos One ZPS18 | 識別子（平文の HTTP） | cic2022 | 6 | q:serial=named q:serial -> opml.radiotime.com:80; q:householdid=ssdp:x-rincon-household -> update-firmware.sonos.com:80 | cic2022:2-Idle__2021_11_17_Idle.pcap フレーム 592023 | Smart Speaker Shenanigans: Making the SONOS One Sing Its Secrets（2023） | 論文で一部 |
| Sonos speaker ZPS1 (PLAY:1) | HTTP でのファームウェア取得 | yourthings | 3 | update-firmware.sonos.com/firmware/Gold/{id}/{id} (8306684 B); update-firmware.sonos.com/firmware/Gold/{id}/{id} (8805698 B) | yourthings:eth1-20180320.2140.1521600000 フレーム 133996 | Smart Speaker Shenanigans: Making the SONOS One Sing Its Secrets（2023） | 論文で一部 |
| Sonos speaker ZPS1 (PLAY:1) | 識別子（平文の HTTP） | yourthings | 156 | xml:deviceId=MAC -> legato.radiotime.com:80; q:householdid=ssdp:x-rincon-household -> update.sonos.com:80 | yourthings:eth1-20180320.1235.1521567300 フレーム 61241 | Smart Speaker Shenanigans: Making the SONOS One Sing Its Secrets（2023） | 論文で一部 |
| TCL / Roku TV | 識別子（平文の HTTP） | yourthings | 2 | h:x-roku-reserved-serial-number=upnp:serialNumber -> cloudservices.roku.com:80 | yourthings:eth1-20180411.2005.1523495100 フレーム 172419 | SoK: Security Evaluation of Home-Based IoT Deployments（2019） | 論文で一部 |
| TP-Link Day/Night Cloud Camera NC220 | 認証情報らしい値（平文） | unsw2016 | 4 | h:x-token -> aps1-relay.tplinkcloud.com:80 | unsw2016:16-09-28.pcap フレーム 567700 | Loi, Sivanathan, Gharakheili, Radford, Sivaraman, 'Systematically Eval（2017） | 論文で一部 |
| TP-Link Day/Night Cloud Camera NC220 | 識別子（平文の HTTP） | iotraffic,unsw2016 | 7 | q:deviceid=named q:deviceid -> aps1-relay.tplinkcloud.com:80; q:id=MAC -> ipc.tplinkcloud.com:80 | iotraffic:pcaps__TPLinkCamera_f4f26D9351f1.pcap フレーム 54418 | Loi, Sivanathan, Gharakheili, Radford, Sivaraman, 'Systematically Eval（2017） | 論文で一部 |
| Withings Aura Sleep Sensor | 認証情報らしい値（平文） | iotraffic,unsw2016 | 15506 | form:sessionid -> scalews.withings.net:80; form:auth -> scalews.withings.net:80 | iotraffic:pcaps__WithingsSleepSensor_0024e42028c6.pcap フレーム 102222 | Network-Level Security and Privacy Control for Smart-Home IoT Devices（2015） | 論文で一部 |
| Withings Aura Sleep Sensor | 識別子（平文の HTTP） | iotraffic,unsw2016 | 6230 | form:auth=MAC -> scalews.withings.net:80; form:mac=named form:mac -> scalews.withings.net:80 | iotraffic:pcaps__WithingsSleepSensor_0024e42028c6.pcap フレーム 102222 | Network-Level Security and Privacy Control for Smart-Home IoT Devices（2015） | 論文で一部 |
| Withings Home | 識別子（平文の HTTP） | yourthings | 4 | form:mac_address=MAC -> scalews.withings.net:80 | yourthings:eth1-20180320.2235.1521603300 フレーム 35540 | Testing Withings Home（2017） | 論文で一部 |
| Withings Smart Baby Monitor | 認証情報らしい値（平文） | iotraffic,unsw2016 | 10068 | form:sessionid -> babyws.withings.net:80; form:auth -> babyws.withings.net:80 | iotraffic:pcaps__WithingsBabyMonitor_0024e41118a8.pcapng フレーム 1132 | Network-Level Security and Privacy Control for Smart-Home IoT Devices（2015） | 論文で一部 |
| Withings Smart Baby Monitor | MAC（HTTP 以外） | iotraffic,unsw2016 | 10 | aa:bb:cc:dd:ee:ff in tcp/1935 payload | iotraffic:pcaps__WithingsBabyMonitor_0024e41118a8.pcapng フレーム 276068 | Network-Level Security and Privacy Control for Smart-Home IoT Devices（2015） | 論文で一部 |
| Withings Smart Baby Monitor | 識別子（平文の HTTP） | iotraffic,unsw2016 | 1088 | form:auth=MAC -> babyws.withings.net:80 | iotraffic:pcaps__WithingsBabyMonitor_0024e41118a8.pcapng フレーム 543 | Network-Level Security and Privacy Control for Smart-Home IoT Devices（2015） | 論文で一部 |
| Withings Smart Scale | 識別子（平文の HTTP） | iotraffic | 1 | form:mac_address=MAC -> wbs02-ws.withings.net:80 | iotraffic:pcaps__WithingsSmartScale_0024e41b6f96.pcap フレーム 28301 | Network-Level Security and Privacy Control for Smart-Home IoT Devices（2015） | 論文で一部 |
| unknown webcam | MAC（HTTP 以外） | yourthings | 28 | aabbccddeeff in udp/8765 payload | yourthings:eth1-20180320.0250.1521532200 フレーム 544406 | Alrawi, Lever, Antonakakis, Monrose, 'SoK: Security Evaluation of Home（2019） | 論文で一部 |

- **Insteon Hub Pro（論文で一部）**：Ren ほか（IMC 2019、§6.2、PDF p.10）が、Insteon のハブが MAC を平文で送ると報告している。IMC なので「論文で一部」にした（2026-11-11）。Alrawi ほか（IEEE S&P 2019、Table VII p.18）は Insteon Hub と クラウドの間を暗号化なしとするが、MAC は示していない。Hub と Hub Pro が同じ型かは未確認。
- **同じ研究室の評価と合わないもの**：Loi ほか（2017、UNSW）は、Pix-Star、Withings の睡眠センサー、Samsung SmartCam を「平文なし」と評価している。こちらはどれも平文の送信を観測した。同じ個体かは未確認。
- **項目名だけで拾ったもの**（Bose の `q:mac`、Amazon Echo の `q:serial` など）は、値が本当にその識別子かを確かめていない。

## パケットでの確認（「見つからず」と「ブログ等のみ」の 20 件）

`scripts/claims/sweep/verify.py` で、根拠のキャプチャを tshark で開き直して確かめた（2026-11-10）。値はメモリの中で比べ、長さ、形、一致の有無だけを見た。宛先の DNS の応答は、どのキャプチャにもなかった（名前は HTTP の Host ヘッダーによる）。

| 製品 | 確かめた根拠 | 結果 | 判定 |
|---|---|---|---|
| Invoxia Triby | iotraffic `TribySpeaker_18B79E022044.pcap` フレーム 7741〜937874 | `developer.invoxia.com/update/triby/update.pup` への GET 107 回で `mac` が機器の MAC と一致（値は 1 種類）。`airable.io/authentication` への GET 7 回で `device` が MAC と一致 | 確認 |
| Invoxia Triby | 同 フレーム 60097〜483309 | `airable.io` への GET 21 回に平文の Basic 認証。ユーザー名 64 文字（6 種類）、パスワード 32 文字（毎回違う）。どちらも MAC ではない | 確認 |
| Invoxia Triby | 同 TCP ストリーム 1778 | `update.pup` を HTTP で取得（206、4,064,439 バイト、text/plain）。中身のエントロピー 8.00 で、暗号化か圧縮 | 確認 |
| Invoxia Triby | 同 フレーム 10、11 | tcp/5228 への通信は、メッセージの中身（REGISTER、INVITE、Via、CSeq）から平文の SIP。ユーザー名が `triby_` と MAC。206,593 パケット中 21,991 に MAC | 確認 |
| Nest Guard | yourthings `eth1-20180410.0045.1523339100` フレーム 49432、66102 | tcp/11095 の最初のメッセージ（520 バイト）の 416 バイト目に MAC の 6 バイト。TLS のレコードではなく、証明書の中でもない | 確認 |
| HeimVision カメラ | cic `1-Power/Cameras/HeimVision Camera/POWER/heimvisioncamPOWER_1.pcap` フレーム 62 | `esd.closeli.com/lookup/v6/assignRelayIp` への POST の `device_id`（英字 5 文字、`_`、MAC の 12 文字） | 確認 |
| Home Eye カメラ | cic `.../Home Eye Camera/POWER/homeeyecamPOWER_1.pcap` フレーム 239〜948 | **写真（image/jpg、約 204 KB）を HTTP で PUT**（3 回。本文の先頭が JPEG）。宛先は `xyxcamera.oss-cn-hongkong.aliyuncs.com`。OSS の署名のアクセスキー ID は 6 回とも同じ値（24 文字）、署名は毎回違う | 確認 |
| SimCam カメラ | cic `2021_11_02_Active.pcap` フレーム 1234〜631073 | **人物検知の画像（JPEG、22〜25 KB）を HTTP で PUT**（15 回、パス `.../SimCam/{id}/PersonDetect/{id}`）。宛先は S3 のバケット。AWS4 の署名のアクセスキー ID は 15 回とも同じ値（20 文字） | 確認 |
| Samsung SmartCam | iotraffic `SamsungCamera_00166cab6b88.pcap` フレーム 17830〜3023532 | `www.samsungsmartcam.com/web/event.stw` への POST 13,310 回すべてで `serial` が UPnP のシリアル番号と一致（値は 1 種類） | 確認 |
| Samsung Pan/Tilt 1080P カメラ | deakin `2023-07-26.pcap` フレーム 278764、`2023-08-16.pcap` | 同じ宛先への POST の `serial`（15 文字、値は 1 種類）。08-16 では mDNS の `sn` と一致（2 回とも） | 確認 |
| Pix-Star フォトフレーム | iotraffic `PixStarPhotoFrame_e076d033bb85.pcap` フレーム 814〜81232、deakin `2023-07-26.pcap` フレーム 630490 | `iptime.pix-star.com/iptime` への GET の `usr` が MAC と一致（2016〜17 年 23 回、2023 年 1 回） | 確認 |
| Netatmo 気象計 | cic `1-Power/Other/Netatmo Weather Station/POWER/netatmoweatherPOWER_1.pcap` フレーム 29 | tcp/25050 の最初のメッセージ（52 バイト、バイナリ）の 9 バイト目に MAC を文字で（16 パケット中 1） | 確認 |
| Borun カメラ | cic `.../Borun Camera/POWER/boruncamPOWER_1.pcap` フレーム 91、117 | udp/8877 の最初のメッセージ（84 バイト）の 58 バイト目に MAC を文字で（4 パケット中 2）。HTTP の `deviceid` は 8 文字で MAC ではない | 確認 |
| Amcrest カメラ | cic `.../Amcrest/POWER/amcrestcamPOWER_1.pcap` フレーム 143 | udp/8802 の文字のメッセージ（258 バイト）の 20 バイト目に、機器が mDNS で名乗る名前（18 文字） | 確認 |
| TP-Link NC220 | unsw2016 `16-09-30.pcap` フレーム 493236 | MAC は 2,876 パケット中 1 つだけ。宛先は UNSW の範囲のアドレスで、メーカーのサーバーではない | 弱い |
| Apple HomePod | yourthings `eth1-20180321.2015.1521681300` フレーム 61634〜73255 | `x-playback-session-id` は再生ごとの UUID（3 回で 2 種類）。機器の識別子でも認証情報でもない | 外す |
| August Doorbell Cam | iotraffic `AugustDoorBell_e076d03f00ae.pcap` フレーム 5122643、5490378 | その位置のパケットに MAC が見つからない（1 つはペイロードなし）。自動の検出の誤り | 外す |
| Smart Board | cic `2-Idle/2021_12_20_Idle.pcap` フレーム 9926 | Chrome の部品の差分更新（CRX diff）。署名つきの設計どおりの動き（Chromium の Omaha 3.1 の文書） | 外す |

**値（2026-11-11 に読み直し。認証情報は quarant-results の `claims/sweep-credentials.md`）**：

| 製品 | 値 |
|---|---|
| Invoxia Triby | `mac` と `device` は機器の MAC `18b79e022044`。tcp/5228 の SIP（フレーム 10）は `User-Agent: invoxia KTP1 10.48.1 [18:B7:9E:02:20:44]`、`Contact: "Triby-2044" <sip:smarthomeunsw.gmail.com.triby_18b79e022044@sip.invoxia.com>` で、MAC と、収録した研究室のアカウントのメールアドレスが出ている |
| Nest Guard | tcp/11095 のフレーム 49432 に、`07AA01AD501706SQ`（Nest の製品のシリアル番号の形）と MAC 18:b4:30:40:1e:c5 の 6 バイト。前後のバイトは Weave の TLV の形で、機器の証明書の一部と見られる（推定、未確認） |
| HeimVision カメラ | `device_id=xxxxS_4401bbec104a`（MAC 44:01:bb:ec:10:4a を含む。cic `2-Idle/2021_11_08_Idle.pcap` フレーム 799778〜873811） |
| Samsung SmartCam | `serial=KHNL6V2H20003LX`（UPnP のシリアル番号と一致、13,310 回） |
| Samsung Pan/Tilt 1080P カメラ | `serial=ZDZ56V2K100594B`（mDNS の `sn` と一致。deakin `2024-05-19.pcap` フレーム 531351〜2246513） |
| Pix-Star フォトフレーム | `usr=e076d033bb85`（2016〜17 年、23 回）、`usr=b002476f6337`（deakin `2023-08-18.pcap` フレーム 256204）。どちらも機器の MAC |
| Netatmo 気象計 | tcp/25050 に `70:ee:50:03:b8:ac`（iotraffic `NetatmoWeatherStation_70ee5003b8ac.pcap` フレーム 1992） |
| Borun カメラ | udp/8877 に `49833595.nvdvr.net` と MAC の文字 `C0E7BF0A79D1`（cic `2-Idle/2021_11_26_Idle.pcap` フレーム 805）。HTTP の `deviceid=49833595` |
| TP-Link NC220（弱い） | udp/40043 のフレーム 504251 は、16 バイトの頭のあとに `HTTP/1.0 200 OK`、`Server: Streamd,F4F26D9351F1` が続く。宛先 129.94.5.88 は UNSW の範囲で、アプリの端末かは未確認 |
| Apple HomePod（外す） | `X-Playback-Session-Id` は `9ACA8A33-A82B-4C49-8B91-8115C0764A07` など再生ごとの UUID |

- 16 件を確認、1 件は弱い、3 件は外す。
- Home Eye と SimCam は、識別子より重い。カメラの画像そのものが平文で送られていた。
- 「見つからず」は探した範囲の話で、新しいとは言わない。

### 画像の送信の先行研究（Home Eye、SimCam）

画像の送信に絞って探し直した（22 回の検索。結果は [sweep/prior-images.tsv](sweep/prior-images.tsv)）。

| 所見 | 区分 | いちばん近い資料 |
|---|---|---|
| Home Eye：写真を平文の HTTP で OSS に送る | ブログ等のみ（系統の推定つき） | M. Lendvai（LRQA）, Hacking a spy camera, 2026-08-23：別の白ラベルのカメラで、アプリと OSS の間が平文の HTTP、OSS の鍵がファームウェアとアプリに埋め込まれていた |
| Home Eye：OSS のアクセスキー ID が平文の要求に毎回同じ値で出る | ブログ等のみ（同上。論点も一部違う） | 同上 |
| SimCam：人物検知の画像を平文の HTTP で S3 に送る | 見つからず | ― |
| SimCam：AWS のアクセスキー ID が平文の要求に毎回同じ値で出る | 見つからず | ― |

- **Home Eye の系統**：OSS への PUT のパスの先頭が PPPP 形式の機器 ID で、頭の文字は W. Palant の PPPP の一覧で HomeEye のアプリ（`shix.homeeye.camera`）の行にある。LRQA の機器の頭の文字も同じ行にある。同じ系統と見るのは推定で、製造元は未確認。
- **SimCam**：製造元は Simshine（深圳または武漢。アプリ SIMCAM AI）。データセットの機種名は SIMCAM 1S（Kostas ほか, arXiv 2307.08679 の表による）。
- **SimCam のメーカーの説明**：TechCrunch（2019-09-10）、App Store、a&s（2019）、Digital Trends は、映像を機器の中で処理すると紹介している。人物検知の画像をクラウドに平文で送る観測とは食い違う可能性がある。ただし、説明の時期（収録の 2021-11 より前か）と、範囲（検知の画像を含むか）は未確認。
- 見えているのはアクセスキー ID だけで、秘密鍵は見えていない。同じキーがほかの機器でも使われているか、署名つきの要求を再送できるかは、パッシブでは確かめられない。

## 取りこぼしていたダウンロード（2026-11-11）

候補を選ぶ規則が、ファームウェアの取得をパス（`{id}` に置き換えた形）だけで見ていたため、ホスト名でしか分からない取得と、パスに手がかりのない取得を落としていた。規則を直し（ホスト名も見る。ほかの 1 MB 以上の平文のダウンロードは、音声・動画・画像を除いて「中身を確かめる」候補にする）、`verify.py dl` で確かめた。

| 製品 | 根拠 | 要求と応答 | 判定 |
|---|---|---|---|
| Belkin WeMo Link | yourthings `eth1-20180321.1855.1521676500` ストリーム 76 | `fw.xbcs.net/wemo/owrt/WeMo_WW_2.00.11054.OWRT.PVT_LED_Light.bin.gpg?mac=94103ECC6794`、200、4,770,906 バイト、エントロピー 8.00 | ファームウェアを HTTP で取得（ファイルは GPG の形式） |
| Belkin WeMo Motion Sensor | 同 ストリーム 73 | `.../WeMo_WW_2.00.11054.OWRT.PVT_SNS.bin.gpg?mac=08863B6F7A14`、200、4,371,159 バイト | 同上 |
| Belkin WeMo Switch | 同 ストリーム 70 | `.../WeMo_WW_2.00.11054.OWRT.PVT_SNS.bin.gpg?mac=08863B70D738`、200、4,371,159 バイト | 同上 |
| Belkin WeMo Crock-Pot | 同 ストリーム 71 | `.../WeMo_WW_2.00.10926.OWRT.PVT_Jarden-trans.bin.gpg?mac=94103E5C2E30`、200、4,436,078 バイト | 同上 |
| Withings Smart Scale | iotraffic `WithingsSmartScale_0024e41b6f96.pcap` ストリーム 168 | `cdnfw.withings.net/wbs02/wbs02_1701.bin`、200、752,636 バイト、エントロピー 7.10 | ファームウェアを HTTP で取得 |
| Amazon Echo | iotraffic `AmazonEcho_44650d56ccd3.pcap` ストリーム 28111、28488 | `amzdigitaldownloads.edgesuite.net/obfuscated-otav3-9/.../libc6-4172.ipk`（1,399,132 バイト）、`.../doppler-4172.ipk`（200、56,637,742 バイト、2016-10-27）など 16 回 | ソフトウェアの更新のパッケージを HTTP で取得 |
| Lutron Caseta Smart Bridge | yourthings `eth1-20180414.0610.1523704200` ストリーム 366、`eth1-20180419.0840.1524145200` ストリーム 193 | `s3.amazonaws.com/caseta/final/06.05.09f000/kernel-4.4.001.deb`（200、2,977,678 バイト）、`06.05.10f000` の同じ名前（2,977,710 バイト） | ファームウェアの部品を HTTP で取得 |
| Ring Video Doorbell | yourthings `eth1-20180413.1545.1523652300` ストリーム 576 | `fw.ring.com/doorbots_api/v2_firmwares/1550/download?component=flash`（Basic 認証つき） | 既に [ring-prior-work.md](ring-prior-work.md) で確認済み |
| Samsung Smart TV | yourthings `eth1-20180413.1545.1523652300` ストリーム 233 | `apps.samsungcloudcdn.com/files/widget/.../enc_111477000528_3.3.65.tmg?AWSAccessKeyId=...&Signature=...`、200、4,481,024 バイト（squashfs） | アプリのパッケージ。URL に S3 の署名（認証情報、値は quarant-results） |
| Apple HomePod | yourthings `eth1-20180328.0620.1522236000` ストリーム 273 | `appldnld.apple.com/ios11.0/.../com_apple_MobileAsset_VoiceServices_GryphonVoice/....zip`（595,567,472 バイト） | Siri の音声データ。ファームウェアではない |
| Roku 4 | yourthings `eth1-20180415.1550.1523825400` ストリーム 638 | `index.ehub.netflix.com/item/SpeedTest?size=12500000` | 速度の測定。外す |

- 先行研究の区分はまだ付けていない（次の作業）。

## パケットでの確認（「論文で一部」の 41 件、2026-11-11）

`verify.py`（値をそのまま出す版）と `verify_all.py` で、根拠のキャプチャを tshark で開き直した。出力は外付けディスクの `~/datasets/claims/sweep/verify/ids-partial.txt`。認証情報の値は非公開のリポジトリ quarant-results の `claims/sweep-credentials.md` にだけ書いた。

| 製品 | 確かめた根拠 | 値と結果 | 判定 |
|---|---|---|---|
| TP-Link NC220 | unsw2016 `16-09-28.pcap` フレーム 567700、567706、`16-09-30.pcap` フレーム 493448、493482 | `aps1-relay.tplinkcloud.com:80/relayservice?deviceid=FFFF47A2F522CCC6D520571EDEDD61460000E7B2&type=video` への POST。本文は multipart で、部品の型は `video/x-h264`。最初の 500 KB に H.264 の SPS、PPS、IDR（NAL の型 7、8、5）がそのまま入っている。`type=audio`（AAC）の POST もある。`X-token` は 4 回とも同じ値（認証情報）。本文の中の応答に `Server: Streamd,F4F26D9351F1`（機器の MAC） | **確認（映像と音声が平文）** |
| Roku 4 | yourthings `eth1-20180415.1640.1523828400` フレーム 21853、21895 | `cloudservices.roku.com` への GET の `X-Roku-Reserved-Serial-Number: YY007G478132`。UPnP のシリアル番号（`eth1-20180320.1550.1521579000`）と一致 | 確認 |
| Roku TV（TCL） | yourthings `eth1-20180415.1550.1523825400` フレーム 73456 | 同じヘッダーに `2N004E596344`。UPnP のシリアル番号と一致 | 確認 |
| Belkin NetCam HD | iotraffic `BelkinCamera_b4750eece5a9.pcap` フレーム 38222〜661844 | `devices.xbcs.net:8899/ToolService/log/uploadWdLogFile/B4750EECE5A8` への PUT 8 回（本文は JSON、800〜6,274 バイト）。パスの値は UPnP の macAddress と一致（Ethernet の MAC は b4:75:0e:ec:e5:a9） | 確認 |
| Belkin WeMo Link | yourthings `eth1-20180321.1855.1521676500` フレーム 10293 | `fw.xbcs.net/wemo/owrt/...?mac=94103ECC6794`。UPnP の macAddress と一致 | 確認 |
| Belkin WeMo Motion Sensor | 同 フレーム 6908 | `mac=08863B6F7A14`。UPnP の macAddress と一致 | 確認 |
| Belkin WeMo Switch | 同 フレーム 6614 | `mac=08863B70D738`。UPnP の macAddress と一致 | 確認 |
| Belkin WeMo Crock-Pot | yourthings `eth1-20180320.0755.1521550500` フレーム 89570 | `devices.xbcs.net:8899/ToolService/log/uploadWdLogFile/94103E5C2E30` への PUT。UPnP の macAddress と一致 | 確認 |
| Withings Aura Sleep Sensor | iotraffic `WithingsSleepSensor_0024e42028c6.pcap` フレーム 1099〜1554793 | `scalews.withings.net/cgi-bin/session` への POST 3,020 回の `auth` が `00:24:e4:20:28:c6`（機器の MAC、1,506 回）と `00:24:e4:20:69:6c`（1,514 回。Withings の OUI の別の MAC、どの機器かは未確認）。`sessionid` は 3,033 種類（認証情報） | 確認 |
| Withings Smart Baby Monitor | iotraffic `WithingsBabyMonitor_0024e41118a8.pcapng` フレーム 543〜684917、60706 | `babyws.withings.net/cgi-bin/session` の `auth` が機器の MAC `00:24:e4:11:18:a8`（544 回）。tcp/1935 のフレーム 60706 に `_Withings_` と `00:24:e4:11:18:a8-50cfb6f0b78335f2f00fba3751674775`（77,531 パケット中 3）。`sessionid` は 544 種類（認証情報） | 確認 |
| Withings Smart Scale | iotraffic `WithingsSmartScale_0024e41b6f96.pcap` フレーム 28301 | `wbs02-ws.withings.net/cgi-bin/v2/certificate` の `mac_address=00:24:e4:1b:6f:96`（機器の MAC） | 確認 |
| Withings Home | yourthings `eth1-20180411.2025.1523496300` フレーム 56153、59581 | `scalews.withings.net/cgi-bin/v2/certificate` の `mac_address=00:24:e4:2b:a5:34`（機器の MAC） | 確認 |
| Insteon Camera | unsw2016 `16-09-28.pcap` フレーム 1005362 | `connect.insteon.com/setinfo.asp?mac=00626E51272E`。UNSW の一覧の有線の Insteon Camera の MAC（00:62:6e:51:27:2e）。このフレームは無線の Insteon Camera（e8:ab:fa:19:de:4f）から送られていた | 確認 |
| Insteon Hub Pro | yourthings `eth1-20180414.1925.1523751900` フレーム 141168 | `connect.insteon.com/SetInfo.asp?mac=544A162CC9E3`。ハブの MAC（54:4a:16:f9:54:18）とは違う。同じ OUI の値で、どの機器のものかは未確認 | 弱い |
| D-Link DCH-S161 | cic `2-Idle/2021_12_16_Idle.pcap` フレーム 462331〜466813 | `mp-us-fwd.auto.mydlink.com/fw-upgrade?device_id=F0B4D2F96095`（機器の MAC）3 回 | 確認 |
| Philips Hue Bridge | yourthings `eth1-20180320.0250.1521532200` フレーム 123004〜299497 | `dcp.cpp.philips.com:80` への POST 4 回の `Authorization: CBAuth` に `Client="001788fffe21f7e4"`（MAC 00:17:88:21:f7:e4 から作るブリッジ ID）と SSOToken（認証情報） | 確認 |
| Philips Hue Bridge | iotraffic `PhilipsHue_0017882b9a25.pcap` フレーム 30241〜3925289 | `bridge.meethue.com:80/queue/getmessage`（130.211.93.93）への POST 8,370 回の `auth`（40 桁、8,368 種類。認証情報） | 確認 |
| Philips Hue Bridge | yourthings `eth1-20180412.0210.1523517000` ストリーム 63、応答フレーム 23594 | `fds.cpp.philips.com:80/firmware/...` を HTTP で取得（200、7,632,617 バイト、エントロピー 8.00） | 確認 |
| Ring Video Doorbell | yourthings `eth1-20180320.0145.1521528300` フレーム 3774〜95081 | `vod.ring.com` への GET 29 回の Basic 認証。ユーザー名は機器の MAC（001dc923f600）、パスワードは 1 種類（認証情報） | 確認 |
| Ring Video Doorbell | iotraffic `RingDoorBell_884aea31669d.pcap` フレーム 4505 | udp/15063 の SIP の `From: <sip:884aea31669d@ring.com>`（機器の MAC） | 確認 |
| August Doorbell Cam | yourthings `eth1-20180411.2030.1523496600` フレーム 89263 | `august.pubnub.com/publish/...` の `auth` が `sec-c-` で始まる 54 文字（PubNub の秘密鍵の形。認証情報） | 確認 |
| August Doorbell Cam | iotraffic `AugustDoorBell_e076d03f00ae.pcap` フレーム 374〜50423 | `pubsub.pubnub.com` の `uuid` が `27a1dc6b490f`（33 回）と `39f80d0b29c3`（2 回）。機器の MAC ではない | 弱い |
| Sonos PLAY:1 | yourthings `eth1-20180413.1730.1523658600` フレーム 87608〜103971 | `legato.radiotime.com/Radio.asmx` への POST 14 回の `deviceId` が `5C-AA-FD-6C-E0-D4:F`（MAC を含む） | 確認 |
| Sonos PLAY:1 | yourthings `eth1-20180413.1630.1523655000` ストリーム 771、応答フレーム 162738 | `update-firmware.sonos.com/firmware/Gold/...` を HTTP で取得（200、8,826,617 バイト） | 確認 |
| Sonos One | cic `2-Idle/2021_11_17_Idle.pcap` ストリーム 6321、応答フレーム 640534 | `update-firmware.sonos.com/firmware/Prod/...` を HTTP で取得（200、47,489,420 バイト） | 確認 |
| Sonos One | cic `4-Scenarios/6-IoT and Non-IoT/IoTNonIoT_1.pcap` フレーム 39444、41352 | `opml.radiotime.com/Tune.ashx` の `serial=AFRUKRYCPGTZ6HTUTBQIYEJY662A`。機器の識別子との関係は未確認。`sid=s189577` は TuneIn の局の ID の形で、認証情報ではない | 弱い（serial）、外す（sid） |
| Amazon Echo | iotraffic `AmazonEcho_44650d56ccd3.pcap` フレーム 3450200〜4526692 | 同じ宛先の `serial=AGOKDHJPYEPDDGQQLVJWAZQD6LLA`（関係は未確認）、`sid=p212`（番組の ID の形） | 弱い（serial）、外す（sid） |
| NVIDIA Shield TV | yourthings `eth1-20180411.2015.1523495700` ストリーム 249、フレーム 92152、92198 | `ota-downloads.nvidia.com` から `productionBL-droid-signed-foster_e-full_ota-1915764_910.7870.20170601125901.zip` を HTTP で取得（206、1,191,918,991 バイト、ZIP） | 確認 |
| unknown webcam | yourthings `eth1-20180320.0250.1521532200` フレーム 544406 | udp/8765 の 128 バイト目に MAC の文字 `001216abc022`（20 パケット中 2） | 確認 |
| Samsung Smart TV | yourthings `eth1-20180410.0025.1523337900` フレーム 124972 | `cm.everesttech.net/cm/dd` の `d_uuid=89322744661981446711498655573062532140`（38 桁）。機器の識別子との関係は未確認。`mboxSession`（フレーム 118613）は分析のセッションで機器の認証情報ではない。4 KB の `OUITHeaders.dat` はファームウェアそのものではない | 弱い（d_uuid）、外す（ほか 2 件） |
| Bose SoundTouch 10 | yourthings `eth1-20180413.1930.1523665800` フレーム 78408〜110279 | `bose.vtuner.com` の `mac=92b1b3329e7608a4b608d4773d09f9da`（32 桁で固定）。MAC でも MAC の MD5 でもない。`token=0` は認証情報ではない | 弱い（mac）、外す（token） |
| Logitech Harmony Hub | yourthings `eth1-20180321.2320.1521692400` フレーム 1176、83129 | `pubsub.pubnub.com` の `uuid=v1ggtg3a-uz30-4f7d-8v71-qysw68jvg8hs`。機器の識別子との関係は未確認 | 弱い |

- 41 件のうち 29 件を確認、7 件は弱い、5 件は外す。
- **新しく分かった重いもの**：TP-Link NC220 は、遠隔での視聴のときに、映像（H.264）と音声（AAC）を平文の HTTP で TP-Link の中継に送っていた。識別子の候補として拾ったものの中身だった。
- 値の一致は、機器が LAN で名乗った値（UPnP、mDNS）と MAC とで確かめた。「弱い」は、値は出ているが、機器の識別子だと示せていないもの。

## TLS（105 件）

| 種類 | 除く | 論文で一部 | 対応表にない | 未確認 |
|---|---|---|---|---|
| 1.0/1.1 を選んだ、または 1.1 までしか提示しない | 0 | 17 | 8 | 3 |
| RC4、DES、export、NULL、匿名の暗号（3DES だけは数えない） | 0 | 24 | 9 | 3 |
| 前方秘匿性のある握手がない | 0 | 10 | 13 | 1 |
| サーバー証明書（RSA 2048 ビット未満、SHA-1/MD5、自己署名、期限切れ） | 7 | 6 | 7 | 1 |

- **論文で一部に移したもの（2026-11-11）**：Amazon Echo Spot（2 件）、Fire TV（2 件）、Harman Kardon Invoke、LG webOS TV、Hue（2 件）、Ring（2 件）、Samsung Smart TV、SmartThings Hub、Roku TV の 13 件。根拠は IoTLS（Paracha ほか、IMC 2021、Table 6 p.169、Fig. 2・3 p.171、§5.1 p.172）と Bradley ほか（FPS 2022、Fig. 3 p.8）だけで、どちらも 4 会議ではない。
- **除く（7 件）**：下の表。どれも YourThings と同じ試験環境の同じ機器を、Alrawi ほかが扱っている。ただし、論文の印は自己署名と「vuln SSL」（Nessus で端点を調べた結果）で、こちらの観測は SHA-1 や RSA 1024 の証明書。「vuln SSL」に SHA-1 が含まれるかは論文に書かれておらず未確認。性質が違えば「論文で一部」に移す（判断待ち）。

| 製品 | こちらの観測（サーバー証明書） | 理由 |
|---|---|---|
| August Doorbell Cam | SHA-1（発行者 August Home Inc）241 回 | Alrawi ほか, SoK: Security Evaluation of Home-Based IoT Deployments, IEEE S&P 2019, Table V p.17（August Doorbell：self-signed ✓、vuln SSL ✓） |
| LIFX Color 1000 | SHA-1（LIFX Labs）25 回 | 同 Table V p.17（LIFX Virtual Bulb：self-signed ✓、vuln SSL ✓） |
| Nest Cam | SHA-1（Dropcam）117 回 | 同 Table V p.17（Nest Camera：self-signed ✓、vuln SSL ✓） |
| Nest Cam IQ | SHA-1（Dropcam）336 回 | 同 Table V p.17（Nest Cam IQ：self-signed ✓） |
| Roku 4 | SHA-1（Roku, Inc.）84 回 | 同 Table V p.17（Roku 4：self-signed ✓、vuln SSL ✓） |
| Roku TV（TCL） | SHA-1（Roku, Inc.）58 回 | 同 Table V p.17（Roku TV：self-signed ✓、vuln SSL ✓） |
| SmartThings Hub | RSA 1024・SHA-1（SmartThings、Physical Graph）3,443 回 | 同 Table V p.17（Samsung SmartThings：self-signed ✓、vuln SSL ✓）。IoTLS Table 7 p.172 も |
- **対応表の論文にない製品**：Arlo Q、Atomi、Awair、BlipCare、D-Link DCH-S161、Dropcam、Globe、Gosund、HP ENVY、HeimVision の電球、Invoxia Triby、Netatmo Welcome、Pix-Star、Samsung のカメラ 2 機種、TP-Link NC220、Teckin、Withings Smart Scale、Yutron、iHome。
- **論文と合わないもの**：Samsung Smart TV は 13 回の握手で 3DES が選ばれていた（IoTLS は、安全でない暗号が選ばれたのは Wink Hub 2 と LG TV だけとする。p.172）。Harman Kardon Invoke は 2018-03 に TLS 1.0 が選ばれていた（IoTLS は 1.2 未満に対応しないとする）。

### TLS のパケットでの確認（2026-11-11）

`verify.py tls` と `verify_tls_all.py` で、候補ごとに最初の根拠のフレームの握手を tshark で開き直した（ClientHello の版と暗号の一覧、ServerHello の版と暗号、証明書の鍵・署名・発行者・期限）。出力は `~/datasets/claims/sweep/verify/tls.txt`、`tls-2.txt`。

- 105 件すべてで、根拠の握手に自動の検出と同じ性質があった（版 27、暗号 36、前方秘匿性 22、証明書 20）。確かめたのは握手 1 つずつで、回数は洗い出しの集計による。
- 例：Amazon Echo（iotraffic `AmazonEcho_44650d56ccd3.pcap` フレーム 173、177）は TLS 1.0 までしか提示せず RC4、DES、3DES も並べ、サーバーは TLS 1.0 の `TLS_RSA_WITH_AES_256_CBC_SHA` を選んだ。August Doorbell Cam（同 `AugustDoorBell_e076d03f00ae.pcap` フレーム 39〜59）のサーバー証明書は SHA-1 で、発行者は August の私設の CA。機器も同じ CA のクライアント証明書（`CN=August Doorbell Cam`）を出していた。Samsung Smart TV（yourthings `eth1-20180418.0945.1524062700` フレーム 134983）は、Amazon Video のサーバーが TLS 1.0 の `TLS_RSA_WITH_3DES_EDE_CBC_SHA` を選んだ。
- Awair（iotraffic `AwairAirQuality_70886b100fc6.pcap` フレーム 22、24）は、機器は DHE の暗号を提示したが、サーバーが RSA 鍵交換を選んだ。前方秘匿性がないのはサーバーの選択による。
- Netatmo Smart Indoor Camera（deakin `2024-04-14.pcap` フレーム 3113917）は SSL 3.0 の ClientHello を 3 回送った。サーバーの応答はない。

### Deakin のやり直し（2026-11-11）

Deakin は Linux cooked の形式で、パケットに宛先の MAC がない。`expose.py` はこれまで、サーバーから機器への通信をすべて捨てていた（ServerHello、証明書、HTTP の応答、ダウンロードが見えていなかった）。機器が送ったパケットから機器の IP アドレスを覚え、その宛先の通信を機器に結びつけるように直し、Deakin の 34 日分をやり直した。2023-07-26 の 1 日分では、選ばれた暗号が分かる握手が 1 から 327 に増えた。

- 新しい候補（`verify.py tls` で確かめた）：Echo Show 8（`2023-08-15.pcap` フレーム 1135020、`api.amazonvideo.com` のサーバーが TLS 1.0 の `TLS_RSA_WITH_AES_256_CBC_SHA` を選んだ。YourThings の Samsung Smart TV、CIC の Echo Spot と同じ形）、Samsung Smart Monitor M80B（`2023-07-26.pcap` フレーム 1322042、`*.samsungcloudsolution.net` の証明書が SHA-1、発行者 Samsung Hubsite CA）、TOPERSUN と Perfk（どちらも Tuya の OUI、ポート 8886 で `TLS_PSK_WITH_AES_128_CBC_SHA256` だけ）。
- この 4 件の先行研究（[sweep/prior-tls.tsv](sweep/prior-tls.tsv)）：
  - Echo Show 8：論文で一部。Moghaddam ほか（ACM CCS 2019、付録 D p.16）が、Roku と Fire TV の Amazon Prime Video が amazonvideo.com に TLS 1.0 でつなぐと書く。機器が違い、付録の集計で、ClientHello の指紋の話なので「除く」にはしない。
  - M80B：論文で一部。OS3 の学生報告（2013、Fig. 9 p.16）に、Samsung TV の `www.samsungotn.net` の証明書の発行者が Samsung Hubsite CA とある（署名の方式は書いていない）。SHA-1 と `*.samsungcloudsolution.net` の報告は見つからなかった。
  - TOPERSUN、Perfk：ブログ等のみ。heise（2019-11-18）と tuya-convert が、Tuya のクラウドとの PSK-AES128-CBC-SHA256 と、PSK を握手の値から計算できた古い方式を書く。前方秘匿性がないことを文章で書いた資料は見つからなかった。Jia ほか（S&P 2020、Table I p.474）は ClientId とセッションの問題で、TLS-PSK は扱っていない。
  - パケットでの確認（`2023-07-26.pcap` の最初の 300,000 フレーム）：ポート 8886 の ClientKeyExchange 21 回（TOPERSUN 19、Perfk の 2 台が 1 回ずつ。例 フレーム 4398）の PSK ID は、どれも 49 バイトで先頭が 0x02。サーバーの hint は `1dHRsc2NjbHltbGx3eWh5` と `0000000000000000`（tuya-cloudcutter の既定の値と同じ）。tuya-convert の issue #483 によると 0x02 は機器ごとの鍵を使う新しい方式で、古い方式の弱さは当てはまらない（こちらの読み）。ポート 8886 の中身が MQTT かは確かめていない。
- Withings Body+ と BPM Connect は TLS 1.3（`TLS_CHACHA20_POLY1305_SHA256`）が選ばれていた。主張の判定（[compare-sweep.md](compare-sweep.md)）を直した。
- ほかの 4 つのデータセットは Ethernet の形式で、影響はない。

## UNSW 2018 を足した（2026-11-11）

データセットを広げるため、UNSW の SOSR 2019 のデータ（[iotanalytics.unsw.edu.au/attack-data.html](https://iotanalytics.unsw.edu.au/attack-data.html)、MIT-0）のうち、正常な日の 27 本（2018-05-28〜10-29、38.4 GB）を落として洗い出しにかけた。攻撃を含む日は使っていない。機器は UNSW 2016・UNSW-IoTraffic と同じ研究室のもの（MAC で照らした）に、Google Home、Chromecast Ultra、機種の分からない 3 台が加わる。候補は全部で 193 件・84 製品になり、UNSW 2018 を含むものは 57 件。

**同じ機器の時期による変化**（公開のアドレスへの通信のうち、平文の HTTP・テキストの割合）：

| 製品 | UNSW 2016 | UNSW-IoTraffic（2016-17） | UNSW 2018 |
|---|---|---|---|
| TP-Link NC220 | 91.9% | 10.9% | 0.3% |
| Samsung SmartCam | 24.1% | 8.4% | 0.0%（シリアル番号つきのイベントの平文の POST がなくなった） |
| Amazon Echo | 86.8% | 73.7% | 30.5% |
| Belkin WeMo Switch | 4.3% | 3.8% | 0.0% |
| Philips Hue Bridge | ― | 70.9% | 86.3% |
| Invoxia Triby | 90.0% | 84.8% | 81.3% |

**UNSW 2018 だけで見えたもの**（`verify.py` で確かめた）：

| 機器 | 根拠 | 中身 |
|---|---|---|
| Google Home | `18-10-16.pcap` ストリーム 27039、応答フレーム 3782705 | `r4---sn-55goxu-ntqe.gvt1.com/edgedl/googletv-eureka/stable-channel/ota.137090.tz_stable-channel.chirp-b4....zip` を HTTP で取得（200、78,939,722 バイト、ZIP） |
| Chromecast Ultra | 同 ストリーム 24067、応答フレーム 3231884 | 同じ場所から `ota.137090.tz_stable-channel.luther-b4....zip`（200、89,409,130 バイト） |
| HP ENVY | `18-05-28.pcap` フレーム 2199381〜2931413 | `chat.hpeprint.com/chat/shortReport` への POST 16 回の `printerUuid=1c852a4d-b800-1f08-abcd-705a0fe49bc0`（末尾が機器の MAC） |
| 機種不明（Espressif の MAC 84:f3:eb:52:42:db） | `18-10-11.pcap` フレーム 102253〜3514587、1006965 | Tuya のクラウド：`a.tuyaus.com/gw.json` への POST 101 回の `gwId=7050050484f3eb5242db`（MAC を含む）。ポート 1883 の平文の MQTT（MQIsdp）の clientId も同じ値（3,698 パケット中 253 に MAC） |
| 機種不明の Withings（`wbs04-ws.withings.net`） | `18-05-28.pcap` フレーム 3737208〜3737235 | 自己署名の証明書（`*.withings.net`）、`TLS_RSA_WITH_AES_128_CBC_SHA256` |

- Chromecast の `shardbypass=yes` は認証情報ではない（外す）。
- 文書との比べ合わせは [compare-sweep.md](compare-sweep.md)、先行研究は [sweep/prior-claims.tsv](sweep/prior-claims.tsv) の最後の 4 行。

## IoT-23 の正常な 3 シナリオを足した（2026-11-11）

IoT-23（Stratosphere Lab、プラハ工科大学。Garcia ほか 2020、Zenodo doi:10.5281/zenodo.4743746、CC BY 4.0）の正常なシナリオ 3 つを `mcfp.felk.cvut.cz` から落とした（約 510 MB、`~/datasets/raw/iot-23-benign/`）。1 シナリオに 1 台。

| シナリオ | 機器（README） | 期間 | MAC |
|---|---|---|---|
| CTU-Honeypot-Capture-4-1 | Philips Hue Bridge | 2018-10-25〜26（1 本、21,664 パケット） | 00:17:88:75:b3:82 |
| CTU-Honeypot-Capture-5-1 | Amazon Echo Dot（世代は不明） | 2018-09-21（約 5.5 時間、398,313 パケット。ファイルの最後が切れている） | 4c:ef:c0:27:56:1e |
| CTU-Honeypot-Capture-7-1 | Somfy のドアロック（機種は不明） | 2019-07-03〜08（6 本。Somfy-03 の最後が切れている） | 5c:cf:7f:1e:76:54（Espressif の OUI。最初のファイル名は `first_start_somfy_gateway`） |

候補は 194 件・85 製品になった。新しいのは Somfy の 1 件で、Echo と Hue は既存の候補に IoT-23 が加わった。

| 機器 | 根拠 | 中身 |
|---|---|---|
| Hue Bridge | `2018-10-25-14-06-32-192.168.1.132.pcap` フレーム 869〜20655、19618〜19654、3835〜20992 | 公開のアドレスへの通信の 71.5%（205,735 バイト中 147,181）が平文の HTTP。`dcp.dc1.philips.com:80`（43 回）と `www.ecdinterface.philips.com:80`（5 回）への POST の `Authorization: CBAuth` に、MAC から作った `Client="001788fffe75b382"` と SSO トークン。`diagnostics.meethue.com:80/bridges/ws/stats` の問い合わせ文字列に `sso` と `auth`（8 回）。YourThings、CIC、UNSW の Hue と同じ形。値は quarant-results |
| Echo Dot | `2018-09-21-capture.pcap` フレーム 215、1405、1493 ほか | 99.9% が TLS。86 回の握手すべてで TLS 1.2（ECDHE）が選ばれた。機器は RC4（75 回）、3DES（9 回）、DES・export・MD5（8 回）も提示した。平文 0.1% は `prod.amazoncrl.com` の失効リストの取得。UNSW 2018 の Echo（第 1 世代）とは機種が違う |
| Somfy | `Somfy-01/…first_start_somfy_gateway.pcap` フレーム 440〜447 ほか、握手 4 回 | 機器が提示したのは RSA 鍵交換の暗号だけ（`TLS_RSA_*` と `TLS_RSA_PSK_*` の 8 種類。SNI なし）。サーバーは 4 回とも `TLS_RSA_WITH_AES_128_CBC_SHA256` を選んだ（前方秘匿性なし）。証明書は `*.opendoors.net`（GoDaddy）。通信の大半は、1 日続く 1 本の TLS 接続（18.195.134.106:443） |

- Hue の `/bridges/fullconfig` への POST（フレーム 12413）の本文は 16 進の文字列で、中身は読めない。
- 文書との比べ合わせは [compare-sweep.md](compare-sweep.md)。Hue と Echo は UNSW 2018 で集めた 2018 年の文書を使った（収録はチェコで、地域の版は未確認）。

## 限界

- 値は記録していないので、値の一致は、機器が LAN で名乗った値と MAC とだけ比べている。
- TCP は順序をそろえるが、欠けた区間は埋めない。HTTP の本文は 32 KB まで。
- UNSW 2018 の正常な日の 27 本と、IoT-23 の正常な 3 シナリオは、2026-11-11 に加えた（上）。IoT-23 の README には「Stratosphere Lab の許可が要る」とあるが、Zenodo の記録は CC BY 4.0。
- 先行研究の検索は製品ごとに 3〜5 回。読めなかった資料は prior-ids.tsv の notes に未確認と書いた。分類は人がまだ確かめていない。

## 次

- 分類を人が確かめる。特に「除く」と「論文で一部」の境目（証明書の 7 件、Insteon、Roku）。
- 「論文で一部」の 41 件のパケットでの確認は済んだ（2026-11-11、上）。
- SimCam の「機器の中で処理する」という説明の時期と範囲を、当時の文書で確かめる（食い違いの候補）。
