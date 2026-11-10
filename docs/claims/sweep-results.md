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
- **確かめ方**：Sonos の既知の結果（YourThings 2018-03-20 のフレーム 60977 の serial と householdid、フレーム 4429 の UPnP のシリアル）を自動で再現した。「見つからず」と「ブログ等のみ」の 20 件は、パケットで確かめた（下）。**「論文で一部」と TLS の候補は自動の検出のままで、パケットでは確かめていない。**

## 数

- 候補：74 製品、166 件（[sweep/candidates.tsv](sweep/candidates.tsv)）。
- 識別子など 61 件：除く 1、論文で一部 40、ブログ等のみ 9、見つからず 11。
- TLS 105 件：除く 20、論文で一部 42、対応表の論文にない 35、未確認 8。

区分は教授の基準に合わせた。

- **除く**：S&P、USENIX Security、CCS、NDSS、IMC、PETS で、同じ機器の同じ問題が示されている。
- **論文で一部**：ほかの会議、集計だけ、同じメーカーの別の機種、または問題の別の面。
- **ブログ等のみ**：ブログ、勧告、CVE、講演、GitHub。
- **見つからず**：探した範囲で報告がない。**新しいという意味ではない。**

## 識別子・認証情報・ファームウェア（61 件）

「最初の根拠」はデータセット、ファイル、フレーム番号。中身の項目名と宛先は [sweep/candidates.tsv](sweep/candidates.tsv) の detail、先行研究の書誌と違いは [sweep/prior-ids.tsv](sweep/prior-ids.tsv)。

| 製品 | 種類 | データ | 回数 | 平文で送っていたもの（項目 → 宛先） | 最初の根拠 | 先行研究 | 区分 |
|---|---|---|---|---|---|---|---|
| August Doorbell Cam | MAC（HTTP 以外） | iotraffic | 2 | raw bytes in tcp/443 payload; raw bytes in tcp/68 payload | iotraffic:pcaps__AugustDoorBell_e076d03f00ae.pcap フレーム 5122643 | ― | 見つからず |
| HeimVision camera | 識別子（平文の HTTP） | cic2022 | 28 | form:device_id=MAC -> esd.closeli.com:80 | cic2022:1-Power__Cameras__HeimVision Camera__POWER__heimvisioncamPOWER_1.pcap フレーム 62 | ― | 見つからず |
| Home Eye camera | 認証情報らしい値（平文） | cic2022 | 82 | h:authorization:oss -> xyxcamera.oss-cn-hongkong.aliyuncs.com:80 | cic2022:1-Power__Cameras__Home Eye Camera__POWER__homeeyecamPOWER_1.pcap フレーム 25 | ― | 見つからず |
| Invoxia Triby | 認証情報らしい値（平文） | iotraffic,unsw2016 | 23 | h:authorization:basic -> 8937406324.airable.io:80 | iotraffic:pcaps__TribySpeaker_18B79E022044.pcap フレーム 60097 | ― | 見つからず |
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
| Insteon Hub Pro | 識別子（平文の HTTP） | yourthings | 197 | q:mac=named q:mac -> connect.insteon.com:80 | yourthings:eth1-20180411.1935.1523493300 フレーム 52663 | Information Exposure From Consumer IoT Devices（2019） | 除く（トップ会議） |

- **Insteon Hub Pro（除く）**：Ren ほか（IMC 2019、§6.2）が、Insteon のハブが MAC を平文で送ると報告している。Hub と Hub Pro が同じ型かは未確認。
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

## TLS（105 件）

| 種類 | 除く | 論文で一部 | 対応表にない | 未確認 |
|---|---|---|---|---|
| 1.0/1.1 を選んだ、または 1.1 までしか提示しない | 3 | 13 | 8 | 3 |
| RC4、DES、export、NULL、匿名の暗号（3DES だけは数えない） | 9 | 15 | 9 | 3 |
| 前方秘匿性のある握手がない | 1 | 8 | 12 | 1 |
| サーバー証明書（RSA 2048 ビット未満、SHA-1/MD5、自己署名、期限切れ） | 7 | 6 | 6 | 1 |

- **除く**：Amazon Echo Spot、Fire TV、Harman Kardon Invoke、LG webOS TV、Hue、Ring、Samsung Smart TV、SmartThings Hub、Roku TV（IoTLS、IMC 2021）。証明書は August、LIFX、Nest Cam、Nest Cam IQ、Roku 4、Roku TV、SmartThings Hub（Alrawi ほか、S&P 2019、Table V の自己署名）。ただし証明書の 7 件は、論文が自己署名、こちらは SHA-1 や RSA 1024 で、性質が違う。
- **対応表の論文にない製品**：Arlo Q、Atomi、Awair、BlipCare、D-Link DCH-S161、Dropcam、Globe、Gosund、HP ENVY、HeimVision の電球、Invoxia Triby、Netatmo Welcome、Pix-Star、Samsung のカメラ 2 機種、TP-Link NC220、Teckin、Withings Smart Scale、Yutron、iHome。
- **論文と合わないもの**：Samsung Smart TV は 13 回の握手で 3DES が選ばれていた（IoTLS は、安全でない暗号が選ばれたのは Wink Hub 2 と LG TV だけとする。p.172）。Harman Kardon Invoke は 2018-03 に TLS 1.0 が選ばれていた（IoTLS は 1.2 未満に対応しないとする）。

## 限界

- 値は記録していないので、値の一致は、機器が LAN で名乗った値と MAC とだけ比べている。
- TCP は順序をそろえるが、欠けた区間は埋めない。HTTP の本文は 32 KB まで。
- UNSW 2018 と IoT-23 は、保存先へのリンクが切れていて使っていない。
- 先行研究の検索は製品ごとに 3〜5 回。読めなかった資料は prior-ids.tsv の notes に未確認と書いた。分類は人がまだ確かめていない。

## 次

- 分類を人が確かめる。特に「除く」と「論文で一部」の境目（Insteon、Roku、証明書）。
- 「論文で一部」の候補（40 件）も、同じ方法でパケットで確かめる。
- SimCam の「機器の中で処理する」という説明の時期と範囲を、当時の文書で確かめる（食い違いの候補）。
