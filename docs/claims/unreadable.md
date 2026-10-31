# 読めなかった文書

アーカイブにはあるが、文字を取り出せなかった文書（[coverage.tsv](coverage.tsv) の status が unreadable のもの）。多くは本文を JavaScript で表示するページで、ブラウザで開けば読める可能性がある。PDF は文字の層がない（画像だけの）もの。

ブラウザで開いて、セキュリティについての記述があれば PDF で保存し、`~/datasets/claims/snapshots/` に置く。そのあと主張を [claims.tsv](claims.tsv) に加える。

| 製品 | 文書 | URL | メモ |
|---|---|---|---|
| Amazon Echo (1st gen) | D1 | https://web.archive.org/web/20180312152259/https://www.amazon.com/Amazon-Echo-Bluetooth-Speaker-with-WiFi-Alexa/dp/B00X4WHP5E | newer capture saved as undecoded binary (compressed body); 2017-10 version used instead |
| Apple HomePod | D5 | https://web.archive.org/web/20180209052644/http://help.apple.com/homepod/ | HomePod User Guide; archived page says JavaScript required |
| Apple TV (4th gen) | D5 | https://web.archive.org/web/20170902115938/http://help.apple.com/appletv/ | Apple TV User Guide, JavaScript viewer (same as HomePod guide; not fetched) |
| Belkin NetCam HD | D4 | https://web.archive.org/web/20151002130615/http://www.belkin.com/us/support-article?articleNum=7985 | 'Meet the NetCam F7D7601' article: body script-loaded; netcam.belkin.com is the web app only |
| Belkin NetCam HD | D6 | https://web.archive.org/web/20160711181120/http://www.belkin.com:80/us/support-article?articleNum=5014 | 'Updating the WEMO NetCam HD F7D7602 Firmware': body script-loaded; no release notes found |
| Belkin WeMo Link, Belkin WeMo Motion Sensor, Belkin WeMo Switch, WeMo Crock-Pot | D4 | https://web.archive.org/web/20180329200532/http://www.belkin.com:80/us/support-article?articleNum=27353 | 'Updating the firmware of your Wemo device'; body loaded by JavaScript, text not in snapshot |
| Belkin WeMo Link, Belkin WeMo Motion Sensor, Belkin WeMo Switch, WeMo Crock-Pot | D4 | https://web.archive.org/web/20180131131541/http://www.belkin.com:80/us/support-article?articleNum=8297 | WeMo firmware update troubleshooting; body loaded by JavaScript |
| Bose SoundTouch 10 | D3 | https://web.archive.org/web/20170218023314/http://downloads.bose.com/ced/soundtouch/ | SoundTouch downloads directory page; no text. No SoundTouch app privacy page found (only a Bose Connect one) |
| D-Link DCS-5009L | D1 | https://web.archive.org/web/20170927191232/http://www.dlink.com:80/uk/en/products/dcs-5009l-pan-tilt-wifi-camera | UK product page: archived text has only 8 lines (script-rendered) |
| D-Link DCS-5009L | D4 | https://web.archive.org/web/20171121052811/http://www.mydlink.com:80/faq | mydlink FAQ: archived text empty (script-rendered) |
| D-Link DCS-5009L | D6 | https://web.archive.org/web/20170705201654/http://support.dlink.com/productinfo.aspx?m=DCS-5009L | firmware downloads and release notes table loaded by script after selecting hardware revision |
| Insteon Hub Pro | D5 | https://web.archive.org/web/20170529083121/http://cache.insteon.com/documentation/2243-222qs-en.pdf | quick start PDF has no text layer (pdftotext gives 0 lines); needs OCR or a person |
| Logi Circle | D4 | https://web.archive.org/web/20180313165545/http://support.logitech.com:80/en_us/product/circle/faq | FAQ list is a script template ({{x.Title}}) |
| Nest Cam, Nest Cam IQ, Nest Protect, Nest Secure (Nest Guard) | D4 | https://web.archive.org/web/20180305022742/https://nest.com/support/article/KRACK-vulnerability | KRACK advisory; archived page has only the support-site shell, article body loaded by JavaScript |
| Nest Cam, Nest Cam IQ, Nest Protect, Nest Secure (Nest Guard) | D4 | https://web.archive.org/web/20180131092931/https://nest.com/support/article/How-to-use-2-step-verification-to-add-stronger-security-to-your-Nest-Account | 2-step verification article; body loaded by JavaScript |
| Nest Cam | D5 | https://web.archive.org/web/20190923193712/https://nest.com/support/images/misc-nest-cam-2/us-nc-welcome-guide.pdf | welcome guide PDF has no text layer (pdftotext 0 lines); after capture |
| Nest Cam | D5 | https://web.archive.org/web/20170505205126/https://nest.com/support/article/Download-Nest-Cam-documents-and-get-started-using-your-camera | manual download page, JavaScript (not fetched) |
| Nest Cam, Nest Cam IQ | D6 | https://web.archive.org/web/20170331022249/https://nest.com/support/article/Nest-Cam-and-Dropcam-software-update-history | software update history; JavaScript-rendered support article (not fetched); only 2017-03 capture |
| Nest Protect | D4 | https://web.archive.org/web/20171007170837/https://nest.com/support/article/How-does-Nest-Protect-connect-wirelessly | JavaScript-rendered support article (not fetched) |
| Nest Protect | D5 | https://web.archive.org/web/20180130114704/https://nest.com/support/article/Download-Nest-Protect-documents-and-get-started-using-your-smoke-and-carbon-monoxide-detector | manual download page, JavaScript (not fetched); no Protect manual PDF archived under nest.com/support/images or nest.com |
| Philips Hue Bridge | D5 | https://web.archive.org/web/20160308233356/http://www2.meethue.com:80/media/2999123/Hue-Bridge.pdf | Hue Bridge leaflet/manual PDF has no text layer |
| Ring Video Doorbell | D5 | https://web.archive.org/web/20191014034436/https://support.ring.com/hc/en-us/article_attachments/115016351046/RVD2_manual_English.pdf | archived PDF truncated at 1 MB, pdftotext fails; also Doorbell_2_Manual_EN.pdf (20191014034616) truncated; both after ca |
| Roku 4, Roku TV | D3 | https://web.archive.org/web/20180323015954/https://docs.roku.com/doc/userprivacypolicy/en-us | JavaScript page (text is only 'Roku'); use the API URL above or open in a browser |
| Roku 4, Roku TV | D3 | https://web.archive.org/web/20180124182901/https://support.roku.com/article/privacy.policy | JavaScript page |
| Roku 4, Roku TV | D4 | https://web.archive.org/web/20180412154821/https://support.roku.com/article/208755668-how-can-i-update-the-software-on-my-roku-player- | JavaScript page; open in a browser |
| Roku 4, Roku TV | D4 | https://web.archive.org/web/20171216183735/https://support.roku.com/article/220128567-how-do-i-create-or-update-the-pin-on-my-roku-account- | JavaScript page |
| Roku 4, Roku TV | D6 | https://web.archive.org/web/20180429090228/https://support.roku.com/article/228844467-roku-os-software-release-notes | JavaScript page; after capture (earliest archived) |
| Roku TV | D1 | https://web.archive.org/web/20180412090551/https://www.roku.com/roku-tv | JavaScript page; earlier pass saved only 'Roku' (snapshots 2018-03-29, 2018-04-12) |
| Samsung Smart TV | D1 | https://web.archive.org/web/20180208045744/http://www.samsung.com/us/smarttv/index.html?cid=ppc_smt_goo_Smart+TV+-+Awareness_Smart+TV_smart+tv&amp;K_CLICKID=5b86c4c9-6936-eac8-bbe5-00004db65f45 | only capture of the Smart TV page; text is a title only. Model unknown, so no model page |
| Sonos PLAY:1 | D3 | https://web.archive.org/web/20160805094518/http://www.sonos.com/documents/eula/EN/EULA_EN.pdf | EULA PDF has no text layer (pdftotext gives nothing) |
| WeMo Crock-Pot | D5 | https://web.archive.org/web/20150908012826/https://www.crock-pot.com/on/demandware.static/-/Sites-crock-pot-Library/default/dw856ce166/documents/instruction-manuals/SCCPWM600-V1_%20WeMo%20Slow%20Cooker_%20UserGuide.pdf | user guide PDF (8 MB, Illustrator, text outlined): pdftotext returns no text |
| iRobot Roomba | D2 | https://web.archive.org/web/20180324031612/http://www.irobot.com:80/Legal/Data-Security.aspx | page body is loaded by JavaScript; snapshot text has only navigation (also 2018-06-24 copy). Open in a browser. |
| iRobot Roomba | D3 | https://web.archive.org/web/20180329213230/http://www.irobot.com:80/Legal/Privacy-Policy.aspx? | JavaScript-only body (also 2018-03-01 copy). Open in a browser. |
| iRobot Roomba | D4 | https://web.archive.org/web/20170919075612/https://homesupport.irobot.com/app/answers/detail/a_id/10228 | 'Unable to verify robot certificate' article: body not in archived HTML text |
