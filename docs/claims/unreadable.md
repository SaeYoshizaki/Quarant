# 読めなかった文書

アーカイブにはあるが、最初の取得で文字を取り出せなかった文書 34 件を、2026-11-01 にブラウザ（Chrome）で開き直し、文字の層がない PDF は OCR（tesseract）にかけた。結果は 14 件が読め、20 件は読めなかった。読めたものの主張は [claims.tsv](claims.tsv) に加え、[coverage.tsv](coverage.tsv) の status を found にした。

ブラウザで読むときは、本文を後から読み込む通信の URL を調べ、その URL のアーカイブを取得して保存した（引用の照合に使えるように）。それができないもの（本文がスクリプトの中にあるもの）は、表示された文字のうち主張に関わる行だけを抜粋として保存した。

## 読めなかった文書（20 件）

多くは、ページの枠はアーカイブされているが、本文を読み込む通信がアーカイブされていないもの。ブラウザで開いても本文は出ない。

| 製品 | 文書 | URL | 理由 |
|---|---|---|---|
| Apple HomePod | D5 | https://web.archive.org/web/20180209052644/http://help.apple.com/homepod/ | the help viewer loads its chapters from help.apple.com/homepod/en.lproj/..., which are not archived (only images and the shell) |
| Apple TV (4th gen) | D5 | https://web.archive.org/web/20170902115938/http://help.apple.com/appletv/ | only the table of contents (en.lproj/navigation.json, 2018-04-09) is archived; it lists update topics but no chapter text |
| Belkin NetCam HD | D4 | https://web.archive.org/web/20151002130615/http://www.belkin.com/us/support-article?articleNum=7985 | body is an iframe of belkin.force.com/Articles/apex/pkb_viewArticle?articleNum=...; this article is not among the 211 archived ones |
| Belkin NetCam HD | D6 | https://web.archive.org/web/20160711181120/http://www.belkin.com:80/us/support-article?articleNum=5014 | same Belkin knowledge-base iframe, not archived |
| Belkin WeMo Link, Belkin WeMo Motion Sensor, Belkin WeMo Switch, WeMo Crock-Pot | D4 | https://web.archive.org/web/20180329200532/http://www.belkin.com:80/us/support-article?articleNum=27353 | same Belkin knowledge-base iframe, not archived (checked in the browser) |
| Belkin WeMo Link, Belkin WeMo Motion Sensor, Belkin WeMo Switch, WeMo Crock-Pot | D4 | https://web.archive.org/web/20180131131541/http://www.belkin.com:80/us/support-article?articleNum=8297 | same Belkin knowledge-base iframe, not archived |
| Bose SoundTouch 10 | D3 | https://web.archive.org/web/20170218023314/http://downloads.bose.com/ced/soundtouch/ | the only capture is an empty page |
| D-Link DCS-5009L | D1 | https://web.archive.org/web/20170927191232/http://www.dlink.com:80/uk/en/products/dcs-5009l-pan-tilt-wifi-camera | both captures of the UK page are the site's 404 page; the US product page (2016-11-05) was already read |
| Nest Cam | D5 | https://web.archive.org/web/20170505205126/https://nest.com/support/article/Download-Nest-Cam-documents-and-get-started-using-your-camera | same Nest support API, not archived |
| Nest Cam | D5 | https://web.archive.org/web/20190923193712/https://nest.com/support/images/misc-nest-cam-2/us-nc-welcome-guide.pdf | the archived PDF is damaged (no trailer; pages cannot be rendered); after capture anyway |
| Nest Cam, Nest Cam IQ | D6 | https://web.archive.org/web/20170331022249/https://nest.com/support/article/Nest-Cam-and-Dropcam-software-update-history | same Nest support API, 404 in the replay (checked in the browser) |
| Nest Cam, Nest Cam IQ, Nest Protect, Nest Secure (Nest Guard) | D4 | https://web.archive.org/web/20180305022742/https://nest.com/support/article/KRACK-vulnerability | page loads its body from nest.com/salesforce/api/en_us/sup-articles/<name>, which is not archived (404) |
| Nest Cam, Nest Cam IQ, Nest Protect, Nest Secure (Nest Guard) | D4 | https://web.archive.org/web/20180131092931/https://nest.com/support/article/How-to-use-2-step-verification-to-add-stronger-security-to-your-Nest-Account | body from nest.com/salesforce/api/en_us/sup-articles/<name>; not archived on any date 2016-2020 |
| Nest Protect | D4 | https://web.archive.org/web/20171007170837/https://nest.com/support/article/How-does-Nest-Protect-connect-wirelessly | same Nest support API, not archived |
| Nest Protect | D5 | https://web.archive.org/web/20180130114704/https://nest.com/support/article/Download-Nest-Protect-documents-and-get-started-using-your-smoke-and-carbon-monoxide-detector | same Nest support API, not archived |
| Ring Video Doorbell | D5 | https://web.archive.org/web/20191014034436/https://support.ring.com/hc/en-us/article_attachments/115016351046/RVD2_manual_English.pdf | the archived copy itself is cut at 1 MB (refetched: same); the other Ring manual too |
| Roku 4, Roku TV | D3 | https://web.archive.org/web/20180124182901/https://support.roku.com/article/privacy.policy | article HTML has no body; its API (support.roku.com/api/v1/en-us/article/...) is not archived; the policy itself was read from the docs.roku.com text version (row 22) |
| Roku 4, Roku TV | D4 | https://web.archive.org/web/20180412154821/https://support.roku.com/article/208755668-how-can-i-update-the-software-on-my-roku-player- | article HTML has no body; API not archived on any date |
| Roku 4, Roku TV | D6 | https://web.archive.org/web/20180429090228/https://support.roku.com/article/228844467-roku-os-software-release-notes | article HTML has no body; API not archived |
| Samsung Smart TV | D1 | https://web.archive.org/web/20180208045744/http://www.samsung.com/us/smarttv/index.html?cid=... | the capture redirects to the samsung.com/us home page; no Smart TV page content |

## 読めた文書（14 件）

| 製品 | 文書 | 元の URL | 読んだもの | 結果 |
|---|---|---|---|---|
| Amazon Echo (1st gen) | D1 | https://web.archive.org/web/20180312152259/https://www.amazon.com/Amazon-Echo-Bluetooth-Speaker-with-WiFi-Alexa/dp/B00X4WHP5E | https://web.archive.org/web/20180312152259/https://www.amazon.com/Amazon-Echo-Bluetooth-Speaker-with-WiFi-Alexa/dp/B00X4WHP5E | read：refetched and decompressed; only "updates are delivered automatically"; the rest is reviews and accessories |
| D-Link DCS-5009L | D4 | https://web.archive.org/web/20171121052811/http://www.mydlink.com:80/faq | https://web.archive.org/web/20171113152917/https://www.mydlink.com/faq | read in browser, no security claim：the 2017-11-21 capture gives a Wayback internal error; the 2017-11-13 one shows only the top-FAQ titles (registration, setup, notifications); answers are not archived |
| D-Link DCS-5009L | D6 | https://web.archive.org/web/20170705201654/http://support.dlink.com/productinfo.aspx?m=DCS-5009L | (browser; excerpt saved as dlink-dcs5009l-support-browser-20170705201654.txt) | read in browser (partly)：firmware list and FAQ come from support.dlink.com/ajax/ajax.ashx, not archived; the page says the product is discontinued and free support ends 2018-07-01 |
| Insteon Hub Pro | D5 | https://web.archive.org/web/20170529083121/http://cache.insteon.com/documentation/2243-222qs-en.pdf | (OCR, insteon_2243_222_qs-20170529-ocr.txt) | read by OCR, no security claim：setup steps only |
| Logi Circle | D4 | https://web.archive.org/web/20180313165545/http://support.logitech.com:80/en_us/product/circle/faq | https://web.archive.org/web/20180313165545/http://support.logitech.com:80/en_us/product/circle/faq (articles embedded as JSON in the page; turned into text) | read：60 FAQ articles; one on footage security: unique device key and certificate, AES 256 for audio/video, bank-level encryption for all transfers |
| Philips Hue Bridge | D5 | https://web.archive.org/web/20160308233356/http://www2.meethue.com:80/media/2999123/Hue-Bridge.pdf | (OCR, hue_bridge_manual-20160308-ocr.txt) | read by OCR, no security claim：setup leaflet only |
| Roku 4, Roku TV | D3 | https://web.archive.org/web/20180323015954/https://docs.roku.com/doc/userprivacypolicy/en-us | https://web.archive.org/web/20161120154530/https://docs.roku.com/api/v1.0/docs/UserPrivacyPolicy/en/US/text | read (older version)：2018 body (api .../7/html) not archived; the 2016-11-20 text version is the only one; storage security (not assessable), disclaimer |
| Roku 4, Roku TV | D4 | https://web.archive.org/web/20171216183735/https://support.roku.com/article/220128567-how-do-i-create-or-update-the-pin-on-my-roku-account- | https://web.archive.org/web/20191231191942/https://support.roku.com/api/v1/en-us/article/220128567?blocks=true&sideloads=true | read (after capture), no encryption claim：only the 2019-12 API version exists; purchase PIN instructions |
| Roku TV | D1 | https://web.archive.org/web/20180412090551/https://www.roku.com/roku-tv | (browser; excerpt saved as roku-tv-page-browser-20180412090551.txt) | read in browser：body text comes from a script bundle; only automatic software updates, no encryption claim |
| Sonos PLAY:1 | D3 | https://web.archive.org/web/20160805094518/http://www.sonos.com/documents/eula/EN/EULA_EN.pdf | (OCR, sonos_eula-20160805-ocr.txt) | read by OCR：EULA: no obligation to provide updates (disclaimer); no encryption claim |
| WeMo Crock-Pot | D5 | https://web.archive.org/web/20150908012826/https://www.crock-pot.com/on/demandware.static/-/Sites-crock-pot-Library/default/dw856ce166/documents/instruction-manuals/SCCPWM600-V1_%20WeMo%20Slow%20Cooker_%20UserGuide.pdf | (OCR, crockpot_wemo_ug-20150908-ocr.txt) | read by OCR, no security claim：electrical safety and Wi-Fi setup only |
| iRobot Roomba | D2 | https://web.archive.org/web/20180324031612/http://www.irobot.com:80/Legal/Data-Security.aspx | https://web.archive.org/web/20181110041231/https://webapi.irobot.com//Legal/Documents/North-America/United-States/Legal-Documents/Data-Security.aspx?sc_lang=en | read (after capture)：body is an embedded page; earliest capture of it is 2018-11-10; claims: AES-256 + TLS 1.2, encrypted in transit and at rest, signed updates |
| iRobot Roomba | D3 | https://web.archive.org/web/20180329213230/http://www.irobot.com:80/Legal/Privacy-Policy.aspx? | https://web.archive.org/web/20180301175448/http://www.irobot.com/Legal/Documents/North-America/United-States/Legal-Documents/Privacy-Policy.aspx?sc_lang=en | read：body is an embedded page; safeguards (vague), cannot guarantee 100% (disclaimer) |
| iRobot Roomba | D4 | https://web.archive.org/web/20170919075612/https://homesupport.irobot.com/app/answers/detail/a_id/10228 | (browser) | read, no security claim：troubleshooting instruction only |
