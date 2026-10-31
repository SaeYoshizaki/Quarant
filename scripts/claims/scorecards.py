#!/usr/bin/env python3
"""Network properties from the YourThings scorecards (yourthings.info/devices/<slug>).

Usage: scorecards.py <html dir> <devices.tsv> <out.tsv>

<html dir> holds the saved scorecard pages, one <slug>.html each (fetched by
hand with curl; the pages are public). Writes the properties that concern
encryption, with the firmware version and evaluation date of the device.
Scores are "points/maximum", higher is worse (yourthings.info/method).
"""
import csv
import html
import re
import sys
from pathlib import Path

SLUG_LABEL = {
    "almond": "SecurifiAlmond", "amazon_echo": "AmazonEchoGen1", "amazon_fire": "AmazonFireTV",
    "apple_homepod": "AppleHomePod", "apple_tv": "AppleTV(4thGen)", "august_doorbell": "AugustDoorbellCam",
    "belkin_netcam": "BelkinNetcam", "belkin_link": "BelkinWeMoLink", "belkin_motion": "BelkinWeMoMotionSensor",
    "belkin_switch": "BelkinWeMoSwitch", "bose_soundtouch": "BoseSoundTouch10", "canary_camera": "Canary",
    "caseta_hub": "CasetaWirelessHub", "myq_garage": "ChamberlainmyQGarageOpener", "cn_webcam": "ChineseWebcam",
    "dlink_camera": "D-LinkDCS-5009LCamera", "google_home": "GoogleHome", "google_home_m": "GoogleHomeMini",
    "google_onhub": "", "harmon_invoke": "HarmonKardonInvoke", "insteon_hub": "InsteonHub",
    "koogeek_bulb": "KoogeekLightbulb", "lifx_bulb": "LIFXVirtualBulb", "logitech_hub": "LogitechHarmonyHub",
    "logitech_circle": "LogitechLogiCircle", "veralite": "MiCasaVerdeVeraLite", "nest_iq": "NestCamIQ",
    "nest_cam": "NestCamera", "nest_guard": "NestGuard", "netgear_cam": "NetgearArloCamera",
    "nvidia_shield": "nVidiaShield", "philips_hue": "PhilipsHUEHub", "piper_cam": "PiperNV",
    "ring_doorbell": "RingDoorbell", "roku4": "Roku4", "rokutv": "RokuTV", "roomba": "Roomba",
    "smartthings": "SamsungSmartThingsHub", "samsung_tv": "SamsungSmartTV", "sonos": "Sonos",
    "tplink_bulb": "TP-LinkSmartWiFiLEDBulb", "tplink_plug": "TP-LinkWiFiPlug",
    "belkin_crockpot": "BelkinWeMoCrockpot", "wink2": "Wink2Hub", "withings_cam": "WithingsHome",
}
PROPS = ["Encryption Device-to-Cloud", "Encryption Mobile-to-Device", "HTTP", "Custom Protocol", "UPnP", "NTPv3",
         "Vulnerable TLS/SSL version", "Self-Signed Certificates", "Name Mismatch on Certificate",
         "Cleartext Authentication", "MITM Device-to-Cloud"]


def lines(path):
    t = re.sub(r"(?s)<script.*?</script>|<style.*?</style>", "", path.read_text(errors="ignore"))
    return [s.strip() for s in html.unescape(re.sub(r"<[^>]+>", "\n", t)).splitlines() if s.strip()]


def main():
    html_dir, devices_tsv, out = sys.argv[1:4]
    product = {r["label"]: f"{r['vendor']} {r['product']}" for r in csv.DictReader(open(devices_tsv), delimiter="\t")
               if r["dataset"] == "yourthings"}
    with open(out, "w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["slug", "label", "catalog_product", "firmware", "evaluated", *PROPS, "source"])
        for slug, label in sorted(SLUG_LABEL.items()):
            L = lines(Path(html_dir) / f"{slug}.html")
            v = {}
            for i, s in enumerate(L):
                # each property is "<name> ( ? ) <points>/<max>"
                if re.fullmatch(r"\d+/\d+", s) and i >= 4 and L[i - 1] == ")" and L[i - 3] == "(":
                    v.setdefault(L[i - 4], s)
                for k in ("Firmware Version:", "Evaluation Date:"):
                    if s.startswith(k):
                        v.setdefault(k, s[len(k):].strip())
            w.writerow([slug, label, product.get(label, ""), v.get("Firmware Version:", ""),
                        v.get("Evaluation Date:", ""), *(v.get(p, "") for p in PROPS),
                        f"https://yourthings.info/devices/{slug}"])


if __name__ == "__main__":
    main()
