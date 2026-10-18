#!/usr/bin/env python3
"""YourThings: which MACs are IoT devices. A device is IoT when its IP is in
the dataset's device_mapping.csv (yourthings.info/assets/device_mapping.csv,
static IPs) and the name is not network infrastructure or a phone, tablet,
PC or game console. Everything else (unmapped hosts) is excluded.

usage: yourthings_iot.py DEVICE_MAPPING_CSV RUNS_DIR OUT_NON_IOT_TXT OUT_IOT_JSON
"""
import csv
import glob
import json
import os
import sys

NOT_IOT = {"Gateway", "GoogleOnHub", "AndroidTablet", "iPhone", "iPad", "UbuntuDesktop", "XboxOneX"}


def main():
    mapping, runs, out_non, out_iot = sys.argv[1:5]
    m = {row[1].strip(): row[0].strip() for row in csv.reader(open(mapping)) if len(row) >= 2}
    iot, non = {}, set()
    for p in sorted(glob.glob(os.path.join(runs, "yt-*", "device_inventory.json"))):
        for d in json.load(open(p)).get("devices") or []:
            mac = (d.get("mac_address") or "").lower()
            if not mac:
                continue
            name = m.get(d["ip"])
            if name and name not in NOT_IOT:
                iot[mac] = name
            else:
                non.add(mac)
    non -= set(iot)
    with open(out_non, "w") as f:
        f.write("# YourThings 2018: MACs not mapped to an IoT device in device_mapping.csv: unmapped hosts, "
                "the gateway, the Google OnHub router, and the phones, tablets and PCs the mapping lists.\n")
        f.write("\n".join(sorted(non)) + "\n")
    json.dump(iot, open(out_iot, "w"), indent=1, sort_keys=True)
    print(f"IoT {len(iot)} non-IoT {len(non)}")


if __name__ == "__main__":
    main()
