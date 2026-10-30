#!/usr/bin/env python3
"""Collect model hints per device from Quarant analysis runs.

Usage: collect_hints.py <out.tsv> <run_dir>...

For each MAC address, lists the distinct values of identity attributes that
often name a product or firmware (DHCP hostname and vendor class, mDNS
hostname, SSDP server, OUI vendor). Values can contain serial numbers or
personal names, so write the output outside the repository.
"""
import collections
import json
import sys
from pathlib import Path

ATTRS = {
    ("hostname", "dhcp"), ("hostname", "mdns"), ("dhcp_vendor_class", "dhcp"),
    ("ssdp_server", "ssdp"), ("mac_vendor", "oui_registry"),
}


def main():
    out, runs = sys.argv[1], sys.argv[2:]
    hints = collections.defaultdict(lambda: collections.defaultdict(set))
    where = collections.defaultdict(set)
    for run in runs:
        inv = Path(run) / "device_inventory.json"
        if not inv.exists():
            continue
        for dev in json.loads(inv.read_text()).get("devices", []):
            mac = (dev.get("mac_address") or "").lower()
            if not mac:
                continue
            where[mac].add(Path(run).name)
            for ev in dev.get("identity_evidence") or []:
                key = (ev.get("attribute"), ev.get("source"))
                if key in ATTRS and ev.get("value"):
                    hints[mac][key[0] + "/" + key[1]].add(str(ev["value"]))
    with open(out, "w") as f:
        f.write("mac\truns\thints\n")
        for mac in sorted(where):
            h = "; ".join(f"{k}={'|'.join(sorted(v))}" for k, v in sorted(hints[mac].items()))
            f.write(f"{mac}\t{len(where[mac])}\t{h}\n")


if __name__ == "__main__":
    main()
