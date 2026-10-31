#!/usr/bin/env python3
"""Fill the date-offset columns of claims.tsv.

Usage: claim_offsets.py <claims.tsv> <devices.json>

For each claim, the capture window is the period in which the product was
seen in that dataset (devices.json, built by build_catalog.py). The offset
is the snapshot date minus the capture end when the snapshot is later, and
the snapshot date minus the capture start when it is earlier, so that a
negative value says how old the document was when the capture began and a
positive value how long after the capture it was archived. Rows can then be
sorted or filtered by months without deciding a cut-off now.
"""
import csv
import json
import sys
from datetime import date


def day(s):
    return date.fromisoformat(s)


def main():
    path, catalog = sys.argv[1], sys.argv[2]
    products = json.load(open(catalog))["products"]
    window = {}
    for p in products:
        for ds, w in p["datasets"].items():
            name = f"{p['vendor']} {p['product']}".lower()
            window[(ds, name)] = (w["first_seen"], w["last_seen"])
    rows = list(csv.DictReader(open(path), delimiter="\t"))
    fields = list(rows[0].keys())
    for col in ("capture_start", "capture_end", "offset_days", "offset_months"):
        if col not in fields:
            fields.append(col)
    for r in rows:
        key = (r["dataset"], r["catalog_product"].lower())
        if key not in window:
            sys.exit(f"no capture window for {key}")
        start, end = window[key]
        snap = day(r["snapshot"])
        if snap > day(end):
            off = (snap - day(end)).days
        elif snap < day(start):
            off = (snap - day(start)).days
        else:
            off = 0
        r["capture_start"], r["capture_end"] = start, end
        r["offset_days"] = str(off)
        r["offset_months"] = f"{off / 30.44:.1f}"
        r["timing"] = "before" if off < 0 else "after" if off > 0 else "during"
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
