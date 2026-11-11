#!/usr/bin/env python3
"""Add the claims and coverage rows of the document collection to the shared tables.

usage: merge_collect.py <claims.tsv> <coverage.tsv> <collect dir>...

Each collect dir may hold claims.tsv and coverage.tsv with the same columns as the shared tables
(timing, offsets and capture dates may be missing; claim_offsets.py fills them afterwards). Rows
already in the shared table (same dataset, product, doc, url, quote and type, or url and status for
coverage) are skipped. The dataset code cic-iot-2022 is written as cic2022, the code of devices.json.
"""
import csv
import sys
from pathlib import Path

DATASET = {"cic-iot-2022": "cic2022"}


def read(p):
    return list(csv.DictReader(open(p), delimiter="\t"))


def write(p, fields, rows):
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t", lineterminator="\n", extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: (r.get(k) or "").replace("\t", " ").replace("\n", " ") for k in fields})


def merge(shared, name, dirs, key):
    rows = read(shared)
    fields = list(rows[0].keys())
    for r in rows:
        r["dataset"] = DATASET.get(r["dataset"], r["dataset"])
    seen = {key(r) for r in rows}
    added = 0
    for d in dirs:
        p = Path(d) / name
        if not p.exists():
            continue
        for r in read(p):
            r["dataset"] = DATASET.get(r.get("dataset", ""), r.get("dataset", ""))
            if key(r) in seen or not r.get("product"):
                continue
            seen.add(key(r))
            rows.append(r)
            added += 1
    write(shared, fields, rows)
    print(f"{shared}: {added} rows added, {len(rows)} in all")


def main():
    claims, coverage, *dirs = sys.argv[1:]
    merge(claims, "claims.tsv", dirs, lambda r: (r["dataset"], r["product"], r["doc"], r["url"].strip(), r["quote"].strip(), r["type"]))
    merge(coverage, "coverage.tsv", dirs, lambda r: (r["dataset"], r["product"], r["doc"], r["url"].strip(), r["status"]))


if __name__ == "__main__":
    main()
