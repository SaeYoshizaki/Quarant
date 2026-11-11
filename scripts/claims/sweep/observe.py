#!/usr/bin/env python3
"""Print what the sweep saw for one product, to set beside its claims.

usage: observe.py <report dir> <dataset> <product>...

<report dir> holds the report.py output (findings.tsv, ids.tsv, tls.tsv, dl.tsv, flows.tsv).
<product> is the catalog name ("vendor product", as in claims.tsv catalog_product); several may be given.
The report tables add the model to the name ("D-Link Water Sensor DCH-S161"), so a name matches as a prefix.
Prints, per device of the product: payload bytes to public addresses by kind, the findings with their
first evidence, the plaintext identifier fields, the TLS summary and the plaintext downloads.
"""
import csv
import sys
from pathlib import Path


def rows(p):
    return list(csv.DictReader(open(p), delimiter="\t", quoting=csv.QUOTE_NONE))


def main():
    rep, ds, *products = sys.argv[1:]
    want = {p.lower() for p in products}
    match = lambda p: any(p.lower() == w or p.lower().startswith(w + " ") for w in want)
    pick = lambda name: [r for r in rows(Path(rep) / name) if r["dataset"] == ds and match(r["product"])]
    for r in pick("flows.tsv"):
        kinds = {k: int(v) for k, v in r.items() if k not in ("dataset", "product", "mac") and v and v != "0"}
        total = sum(kinds.values())
        print(f'{r["product"]} {r["mac"]}: payload to public addresses {total} B: ' +
              ", ".join(f"{k} {v} ({100 * v / total:.1f}%)" for k, v in sorted(kinds.items(), key=lambda x: -x[1])))
    print("findings:")
    for r in pick("findings.tsv"):
        print(f'  {r["mac"]} {r["cat"]}: {r["detail"][:200]} (count {r["count"]}, files {r["files"]}, first {r["first_file"]}#{r["first_frame"]})')
    print("plaintext identifier fields:")
    for r in pick("ids.tsv"):
        print(f'  {r["mac"]} {r["where"]} {r["key"]} [{r["cats"]}] lan={r["lan_ids"]} shape {r["shape"]} len {r["len"]} '
              f'count {r["count"]} values {r["values"]} first {r["first_file"]}#{r["first_frame"]}')
    print("TLS:")
    for r in pick("tls.tsv"):
        print(f'  {r["mac"]} {r["side"]}: {r["handshakes"]} handshakes; offered max {r["offered_max"]}; offered weak {r["offered_weak"] or "none"}; '
              f'offered FS {r["offered_fs"]}; chosen {r["chosen_version"]}; chosen FS {r["chosen_fs"]}; test excluded {r["excluded_test"]}')
        print(f'    suites: {r["top_suites"][:300]}')
        print(f'    certs: {r["certs"][:300]}')
    print("plaintext downloads:")
    for r in pick("dl.tsv"):
        print(f'  {r["mac"]} {r["host"]}{r["path"][:80]} {r["size"]} B {r["ctype"]} {r["ext"]} x{r["count"]} first {r["first_file"]}#{r["first_frame"]}')


if __name__ == "__main__":
    main()
