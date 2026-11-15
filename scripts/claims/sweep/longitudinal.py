#!/usr/bin/env python3
"""Products seen in two or more datasets, side by side by year: share of plaintext HTTP, TLS versions and the
suites the servers chose (from report.py's flows.tsv and tls.tsv).

usage: longitudinal.py <devices.json> <report dir> <out.md>
"""
import collections
import csv
import json
import sys

ORDER = ["unsw2016", "iotraffic", "yourthings", "unsw2018", "iot23", "cic2022", "deakin"]
YEAR = {"unsw2016": "2016", "iotraffic": "2016-17", "yourthings": "2018", "unsw2018": "2018",
        "iot23": "2018-19", "cic2022": "2021", "deakin": "2023-24"}
NAME = {"unsw2016": "UNSW 2016", "iotraffic": "UNSW-IoTraffic", "yourthings": "YourThings", "unsw2018": "UNSW 2018",
        "iot23": "IoT-23", "cic2022": "CIC IoT 2022", "deakin": "Deakin"}


def main():
    devices, report, out = sys.argv[1:4]
    rows = json.load(open(devices))["rows"]
    flows = {(r["dataset"], r["mac"].lower()): r for r in csv.DictReader(open(f"{report}/flows.tsv"), delimiter="\t")}
    tls = collections.defaultdict(list)
    for r in csv.DictReader(open(f"{report}/tls.tsv"), delimiter="\t"):
        if r["side"] == "client-public":
            tls[(r["dataset"], r["mac"].lower())].append(r)
    byprod = collections.defaultdict(list)
    for r in rows:
        byprod[(r["vendor"], r["product"])].append(r)
    lines = ["# 同じ製品を年をまたいで見る", "",
             "2 つ以上のデータセットにある製品の、公開のアドレスへの通信（`scripts/claims/sweep/longitudinal.py` で作る）。"
             "平文は HTTP の割合（バイト）、TLS は機器側の握手でサーバーが選んだ版と暗号（多い順に 2 つ）。"
             "同じ MAC は同じ個体。MAC が違う行は、同じ製品の別の個体（機種が違うこともある）。", "",
             "| 製品 | データ（年） | MAC | 公開への量 | 平文の HTTP | TLS の版 | 選ばれた暗号 |",
             "|---|---|---|---|---|---|---|"]
    n = 0
    for (vendor, product), units in sorted(byprod.items()):
        if len({u["dataset"] for u in units}) < 2:
            continue
        n += 1
        for u in sorted(units, key=lambda u: ORDER.index(u["dataset"])):
            key = (u["dataset"], u["mac"].lower())
            f = flows.get(key)
            if f:
                total = sum(int(f[c] or 0) for c in f if c not in ("dataset", "product", "mac"))
                http = int(f["http"] or 0)
                size = f"{total / 1e6:.1f} MB"
                plain = f"{100 * http / total:.1f}%" if total else "―"
            else:
                size, plain = "―", "―"
            t = tls.get(key, [])
            vers = "; ".join(x["chosen_version"] for x in t) or "―"
            suites = "; ".join("; ".join(x["top_suites"].split("; ")[:2]) for x in t) or "―"
            model = f"（{u['model']}）" if u.get("model") else ""
            lines.append(f"| {vendor} {product}{model} | {NAME[u['dataset']]}（{YEAR[u['dataset']]}） | {u['mac']} | {size} | {plain} | {vers} | {suites} |")
    lines += ["", f"{n} 製品。"]
    open(out, "w").write("\n".join(lines) + "\n")
    print(n, "products")


if __name__ == "__main__":
    main()
