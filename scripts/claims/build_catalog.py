#!/usr/bin/env python3
"""Build the device catalog for the vendor-claim comparison (D31).

Usage: build_catalog.py <devices.tsv> <datasets dir> <out.md> <out.json>

devices.tsv is hand-curated: one row per device in each dataset, with the
maker, product and (when known) model. This script adds, from the Quarant
runs, when each MAC address was seen and in how many runs, and groups the
rows by product so that one product's claims can be collected once.
"""
import collections
import csv
import json
import sys
from pathlib import Path

RUNS = {
    "unsw2016": ("UNSW IoT traces 2016", "runs-fix4/unsw-*"),
    "iotraffic": ("UNSW-IoTraffic 2016-17", "runs-oss1-iotraffic/*/q"),
    "unsw2018": ("UNSW attacks 2018", "runs-fix4/unswatk-*"),
    "iot23": ("IoT-23 (benign)", "runs-fix4/iot23-CTU-Honeypot*"),
    "yourthings": ("YourThings 2018", "runs-yt5/*"),
    "cic2022": ("CIC IoT 2022", "runs-cic/*"),
    "deakin": ("Deakin 2023", "runs-oss1-deakin/*/q"),
}


def seen_by_mac(root, pattern):
    seen = {}
    for inv in sorted(root.glob(pattern + "/device_inventory.json")):
        for dev in json.loads(inv.read_text()).get("devices", []):
            mac = (dev.get("mac_address") or "").lower()
            if not mac:
                continue
            s = seen.setdefault(mac, {"runs": set(), "first": None, "last": None})
            s["runs"].add(inv.parent)
            for key, pick in (("first_seen", min), ("last_seen", max)):
                v = (dev.get(key) or "")[:10]
                # Some per-device captures carry clock-reset timestamps (1970, 1981).
                if v and v >= "2000":
                    slot = "first" if key == "first_seen" else "last"
                    s[slot] = v if s[slot] is None else pick(s[slot], v)
    return seen


def main():
    tsv, root, out_md, out_json = sys.argv[1], Path(sys.argv[2]), sys.argv[3], sys.argv[4]
    rows = list(csv.DictReader(open(tsv), delimiter="\t"))
    seen = {ds: seen_by_mac(root, pat) for ds, (_, pat) in RUNS.items()}
    for r in rows:
        s = seen[r["dataset"]].get(r["mac"].lower())
        r["runs_seen"] = len(s["runs"]) if s else 0
        r["first_seen"] = (s["first"] or "") if s else ""
        r["last_seen"] = (s["last"] or "") if s else ""

    products = collections.OrderedDict()
    for r in sorted(rows, key=lambda r: (r["vendor"].lower(), r["product"].lower())):
        if r["category"] == "unknown" or r["vendor"] == "unknown":
            continue
        # Different models of one product line make different claims, so they stay apart.
        p = products.setdefault((r["vendor"], r["product"], r["model"]), {
            "vendor": r["vendor"], "product": r["product"], "category": r["category"],
            "models": set(), "datasets": collections.OrderedDict()})
        if r["model"]:
            p["models"].add(r["model"])
        if r["runs_seen"]:
            d = p["datasets"].setdefault(r["dataset"], [r["first_seen"], r["last_seen"], 0])
            d[0] = min(x for x in (d[0], r["first_seen"]) if x) if r["first_seen"] else d[0]
            d[1] = max(d[1], r["last_seen"])
            d[2] += 1

    json.dump({"rows": rows, "products": [
        {**p, "models": sorted(p["models"]), "datasets": {k: {"first_seen": v[0], "last_seen": v[1], "units": v[2]}
                                                          for k, v in p["datasets"].items()}}
        for p in products.values()]}, open(out_json, "w"), ensure_ascii=False, indent=1)

    order = list(RUNS)
    with open(out_md, "w") as f:
        f.write("# データセットの機器の一覧\n\n")
        f.write("製造者の主張と通信を突き合わせる（D31）ための一覧。元の表は [devices.tsv](devices.tsv)（手で作成）、"
                "観測の期間は `scripts/claims/build_catalog.py` が Quarant の解析結果（`device_inventory.json`）から付ける。\n\n")
        f.write("機器の特定の仕方：UNSW 2016 は `List_Of_Devices.txt`、UNSW-IoTraffic はファイル名、YourThings は "
                "`device_mapping.csv`（IP の対応）、Deakin は `macAddresses.csv`。UNSW 2018 には機器の一覧がないので、"
                "MAC アドレスを UNSW 2016 と UNSW-IoTraffic の一覧と照らした（どちらにもない 3 台と、名乗りだけで分かった 2 台は note に書いた）。"
                "CIC IoT 2022 は、機器ごとに 1 台ずつ電源を入れた Power の 3 回のキャプチャすべてに現れ、他の機器のキャプチャにはほぼ現れない MAC アドレスを、その機器とした。"
                "IoT-23 は正常な 3 シナリオだけを載せた（感染させた機器は主に Raspberry Pi で、製造者の主張がない）。"
                "スマートフォン、PC、ゲートウェイ、ゲーム機は載せていない。\n\n"
                "限界：YourThings で解析したのは 2018-04-10〜12 だけ。型番が空の製品は、主張を集めるときに製品のページから型番を絞る必要がある。\n\n")
        f.write("## データセットごとの台数\n\n| データセット | 一覧の行 | 解析結果で見えた | 製品が分からない |\n|---|---|---|---|\n")
        for ds in order:
            rs = [r for r in rows if r["dataset"] == ds]
            f.write(f"| {RUNS[ds][0]} | {len(rs)} | {sum(1 for r in rs if r['runs_seen'])} | "
                    f"{sum(1 for r in rs if r['category'] == 'unknown' or r['vendor'] == 'unknown')} |\n")
        multi = [p for p in products.values() if len(p["datasets"]) >= 2]
        f.write(f"\n製品（製造者 × 製品名 × 型番）：{len(products)} 件。そのうち解析結果で見えたもの："
                f"{sum(1 for p in products.values() if p['datasets'])} 件、2 つ以上のデータセットで見えたもの：{len(multi)} 件。\n\n")
        f.write("## 製品の一覧\n\n期間は解析結果で機器が見えた日（キャプチャ時刻。2000 年より前の時刻は、機器の時計が戻ったものとして除く）。型番は、データセットのラベルか機器の名乗りで分かったものだけ書く（根拠は devices.tsv の model_basis）。\n\n")
        f.write("| 製造者 | 製品 | 型番 | 種類 | " + " | ".join(RUNS[d][0] for d in order) + " |\n")
        f.write("|---|---|---|---|" + "---|" * len(order) + "\n")
        for p in products.values():
            cells = []
            for d in order:
                v = p["datasets"].get(d)
                cells.append(f"{v[0]}〜{v[1]}" + (f"（{v[2]} 台）" if v[2] > 1 else "") if v else "")
            f.write(f"| {p['vendor']} | {p['product']} | {', '.join(sorted(p['models']))} | {p['category']} | " + " | ".join(cells) + " |\n")
        unk = [r for r in rows if r["category"] == "unknown" or r["vendor"] == "unknown"]
        f.write("\n## 製品が分からない機器（主張を集められない）\n\n")
        for r in unk:
            f.write(f"- {RUNS[r['dataset']][0]}：{r['label']}（{r['note']}）\n")
        miss = [r for r in rows if not r["runs_seen"] and r not in unk]
        f.write("\n## 一覧にはあるが、解析結果では見えなかった機器\n\n")
        for r in miss:
            f.write(f"- {RUNS[r['dataset']][0]}：{r['label']}" + (f"（{r['note']}）" if r["note"] else "") + "\n")


if __name__ == "__main__":
    main()
