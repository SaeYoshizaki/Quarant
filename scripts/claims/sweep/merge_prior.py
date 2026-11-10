#!/usr/bin/env python3
"""Join the prior-work checks with the candidates and print the Markdown table for sweep-results.md.

usage: merge_prior.py <candidates.tsv> <out prior-ids.tsv> <result.tsv>...

The result files are the prior-work checks per group (columns vendor, product, kind, class,
sources, what_source_says, difference, queries, notes). Rows are matched on vendor, product, kind.
"""
import csv
import re
import sys

KIND = {"id-plain": "識別子（平文の HTTP）", "id-other": "MAC（HTTP 以外）", "cred-plain": "認証情報らしい値（平文）",
        "fw-http": "HTTP でのファームウェア取得"}
CLASS = {"NG-top": "除く（トップ会議）", "PAPER-PARTIAL": "論文で一部", "BLOG": "ブログ等のみ", "NONE-FOUND": "見つからず"}
ORDER = {"NONE-FOUND": 0, "BLOG": 1, "PAPER-PARTIAL": 2, "NG-top": 3}


def rows(p):
    return list(csv.DictReader(open(p), delimiter="\t", quoting=csv.QUOTE_NONE))


def short_source(s):
    s = re.sub(r"^\(\d\)\s*", "", s or "").strip()
    if not s or s in ("-", "none found"):
        return "―"
    title = s.split(";")[0].strip(" '\"")[:70]
    year = re.search(r"\b(19|20)\d{2}\b", s)
    return f"{title}（{year.group(0)}）" if year else title


def main():
    cand_p, out_p, *results = sys.argv[1:]
    cand = {(r["vendor"], r["product"], r["kind"]): r for r in rows(cand_p)}
    merged = []
    for p in results:
        for r in rows(p):
            c = cand[(r["vendor"], r["product"], r["kind"])]
            merged.append({**r, "datasets": c["datasets"], "count": c["count"], "detail": c["detail"], "evidence": c["evidence"]})
    cols = ["vendor", "product", "kind", "datasets", "count", "detail", "evidence", "class", "sources", "what_source_says",
            "difference", "notes"]
    with open(out_p, "w") as o:
        o.write("\t".join(cols) + "\n")
        for r in merged:
            o.write("\t".join(str(r.get(k, "")).replace("\t", " ").replace("\n", " ") for k in cols) + "\n")
    print("| 製品 | 種類 | データ | 回数 | 平文で送っていたもの（項目 → 宛先） | 最初の根拠 | 先行研究 | 区分 |")
    print("|---|---|---|---|---|---|---|---|")
    for r in sorted(merged, key=lambda r: (ORDER[r["class"]], r["vendor"], r["product"], r["kind"])):
        product = " ".join(dict.fromkeys(f'{r["vendor"]} {r["product"]}'.split()))
        detail = "; ".join(re.sub(r" \(\d+\)$", "", x) for x in r["detail"].split("; ")[:2]).replace("|", "/")
        ev = r["evidence"].split("; ")[0].replace("#", " フレーム ")
        src = "―" if r["class"] == "NONE-FOUND" else short_source(r["sources"]).replace("|", "/")
        print(f'| {product} | {KIND[r["kind"]]} | {r["datasets"]} | {r["count"]} | {detail} | {ev} | {src} | {CLASS[r["class"]]} |')


if __name__ == "__main__":
    main()
