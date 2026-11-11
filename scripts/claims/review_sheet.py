#!/usr/bin/env python3
"""Write the owner's check sheet: one row per discrepancy candidate of the non-YourThings datasets.

usage: review_sheet.py <claims.tsv> <out.md>
"""
import csv
import sys


def main():
    claims, out = sys.argv[1:3]
    rows = [r for r in csv.DictReader(open(claims), delimiter="\t")
            if r["dataset"] != "yourthings" and "contradiction" in r["judgment"]]
    rows.sort(key=lambda r: (r["catalog_product"], r["snapshot"]))
    lines = ["# 人が確かめる表：公式文書と通信の食い違いの候補", "",
             "[compare-sweep.md](compare-sweep.md) の候補を、1 行ずつ確かめるための表（`scripts/claims/review_sheet.py` で作る）。"
             "引用は [claims.tsv](claims.tsv) の quote（保存した本文と照合済み）、URL は Wayback の版。観測の根拠は PCAP のファイルとフレーム。"
             "「確認」の列に結果を書く（正しい／直す／外す と理由）。", "",
             "| # | 製品（データ） | 判定 | 引用（文書、版の日付、収録との関係） | 観測（根拠） | 注意 | 確認 |",
             "|---|---|---|---|---|---|---|"]
    cell = lambda s: s.replace("|", "/")
    for i, r in enumerate(rows, 1):
        quote = f"「{cell(r['quote'])}」（{r['doc']}、[{r['snapshot']}]({r['url']})、{r['timing']}）"
        lines.append(f"| {i} | {r['catalog_product']}（{r['dataset']}） | {r['judgment']} | {quote} | {cell(r['evidence'])} | {cell(r['note'])} | |")
    lines += ["", "- 判定の言葉：contradiction candidate（食い違いの候補）、wording-level contradiction（中身のない平文だけ）。T の番号は [method.md](method.md) の型。",
              "- 先行研究は [sweep/prior-claims.tsv](sweep/prior-claims.tsv)。"]
    open(out, "w").write("\n".join(lines) + "\n")
    print(len(rows), "rows")


if __name__ == "__main__":
    main()
