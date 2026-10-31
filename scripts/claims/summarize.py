#!/usr/bin/env python3
"""Summarise claims.tsv per product and per claim.

Usage: summarize.py <claims.tsv> <dataset>

Prints Markdown tables: claims by judgment and wording, and one line per
product with its strongest judgment (contradiction candidate first).
"""
import collections
import csv
import sys

ORDER = ["contradiction candidate (T1a)", "contradiction candidate (T2)", "contradiction candidate (T3)",
         "contradiction candidate (T4)", "contradiction candidate (T5)", "wording-only contradiction",
         "consistent (as observed)", "not visible", "not assessable"]
JA = {"contradiction candidate": "食い違いの候補", "wording-only contradiction": "文言の上で食い違い",
      "consistent (as observed)": "一致（見えた範囲で）", "not visible": "見えない", "not assessable": "判定できない"}


def ja(j):
    for k, v in JA.items():
        if j.startswith(k):
            return v + j[len(k):]
    return j


def main():
    rows = [r for r in csv.DictReader(open(sys.argv[1]), delimiter="\t") if r["dataset"] == sys.argv[2]]
    real = [r for r in rows if not r["quote"].startswith("(")]
    print(f"主張 {len(real)} 件（ほかに「主張なし」の文書 {len(rows) - len(real)} 件）、製品 {len({r['product'] for r in rows})} 件。\n")
    print("| 判定 | 主張 | うち具体的 | うち曖昧 |\n|---|---|---|---|")
    c = collections.Counter(r["judgment"] for r in real)
    for j in ORDER:
        if c[j]:
            sp = sum(1 for r in real if r["judgment"] == j and r["specificity"] == "specific")
            va = sum(1 for r in real if r["judgment"] == j and r["specificity"] == "vague")
            print(f"| {ja(j)} | {c[j]} | {sp} | {va} |")
    print("\n| 書き方 | 主張 |\n|---|---|")
    for k, n in collections.Counter(r["specificity"] for r in real).most_common():
        print(f"| {k} | {n} |")

    by = collections.defaultdict(list)
    for r in rows:
        by[r["product"]].append(r)
    best = {p: min((ORDER.index(r["judgment"]) for r in rs if r["judgment"] in ORDER), default=len(ORDER) - 1)
            for p, rs in by.items()}
    print("\n| 製品ごとのいちばん強い判定 | 製品 |\n|---|---|")
    groups = collections.defaultdict(list)
    for p, i in best.items():
        groups[ORDER[i].split(" (T")[0]].append(p)
    for j in ["contradiction candidate", "wording-only contradiction", "consistent (as observed)", "not visible", "not assessable"]:
        if groups[j]:
            print(f"| {ja(j)}（{len(groups[j])}） | {', '.join(sorted(groups[j]))} |")


if __name__ == "__main__":
    main()
