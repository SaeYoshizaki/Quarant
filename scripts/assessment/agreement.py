#!/usr/bin/env python3
"""Inter-annotator agreement between two independent classifications of the
ETSI TS 103 701 test cases (Cohen's kappa, percent agreement, confusion
matrix, disagreement list).

usage: agreement.py PASS1_DIR PASS2_DIR [OUT_MD]
Each directory holds part-A.json, part-B.json, part-C.json.
"""
import collections
import json
import os
import sys


def load(d):
    out = {}
    for p in ("part-A.json", "part-B.json", "part-C.json"):
        for c in json.load(open(os.path.join(d, p))):
            out[c["test_case"]] = c
    return out


def kappa(pairs):
    n = len(pairs)
    if n == 0:
        return float("nan"), 0.0
    po = sum(a == b for a, b in pairs) / n
    ca = collections.Counter(a for a, _ in pairs)
    cb = collections.Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return ((po - pe) / (1 - pe) if pe < 1 else 1.0), po


def table(pairs, labels):
    m = collections.Counter(pairs)
    rows = ["| 1回目 \\ 2回目 | " + " | ".join(labels) + " |", "|---" * (len(labels) + 1) + "|"]
    for a in labels:
        rows.append(f"| {a} | " + " | ".join(str(m[(a, b)]) for b in labels) + " |")
    return rows


def view(c, model):
    """Fields of one observer model (rubric v3), or the top level (v2)."""
    return c.get(model, c)


def main():
    p1, p2 = load(sys.argv[1]), load(sys.argv[2])
    out_md = sys.argv[3] if len(sys.argv) > 3 else None
    only1, only2 = sorted(set(p1) - set(p2)), sorted(set(p2) - set(p1))
    common = [k for k in p1 if k in p2]
    lines = ["# 分類の一致率（1 回目と、独立に行った 2 回目）", "",
             f"- 共通の試験ケース: {len(common)}（1 回目だけ: {len(only1)}、2 回目だけ: {len(only2)}）"]
    if only1 or only2:
        lines.append(f"- 片方にしかない ID: {only1 + only2}")
    models = ["N", "ND"] if all("N" in p1[k] and "N" in p2[k] for k in common) else ["(v2)"]
    for model in models:
        mname = {"N": "モデル N（通信の観測者）", "ND": "モデル ND（通信＋公開文書）"}.get(model, model)
        lines += ["", f"# {mname}"]
        for field, labels in (("passive_class", ["observed", "inferred", "reference", "not_assessable"]),
                              ("verdict_reach", ["pass_and_fail", "fail_only", "pass_only", "none"])):
            pairs = [(view(p1[k], model)[field], view(p2[k], model)[field]) for k in common]
            k, po = kappa(pairs)
            lines += ["", f"## {field}", "", f"- 一致率: {po:.3f}、Cohen の κ: {k:.3f}", ""] + table(pairs, labels)
        pairs = [(view(p1[k], model)["verdict_reach"] != "none", view(p2[k], model)["verdict_reach"] != "none") for k in common]
        k, po = kappa(pairs)
        lines += ["", "## 判定に到達できるか（2 値）", "", f"- 一致率: {po:.3f}、Cohen の κ: {k:.3f}"]
        dis = [k for k in common if (view(p1[k], model)["passive_class"], view(p1[k], model)["verdict_reach"]) !=
               (view(p2[k], model)["passive_class"], view(p2[k], model)["verdict_reach"])]
        lines += ["", f"## 食い違い（{len(dis)} 件）", "", "| 試験ケース | 1回目 | 2回目 |", "|---|---|---|"]
        for k in dis:
            a, b = view(p1[k], model), view(p2[k], model)
            lines.append(f"| {k} | {a['passive_class']}/{a['verdict_reach']} | {b['passive_class']}/{b['verdict_reach']} |")
    text = "\n".join(lines) + "\n"
    if out_md:
        open(out_md, "w").write(text)
    print(text)


if __name__ == "__main__":
    main()
