#!/usr/bin/env python3
"""Build the final ETSI TS 103 701 passive-assessability labels from two
independent annotation passes and the adjudication of Model N disagreements.

- Model N (network observer): agreed labels, else the adjudicated verdict_reach.
- Model ND (network + manufacturer documents): reported as the range between
  the two annotators (not adjudicated).

usage: finalize.py PASS1_DIR PASS2_DIR ADJUDICATION_JSON OUT_DIR
"""
import collections
import json
import os
import sys

REACH = ["pass_and_fail", "fail_only", "pass_only", "none"]
JA = {"pass_and_fail": "合否とも", "fail_only": "不合格のみ", "pass_only": "合格のみ", "none": "判定できない"}
RANK = {"none": 0, "pass_only": 1, "fail_only": 1, "pass_and_fail": 2}


def load(d):
    out = {}
    for p in ("part-A.json", "part-B.json", "part-C.json"):
        for c in json.load(open(os.path.join(d, p))):
            out[c["test_case"]] = c
    return out


def main():
    p1, p2 = load(sys.argv[1]), load(sys.argv[2])
    adj = {d["test_case"]: d for d in json.load(open(sys.argv[3]))["decisions"]}
    out_dir = sys.argv[4]
    final = []
    for k, c1 in p1.items():
        c2 = p2[k]
        n1, n2 = c1["N"]["verdict_reach"], c2["N"]["verdict_reach"]
        if n1 == n2:
            n, src = n1, "agreed"
        elif k in adj:
            n, src = adj[k]["verdict_reach"], f"adjudicated ({adj[k]['principle']})"
        else:
            sys.exit(f"{k}: Model N disagreement without adjudication")
        nd1, nd2 = c1["ND"]["verdict_reach"], c2["ND"]["verdict_reach"]
        if RANK[nd1] < RANK[n] and RANK[nd2] < RANK[n]:
            nd1 = nd2 = n  # ND is never weaker than N
        final.append({"test_case": k, "test_group": c1["test_group"], "type": c1["type"],
                      "summary": c1["summary"], "N": n, "N_source": src,
                      "ND_pass1": nd1, "ND_pass2": nd2,
                      "outside_procedure_cues": c1.get("outside_procedure_cues") or c2.get("outside_procedure_cues") or ""})
    groups = collections.OrderedDict()
    for f in final:
        groups.setdefault(f["test_group"], []).append(f)
    best = lambda vals: max(vals, key=lambda v: (RANK[v], v == "fail_only"))
    rows = []
    for g, cs in groups.items():
        rows.append({"test_group": g, "N": best([c["N"] for c in cs]),
                     "ND_min": min(best([c["ND_pass1"] for c in cs]), best([c["ND_pass2"] for c in cs]), key=lambda v: RANK[v]),
                     "ND_max": max(best([c["ND_pass1"] for c in cs]), best([c["ND_pass2"] for c in cs]), key=lambda v: RANK[v]),
                     "cues": any(c["outside_procedure_cues"] for c in cs)})
    json.dump({"test_cases": final, "test_groups": rows}, open(os.path.join(out_dir, "ts103701-final.json"), "w"),
              ensure_ascii=False, indent=1)
    gN = collections.Counter(r["N"] for r in rows)
    tN = collections.Counter(f["N"] for f in final)
    nd_reach_min = sum(1 for r in rows if r["ND_min"] != "none")
    nd_reach_max = sum(1 for r in rows if r["ND_max"] != "none")
    cue_only = sum(1 for r in rows if r["N"] == "none" and r["cues"])
    L = ["# ETSI TS 103 701：パッシブな観測者による判定可能性（最終版）", "",
         "2 回の独立した分類と、モデル N の食い違いの裁定（[adjudication.json](adjudication.json)）から生成。一致率は [agreement.md](agreement.md)。", "",
         f"- 要件（試験グループ）: {len(rows)}、試験ケース: {len(final)}", "",
         "## モデル N（通信の観測者）", "", "| 判定の向き | 要件数 | 試験ケース数 |", "|---|---|---|"]
    for r in REACH:
        L.append(f"| {JA[r]} | {gN[r]} | {tN[r]} |")
    L += ["", f"- 判定できない要件のうち、手順外の手がかりは観測できるもの: {cue_only}",
          "", "## モデル ND（通信＋製造者の公開文書）", "",
          f"- 何らかの判定に到達できる要件: {nd_reach_min}〜{nd_reach_max}（2 人の分類の幅。裁定していない）",
          "", "## 要件ごと", "", "| 要件 | N | ND（幅） | 手順外の手がかり |", "|---|---|---|---|"]
    for r in rows:
        nd = JA[r["ND_min"]] if r["ND_min"] == r["ND_max"] else f"{JA[r['ND_min']]}〜{JA[r['ND_max']]}"
        L.append(f"| {r['test_group']} | {JA[r['N']]} | {nd} | {'あり' if r['cues'] else ''} |")
    open(os.path.join(out_dir, "ts103701-final.md"), "w").write("\n".join(L) + "\n")
    print(f"groups={len(rows)} N={dict(gN)} ND_reachable={nd_reach_min}-{nd_reach_max} cue_only={cue_only}")


if __name__ == "__main__":
    main()
