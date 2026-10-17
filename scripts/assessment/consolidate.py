#!/usr/bin/env python3
"""Merge per-range classifications of ETSI TS 103 701 test cases into one
dataset and a Markdown summary.

Inputs are JSON arrays produced with docs/assessment/RUBRIC.md. The standard's
text itself is not stored in the repository (copyright); only clause IDs and
paraphrased summaries are.

usage: consolidate.py OUT_DIR part-A.json part-B.json part-C.json
"""
import collections
import json
import re
import sys

ORDER = {"observed": 3, "inferred": 2, "reference": 1, "not_assessable": 0}
REACH = {"pass_and_fail": 3, "fail_only": 2, "pass_only": 1, "none": 0}
REACH_JA = {"pass_and_fail": "合否とも", "fail_only": "不合格のみ", "pass_only": "合格のみ", "none": "判定できない"}


def derive(c):
    """passive_class as defined by rubric v2 (mechanical)."""
    if c["verdict_reach"] == "none":
        return "not_assessable"
    if c.get("assumptions"):
        return "inferred"
    if c.get("uses_reference"):
        return "reference"
    return "observed"
JA = {"observed": "観測", "inferred": "推定", "reference": "照合", "not_assessable": "判定不能"}


def key(tc):
    # IDs such as "5.1-2A-1": compare numbers numerically and letters after them.
    return [(0, int(t), "") if t.isdigit() else (1, 0, t) for t in re.findall(r"\d+|[A-Za-z]+", tc)]


def main():
    out_dir, parts = sys.argv[1], sys.argv[2:]
    cases = []
    for p in parts:
        with open(p) as f:
            cases.extend(json.load(f))
    cases.sort(key=lambda c: key(c["test_case"]))
    ids = [c["test_case"] for c in cases]
    dupes = [i for i, n in collections.Counter(ids).items() if n > 1]
    if dupes:
        sys.exit(f"duplicate test cases: {dupes}")
    for c in cases:
        if c.get("verdict_reach") not in REACH:
            sys.exit(f"missing/bad verdict_reach in {c['test_case']}")
        if c["passive_class"] != derive(c):
            sys.exit(f"{c['test_case']}: passive_class {c['passive_class']} != derived {derive(c)}")

    groups = collections.OrderedDict()
    for c in cases:
        groups.setdefault(c["test_group"], []).append(c)
    group_rows = []
    for g, cs in groups.items():
        best = max(cs, key=lambda c: ORDER[c["passive_class"]])["passive_class"]
        reach = max(cs, key=lambda c: REACH[c["verdict_reach"]])["verdict_reach"]
        cues = [c["outside_procedure_cues"] for c in cs if c.get("outside_procedure_cues")]
        group_rows.append({
            "test_group": g,
            "provision": cs[0]["provision"],
            "passive_class": best,
            "verdict_reach": reach,
            "conditional": cs[0].get("conditional"),
            "condition_passive": cs[0].get("condition_passive"),
            "opportunistic": any(c.get("opportunistic") for c in cs),
            "outside_procedure_cues": cues,
            "test_cases": [c["test_case"] for c in cs],
            "has_conceptual": any(c["type"] == "conceptual" for c in cs),
            "quarant_capabilities": sorted({q for c in cs for q in c.get("quarant_capabilities") or []}),
        })

    with open(f"{out_dir}/ts103701-passive.json", "w") as f:
        json.dump({"standard": "ETSI TS 103 701 V2.1.1 (2025-05) / ETSI EN 303 645 V3.1.3",
                   "rubric": "docs/assessment/RUBRIC.md",
                   "test_cases": cases, "test_groups": group_rows}, f, ensure_ascii=False, indent=1)

    tc_counts = collections.Counter(c["passive_class"] for c in cases)
    tc_by_type = collections.Counter((c["type"], c["passive_class"]) for c in cases)
    g_counts = collections.Counter(g["passive_class"] for g in group_rows)
    g_reach = collections.Counter(g["verdict_reach"] for g in group_rows)
    tc_reach = collections.Counter(c["verdict_reach"] for c in cases)
    cue_groups = [g for g in group_rows if g["verdict_reach"] == "none" and g["outside_procedure_cues"]]
    tso = collections.defaultdict(collections.Counter)
    for g in group_rows:
        tso[g["test_group"].split("-")[0]][g["passive_class"]] += 1

    lines = ["# ETSI TS 103 701 試験ケースのパッシブ評価可能性", "",
             "自動生成（`scripts/assessment/consolidate.py`）。分類基準は [RUBRIC.md](RUBRIC.md)。規格の本文はリポジトリに含めず、条項番号と要約（言い換え）だけを置く。", "",
             f"- 試験グループ（要件）: {len(group_rows)}、試験ケース: {len(cases)}", "",
             "## 要件（試験グループ）単位", "",
             "| 区分 | 件数 |", "|---|---|"]
    for k in ORDER:
        lines.append(f"| {JA[k]}（{k}） | {g_counts[k]} |")
    lines += ["", "| 判定の向き | 要件数 | 試験ケース数 |", "|---|---|---|"]
    for k in REACH:
        lines.append(f"| {REACH_JA[k]}（{k}） | {g_reach[k]} | {tc_reach[k]} |")
    lines += ["", f"- 規格の手順では判定できないが、パッシブな手がかりは観測できる要件: {len(cue_groups)}",
              f"- 偶発的な出来事（障害、更新の配信など）に頼る要件: {sum(1 for g in group_rows if g['opportunistic'])}"]
    lines += ["", "## 試験ケース単位", "", "| 区分 | conceptual | functional | 合計 |", "|---|---|---|---|"]
    for k in ORDER:
        lines.append(f"| {JA[k]} | {tc_by_type[('conceptual', k)]} | {tc_by_type[('functional', k)]} | {tc_counts[k]} |")
    lines += ["", "## TSO（カテゴリ）別の要件数", "", "| TSO | 観測 | 推定 | 照合 | 判定不能 |", "|---|---|---|---|---|"]
    for t in sorted(tso, key=key):
        c = tso[t]
        lines.append(f"| {t} | {c['observed']} | {c['inferred']} | {c['reference']} | {c['not_assessable']} |")
    lines += ["", "## 要件ごとの一覧", "", "| 試験グループ | 区分 | 判定の向き | 手順外の手がかり | Quarant の対応機能 |", "|---|---|---|---|---|"]
    for g in group_rows:
        cue = "あり" if g["outside_procedure_cues"] else ""
        lines.append(f"| {g['test_group']} | {JA[g['passive_class']]} | {REACH_JA[g['verdict_reach']]} | {cue} | {', '.join(g['quarant_capabilities'])} |")
    with open(f"{out_dir}/ts103701-passive.md", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"groups={len(group_rows)} cases={len(cases)} group_classes={dict(g_counts)}")


if __name__ == "__main__":
    main()
