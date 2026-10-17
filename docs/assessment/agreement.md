# 分類の一致率（1 回目と、独立に行った 2 回目）

- 共通の試験ケース: 131（1 回目だけ: 0、2 回目だけ: 0）

# モデル N（通信の観測者）

## passive_class

- 一致率: 0.847、Cohen の κ: 0.515

| 1回目 \ 2回目 | observed | inferred | reference | not_assessable |
|---|---|---|---|---|
| observed | 0 | 0 | 0 | 0 |
| inferred | 0 | 15 | 0 | 3 |
| reference | 0 | 0 | 0 | 0 |
| not_assessable | 0 | 17 | 0 | 96 |

## verdict_reach

- 一致率: 0.847、Cohen の κ: 0.523

| 1回目 \ 2回目 | pass_and_fail | fail_only | pass_only | none |
|---|---|---|---|---|
| pass_and_fail | 0 | 0 | 0 | 0 |
| fail_only | 0 | 14 | 0 | 3 |
| pass_only | 0 | 0 | 1 | 0 |
| none | 0 | 14 | 3 | 96 |

## 判定に到達できるか（2 値）

- 一致率: 0.847、Cohen の κ: 0.515

## 食い違い（20 件）

| 試験ケース | 1回目 | 2回目 |
|---|---|---|
| 5.1-1-1 | not_assessable/none | inferred/fail_only |
| 5.1-5-1 | not_assessable/none | inferred/fail_only |
| 5.2-2-1 | not_assessable/none | inferred/fail_only |
| 5.3-1-2 | inferred/fail_only | not_assessable/none |
| 5.3-2-2 | inferred/fail_only | not_assessable/none |
| 5.3-3-1 | not_assessable/none | inferred/pass_only |
| 5.3-4A-1 | not_assessable/none | inferred/pass_only |
| 5.3-5-1 | not_assessable/none | inferred/pass_only |
| 5.3-8-1 | not_assessable/none | inferred/fail_only |
| 5.4-3-1 | not_assessable/none | inferred/fail_only |
| 5.4-4-1 | not_assessable/none | inferred/fail_only |
| 5.5-4-1 | not_assessable/none | inferred/fail_only |
| 5.5-5-1 | not_assessable/none | inferred/fail_only |
| 5.6-2-1 | not_assessable/none | inferred/fail_only |
| 5.9-3-1 | not_assessable/none | inferred/fail_only |
| 5.11-1-2 | not_assessable/none | inferred/fail_only |
| 5.12-1-1 | not_assessable/none | inferred/fail_only |
| 5.13-1B-2 | not_assessable/none | inferred/fail_only |
| 6-2-1 | not_assessable/none | inferred/fail_only |
| 6-6-2 | inferred/fail_only | not_assessable/none |

# モデル ND（通信＋公開文書）

## passive_class

- 一致率: 0.824、Cohen の κ: 0.644

| 1回目 \ 2回目 | observed | inferred | reference | not_assessable |
|---|---|---|---|---|
| observed | 0 | 0 | 0 | 0 |
| inferred | 0 | 42 | 0 | 2 |
| reference | 0 | 0 | 0 | 0 |
| not_assessable | 0 | 21 | 0 | 66 |

## verdict_reach

- 一致率: 0.794、Cohen の κ: 0.639

| 1回目 \ 2回目 | pass_and_fail | fail_only | pass_only | none |
|---|---|---|---|---|
| pass_and_fail | 5 | 0 | 0 | 0 |
| fail_only | 1 | 24 | 2 | 2 |
| pass_only | 0 | 1 | 9 | 0 |
| none | 0 | 20 | 1 | 66 |

## 判定に到達できるか（2 値）

- 一致率: 0.824、Cohen の κ: 0.644

## 食い違い（27 件）

| 試験ケース | 1回目 | 2回目 |
|---|---|---|
| 5.1-1-1 | not_assessable/none | inferred/fail_only |
| 5.1-4-1 | inferred/pass_only | inferred/fail_only |
| 5.1-5-1 | not_assessable/none | inferred/fail_only |
| 5.2-2-1 | not_assessable/none | inferred/fail_only |
| 5.3-1-2 | inferred/fail_only | not_assessable/none |
| 5.3-2-2 | inferred/fail_only | not_assessable/none |
| 5.3-4B-1 | not_assessable/none | inferred/pass_only |
| 5.3-8-1 | not_assessable/none | inferred/fail_only |
| 5.3-13-2 | inferred/fail_only | inferred/pass_only |
| 5.3-14-2 | inferred/fail_only | inferred/pass_only |
| 5.4-3-1 | not_assessable/none | inferred/fail_only |
| 5.4-4-1 | not_assessable/none | inferred/fail_only |
| 5.6-1-1 | not_assessable/none | inferred/fail_only |
| 5.6-2-1 | not_assessable/none | inferred/fail_only |
| 5.6-5-1 | not_assessable/none | inferred/fail_only |
| 5.8-3-1 | inferred/fail_only | inferred/pass_and_fail |
| 5.9-3-1 | not_assessable/none | inferred/fail_only |
| 5.11-1-1 | not_assessable/none | inferred/fail_only |
| 5.11-1-2 | not_assessable/none | inferred/fail_only |
| 5.11-2-1 | not_assessable/none | inferred/fail_only |
| 5.11-3-1 | not_assessable/none | inferred/fail_only |
| 5.12-1-1 | not_assessable/none | inferred/fail_only |
| 5.12-2-1 | not_assessable/none | inferred/fail_only |
| 5.12-3-1 | not_assessable/none | inferred/fail_only |
| 5.13-1B-2 | not_assessable/none | inferred/fail_only |
| 6-2-1 | not_assessable/none | inferred/fail_only |
| 6-3A-1 | not_assessable/none | inferred/fail_only |
