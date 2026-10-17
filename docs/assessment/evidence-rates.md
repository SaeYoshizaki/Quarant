# E4：違反の証拠が実際の通信に現れる率

`scripts/assessment/evidence_rates.py` で生成。値は「証拠が 1 回以上現れた機器数 / 通信が観測された機器数」。機器は MAC で数える（同じデータセットの複数日に現れても 1 台）。
状態 candidate_only の行は候補の数（上限）であり、違反の確定ではない。

| 要件 | 状態 | UNSW traces 2016 | UNSW attacks 2018 | IoT-23 2018-19 | Laptop 2026 (not IoT) |
|---|---|---|---|---|---|
| （通信が観測された機器） | | 25 | 32 | 18 | 1 |
| 5.1-1 | candidate_only | 2 (8%) | 1 (3%) | 0 (0%) | 0 (0%) |
| 5.1-2 | candidate_only | 2 (8%) | 1 (3%) | 0 (0%) | 0 (0%) |
| 5.1-2A | implemented | 1 (4%) | 1 (3%) | 0 (0%) | 0 (0%) |
| 5.1-3 | implemented | 12 (48%) | 13 (41%) | 0 (0%) | 0 (0%) |
| 5.1-5 | not_implemented | — | — | — | — |
| 5.2-2 | not_implemented | — | — | — | — |
| 5.3-4A | candidate_only | 1 (4%) | 3 (9%) | 0 (0%) | 0 (0%) |
| 5.3-7 | candidate_only | 1 (4%) | 1 (3%) | 0 (0%) | 0 (0%) |
| 5.3-8 | not_implemented | — | — | — | — |
| 5.5-1 | implemented | 12 (48%) | 13 (41%) | 0 (0%) | 0 (0%) |
| 5.5-4 | not_implemented | — | — | — | — |
| 5.5-5 | not_implemented | — | — | — | — |
| 5.5-6 | implemented | 4 (16%) | 2 (6%) | 1 (6%) | 0 (0%) |
| 5.5-7 | implemented | 3 (12%) | 2 (6%) | 1 (6%) | 0 (0%) |
| 5.6-2 | candidate_only | 5 (20%) | 10 (31%) | 5 (28%) | 0 (0%) |
| 5.8-1 | implemented | 1 (4%) | 1 (3%) | 0 (0%) | 0 (0%) |
| 5.8-2 | candidate_only | 1 (4%) | 1 (3%) | 0 (0%) | 0 (0%) |
| 5.9-2 | not_implemented | — | — | — | — |
| 5.9-3 | candidate_only | 1 (4%) | 0 (0%) | 3 (17%) | 0 (0%) |
| 5.11-1 | not_implemented | — | — | — | — |
| 5.12-1 | candidate_only | 0 (0%) | 0 (0%) | 0 (0%) | 0 (0%) |
| 5.13-1B | not_implemented | — | — | — | — |
| 6-8 | candidate_only | 1 (4%) | 2 (6%) | 1 (6%) | 0 (0%) |
