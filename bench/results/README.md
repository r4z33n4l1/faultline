# Corpus bench results

These numbers are pre-validator heuristic runs. They are not Faultline product results.
Faultline ran with no provider, so the model column is `none, heuristic`.
Semgrep is the free static baseline. Its stage is `scan` because it has no candidate validator.
Precision and recall use the same site-level matrix as `faultline bench`: class, path, and line overlap.
Unmatched detections are not false positives. A rate is `n/a` when its denominator is zero.
The score is TPR minus FPR.

Raw scanner output is not committed. It can quote corpus source.

| corpus     | tool      | version | model           | stage      | commit       | class      | TP  | FP  | FN  | TN  | precision | recall | score |
| ---------- | --------- | ------- | --------------- | ---------- | ------------ | ---------- | --- | --- | --- | --- | --------- | ------ | ----- |
| dvna       | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | authz_idor | 0   | 0   | 2   | 1   | n/a       | 0.000  | 0.000 |
| dvna       | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | injection  | 2   | 0   | 1   | 1   | 1.000     | 0.667  | 0.667 |
| dvna       | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | secrets    | 0   | 0   | 2   | 1   | n/a       | 0.000  | 0.000 |
| dvna       | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a   |
| dvna       | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | overall    | 2   | 0   | 5   | 3   | 1.000     | 0.286  | 0.286 |
| juice-shop | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | authz_idor | 0   | 0   | 5   | 2   | n/a       | 0.000  | 0.000 |
| juice-shop | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | injection  | 0   | 0   | 6   | 2   | n/a       | 0.000  | 0.000 |
| juice-shop | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | secrets    | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000 |
| juice-shop | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | ssrf       | 0   | 0   | 1   | 1   | n/a       | 0.000  | 0.000 |
| juice-shop | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | overall    | 0   | 0   | 15  | 6   | n/a       | 0.000  | 0.000 |
| nodegoat   | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | authz_idor | 0   | 0   | 2   | 2   | n/a       | 0.000  | 0.000 |
| nodegoat   | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | injection  | 1   | 0   | 1   | 1   | 1.000     | 0.500  | 0.500 |
| nodegoat   | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | secrets    | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000 |
| nodegoat   | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | ssrf       | 0   | 0   | 1   | 0   | n/a       | 0.000  | n/a   |
| nodegoat   | faultline | 0.0.0   | none, heuristic | candidates | 7116755c6e8c | overall    | 1   | 0   | 7   | 4   | 1.000     | 0.125  | 0.125 |
| dvna       | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | authz_idor | 0   | 0   | 2   | 1   | n/a       | 0.000  | 0.000 |
| dvna       | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | injection  | 1   | 0   | 2   | 1   | 1.000     | 0.333  | 0.333 |
| dvna       | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | secrets    | 1   | 0   | 1   | 1   | 1.000     | 0.500  | 0.500 |
| dvna       | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a   |
| dvna       | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | overall    | 2   | 0   | 5   | 3   | 1.000     | 0.286  | 0.286 |
| juice-shop | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | authz_idor | 0   | 0   | 5   | 2   | n/a       | 0.000  | 0.000 |
| juice-shop | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | injection  | 5   | 1   | 1   | 1   | 0.833     | 0.833  | 0.333 |
| juice-shop | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | secrets    | 1   | 0   | 2   | 1   | 1.000     | 0.333  | 0.333 |
| juice-shop | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | ssrf       | 0   | 0   | 1   | 1   | n/a       | 0.000  | 0.000 |
| juice-shop | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | overall    | 6   | 1   | 9   | 5   | 0.857     | 0.400  | 0.233 |
| nodegoat   | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | authz_idor | 0   | 0   | 2   | 2   | n/a       | 0.000  | 0.000 |
| nodegoat   | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | injection  | 1   | 0   | 1   | 1   | 1.000     | 0.500  | 0.500 |
| nodegoat   | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | secrets    | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000 |
| nodegoat   | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | ssrf       | 1   | 0   | 0   | 0   | 1.000     | 1.000  | n/a   |
| nodegoat   | semgrep   | 1.183.0 | none, heuristic | scan       | 7116755c6e8c | overall    | 2   | 0   | 6   | 4   | 1.000     | 0.250  | 0.250 |

## Runs

Commit prefixes in the table match these files.

- `2026-11-01-7116755c6e8cbac52a5e1256375ac9fb4e946ef4-faultline-candidates.json` — faultline 0.0.0, stage candidates, commit `7116755c6e8cbac52a5e1256375ac9fb4e946ef4`. Inventory truncated for juice-shop at Faultline's file and byte caps.
- `2026-11-01-7116755c6e8cbac52a5e1256375ac9fb4e946ef4-semgrep-scan.json` — semgrep 1.183.0, stage scan, commit `7116755c6e8cbac52a5e1256375ac9fb4e946ef4`. Rulesets: p/javascript, p/typescript, p/nodejsscan, p/secrets.
