# Corpus bench results

These numbers are pre-validator heuristic runs. They are not Faultline product results.
Faultline ran with no provider, so the model column is `none, heuristic`.
The findings stage runs the heuristic validator and still calls no model.
Semgrep is the free static baseline. Its stage is `scan` because it has no candidate validator.
Precision and recall use the same site-level matrix as `faultline bench`: class, path, and line overlap.
Unmatched detections are not false positives. A rate is `n/a` when its denominator is zero.
The score is TPR minus FPR.

Held-out apps are a separate fetch group (`--group heldout`). Their labels are under `bench/heldout` and their scores are under `bench/results/heldout`.
Held-out labels must not drive heuristic changes. A miss on that set is not a reason to edit a hunter, a validator, or recon.

Raw scanner output is not committed. It can quote corpus source.

| corpus          | tool      | version | model           | stage                      | commit       | class      | TP  | FP  | FN  | TN  | precision | recall | score  |
| --------------- | --------- | ------- | --------------- | -------------------------- | ------------ | ---------- | --- | --- | --- | --- | --------- | ------ | ------ |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | authz_idor | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | injection  | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000  |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | secrets    | 2   | 0   | 1   | 1   | 1.000     | 0.667  | 0.667  |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | overall    | 2   | 0   | 4   | 2   | 1.000     | 0.333  | 0.333  |
| pixi            | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | authz_idor | 1   | 0   | 3   | 2   | 1.000     | 0.250  | 0.250  |
| pixi            | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | injection  | 1   | 0   | 2   | 1   | 1.000     | 0.333  | 0.333  |
| pixi            | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | secrets    | 1   | 0   | 4   | 0   | 1.000     | 0.200  | n/a    |
| pixi            | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| pixi            | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | overall    | 3   | 0   | 9   | 3   | 1.000     | 0.250  | 0.250  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | authz_idor | 0   | 0   | 2   | 2   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | injection  | 1   | 1   | 5   | 1   | 0.500     | 0.167  | -0.333 |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | secrets    | 0   | 0   | 4   | 1   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | ssrf       | 1   | 0   | 0   | 1   | 1.000     | 1.000  | 1.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | candidates                 | e47192429e20 | overall    | 2   | 1   | 11  | 5   | 0.667     | 0.154  | -0.013 |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | authz_idor | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | injection  | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000  |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | secrets    | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000  |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | overall    | 0   | 0   | 6   | 2   | n/a       | 0.000  | 0.000  |
| pixi            | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | authz_idor | 0   | 0   | 4   | 2   | n/a       | 0.000  | 0.000  |
| pixi            | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | injection  | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000  |
| pixi            | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | secrets    | 0   | 0   | 5   | 0   | n/a       | 0.000  | n/a    |
| pixi            | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| pixi            | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | overall    | 0   | 0   | 12  | 3   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | authz_idor | 0   | 0   | 2   | 2   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | injection  | 0   | 0   | 6   | 2   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | secrets    | 0   | 0   | 4   | 1   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | ssrf       | 0   | 0   | 1   | 1   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings                   | e47192429e20 | overall    | 0   | 0   | 13  | 6   | n/a       | 0.000  | 0.000  |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | authz_idor | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | injection  | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000  |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | secrets    | 2   | 0   | 1   | 1   | 1.000     | 0.667  | 0.667  |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| nodejs-goof     | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | overall    | 2   | 0   | 4   | 2   | 1.000     | 0.333  | 0.333  |
| pixi            | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | authz_idor | 0   | 0   | 4   | 2   | n/a       | 0.000  | 0.000  |
| pixi            | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | injection  | 1   | 0   | 2   | 1   | 1.000     | 0.333  | 0.333  |
| pixi            | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | secrets    | 1   | 0   | 4   | 0   | 1.000     | 0.200  | n/a    |
| pixi            | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| pixi            | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | overall    | 2   | 0   | 10  | 3   | 1.000     | 0.167  | 0.167  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | authz_idor | 0   | 0   | 2   | 2   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | injection  | 1   | 0   | 5   | 2   | 1.000     | 0.167  | 0.167  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | secrets    | 0   | 0   | 4   | 1   | n/a       | 0.000  | 0.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | ssrf       | 1   | 0   | 0   | 1   | 1.000     | 1.000  | 1.000  |
| vulnerable-node | faultline | 0.0.0   | none, heuristic | findings-keep-inconclusive | e47192429e20 | overall    | 2   | 0   | 11  | 6   | 1.000     | 0.154  | 0.154  |
| nodejs-goof     | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | authz_idor | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| nodejs-goof     | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | injection  | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000  |
| nodejs-goof     | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | secrets    | 1   | 0   | 2   | 1   | 1.000     | 0.333  | 0.333  |
| nodejs-goof     | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| nodejs-goof     | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | overall    | 1   | 0   | 5   | 2   | 1.000     | 0.167  | 0.167  |
| pixi            | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | authz_idor | 0   | 0   | 4   | 2   | n/a       | 0.000  | 0.000  |
| pixi            | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | injection  | 0   | 0   | 3   | 1   | n/a       | 0.000  | 0.000  |
| pixi            | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | secrets    | 0   | 0   | 5   | 0   | n/a       | 0.000  | n/a    |
| pixi            | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | ssrf       | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a    |
| pixi            | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | overall    | 0   | 0   | 12  | 3   | n/a       | 0.000  | 0.000  |
| vulnerable-node | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | authz_idor | 0   | 0   | 2   | 2   | n/a       | 0.000  | 0.000  |
| vulnerable-node | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | injection  | 1   | 0   | 5   | 2   | 1.000     | 0.167  | 0.167  |
| vulnerable-node | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | secrets    | 0   | 0   | 4   | 1   | n/a       | 0.000  | 0.000  |
| vulnerable-node | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | ssrf       | 0   | 0   | 1   | 1   | n/a       | 0.000  | 0.000  |
| vulnerable-node | semgrep   | 1.183.0 | none, heuristic | scan                       | e47192429e20 | overall    | 1   | 0   | 12  | 6   | 1.000     | 0.077  | 0.077  |

## Runs

Commit prefixes in the table match these files.

- `2026-11-01-e47192429e209ea44a7d0e8787a7050d86183b41-faultline-candidates.json` — faultline 0.0.0, stage candidates, commit `e47192429e209ea44a7d0e8787a7050d86183b41`. Inventory truncated for pixi at Faultline's file and byte caps.
- `2026-11-01-e47192429e209ea44a7d0e8787a7050d86183b41-faultline-findings.json` — faultline 0.0.0, stage findings, commit `e47192429e209ea44a7d0e8787a7050d86183b41`. Inventory truncated for pixi at Faultline's file and byte caps.
- `2026-11-01-e47192429e209ea44a7d0e8787a7050d86183b41-faultline-findings-keep-inconclusive.json` — faultline 0.0.0, stage findings-keep-inconclusive, commit `e47192429e209ea44a7d0e8787a7050d86183b41`. Inventory truncated for pixi at Faultline's file and byte caps.
- `2026-11-01-e47192429e209ea44a7d0e8787a7050d86183b41-semgrep-scan.json` — semgrep 1.183.0, stage scan, commit `e47192429e209ea44a7d0e8787a7050d86183b41`. Rulesets: p/javascript, p/typescript, p/nodejsscan, p/secrets.
