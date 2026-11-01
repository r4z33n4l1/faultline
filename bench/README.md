# Faultline bench

`faultline bench` measures a scan against labeled sites. The command is the entry point because it needs the same provider flags, output directory, and exit codes as `scan`. A package script would only wrap that command.

A bench file is one run. It is not a Faultline product result. Cite a number only when that run recorded a provider name, a model id, and a commit sha. `citable` in `bench-result.json` is true only in that case. The commit is `git rev-parse HEAD` in the process working directory, usually the Faultline checkout. Labels are independent of the current heuristic, so a safe site that the pre-pass flags is a false positive.

## Command

```bash
pnpm exec faultline bench bench/seeded-app
pnpm exec faultline bench bench/seeded-app --stage findings --out ./faultline-bench
```

`--stage` defaults to `candidates`. That stage scores `candidates.json` from the scan bench just ran and skips validation. `--stage findings` scores `findings.json` from that same scan and runs the validator. Bench does not promote candidates except through that findings-stage validation.

`--provider` and `--model` are the same flags as `scan`. With no provider, hunters emit the heuristic pre-pass and no model is called. `--provider fake` does not use the network. It also does not emit those heuristic candidates, except filename-only env candidates, which this corpus does not use.

Real model runs are manual. They spend your own API key. Do not set `FAULTLINE_PROVIDER` in CI. The tests call the command with an empty environment or with `FakeProvider`, and they do not open a socket.

The command exits 0 after it writes a score, including a low score. It exits 1 when the target or truth file cannot be read, a label's line range falls outside its file, or the scan fails.

## Corpus

`bench/seeded-app` is Parcel Desk, a small Express TypeScript app. It is scanned as text. Nothing starts it, and it is not one of the hunter fixtures under `test/fixtures`.

`bench/corpus` labels three public training apps: OWASP NodeGoat, DVNA, and OWASP Juice Shop. Their source is not in this repo. `faultline bench --corpus <name>` shallow-fetches the pinned sha into `bench/.cache/` and scores `bench/corpus/<name>/truth.json`. `pnpm bench:fetch` fetches every pin. `--baseline semgrep` scores Semgrep OSS with the same harness. `--sarif` imports a SARIF file and does not run the tool that produced it. The method, the gaps, and the tools that are not run are in [corpus/README.md](corpus/README.md). Committed scores are in [results/README.md](results/README.md).

The truth file has 17 vulnerable sites and 17 look-alike safe sites, across authz/IDOR, injection, secrets, and SSRF. Safe sites include an ownership or tenant check, a parameterized query, an allowlisted column or expression, `execFile`, a hostname allowlist, a host compared to a constant, a fixed base URL with `encodeURIComponent`, a fetch of a constant URL, placeholder secrets, and a documented example access key id assembled at runtime.

There is no exploit payload and no runner. The vulnerable lines are the bugs under test.

### Secrets

These values are synthetic bench strings, not live credentials. Do not replace them with real keys.

| Name                             | Value                    | Label                             |
| -------------------------------- | ------------------------ | --------------------------------- |
| `jwtSigningSecret`               | `q7Nw2mK9p4R8tX1vB6cL3d` | vulnerable, hardcoded             |
| `partnerApiKey`                  | `b7k2m9q4w8r1t6y3p0n5h`  | vulnerable, hardcoded             |
| `sessionToken`                   | `m4Q8z2W6k1N7p3R9t5V0`   | vulnerable, hardcoded, and logged |
| `client_secret` in `config.yaml` | `n8Q2m4K7p1R6tX9vB3cL0w` | vulnerable, cleartext config      |
| `sampleJwtSecret`                | `placeholder-jwt`        | safe placeholder                  |
| `apiKey`                         | `example-api-key`        | safe placeholder                  |
| `password` in `config.yaml`      | `changeme`               | safe placeholder                  |
| `api_key` in `config.yaml`       | `example-api-key`        | safe placeholder                  |

`documentedAccessKeyId` is the public AWS example access key id, joined from the fragments `AKIA`, `IOSFODNN7`, and `EXAMPLE` so the pattern is not one literal. Those fragments are the example published in the [AWS IAM access key documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html). That site is labeled safe: it is the documented example, not a live credential.

## Truth file

`bench/seeded-app/truth.json` is checked with `truthFileSchema` in `src/schema/truth.ts`. The JSON Schema export is `schema/truth.schema.json`, generated with the other schemas.

Each entry has:

- `id`
- `class`: `authz_idor`, `injection`, `secrets`, or `ssrf`
- `cwe`
- `file`, relative to the scanned directory
- `start_line` and `end_line`
- `vulnerable`: `true` or `false`

Ids are unique. `end_line` is at least `start_line`. Bench also checks that the file exists inside the target and that `end_line` is not past the end of the file.

## Matching

A detection matches a label when all of these hold:

- the class is the same
- the path is the same after `\` is treated as `/` and a leading `./` is removed
- the inclusive line ranges overlap (`start <= other end` and `other start <= end`)

CWE is stored on the label and is not a match key. A detection with only a start line uses that line as its end.

The matrix is site-level, in the OWASP Benchmark sense: each labeled site is one cell.

| Outcome | Meaning                                  |
| ------- | ---------------------------------------- |
| TP      | vulnerable label with at least one match |
| FN      | vulnerable label with no match           |
| FP      | safe label with at least one match       |
| TN      | safe label with no match                 |

Several detections on one label count once. One detection that overlaps two labels counts for each label. A detection that overlaps no label of the same class and file is unmatched. Unmatched detections are listed in the report and are not added to FP. FPR is taken over labeled safe sites, so unlabeled hits do not change its denominator.

Per class, and again on the pooled counts:

- recall = TPR = TP / (TP + FN)
- precision = TP / (TP + FP)
- FPR = FP / (FP + TN)
- score = TPR − FPR

Overall is the pooled matrix, not the average of the class scores. A rate is null, and the markdown shows `n/a`, when its denominator is zero. The score is null when TPR or FPR is null. An empty findings file, with both vulnerable and safe labels, has TPR 0, FPR 0, and score 0.

## Outputs

`--out` defaults to `./faultline-bench`. Bench writes the usual scan files there, plus:

- `bench-result.json`
- `bench-result.md`

The markdown table has TP, FP, FN, TN, recall, precision, FPR, and score for each class and for the overall row. FPR is included so the score can be checked. A second table lists each label's outcome.

## What CI checks

CI runs the scoring function on a synthetic truth set and a synthetic detection list, and it runs `faultline bench` on a tiny temporary app with no provider and with `FakeProvider`. Those tests check the arithmetic, the empty-findings stage, and that the command exits cleanly. They do not assert how many seeded bugs the heuristic pass finds.

CI also checks that `bench/seeded-app/truth.json` parses and that every label's lines exist in its file. That is a fixture check, not a detection rate.

CI checks the public corpus manifest, citations, and excluded lists without checking out those apps. It does not run Semgrep and it does not gate on a corpus score.

## Deferred

- The disproof validator, and any promotion from candidates to findings
- Scoring `faultline pr` instead of a full-tree scan
- Interprocedural taint, a JavaScript parser, or executing the app
- A leaderboard, or a CI gate on recall or score
- Running Cloudflare security-audit, Strix, or Vercel Agent (SARIF import only)
- Raising the inventory cap so a Juice Shop scan is not truncated
