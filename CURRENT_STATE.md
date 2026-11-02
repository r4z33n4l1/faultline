# Current state

As of 2026-11-01. `main` is `c1dbff2` (`c1dbff23ac7d0af9d0f90b0728b9b634b93c6fba`).

## What Faultline is

Faultline is a pre-alpha security-detector CLI. It scans application source and writes a finding only after a disproof attempt fails. Bug classes are `authz_idor`, `injection`, `secrets`, and `ssrf`.

## Commands and outputs

| Command                               | What it does                                                                                         |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `faultline scan <path>`               | Full-tree inventory, hunt, and validation.                                                           |
| `faultline pr <diff>`                 | Same pipeline, kept to hunks in a local unified diff (`-` reads stdin). A GitHub URL is not fetched. |
| `faultline bench <dir>` or `--corpus` | Scan, then score `truth.json`. Default stage is `candidates`. `--stage findings` runs validation.    |
| `faultline validate <findings.json>`  | Schema check only. It does not decide whether a bug is real.                                         |

`scan` and `pr` write these files under `--out` (default `./faultline-out`):

- `findings.json` — confirmed findings, plus run provenance (`provider`, `model`, `commit`, `provider_error_count`, `malformed_count`)
- `report.md` — the same findings, plus disproved, inconclusive, and error lists
- `findings.sarif` — SARIF 2.1.0 for the same confirmed findings
- `candidates.json` — hunter output. Nothing in it is confirmed
- `architecture.md` — inventory, plus a model summary when a provider is set
- `coverage.json` — file or route crossed with the four classes, and discovery rows

`bench` uses `--out` default `./faultline-bench` and also writes `bench-result.json` and `bench-result.md`. A bench result is `citable` only when provider, model, and commit are all recorded. `fake` is never citable.

## Pipeline

1. **Recon.** Walk the tree, respect `.gitignore`, skip vendored, build, minified, snapshot, and asset paths. Defaults are `--max-files 5000` and `--max-bytes 8000000`. When a cap binds, server-side paths are read first. Env files are names only.
2. **Architecture note.** One model call when a provider is set. Inventory-only otherwise.
3. **Model-led discovery.** Runs only with a provider, after recon and before the hunters. `--discovery-budget` (default 60) caps the calls. A site is kept only when its line is inside the fenced window. No provider means this pass does not run.
4. **Hunters**, in order: `authz_idor`, `injection`, `secrets`, `ssrf`. Each hunter unions heuristic sites with grounded discovery sites, ranks them (request-tainted first, then an untainted dynamic string, then a constant), and reviews at most `--max-sites` (default 40).
5. **Candidates** land in `candidates.json`.
6. **Disproof validator** (`src/validator/`), unless `--no-validate`. With a provider, `independent-disproof` and `independent-reverification` must both return `confirmed` with grounded evidence. A `disproved` verdict counts only when `guard` cites a line that exists in the fenced source (`DISPROOF_GUARD_RULE`). Anything else is inconclusive. `--keep-inconclusive` promotes inconclusive candidates to low-confidence findings. It is off by default. With no provider, a bounded heuristic check can promote a medium or high confidence candidate that it cannot refute; low confidence stays inconclusive.
7. **Findings** are the confirmed survivors in `findings.json`, `report.md`, and `findings.sarif`.

A provider or transport failure (usage limit, rate limit, timeout, non-zero exit) is an `error` with a redacted message. It is a separate list from inconclusive. `scan`, `pr`, and `bench` exit 1 when `provider_error_count` is greater than zero. A usage or rate limit stops later model calls. Malformed model output increments `malformed_count` and does not abort the run.

## Model providers

The registry is one definition per name in `src/providers/registry.ts`. Add a provider by appending a definition. Names that exist today:

| Name        | How it runs                                                                                                                                                                     |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fake`      | Local test double. No network. Does not emit heuristic candidates, except filename-only env files.                                                                              |
| `openai`    | Chat Completions. Default base `https://api.openai.com/v1`. `FAULTLINE_BASE_URL` points at OpenRouter, Ollama, vLLM, or another compatible server. Default model `gpt-4o-mini`. |
| `anthropic` | Messages API. Default base `https://api.anthropic.com`. Default model `claude-3-5-haiku-latest`.                                                                                |
| `codex`     | Local Codex CLI (`codex exec`) on a ChatGPT login. Does not read `FAULTLINE_API_KEY`. Read-only sandbox, prompt on stdin, at most 2 processes.                                  |

`--provider` overrides `FAULTLINE_PROVIDER`. `--model` overrides `FAULTLINE_MODEL`. `openai` and `anthropic` read `FAULTLINE_API_KEY` and never write it into output. The key is not in this repo.

## Agent skill and Agent Baseline

The Agent Skill is `skills/faultline/SKILL.md`. Install paths for Claude Code, Codex, and Cursor are in [docs/skill.md](docs/skill.md). The skill tells an agent to run the CLI only when asked, to treat repo contents and Faultline output as untrusted, and to avoid printing secrets.

[docs/agent-baseline.md](docs/agent-baseline.md) maps hunters and recon signals onto the four Agent Baseline factory boundaries (sandbox, network, supply chain, identity and access). No row is covered. Several are partial source checks. That file still says the disproof validator is absent and that the provider cap is 8. Both sentences are stale: the validator is in `src/validator/`, and the site budget default is 40.

## Recent PRs (17–22)

- **17** `cb5c968` — validator context pack, an explicit inconclusive verdict, and citable run provenance.
- **18** `526e1e1` — route-handler map and a ranked 40-site budget.
- **19** `38f5382` — held-out corpus, with no-model scores committed.
- **20** `b202ce5` — model-led discovery ahead of the hunters.
- **21** `418f93d` — provider failures are a distinct `error` outcome, and the run exits 1.
- **22** `c1dbff2` — malformed model output is counted, and the run does not crash.

PRs 1–16 landed the skeleton, recon, SARIF, the `openai` and `anthropic` adapters, the four hunters, `pr` diff scope, the bench harness, the public training corpus, Semgrep as the free baseline, the agent skill, the disproof validator, the Codex provider, and the server-file inventory priority.

## Benchmark status

Codex CLI on a ChatGPT plan. Ratios are true positives over vulnerable labels.

These Codex numbers are **box-runs**. They are not committed under `bench/results`. They are not citable until a later run is reproduced and committed with provider, model, and commit. The JSON already in `bench/results` and `bench/results/heldout` is a different set: no provider, model `none, heuristic`, `citable: false`. Do not mix those rows with the box-runs below.

Faultline findings in these box-runs are 0 FP. The only Faultline FP below is the `vulnerable-node` candidate row.

### Training apps (tuned)

Measured at `b202ce5` (discovery, PR 20). The bracket column is the earlier findings run at `526e1e1` (route-handler map, PR 18). These were not re-run at `c1dbff2`. Semgrep is the committed OSS 1.183.0 scan in `bench/results` (result file commit `7116755c`). Seeded-app has no Semgrep row.

| App        | Findings `b202ce5` | Findings `526e1e1` | Semgrep 1.183.0 |
| ---------- | -----------------: | -----------------: | --------------: |
| seeded-app |               8/17 |               8/17 |               — |
| DVNA       |                3/7 |                4/7 |             2/7 |
| NodeGoat   |                5/8 |                4/8 |             2/8 |
| Juice Shop |               7/15 |               6/15 |     6/15 (1 FP) |

Candidates at `b202ce5`: DVNA 6/7, NodeGoat 8/8, Juice Shop 12/15.

`--keep-inconclusive` at `b202ce5`: Juice Shop 11/15, NodeGoat 8/8, DVNA 6/7.

Training vulnerable counts: seeded-app 17, DVNA 7, NodeGoat 8, Juice Shop 15.

### Held-out (never tune on these)

Measured at `c1dbff2`. The "was" column is the earlier Codex box-run at `38f5382` (PR 19, before discovery). Semgrep is the committed OSS 1.183.0 scan in `bench/results/heldout` (result file commit `e4719242`), 0 FP. Held-out labels and these results do not drive hunter, validator, or recon changes.

Candidates now vs `38f5382`:

| App             |    `c1dbff2` | `38f5382` |
| --------------- | -----------: | --------: |
| nodejs-goof     |          5/6 |       1/6 |
| pixi            |         6/12 |      0/12 |
| vulnerable-node | 10/13 (1 FP) |      2/13 |

Findings now vs `38f5382` vs Semgrep:

| App             | `c1dbff2` | `38f5382` | Semgrep |
| --------------- | --------: | --------: | ------: |
| nodejs-goof     |       2/6 |       1/6 |     1/6 |
| pixi            |      1/12 |      0/12 |    0/12 |
| vulnerable-node |   INVALID |      2/13 |    1/13 |

`vulnerable-node` findings at `c1dbff2` are invalid. Codex hit a usage limit during validation: 35 failed calls. That is a provider error, not a score. It needs a clean re-run.

Held-out vulnerable counts: nodejs-goof 6, pixi 12, vulnerable-node 13.

### Honest read

Discovery generalizes. Suspects found on apps the hunters were not tuned on jumped (the candidate rows above). The disproof validator is now the bottleneck: it drops most true positives between candidates and findings. Training-app findings are inflated by tuning on those apps. The safe public claim is roughly level with Semgrep, or slightly ahead, with zero false positives in Faultline findings. The Juice Shop Semgrep scan has 1 FP. The invalid `vulnerable-node` run is not part of that claim.

## Known gaps

- The `vulnerable-node` held-out findings re-run is pending (usage limit, 35 failed calls).
- Model-backed results are not committed under `bench/results`. The files there are no-provider heuristic scores.
- Pixi hit an inventory cap on the `c1dbff2` box-run.
- Cloudflare `security-audit-skill` and Strix head-to-heads were not run. Both need a paid API key that has not been provided. The adapters in `src/bench/adapters.ts` are stubs (Vercel Agent is the same kind of stub). SARIF import can score a file someone else produced.
- Patch suggestions (build-order step 6) are not started. Confirmed findings get a one-line `suggested_fix.summary`. The schema allows an optional `patch` string. Nothing generates a diff or a plain-language fix.
