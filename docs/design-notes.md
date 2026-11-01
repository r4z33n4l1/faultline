# Faultline design notes (from inspiration research)

Access dates: 2026-10-29 (initial); 2026-10-31 (tools/guides refresh). See `inspiration.md`.

## PR1 — skeleton CLI + findings schema

1. **Native `findings.json` remains the source of truth** (rich Faultline fields). Zod → JSON Schema export. Emit user-facing survivors only (`confirmed`); keep `rejected` / `needs_validation` for debug/tests.
2. **Required confirmed fields:** `id` (stable fingerprint), `class` (kebab attack class), `cwe` (e.g. `CWE-89` Weakness id, optional until mapped), `severity` (`informational|low|medium|high|critical`), `confidence` (`low|medium|high` + reason), `location` `{file, start_line, end_line?, start_column?, end_column?}`, `root_cause` (dedup key), `evidence[]` `{file, line, note}`, `disproof_attempts[]` `{agent_role, verdict: confirmed|rejected|inconclusive, summary}`, `validator_verdict`, `exploitability` (`theoretical|poc|demonstrated` — aligns with SARIF `ai/exploitability`), `suggested_fix` `{strategy, patch?}`, `references[]`.
3. **SARIF 2.1.0 export (PR1 must be exportable):** add `faultline sarif` or `--format sarif` that maps native → OASIS SARIF 2.1.0. Minimum: `version: "2.1.0"`, `runs[0].tool.driver` = Faultline + version, `run.properties["ai/origin"]="generated"`, each result `ruleId` = `CWE-<n>/<class>` or `NOVEL-<class>`, `level` from severity, `rank` from confidence (0–100), `locations` from file/line, `message.text` (+ markdown later), `properties.ai/exploitability`. Do **not** make raw SARIF the only schema — keep native JSON richer for disproof_attempts / root_cause. Cite: OASIS SARIF 2.1.0 + microsoft/sarif-sdk AI conventions.
4. **Validator rules in code:** paths exist; lines ≥ 1; `additionalProperties` false; hunter ≠ validator in run metadata; structural checks before trust (file/function cited exist — AWS steering pattern); OpenSSF: PoC acceptance needs trigger-on-vuln / no-trigger-on-benign / no-trigger-after-fix when execution is available; else stay `theoretical` / `needs_validation`.
5. **CLI:** `faultline scan .` → `findings.json` + `report.md` (+ optional SARIF); `faultline pr <url|diff>` stubs same schema.
6. **ModelProvider** interface only; no vendor hard-wire. Vitest: schema round-trip, rejected excluded from report, SARIF mapper smoke (validates against a minimal SARIF 2.1.0 shape).
7. **Do not** ship coverage-ledger, fleet DB, autofix-merge, or CyberGym-as-CI in PR1.

## Step-7 fixture benchmark (plan now, implement with hunters)

8. Curate **small TS/JS fixtures** (authz miss, SQLi/XSS sink, hardcoded secret, SSRF-ish fetch) with expected labels — score TP/FP/FN like OWASP Benchmark style, not CyberGym scale.
9. Optional later: run against OWASP Benchmark / CVE-Bench subsets for regression; CyberGym/SEC-bench are C/C++ or exploit-heavy — useful as stretch, not PR1 gate. Never publish vendor or public-bench numbers as Faultline product claims without our own labeled run.

## PR2+

10. Per-class hunters + fresh disproof validator (Cloudflare / OpenSSF / Anthropic shape).
11. Thin recon writes `architecture.md` and a pending coverage ledger (PR2). Hunter status updates and a coverage critic wait until multi-run noise hurts.
12. `faultline pr`: inline comments + suggested fix (Factory / Devin / DryRun / ZeroPath pattern).
13. Human-gated patch → prove (Codex / Daybreak / CodeMender posture); SARIF `fixes[]` when patches exist.
14. Dedup by `root_cause` / `id`; re-verify carried confirms on current source.
15. Prefer different models for hunt vs validate when configured; treat target content as untrusted in prompts (Cloudflare Oct PR theme).

## PR2 — recon

Deterministic inventory in `src/recon/` respects `.gitignore`, skips dependency and build directories, skips binaries, and caps file count and bytes. Env and config files are names only; contents are not read. One fenced `ModelProvider` call can write `architecture.md`. With no provider, that file is labeled inventory-only. The CLI accepts `--provider` / `FAULTLINE_PROVIDER` and reads `FAULTLINE_API_KEY` without printing it. `coverage.json` is file or route × `authz_idor` | `injection` | `secrets` | `ssrf`, and recon sets every row to `pending`. Hunters, disproof, and `faultline pr` comments remain later. SARIF export of confirmed findings is in place.

## PR3 — model providers

`openai` (OpenAI-compatible Chat Completions, `FAULTLINE_BASE_URL` for other servers) and `anthropic` (Messages API) implement `ModelProvider` with `fetch`. `--model` / `FAULTLINE_MODEL` selects the model id; each provider has a documented default and no quality ranking. The registry is one definition per provider. Adapters return text only (`jsonSchema` is not sent; tool calls are not executed). Timeouts and bounded retries apply to HTTP 429 and 5xx. API keys stay out of errors and logs. The disproof validator is still later.

## PR4 — authz/IDOR hunter

One hunter per bug class. `src/hunters/types.ts` is `name`, `class`, and `run(ctx) -> Candidate[]`. This PR adds `authz-idor` only. Injection, secrets, and SSRF stay `pending` in the ledger.

Candidates are a strict subset of a finding: class, location, symbol (the cited identifier), root_cause, evidence, suggested severity, confidence with reason, and optional cwe. They are written to `candidates.json` under the same Zod JSON Schema drift check as findings. They are not findings. `findings.json` and SARIF stay empty until a validator exists. `report.md` records only `unvalidated candidates: N, not reported as findings`.

The hunter selects route handlers that take an object id (path, query, or body) and touch a data store, and notes whether auth middleware and an ownership or tenant check are visible. With no provider it emits low-confidence heuristic candidates only for handlers that lack that check. With a provider it makes one fenced model call per selected handler (8 handlers, 4000 source characters, 3 parsed candidates each). Zod drops malformed items. Grounding drops a candidate whose file is not a scanned source file, whose lines fall outside that file, or whose symbol is absent. Fenced source is untrusted data, not instructions. `faultline pr` does not hunt.

## PR5 — injection hunter

Same hunter contract as authz/IDOR. `src/hunters/injection.ts` selects SQL, NoSQL, command, code, and template sinks when request input (`req` / `request` `.params`, `.query`, `.body`, `.headers`, or a recon route handler that reads them) reaches the sink in the same function. Visible parameterization and allowlisting are mitigations. Heuristic candidates are low-confidence and only for unmitigated tainted sinks. CWE is per sink: CWE-89, CWE-943, CWE-78, CWE-94, or CWE-1336. Class is `injection`.

Cap, source fencing, zod parsing, and grounding live in `src/hunters/shared.ts` and `src/hunters/ground.ts`. Authz/IDOR behavior is unchanged. One model call per selected sink, including sinks the pre-pass marked mitigated, with the same 8 / 4000 / 3 bounds. Injection coverage rows become `hunted` or `skipped`. Secrets and SSRF stay `pending`. `findings.json` and SARIF stay empty. `faultline pr` does not hunt.

Not in this pass: interprocedural taint, a full JavaScript parser, executing payloads, and the disproof validator.

## PR6 — secrets hunter

Same hunter contract. `src/hunters/secrets.ts` reviews scanned source files and config files for CWE-798, CWE-312, and CWE-532. Class is `secrets`. Recon still records env and config files by name and does not read them. This hunter reads config file contents. It does not read env files. A committed `.env`-style file is a filename-only candidate unless the name marks it as an example, sample, or template.

The pre-pass matches AWS-style access key ids, Google API keys, GitHub tokens, Stripe live keys (`sk_live_` / `rk_live_`), Slack tokens, PEM private-key blocks, JWT signing secrets assigned to literals, high-entropy literals assigned to sensitive names, and secret-like identifiers passed to `console` or a logger. Lockfiles are skipped. Placeholders (`example`, `dummy`, `changeme`, `xxx`, and the same idea) are skipped. Paths under `test/`, `tests/`, or `__tests__/` are skipped unless that directory is the scan root (relative paths then omit the segment).

Raw secret values are not written to `candidates.json`, `report.md`, `findings.json`, `findings.sarif`, logs, or model prompts. The candidate stores a fingerprint: the first 4 characters, the length, and an 8-hex sha256 prefix. The model sees the site with those literals replaced by `<redacted>`. A model candidate that still contains an observed secret is dropped. Known-format heuristic candidates are medium confidence. Other heuristic candidates are low confidence. With a provider, one fenced call per selected site, same 8 / 4000 / 3 bounds, zod, and grounding. Env filename candidates are emitted on both paths and do not spend a model call.

Secrets coverage rows become `hunted` or `skipped`. Route rows are `skipped` because this hunter reviews files. The ledger has no config-file or env-file unit, so those reviews show up as candidates only. SSRF stays `pending`. `findings.json` and SARIF stay empty. `faultline pr` does not hunt.

Not in this pass: interprocedural secret tracking, a full parser, split-string assembly, manifest and shell scanning, live verification against a provider API, and the disproof validator.

## PR7 — SSRF hunter

Same hunter contract. `src/hunters/ssrf.ts` selects CWE-918 sinks in the same function when request input reaches an outbound HTTP call. Class is `ssrf`. Sinks are `fetch`, `axios` calls, `got`, `node-fetch`, undici `request`, and `http` / `https` `.request` / `.get`, plus a `URL` whose host or path is built from that input. Request input is `req` / `request` `.params`, `.query`, `.body`, and `.headers`, and on Express, Fastify, and Next handlers the route `params` object and `nextUrl.searchParams`.

A webhook or callback field that is stored and then fetched in the same function is flagged. A server-side redirect is flagged when the host is request-controlled: either the client follows redirects by default (`fetch`, `axios`, `got`, `node-fetch`) or the function reads a `Location` header from a user-controlled response and requests it. `http` / `https` and undici `request` do not follow redirects unless the call opts in or the function fetches the location itself.

A hostname allowlist (`includes` / `has`) or a comparison of `hostname` / `host` to a constant before the call is mitigated. The model still reviews that sink. The heuristic pass does not emit it. A fixed absolute base URL whose only request data is a path segment wrapped in `encodeURIComponent` is not a candidate. Heuristic candidates are low confidence. When the function does not mention a private-IP or metadata block (`169.254.169.254`, `localhost`, RFC1918), the candidate notes that. A string block alone does not clear the candidate.

One fenced model call per selected sink, including mitigated sinks, with the shared 8 / 4000 / 3 bounds, zod, and grounding. SSRF coverage rows become `hunted` or `skipped`. `findings.json` and SARIF stay empty. `faultline pr` does not hunt.

Not in this pass: interprocedural taint, a full JavaScript parser, DNS resolution and rebinding, redirect chains across functions, `axios.create` / `got.extend` instances, client-side open redirects that the server does not follow, and the disproof validator.

## PR8 — pull-request diff scope

`faultline pr <diff>` hunts only what a unified diff touches. The argument is a local diff file or `-` for stdin. `--repo` (default `.`) is the checked-out tree after the change. A GitHub pull request URL is not fetched and does not authenticate; the CLI tells the user to pipe `gh pr diff <url>`.

The parser is in-process. It does not spawn a shell. Diffs over 1000000 bytes are rejected. Paths are normalized like other repo paths: `..`, absolute paths, control characters, and backticks are rejected before any read. Deleted files (`+++ /dev/null` or `deleted file mode`), binary patches, and renames with no hunks are ignored. A rename with hunks uses the new path. A file that still exists and only deletes lines stays in scope; the deletion anchors the next new-file line so the context window can see the edit.

Recon inventories the whole `--repo` tree. `architecture.md` marks the changed files. Hunters receive an inventory limited to those files, so authz/IDOR, injection, secrets, and SSRF all run with their existing caps, fencing, grounding, and secret redaction. After the hunters return, a candidate is kept only when its location overlaps a changed hunk expanded by `--context` (default 3, maximum 20). Coverage rows for files outside the diff, and route rows whose line is outside that window, are `skipped` with reason `outside-diff`. Rows the hunters reviewed inside the diff keep the hunter's reason.

Outputs match `scan`: `findings.json`, `report.md`, `findings.sarif`, `candidates.json`, `architecture.md`, and `coverage.json`. `report.md` says the run is PR-scoped and lists the changed files. Findings stay empty. The validator is still a separate change.

Not in this pass: fetching a pull request, inline review comments, applying the diff onto a tree, interprocedural taint, and promoting candidates to findings.

## Bench harness

`faultline bench <dir>` is the measuring tool. It scans the directory, then scores `candidates.json` or, with `--stage findings`, `findings.json` against `truth.json`. The findings stage runs the validator. The candidates stage does not. Matching is class plus normalized path plus inclusive line overlap. The confusion matrix is site-level: a labeled site is one true positive, false positive, false negative, or true negative. The score is TPR minus FPR. Unmatched detections are listed and are not folded into the false-positive count.

`bench/seeded-app` is a separate Express tree from `test/fixtures`, with vulnerable sites and look-alike safe sites for the four hunter classes. Secrets in it are synthetic bench strings or a documented example joined at runtime. CI checks the harness math on a synthetic truth set and checks that seeded labels point at real lines. CI does not assert detection rates on the seeded app, and it does not call a model. A result is citable only when provider, model, and commit are recorded.

`bench/corpus` adds NodeGoat, DVNA, and Juice Shop at pinned commits. The source is fetched into a gitignored cache and is not vendored. Semgrep OSS is the free static baseline. Paid agent tools have a SARIF import stub and are not run. Committed scores are heuristic runs with no model, not product claims.

## Inventory budgets

Recon walks the tree, then reads source and manifests up to `--max-files` (default 5000) and `--max-bytes` (default 8000000). A file over the per-file cap is skipped and the walk continues. Default skips are dependency and build directories, lockfiles, `*.min.js` and other minified bundles, `__snapshots__` and `*.snap` files, and `frontend/src/assets`. `.gitignore` still applies. `--exclude` adds globs. `--include` keeps a matching path that a default skip, gitignore, or exclude would drop, and it does not by itself limit the scan to those paths.

When the file or byte budget would bind, paths under route, controller, handler, api, server, models, or lib directories are read first, then entrypoint filenames and manifests, then files whose header imports express, fastify, koa, `next/server`, sequelize, mongoose, pg, mysql, `child_process`, or an HTTP client. Other files fill whatever budget remains. `coverage.json` `skipped` records each unread path and a reason (`default-exclude`, `gitignore`, `exclude`, `lockfile`, `minified`, `snapshot`, `binary`, `max-file-bytes`, `max-files`, `max-bytes`). `report.md` states when a cap bound. Hunters are unchanged; they still see only the files recon read.
