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

`openai` (OpenAI-compatible Chat Completions, `FAULTLINE_BASE_URL` for other servers) and `anthropic` (Messages API) implement `ModelProvider` with `fetch`. `--model` / `FAULTLINE_MODEL` selects the model id; each provider has a documented default and no quality ranking. The registry is one definition per provider. Adapters return text only (`jsonSchema` is not sent; tool calls are not executed). Timeouts and bounded retries apply to HTTP 429 and 5xx. API keys stay out of errors and logs. Hunters and the disproof validator are still later.
