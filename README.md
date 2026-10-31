# Faultline

Faultline is an open-source security-detector CLI for startup engineering teams. It writes only findings that survived a disproof attempt, as `findings.json`, `report.md`, and `findings.sarif`.

**Status: pre-alpha.** `scan` inventories the target, writes `architecture.md` and `coverage.json`, and runs the authz/IDOR, injection, secrets, and SSRF hunters. Those hunters write `candidates.json` only. Candidates are not validated, so `findings.json` and `findings.sarif` stay empty. `report.md` records the unvalidated candidate count and no candidate details. `pr` runs the same hunters on a local unified diff and keeps a candidate only when its lines overlap a changed hunk. The findings schema and `validate` command work.

## Requirements

- Node.js 20 or newer
- pnpm

## Usage

```bash
pnpm install
pnpm build
pnpm exec faultline validate path/to/findings.json
pnpm exec faultline scan .
pnpm exec faultline pr path/to/change.diff --repo .
gh pr diff https://github.com/org/repo/pull/1 | pnpm exec faultline pr -
```

`scan` writes these files under `--out` (default `./faultline-out`):

- `findings.json`
- `report.md`
- `findings.sarif`
- `candidates.json`
- `architecture.md`
- `coverage.json`

`findings.sarif` is SARIF 2.1.0 for the same confirmed findings as `findings.json`. Paths in it are relative to the scanned directory. `candidates.json` is not a findings file. Nothing in it is confirmed.

## Authz/IDOR hunter

`scan` selects route handlers that take an object identifier (path, query, or body) and touch a data store. It notes whether auth middleware and an ownership or tenant check are visible.

With no provider, a handler that lacks a visible ownership or tenant check becomes a low-confidence candidate. With a provider, Faultline makes one model call per selected handler, at most 8, and fences the handler source as untrusted data. Model output is parsed with zod. Malformed items are discarded. A candidate is dropped when its file is not a scanned source file, its line range falls outside that file, or its cited symbol is not in the file.

Reviewed authz/IDOR coverage rows are `hunted`. Routes that are out of scope, or past the handler cap, are `skipped` with a reason. A validator is not part of this step.

Env and config files are recorded by name during recon. Recon does not read their contents. The secrets hunter reads config files and still does not read env files.

With no provider, `architecture.md` is an inventory-only note and hunter candidates come from the deterministic pre-pass. `scan` can pass inventory and handler source to a `ModelProvider`. Repository content is fenced as untrusted data, not instructions. The adapter returns text only. It does not run tools or execute model output. Faultline still checks its own JSON outputs with zod. Each selected authz/IDOR handler, each selected injection sink, each selected secrets site, and each selected SSRF sink adds one provider call after the architecture summary.

## Injection hunter

`scan` selects sinks in the same handler or function when request input reaches them. The pre-pass looks for SQL built with template strings or concatenation (`query`, `execute`, `raw`, `knex.raw`, `sequelize.query`, `prisma.$queryRawUnsafe`, `prisma.$executeRawUnsafe`), NoSQL `$where` and operator objects built from request input, `child_process` `exec` / `execSync` / `spawn` with `shell: true`, and `eval`, `new Function`, `vm`, or a template render whose source is request input. It notes parameterization and allowlisting.

With no provider, only an unmitigated tainted sink becomes a low-confidence candidate. `execFile`, `spawn` without a shell, bound SQL parameters, and the safe `prisma.$queryRaw` tag are not candidates. With a provider, Faultline makes one model call per selected sink, at most 8, and fences the handler source as untrusted data. Parsing, grounding, and the candidate cap are the same helpers the authz/IDOR hunter uses.

Reviewed injection coverage rows are `hunted`. Handlers with no selected sink, a parameterized query, or a sink past the cap are `skipped` with a reason. Candidates still are not findings.

## Secrets hunter

`scan` reviews source files and config files for hardcoded credentials (CWE-798), cleartext secrets (CWE-312), and secrets passed to a logger or `console` (CWE-532). The pre-pass matches cloud access keys, GitHub tokens, Stripe live keys, Slack tokens, private-key PEM headers, JWT signing secrets assigned to literals, and high-entropy strings assigned to names such as `secret`, `token`, `password`, and `apiKey`. It skips lockfiles, obvious placeholders (`example`, `dummy`, `changeme`, `xxx`), and paths under `test/`, `tests/`, or `__tests__/` unless that directory is the scan root.

Env files stay names only. Recon does not read them, and the secrets hunter does not read them either. A committed env file that is not an example, sample, or template becomes a filename-only candidate. Config file contents are read by this hunter. The raw secret is not stored. Candidates keep a redacted fingerprint (first 4 characters, length, and a sha256 prefix) and the location. Model prompts receive the surrounding source with the literal replaced by `<redacted>`.

With no provider, a known credential format is a medium-confidence heuristic candidate. Other heuristic secrets candidates are low confidence. With a provider, Faultline makes one model call per selected site, at most 8, and fences the redacted source as untrusted data. Parsing, grounding, and the candidate cap are the same helpers the other hunters use. A model response that contains a raw secret seen in the pre-pass is discarded. Filename-only env candidates are still recorded, because their contents are never sent.

Reviewed secrets coverage rows are `hunted`. Files with no selected secret, test paths, and sites past the cap are `skipped` with a reason. Route rows for this class are `skipped` because the hunter reviews files. Candidates still are not findings.

## SSRF hunter

`scan` selects outbound HTTP sinks in the same function when request input reaches them. The pre-pass looks for `fetch`, `axios`, `got`, `node-fetch`, undici `request`, and `http` / `https` `.request` / `.get`, including a `URL` built from that input. It also flags a webhook or callback URL that is stored and then fetched in the same function, and a redirect followed server-side when the host comes from request input. Request input is `req` / `request` `.params`, `.query`, `.body`, and `.headers`, plus route `params` and `nextUrl.searchParams` on Express, Fastify, and Next handlers.

A hard allowlist check on `hostname` or `host`, or a comparison of that host to a constant, is mitigated: the model still reviews it, and the heuristic pass does not emit a candidate. A fixed base URL whose only request data is a path segment passed through `encodeURIComponent` is not a candidate. Other heuristic candidates are low confidence. When the function does not block private or metadata addresses (`169.254.169.254`, `localhost`, RFC1918), the candidate says so.

With a provider, Faultline makes one model call per selected sink, at most 8, and fences the handler source as untrusted data. Parsing, grounding, and the candidate cap are the same helpers the other hunters use. CWE is CWE-918. Class is `ssrf`.

Reviewed SSRF coverage rows are `hunted`. Handlers with no selected sink, a fixed encoded path, an outbound call that does not use request input, or a sink past the cap are `skipped` with a reason. Candidates still are not findings.

## Model providers

`--provider` overrides `FAULTLINE_PROVIDER`. `--model` overrides `FAULTLINE_MODEL`. The API key is `FAULTLINE_API_KEY`. `FAULTLINE_BASE_URL` overrides the provider's base URL. The key is never printed, logged, or written into output files. Do not commit it.

`fake` is a local test double. It does not call the network and returns an empty completion. Heuristic authz/IDOR, injection, secrets, and SSRF candidates are emitted only when no provider is configured, so `--provider fake` does not add them. Filename-only env candidates are the exception: they are recorded either way, and their contents are not read.

`openai` speaks the OpenAI Chat Completions format. The client posts to `{base}/chat/completions`. The default base is `https://api.openai.com/v1`. Point `FAULTLINE_BASE_URL` at OpenRouter, Ollama, vLLM, or another compatible server (for Ollama, `http://127.0.0.1:11434/v1`). Those servers still require `FAULTLINE_API_KEY` to be non-empty; use any placeholder if the server ignores it.

`anthropic` calls the Anthropic Messages API. The client posts to `{base}/v1/messages`. The default base is `https://api.anthropic.com`. The request uses `max_tokens` 4096.

| Provider    | Default model id          |
| ----------- | ------------------------- |
| `openai`    | `gpt-4o-mini`             |
| `anthropic` | `claude-3-5-haiku-latest` |

The default model is only the id sent when you leave `--model` and `FAULTLINE_MODEL` unset. It is not a claim about which model is best. Set a model your account can call.

Calling `openai` or `anthropic` spends money on your own key. Faultline does not ship a key.

```bash
export FAULTLINE_PROVIDER=openai
export FAULTLINE_API_KEY=your-key
pnpm exec faultline scan . --model gpt-4o-mini
```

```bash
export FAULTLINE_PROVIDER=anthropic
export FAULTLINE_API_KEY=your-key
pnpm exec faultline scan .
```

Requests time out after 60 seconds. HTTP 429 and 5xx responses are retried up to twice, with backoff. Other HTTP errors are not retried. A name that is not `fake`, `openai`, or `anthropic` exits with an error and does not invent a summary.

## Pull request scope

`pr` hunts the checked-out tree at `--repo` (default `.`) and keeps work that overlaps a unified diff. Pass a local diff file, or `-` to read the diff from stdin. A GitHub pull request URL is not fetched. Faultline prints a message telling you to pipe `gh pr diff <url>` into `faultline pr -`.

The diff is untrusted input. Faultline does not execute it and does not send it to a shell. A diff larger than 1000000 bytes is rejected. A path that leaves `--repo` (`..`, an absolute path, or a rename to such a path) is rejected. Deleted files, binary files, and renames that do not change a line are skipped. A rename that does change lines is hunted at the new path.

Recon still covers the repository. `architecture.md` and `report.md` say the run is PR-scoped and list the changed files. Every hunter runs, including secrets, but only on changed files, with the same caps and redaction rules as `scan`. A candidate is kept when its line range overlaps a changed hunk. `--context` (default 3, maximum 20) is the number of extra lines around that hunk. Coverage rows outside the diff are `skipped` with reason `outside-diff`.

`pr` writes the same files as `scan`. `findings.json` and `findings.sarif` stay empty until a validator exists.

`validate` prints schema errors with their paths and exits non-zero on failure.

## Develop

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm schema:gen
```

## License

MIT
