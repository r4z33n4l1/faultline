# Faultline

Faultline is an open-source security-detector CLI for startup engineering teams. It writes only findings that survived a disproof attempt, as `findings.json`, `report.md`, and `findings.sarif`.

**Status: pre-alpha.** `scan` inventories the target, writes `architecture.md` and `coverage.json`, and runs the authz/IDOR and injection hunters. Those hunters write `candidates.json` only. Candidates are not validated, so `findings.json` and `findings.sarif` stay empty. `report.md` records the unvalidated candidate count and no candidate details. `pr` still runs an empty pipeline and does not hunt. The findings schema and `validate` command work.

## Requirements

- Node.js 20 or newer
- pnpm

## Usage

```bash
pnpm install
pnpm build
pnpm exec faultline validate path/to/findings.json
pnpm exec faultline scan .
pnpm exec faultline pr https://github.com/org/repo/pull/1
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

Reviewed authz/IDOR coverage rows are `hunted`. Routes that are out of scope, or past the handler cap, are `skipped` with a reason. Secrets and SSRF rows stay `pending`. A validator is not part of this step.

Env and config files are recorded by name. Their contents are not read.

With no provider, `architecture.md` is an inventory-only note and hunter candidates come from the deterministic pre-pass. `scan` can pass inventory and handler source to a `ModelProvider`. Repository content is fenced as untrusted data, not instructions. The adapter returns text only. It does not run tools or execute model output. Faultline still checks its own JSON outputs with zod. Each selected authz/IDOR handler, and each selected injection sink, adds one provider call after the architecture summary.

## Injection hunter

`scan` selects sinks in the same handler or function when request input reaches them. The pre-pass looks for SQL built with template strings or concatenation (`query`, `execute`, `raw`, `knex.raw`, `sequelize.query`, `prisma.$queryRawUnsafe`, `prisma.$executeRawUnsafe`), NoSQL `$where` and operator objects built from request input, `child_process` `exec` / `execSync` / `spawn` with `shell: true`, and `eval`, `new Function`, `vm`, or a template render whose source is request input. It notes parameterization and allowlisting.

With no provider, only an unmitigated tainted sink becomes a low-confidence candidate. `execFile`, `spawn` without a shell, bound SQL parameters, and the safe `prisma.$queryRaw` tag are not candidates. With a provider, Faultline makes one model call per selected sink, at most 8, and fences the handler source as untrusted data. Parsing, grounding, and the candidate cap are the same helpers the authz/IDOR hunter uses.

Reviewed injection coverage rows are `hunted`. Handlers with no selected sink, a parameterized query, or a sink past the cap are `skipped` with a reason. Secrets and SSRF rows stay `pending`. Candidates still are not findings.

## Model providers

`--provider` overrides `FAULTLINE_PROVIDER`. `--model` overrides `FAULTLINE_MODEL`. The API key is `FAULTLINE_API_KEY`. `FAULTLINE_BASE_URL` overrides the provider's base URL. The key is never printed, logged, or written into output files. Do not commit it.

`fake` is a local test double. It does not call the network and returns an empty completion. Heuristic authz/IDOR and injection candidates are emitted only when no provider is configured, so `--provider fake` does not add them.

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

`pr` writes `findings.json`, `report.md`, and `findings.sarif`.

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
