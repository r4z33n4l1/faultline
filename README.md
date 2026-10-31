# Faultline

Faultline is an open-source security-detector CLI for startup engineering teams. It writes only findings that survived a disproof attempt, as `findings.json`, `report.md`, and `findings.sarif`.

**Status: pre-alpha.** `scan` inventories the target and writes `architecture.md` plus a pending `coverage.json`. It does not hunt or validate yet, so findings are empty. `pr` still runs an empty pipeline. The findings schema and `validate` command work.

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
- `architecture.md`
- `coverage.json`

`findings.sarif` is SARIF 2.1.0 for the same confirmed findings as `findings.json`. Paths in it are relative to the scanned directory.

Env and config files are recorded by name. Their contents are not read.

With no provider, `architecture.md` is an inventory-only note. `scan` can pass that inventory to a `ModelProvider` and write the model's text into the summary. Repository content is fenced as untrusted data, not instructions. The adapter returns text only. It does not run tools or execute model output. Faultline still checks its own JSON outputs with zod.

## Model providers

`--provider` overrides `FAULTLINE_PROVIDER`. `--model` overrides `FAULTLINE_MODEL`. The API key is `FAULTLINE_API_KEY`. `FAULTLINE_BASE_URL` overrides the provider's base URL. The key is never printed, logged, or written into output files. Do not commit it.

`fake` is a local test double. It does not call the network and returns an empty completion.

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
