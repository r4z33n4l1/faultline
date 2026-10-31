# Faultline

Faultline is an open-source security-detector CLI for startup engineering teams. It writes only findings that survived a disproof attempt, as `findings.json` and `report.md`.

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
- `architecture.md`
- `coverage.json`

Env and config files are recorded by name. Their contents are not read.

`--provider` or `FAULTLINE_PROVIDER` selects a provider name. The API key is read from `FAULTLINE_API_KEY` and is never printed. No hosted adapter is included yet, so a configured name exits with an error instead of inventing a summary. With no provider configured, `architecture.md` is an inventory-only note. A caller can pass a `ModelProvider`; `scan` then makes one summary call and treats repository content as untrusted data.

`pr` writes `findings.json` and `report.md` only.

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
