# Faultline

Faultline is an open-source security-detector CLI for startup engineering teams. It writes only findings that survived a disproof attempt, as `findings.json` and `report.md`.

**Status: pre-alpha.** `scan` and `pr` run an empty pipeline and write zero findings. The findings schema and `validate` command work; detection does not.

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

`scan` and `pr` write `findings.json` and `report.md` under `--out` (default `./faultline-out`).

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
