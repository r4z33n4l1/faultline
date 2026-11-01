# Installing the Faultline skill

Faultline ships an Agent Skill at `skills/faultline/SKILL.md`. The skill tells a coding agent how to run the CLI on the current repo or a pull request diff, how to read `candidates.json` and `findings.json`, and what not to print. The format is the [Agent Skills specification](https://agentskills.io/specification) (accessed 2026-11-01): YAML frontmatter with `name` and `description`, then Markdown instructions. `name` is `faultline`, matching the directory.

The layout follows [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT, accessed 2026-11-01): a `skills/<name>/SKILL.md` file, frontmatter that says what the skill does and when to use it, and instructions that put safety limits before the commands. Faultline does not copy that skill's text, phase list, prompts, or schemas. Install paths below come from each agent's own docs and from the [skills CLI agent table](https://github.com/vercel-labs/skills/blob/main/docs/agents.md) (accessed 2026-11-01).

## CLI, without a global install

Requires Node.js 20 or newer. Faultline is not on the npm registry. `npm publish` runs `prepublishOnly`, which exits with an error.

`package.json` already has `"bin": { "faultline": "./dist/cli.js" }`. `dist/` is not committed. The `prepare` script is `tsc -p tsconfig.build.json`. npm runs `prepare` when it installs a git dependency, then links the bin.

Node.js 20.20 ships npm 10.8.2. `npx github:r4z33n4l1/faultline` fails there while packing the git repo (`GitFetcher requires an Arborist constructor to pack a tarball`). `npm install` of the same spec still runs `prepare` and links the bin:

```bash
mkdir -p /tmp/faultline-run && cd /tmp/faultline-run
npm init -y
npm install github:r4z33n4l1/faultline
npx faultline scan /path/to/repo --out /path/to/repo/faultline-out
```

npm 10.9.9 can run the shorter command:

```bash
npx github:r4z33n4l1/faultline scan .
```

`npx --package github:...` is the same install with the package and the command separated. Leave it alone on npm 10.8.2; it hits the same packer bug. `github:r4z33n4l1/faultline` tracks the default branch. A branch or commit ref is `github:r4z33n4l1/faultline#<ref>`.

CI, on the Node.js 20 image, installs that ref with `npm install` and scans `test/fixtures/idor-app`. See `.github/workflows/ci.yml` and `scripts/smoke-git-install.sh`. The script checks that the six scan outputs exist and that the tool name and version match this package. It does not print file contents. `npx github:r4z33n4l1/faultline --version` was run locally on npm 10.9.9.

A checkout of this repo does not need npx. `pnpm install` runs `prepare` and compiles `dist/`. Then:

```bash
pnpm exec faultline scan .
```

`pnpm build` is the same compile, if you want to run it again. Do not `npm install -g faultline`. `pnpm dlx` of this git repo refuses to run `prepare` unless `faultline` is listed in `onlyBuiltDependencies`, so that is not an install path.

## Skill files

The skills CLI can copy `skills/faultline` into the directories an agent reads. The CLI itself wants Node.js 22.20 or newer ([skills README](https://github.com/vercel-labs/skills/blob/main/README.md), accessed 2026-11-01). On Node 20, copy the directory by hand. Copy the whole `skills/faultline` directory. Do not rename the folder: `name` has to match it.

```bash
npx skills add https://github.com/r4z33n4l1/faultline --skill faultline -a claude-code
npx skills add https://github.com/r4z33n4l1/faultline --skill faultline -a codex
npx skills add https://github.com/r4z33n4l1/faultline --skill faultline -a cursor
```

Add `-g` for a user-level install. The commands below are the manual equivalent.

### Claude Code

Claude Code loads `.claude/skills/<name>/SKILL.md` for the project and `~/.claude/skills/<name>/SKILL.md` for the user ([Claude Code skills](https://code.claude.com/docs/en/skills), accessed 2026-11-01).

```bash
mkdir -p .claude/skills
cp -R skills/faultline .claude/skills/faultline
```

User-level:

```bash
mkdir -p ~/.claude/skills
cp -R skills/faultline ~/.claude/skills/faultline
```

Commit the project copy if the team should get it. A personal copy under `~/.claude/skills/` is not available to Cowork or cloud sessions.

### Codex

Codex reads `$REPO_ROOT/.agents/skills` and `$HOME/.agents/skills` ([Codex skills](https://developers.openai.com/codex/skills), accessed 2026-11-01). The skills CLI `--agent codex` writes those same paths.

```bash
mkdir -p .agents/skills
cp -R skills/faultline .agents/skills/faultline
```

User-level:

```bash
mkdir -p ~/.agents/skills
cp -R skills/faultline ~/.agents/skills/faultline
```

Restart Codex if the new skill does not appear. Invoke it with `$faultline` or by asking for a Faultline scan.

### Cursor

Cursor loads project skills from `.agents/skills/` and `.cursor/skills/`, and user skills from `~/.agents/skills/` and `~/.cursor/skills/` ([Cursor skills](https://cursor.com/docs/context/skills), accessed 2026-11-01). The skills CLI `--agent cursor` writes the `.agents/skills/` project path.

```bash
mkdir -p .cursor/skills
cp -R skills/faultline .cursor/skills/faultline
```

User-level, including the directory Cloud Agents can sync:

```bash
mkdir -p ~/.cursor/skills
cp -R skills/faultline ~/.cursor/skills/faultline
```

In Agent chat, `/faultline` attaches the skill to one message when it is installed. A scan still runs only when the request asks for one. The skill's own rules say not to scan as a side effect.

## `--provider codex`

`codex` is a Faultline model provider. It runs model calls through the locally installed OpenAI Codex CLI (`codex exec`) so someone signed in with a ChatGPT plan can scan without `FAULTLINE_API_KEY`.

```bash
codex login status
pnpm exec faultline scan . --provider codex
pnpm exec faultline scan . --provider codex --model <model-id>
```

`FAULTLINE_PROVIDER=codex` matches `--provider codex`. `FAULTLINE_CODEX_BIN` is the executable (default `codex` on `PATH`). `--model` and `FAULTLINE_MODEL` are passed as `codex exec -m`. Omit both to use the model already configured in the Codex CLI.

Faultline invokes the CLI non-interactively:

- `spawn` with an argument array and `shell: false`. The prompt is stdin (`-`), never a shell string, so candidate text cannot change the command.
- `--sandbox read-only`, `-c approval_policy="never"`, `--ignore-user-config`, and `--ignore-rules`.
- `-c sandbox_workspace_write.network_access=false` and `-c web_search="disabled"`. Current `codex exec` has no `--no-network` flag. Those settings are what keep the inner agent's commands off the network and off web search. The Codex process itself still contacts the ChatGPT service.
- `--ephemeral` and `--skip-git-repo-check`. `--cd` is a fresh empty temp directory, not the scanned repo.
- `--output-last-message` is the final message. If that file is empty and stdout is JSONL, Faultline keeps the last `agent_message` only.
- Timeout 120 seconds, output cap 1000000 bytes, at most 2 Codex processes at once. Failures are not retried.
- `codex login status` must exit 0 before `exec`. Faultline does not read or copy `~/.codex/auth.json`. API keys and proxy URLs that contain userinfo are not copied into the child environment. Token-like strings are redacted from errors.
- The prompt requires pure text JSON when the request asks for JSON (no markdown fence). Hunters and the disproof validator parse that text with the existing zod schemas. `--output-schema` is not used.

Do not pass `--provider codex` unless the user asked for a model run. The fenced source is sent to Codex. A missing `codex` binary or a failed `codex login status` exits with an error and does not invent a summary.

## After it is installed

Ask the agent to scan the repo or a pull request diff. The skill's run commands write `./faultline-out`. That directory is gitignored in this repository. In another repository, do not commit it.

The skill does not add a `boundary` field to `coverage.json`. That map is [agent-baseline.md](agent-baseline.md).
