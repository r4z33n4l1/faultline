# Installing the Faultline skill

Faultline ships an Agent Skill at `skills/faultline/SKILL.md`. The skill tells a coding agent how to run the CLI on the current repo or a pull request diff, how to read `candidates.json` and `findings.json`, and what not to print. The format is the [Agent Skills specification](https://agentskills.io/specification) (accessed 2026-11-01): YAML frontmatter with `name` and `description`, then Markdown instructions. `name` is `faultline`, matching the directory.

The layout follows [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT, accessed 2026-11-01): a `skills/<name>/SKILL.md` file, frontmatter that says what the skill does and when to use it, and instructions that put safety limits before the commands. Faultline does not copy that skill's text, phase list, prompts, or schemas. Install paths below come from each agent's own docs and from the [skills CLI agent table](https://github.com/vercel-labs/skills/blob/main/docs/agents.md) (accessed 2026-11-01).

## CLI, without a global install

Requires Node.js 20 or newer. Faultline is not on the npm registry. `npm publish` runs `prepublishOnly`, which exits with an error.

`package.json` already has `"bin": { "faultline": "./dist/cli.js" }`. `dist/` is not committed. The `prepare` script is `tsc -p tsconfig.build.json`. npm runs `prepare` when it installs a git dependency, then links the bin. From the repository you want to scan:

```bash
npx github:r4z33n4l1/faultline scan .
```

The same install, with the package and the command separated:

```bash
npx --yes --package github:r4z33n4l1/faultline -- faultline scan . --out ./faultline-out
```

Some npm builds fail that `--package` form for a git spec with `GitFetcher requires an Arborist constructor to pack a tarball`. The positional command above is the one CI runs.

`npx github:r4z33n4l1/faultline` tracks the default branch. A branch or commit ref is `github:r4z33n4l1/faultline#<ref>`. CI uses that form so the job installs the commit under test rather than `main`. See `.github/workflows/ci.yml` and `scripts/smoke-git-install.sh`. The smoke scan target is `test/fixtures/idor-app`. It checks that the six scan outputs exist and that findings, candidates, and coverage parse. It does not print file contents.

A checkout of this repo does not need npx. `pnpm install` runs `prepare` and compiles `dist/`. Then:

```bash
pnpm exec faultline scan .
```

`pnpm build` is the same compile, if you want to run it again. Do not `npm install -g faultline`.

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

## After it is installed

Ask the agent to scan the repo or a pull request diff. The skill's run commands write `./faultline-out`. That directory is gitignored in this repository. In another repository, do not commit it.

The skill does not add a `boundary` field to `coverage.json`. That map is [agent-baseline.md](agent-baseline.md).
