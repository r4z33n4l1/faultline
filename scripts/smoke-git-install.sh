#!/usr/bin/env bash
# Install faultline from git and scan a fixture.
# FAULTLINE_SMOKE_SPEC overrides the package spec. The default is a git+file URL of HEAD.
#
# Node 20.20 ships npm 10.8.2. On that npm, `npx github:owner/repo` fails with
# "GitFetcher requires an Arborist constructor to pack a tarball".
# `npm install github:owner/repo` still runs prepare and links the bin.
# That is the install this script checks. npm 10.9.9 can run `npx github:owner/repo`.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$root/test/fixtures/idor-app"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

spec="${FAULTLINE_SMOKE_SPEC:-}"
if [[ -z "$spec" ]]; then
  if ! git -C "$root" diff --quiet || ! git -C "$root" diff --cached --quiet; then
    echo "smoke-git-install: commit first. A local clone installs HEAD only." >&2
    exit 1
  fi
  git clone --quiet --depth 1 "file://$root" "$tmp/src"
  spec="git+file://$tmp/src"
fi

if [[ ! -d "$fixture" ]]; then
  echo "smoke-git-install: missing fixture $fixture" >&2
  exit 1
fi

expected="$(node -p "require('$root/package.json').version")"

check_out() {
  node --input-type=module - "$1" "$expected" <<'EOF'
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const out = process.argv[2];
const expectedVersion = process.argv[3];
if (out === undefined || out.length === 0 || expectedVersion === undefined) {
  process.exit(1);
}
const names = [
  "findings.json",
  "report.md",
  "findings.sarif",
  "candidates.json",
  "architecture.md",
  "coverage.json",
];
for (const name of names) {
  const text = await readFile(join(out, name), "utf8");
  if (text.length === 0) {
    console.error(`empty ${name}`);
    process.exit(1);
  }
}
const findings = JSON.parse(await readFile(join(out, "findings.json"), "utf8"));
const candidates = JSON.parse(await readFile(join(out, "candidates.json"), "utf8"));
const coverage = JSON.parse(await readFile(join(out, "coverage.json"), "utf8"));
if (!Array.isArray(findings.findings)) {
  console.error("findings.json has no findings array");
  process.exit(1);
}
if (findings.tool?.name !== "faultline" || findings.tool?.version !== expectedVersion) {
  console.error("unexpected findings tool identity");
  process.exit(1);
}
if (!Array.isArray(candidates.candidates)) {
  console.error("candidates.json has no candidates array");
  process.exit(1);
}
if (!Array.isArray(coverage.units) || coverage.units.length === 0) {
  console.error("coverage.json has no units");
  process.exit(1);
}
EOF
}

echo "smoke-git-install: node $(node -v) npm $(npm -v)"
echo "smoke-git-install: npm install $spec"

app="$tmp/app"
mkdir -p "$app"
(
  cd "$app"
  npm init -y >/dev/null
  npm install --no-audit --no-fund "$spec"
)
"$app/node_modules/.bin/faultline" --version
"$app/node_modules/.bin/faultline" scan "$fixture" --out "$tmp/out"
check_out "$tmp/out"

echo "smoke-git-install: ok"
