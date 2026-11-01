#!/usr/bin/env bash
# Install faultline the way `npx github:r4z33n4l1/faultline` does, then scan a fixture.
# FAULTLINE_SMOKE_SPEC overrides the package spec. The default is a git+file URL of HEAD,
# which exercises the same npm prepare + bin path without waiting for a GitHub ref.
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
  git clone --quiet --depth 1 "$root" "$tmp/src"
  spec="git+file://$tmp/src"
fi

if [[ ! -d "$fixture" ]]; then
  echo "smoke-git-install: missing fixture $fixture" >&2
  exit 1
fi

out="$tmp/out"
echo "smoke-git-install: npx --package $spec faultline scan <fixture>"

# `--package` is the explicit form of `npx github:r4z33n4l1/faultline scan .`.
npx --yes --package "$spec" -- faultline --version
npx --yes --package "$spec" -- faultline scan "$fixture" --out "$out"

node --input-type=module - "$out" <<'EOF'
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const out = process.argv[2];
if (out === undefined || out.length === 0) {
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
if (!Array.isArray(candidates.candidates)) {
  console.error("candidates.json has no candidates array");
  process.exit(1);
}
if (!Array.isArray(coverage.units) || coverage.units.length === 0) {
  console.error("coverage.json has no units");
  process.exit(1);
}
EOF

echo "smoke-git-install: ok"
