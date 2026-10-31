import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderCoverageJsonSchema } from "../src/schema/coverage.js";
import { renderFindingsJsonSchema } from "../src/schema/finding.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const check = process.argv.includes("--check");

const files = [
  { label: "schema/findings.schema.json", body: renderFindingsJsonSchema() },
  { label: "schema/coverage.schema.json", body: renderCoverageJsonSchema() },
];

if (check) {
  let failed = false;
  for (const file of files) {
    const target = join(root, file.label);
    let current: string;
    try {
      current = readFileSync(target, "utf8");
    } catch {
      console.error(`${file.label} is missing. Run pnpm schema:gen.`);
      failed = true;
      continue;
    }
    if (current !== file.body) {
      console.error(`${file.label} does not match the Zod schema. Run pnpm schema:gen.`);
      failed = true;
    }
  }
  process.exit(failed ? 1 : 0);
}

for (const file of files) {
  const target = join(root, file.label);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, file.body);
}
