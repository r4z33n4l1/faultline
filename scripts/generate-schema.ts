import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderFindingsJsonSchema } from "../src/schema/finding.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const target = join(root, "schema", "findings.schema.json");
const next = renderFindingsJsonSchema();
const check = process.argv.includes("--check");

if (check) {
  let current = "";
  try {
    current = readFileSync(target, "utf8");
  } catch {
    console.error("schema/findings.schema.json is missing. Run pnpm schema:gen.");
    process.exit(1);
  }
  if (current !== next) {
    console.error(
      "schema/findings.schema.json does not match the Zod schema. Run pnpm schema:gen.",
    );
    process.exit(1);
  }
  process.exit(0);
}

mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, next);
