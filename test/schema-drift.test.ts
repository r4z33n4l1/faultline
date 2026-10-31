import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { renderCoverageJsonSchema } from "../src/schema/coverage.js";
import { renderFindingsJsonSchema } from "../src/schema/finding.js";

it("committed findings schema matches the generator", () => {
  const committed = readFileSync(join(process.cwd(), "schema", "findings.schema.json"), "utf8");
  expect(committed).toBe(renderFindingsJsonSchema());
});

it("committed coverage schema matches the generator", () => {
  const committed = readFileSync(join(process.cwd(), "schema", "coverage.schema.json"), "utf8");
  expect(committed).toBe(renderCoverageJsonSchema());
});
