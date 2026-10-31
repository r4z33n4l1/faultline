import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { renderFindingsJsonSchema } from "../src/schema/finding.js";

it("committed findings schema matches the generator", () => {
  const committed = readFileSync(join(process.cwd(), "schema", "findings.schema.json"), "utf8");
  expect(committed).toBe(renderFindingsJsonSchema());
});
