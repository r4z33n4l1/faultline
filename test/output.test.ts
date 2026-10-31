import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { writeRunOutput } from "../src/output.js";
import { findingsFileSchema, type FindingsFile } from "../src/schema/finding.js";
import { cloneFixture, loadFixture } from "./fixture.js";

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "faultline-"));
}

it("omits rejected candidates from findings.json and report.md", async () => {
  const draft = findingsFileSchema.parse(loadFixture());
  const rejected = {
    ...draft.findings[0],
    id: "fp_rejected_marker",
    class: "ssrf",
    root_cause: "REJECTED_MARKER should never be written.",
    validator_verdict: "rejected",
  };
  const needsValidation = {
    ...draft.findings[1],
    id: "fp_needs_validation_marker",
    root_cause: "NEEDS_VALIDATION_MARKER should never be written.",
    validator_verdict: "needs_validation",
  };

  const dir = await tempDir();
  const written = await writeRunOutput(dir, {
    ...draft,
    findings: [rejected, draft.findings[0], needsValidation, draft.findings[1]],
  });

  expect(written.findings.map((finding) => finding.id)).toEqual([
    "fp_sql_concat_user",
    "fp_hardcoded_token",
  ]);

  const findingsText = await readFile(join(dir, "findings.json"), "utf8");
  const report = await readFile(join(dir, "report.md"), "utf8");
  const sarifText = await readFile(join(dir, "findings.sarif"), "utf8");
  const parsed = findingsFileSchema.parse(JSON.parse(findingsText) as unknown);
  expect(parsed).toEqual(written);
  expect(findingsText).not.toContain("REJECTED_MARKER");
  expect(findingsText).not.toContain("NEEDS_VALIDATION_MARKER");
  expect(report).not.toContain("REJECTED_MARKER");
  expect(report).not.toContain("NEEDS_VALIDATION_MARKER");
  expect(report).toContain("fp_sql_concat_user");
  expect(sarifText).not.toContain("REJECTED_MARKER");
  expect(sarifText).not.toContain("NEEDS_VALIDATION_MARKER");
  expect(sarifText).not.toContain("fp_rejected_marker");
  expect(sarifText).not.toContain("fp_needs_validation_marker");
  expect(sarifText).toContain("SQL query concatenates the user id from the request.");
});

it("refuses to write when a confirmed finding is invalid", async () => {
  const draft = cloneFixture() as unknown as FindingsFile;
  const finding = {
    ...(draft.findings[0] as object),
    location: { file: "src/db.ts", start_line: 0 },
  };
  const dir = await tempDir();
  await expect(
    writeRunOutput(dir, {
      schema_version: "1",
      tool: draft.tool,
      run: draft.run,
      findings: [finding],
    }),
  ).rejects.toThrow(/findings\.0\.location\.start_line/);
  await expect(readFile(join(dir, "findings.json"), "utf8")).rejects.toThrow();
  await expect(readFile(join(dir, "report.md"), "utf8")).rejects.toThrow();
  await expect(readFile(join(dir, "findings.sarif"), "utf8")).rejects.toThrow();
});
