import { describe, expect, it } from "vitest";
import { findingsFileSchema, formatZodIssues } from "../src/schema/finding.js";
import { cloneFixture, firstFinding, loadFixture } from "./fixture.js";

function issues(value: unknown): string {
  const parsed = findingsFileSchema.safeParse(value);
  expect(parsed.success).toBe(false);
  if (parsed.success) {
    return "";
  }
  return formatZodIssues(parsed.error);
}

describe("findings schema", () => {
  it("accepts a valid fixture, including optional cwe, end_line, patch, and provider", () => {
    const parsed = findingsFileSchema.parse(loadFixture());
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings[0]?.cwe).toBe("CWE-89");
    expect(parsed.findings[0]?.exploitability).toBe("theoretical");
    expect(parsed.findings[1]?.cwe).toBeUndefined();
    expect(parsed.findings[1]?.location.end_line).toBeUndefined();
    expect(parsed.findings[1]?.suggested_fix.patch).toBeUndefined();
    expect(parsed.run.provider).toBe("fake");
  });

  it("accepts end_line equal to start_line and a run without provider", () => {
    const file = cloneFixture();
    const finding = firstFinding(file);
    const location = finding.location as { start_line: number; end_line?: number };
    location.start_line = 4;
    location.end_line = 4;
    delete finding.cwe;
    const run = file.run as { provider?: string };
    delete run.provider;
    expect(findingsFileSchema.safeParse(file).success).toBe(true);
  });

  it("rejects an extra key", () => {
    const file = cloneFixture();
    firstFinding(file).extra = true;
    expect(issues(file)).toContain("findings.0");
  });

  it("rejects line 0", () => {
    const file = cloneFixture();
    const location = firstFinding(file).location as { start_line: number };
    location.start_line = 0;
    expect(issues(file)).toContain("findings.0.location.start_line");
  });

  it("rejects an evidence line below 1", () => {
    const file = cloneFixture();
    const evidence = firstFinding(file).evidence as { line: number }[];
    const row = evidence[0];
    if (row === undefined) {
      throw new Error("missing evidence");
    }
    row.line = 0;
    expect(issues(file)).toContain("findings.0.evidence.0.line");
  });

  it("rejects end_line before start_line", () => {
    const file = cloneFixture();
    const location = firstFinding(file).location as { start_line: number; end_line: number };
    location.start_line = 12;
    location.end_line = 10;
    expect(issues(file)).toContain("findings.0.location.end_line");
  });

  it("rejects a bad severity", () => {
    const file = cloneFixture();
    firstFinding(file).severity = "severe";
    expect(issues(file)).toContain("findings.0.severity");
  });

  it("rejects a missing exploitability and an unknown value", () => {
    const missing = cloneFixture();
    delete firstFinding(missing).exploitability;
    expect(issues(missing)).toContain("findings.0.exploitability");

    const bad = cloneFixture();
    firstFinding(bad).exploitability = "weaponized";
    expect(issues(bad)).toContain("findings.0.exploitability");
  });

  it("rejects a cwe id that is not CWE-<digits>", () => {
    for (const cwe of ["cwe-89", "CWE-", "CWE-89 ", "89"]) {
      const file = cloneFixture();
      firstFinding(file).cwe = cwe;
      expect(issues(file)).toContain("findings.0.cwe");
    }
  });

  it("rejects a finding that is not confirmed", () => {
    const file = cloneFixture();
    firstFinding(file).validator_verdict = "rejected";
    expect(issues(file)).toContain("findings.0.validator_verdict");
  });
});
