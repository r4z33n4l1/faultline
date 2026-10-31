import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv, type ValidateFunction } from "ajv";
import { describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import { writeRunOutput } from "../src/output.js";
import {
  FINGERPRINT_KEY,
  SARIF_SCHEMA_URI,
  sarifLogSchema,
  toSarif,
  type SarifLog,
} from "../src/sarif.js";
import {
  FINDING_CLASSES,
  SEVERITIES,
  findingSchema,
  findingsFileSchema,
  type Finding,
  type FindingClass,
  type FindingsFile,
  type Severity,
} from "../src/schema/finding.js";
import { TOOL_VERSION } from "../src/version.js";
import { loadFixture } from "./fixture.js";

const LEVEL_BY_SEVERITY = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  informational: "note",
} as const satisfies Record<Severity, string>;

const require = createRequire(import.meta.url);
// ajv-formats is CJS; require avoids the ESM default-interop mismatch.
const addFormats = require("ajv-formats") as (ajv: Ajv) => Ajv;

const schemaPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "sarif",
  "sarif-schema-2.1.0.json",
);

function baseFinding(): Finding {
  const finding = findingsFileSchema.parse(loadFixture()).findings[0];
  if (finding === undefined) {
    throw new Error("fixture has no findings");
  }
  return finding;
}

interface FindingPatch {
  id?: string;
  class?: FindingClass;
  cwe?: string;
  omitCwe?: boolean;
  severity?: Severity;
  confidence?: Finding["confidence"]["level"];
  exploitability?: Finding["exploitability"];
  file?: string;
  startLine?: number;
  endLine?: number;
  omitEndLine?: boolean;
  rootCause?: string;
}

function makeFinding(patch: FindingPatch = {}): Finding {
  const finding = structuredClone(baseFinding());
  if (patch.id !== undefined) {
    finding.id = patch.id;
  }
  if (patch.class !== undefined) {
    finding.class = patch.class;
  }
  if (patch.omitCwe === true) {
    delete finding.cwe;
  } else if (patch.cwe !== undefined) {
    finding.cwe = patch.cwe;
  }
  if (patch.severity !== undefined) {
    finding.severity = patch.severity;
  }
  if (patch.confidence !== undefined) {
    finding.confidence = { ...finding.confidence, level: patch.confidence };
  }
  if (patch.exploitability !== undefined) {
    finding.exploitability = patch.exploitability;
  }
  if (patch.file !== undefined) {
    finding.location.file = patch.file;
  }
  if (patch.startLine !== undefined) {
    finding.location.start_line = patch.startLine;
  }
  if (patch.omitEndLine === true) {
    delete finding.location.end_line;
  } else if (patch.endLine !== undefined) {
    finding.location.end_line = patch.endLine;
  }
  if (patch.rootCause !== undefined) {
    finding.root_cause = patch.rootCause;
  }
  return findingSchema.parse(finding);
}

function fileWith(findings: Finding[]): FindingsFile {
  const base = findingsFileSchema.parse(loadFixture());
  return { ...base, findings };
}

function ruleIdFor(finding: Finding): string {
  if (finding.cwe === undefined) {
    return `faultline/${finding.class}`;
  }
  return `${finding.cwe}/${finding.class}`;
}

function expectedFingerprint(findingClass: string, file: string, rootCause: string): string {
  return createHash("sha256")
    .update(JSON.stringify([findingClass, file, rootCause]), "utf8")
    .digest("hex");
}

function onlyResult(log: SarifLog): SarifLog["runs"][0]["results"][number] {
  const result = log.runs[0].results[0];
  if (result === undefined) {
    throw new Error("expected one result");
  }
  return result;
}

function artifactUri(log: SarifLog): string {
  const uri = onlyResult(log).locations[0]?.physicalLocation.artifactLocation.uri;
  if (uri === undefined) {
    throw new Error("missing uri");
  }
  return uri;
}

function fingerprint(log: SarifLog): string {
  const value = onlyResult(log).partialFingerprints[FINGERPRINT_KEY];
  if (value === undefined) {
    throw new Error("missing fingerprint");
  }
  return value;
}

let compiled: ValidateFunction | undefined;

function officialSarifValidator(): ValidateFunction {
  if (compiled !== undefined) {
    return compiled;
  }
  const raw = JSON.parse(readFileSync(schemaPath, "utf8")) as {
    $schema?: string;
    id?: string;
    $id?: string;
  };
  expect(raw.id).toBe(SARIF_SCHEMA_URI);
  // Vendored schema is OASIS draft-04 (`id`). Ajv compiles the draft-07 spelling in memory.
  raw.$schema = "http://json-schema.org/draft-07/schema#";
  raw.$id = raw.id;
  delete raw.id;
  const ajv = new Ajv({ allErrors: true, strict: false, validateSchema: false });
  addFormats(ajv);
  compiled = ajv.compile(raw);
  return compiled;
}

function expectValidSarif(value: unknown): void {
  const validate = officialSarifValidator();
  if (!validate(value)) {
    throw new Error(JSON.stringify(validate.errors, null, 2));
  }
}

describe("toSarif", () => {
  it("maps every severity and carries exploitability, confidence, and verdict", () => {
    const exploitabilities = ["theoretical", "poc", "demonstrated"] as const;
    const confidences = ["low", "medium", "high"] as const;
    const findings = SEVERITIES.map((severity, index) =>
      makeFinding({
        id: `severity-${severity}`,
        severity,
        class: "injection",
        cwe: "CWE-89",
        exploitability: exploitabilities[index % exploitabilities.length],
        confidence: confidences[index % confidences.length],
        rootCause: `severity ${severity}`,
        file: `src/${severity}.ts`,
        startLine: index + 1,
        endLine: index + 2,
      }),
    );
    const log = toSarif(fileWith(findings), "/scan");
    expect(log.runs[0].results).toHaveLength(SEVERITIES.length);
    expect(log.runs[0].tool.driver.rules.map((rule) => rule.id)).toEqual(["CWE-89/injection"]);
    for (const [index, severity] of SEVERITIES.entries()) {
      const result = log.runs[0].results[index];
      const finding = findings[index];
      if (result === undefined || finding === undefined) {
        throw new Error(`missing case ${severity}`);
      }
      expect(result.level).toBe(LEVEL_BY_SEVERITY[severity]);
      expect(result.ruleId).toBe("CWE-89/injection");
      expect(result.message).toEqual({ text: `severity ${severity}` });
      expect(result.properties).toEqual({
        "ai/origin": "faultline",
        "ai/exploitability": finding.exploitability,
        confidence: finding.confidence.level,
        validator_verdict: "confirmed",
      });
      expect(result.locations[0]?.physicalLocation.region).toEqual({
        startLine: index + 1,
        endLine: index + 2,
      });
      expect(result).not.toHaveProperty("fixes");
    }
    expect(findings[0]?.suggested_fix.patch).toBeDefined();
    expectValidSarif(log);
  });

  it("maps every class with and without a CWE and dedupes rules", () => {
    const findings: Finding[] = [];
    for (const findingClass of FINDING_CLASSES) {
      findings.push(
        makeFinding({
          id: `cwe-${findingClass}`,
          class: findingClass,
          cwe: "CWE-22",
          rootCause: `with cwe ${findingClass}`,
          file: `src/${findingClass}.ts`,
        }),
        makeFinding({
          id: `plain-${findingClass}`,
          class: findingClass,
          omitCwe: true,
          rootCause: `without cwe ${findingClass}`,
          file: `lib/${findingClass}.ts`,
          omitEndLine: true,
        }),
        makeFinding({
          id: `again-${findingClass}`,
          class: findingClass,
          cwe: "CWE-22",
          rootCause: `again ${findingClass}`,
          file: `src/${findingClass}-again.ts`,
        }),
      );
    }
    const log = toSarif(fileWith(findings), "/scan");
    const expectedIds: string[] = [];
    const seen = new Set<string>();
    findings.forEach((finding, index) => {
      const ruleId = ruleIdFor(finding);
      expect(log.runs[0].results[index]?.ruleId).toBe(ruleId);
      if (!seen.has(ruleId)) {
        seen.add(ruleId);
        expectedIds.push(ruleId);
      }
    });
    expect(log.runs[0].tool.driver.rules.map((rule) => rule.id)).toEqual(expectedIds);
    expect(expectedIds).toEqual(
      FINDING_CLASSES.flatMap((findingClass) => [
        `CWE-22/${findingClass}`,
        `faultline/${findingClass}`,
      ]),
    );
    const injection = log.runs[0].tool.driver.rules.find((rule) => rule.id === "CWE-22/injection");
    expect(injection?.shortDescription.text).toBe("CWE-22 Injection.");
    const secrets = log.runs[0].tool.driver.rules.find((rule) => rule.id === "faultline/secrets");
    expect(secrets?.shortDescription.text).toBe("Exposed secret.");
    const plain = log.runs[0].results.find((result) => result.message.text === "without cwe ssrf");
    expect(plain?.locations[0]?.physicalLocation.region).toEqual({ startLine: 40 });
    expect(plain?.locations[0]?.physicalLocation.region).not.toHaveProperty("endLine");
    expectValidSarif(log);
  });

  it("emits scan-root-relative URIs and a stable fingerprint", () => {
    const rootCause = "same root cause";
    const variants = [
      "src/db.ts",
      "./src/db.ts",
      "src\\db.ts",
      "/scan/src/db.ts",
      "/scan/./src/../src/db.ts",
    ];
    const fingerprintValue = expectedFingerprint("injection", "src/db.ts", rootCause);
    for (const file of variants) {
      const log = toSarif(
        fileWith([
          makeFinding({
            file,
            rootCause,
            id: file,
            startLine: 3,
            severity: "low",
            cwe: "CWE-999",
          }),
        ]),
        "/scan",
      );
      expect(artifactUri(log)).toBe("src/db.ts");
      expect(fingerprint(log)).toBe(fingerprintValue);
      expect(JSON.stringify(log)).not.toContain("/scan");
    }

    const moved = toSarif(
      fileWith([
        makeFinding({
          file: "src/db.ts",
          rootCause,
          id: "other-id",
          startLine: 90,
          omitEndLine: true,
          severity: "critical",
          omitCwe: true,
        }),
      ]),
      "/somewhere-else",
    );
    expect(fingerprint(moved)).toBe(fingerprintValue);

    const changedCause = toSarif(
      fileWith([makeFinding({ rootCause: "different cause", file: "src/db.ts" })]),
      "/scan",
    );
    const changedClass = toSarif(
      fileWith([
        makeFinding({ rootCause, file: "src/db.ts", class: "ssrf", omitCwe: true, id: "ssrf" }),
      ]),
      "/scan",
    );
    const changedFile = toSarif(
      fileWith([makeFinding({ rootCause, file: "src/other.ts", id: "other" })]),
      "/scan",
    );
    expect(fingerprint(changedCause)).not.toBe(fingerprintValue);
    expect(fingerprint(changedClass)).not.toBe(fingerprintValue);
    expect(fingerprint(changedFile)).not.toBe(fingerprintValue);

    const spaced = toSarif(
      fileWith([
        makeFinding({
          file: "/scan/src/my file.ts",
          rootCause: "space",
          id: "space",
          omitEndLine: true,
        }),
      ]),
      "/scan",
    );
    expect(artifactUri(spaced)).toBe("src/my%20file.ts");
    expect(fingerprint(spaced)).toBe(expectedFingerprint("injection", "src/my file.ts", "space"));

    const outside = toSarif(
      fileWith([makeFinding({ file: "/elsewhere/lib/a.ts", rootCause: "out", id: "out" })]),
      "/scan",
    );
    expect(artifactUri(outside)).toBe("../elsewhere/lib/a.ts");

    const escaped = toSarif(
      fileWith([makeFinding({ file: "src/../../outside.ts", rootCause: "rel", id: "rel" })]),
      "/scan",
    );
    expect(artifactUri(escaped)).toBe("../outside.ts");

    const windows = toSarif(
      fileWith([
        makeFinding({ file: "C:\\scan\\src\\win.ts", rootCause: "win", id: "win", omitCwe: true }),
      ]),
      "C:\\scan",
    );
    expect(artifactUri(windows)).toBe("src/win.ts");
    expect(fingerprint(windows)).toBe(expectedFingerprint("injection", "src/win.ts", "win"));

    const otherDrive = toSarif(
      fileWith([
        makeFinding({ file: "D:\\secret\\a.ts", rootCause: "drive", id: "drive", omitCwe: true }),
      ]),
      "C:\\scan",
    );
    expect(artifactUri(otherDrive)).toBe("D/secret/a.ts");
    expect(artifactUri(otherDrive)).not.toMatch(/^[A-Za-z]:/);
    expect(artifactUri(otherDrive).includes("\\")).toBe(false);

    const again = toSarif(
      fileWith([makeFinding({ file: "/scan/src/db.ts", rootCause, id: "rerun" })]),
      "/scan",
    );
    const repeated = toSarif(
      fileWith([makeFinding({ file: "/scan/src/db.ts", rootCause, id: "rerun" })]),
      "/scan",
    );
    expect(again).toEqual(repeated);

    for (const log of [spaced, outside, escaped, windows, otherDrive, again]) {
      for (const result of log.runs[0].results) {
        const uri = result.locations[0]?.physicalLocation.artifactLocation.uri ?? "";
        expect(uri.startsWith("/")).toBe(false);
        expect(uri.includes("\\")).toBe(false);
        expect(uri).not.toMatch(/^[A-Za-z]:/);
        expect(uri.includes("://")).toBe(false);
      }
      expectValidSarif(log);
    }
  });

  it("writes an empty run with driver metadata and no results", () => {
    const file = { ...findingsFileSchema.parse(loadFixture()), findings: [] };
    const log = toSarif(file, "/scan");
    const packagePath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    const pkg = JSON.parse(readFileSync(packagePath, "utf8")) as { version: string };
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toBe(SARIF_SCHEMA_URI);
    expect(log.runs).toHaveLength(1);
    expect(log.runs[0].results).toEqual([]);
    expect(log.runs[0].tool.driver).toEqual({
      name: "faultline",
      version: pkg.version,
      rules: [],
    });
    expect(log.runs[0].tool.driver.version).toBe(TOOL_VERSION);
    expectValidSarif(log);
    expect(toSarif(file, "/scan")).toEqual(log);
  });
});

describe("findings.sarif writer", () => {
  it("drops unconfirmed findings and matches toSarif of the confirmed file", async () => {
    const draft = findingsFileSchema.parse(structuredClone(loadFixture()));
    const confirmed = draft.findings[0];
    const second = draft.findings[1];
    if (confirmed === undefined || second === undefined) {
      throw new Error("fixture findings missing");
    }
    confirmed.location.file = "/repo/src/db.ts";
    const rejected = {
      ...structuredClone(second),
      id: "fp_rejected_marker",
      class: "ssrf",
      root_cause: "REJECTED_MARKER should never be written.",
      validator_verdict: "rejected",
    };
    const needsValidation = {
      ...structuredClone(confirmed),
      id: "fp_needs_validation_marker",
      root_cause: "NEEDS_VALIDATION_MARKER should never be written.",
      validator_verdict: "needs_validation",
    };
    const dir = await mkdtemp(join(tmpdir(), "faultline-sarif-"));
    const written = await writeRunOutput(
      dir,
      {
        ...draft,
        findings: [rejected, confirmed, needsValidation, second],
      },
      { scanRoot: "/repo" },
    );
    expect(written.findings.map((finding) => finding.id)).toEqual([
      "fp_sql_concat_user",
      "fp_hardcoded_token",
    ]);
    const raw = JSON.parse(await readFile(join(dir, "findings.sarif"), "utf8")) as unknown;
    const text = JSON.stringify(raw);
    expect(text).not.toContain("REJECTED_MARKER");
    expect(text).not.toContain("NEEDS_VALIDATION_MARKER");
    expect(text).not.toContain("fp_rejected_marker");
    expect(text).not.toContain("fp_needs_validation_marker");
    expect(text).not.toContain('"fixes"');
    expect(written.findings[0]?.suggested_fix.patch).toBeDefined();
    const parsed = sarifLogSchema.parse(raw);
    expect(parsed).toEqual(toSarif(written, "/repo"));
    expect(parsed.runs[0].results).toHaveLength(2);
    expect(parsed.runs[0].results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      "src/db.ts",
    );
    expect(parsed.runs[0].results.map((result) => result.ruleId)).toEqual([
      "CWE-89/injection",
      "faultline/secrets",
    ]);
    expect(parsed.runs[0].results.map((result) => result.level)).toEqual(["error", "note"]);
    expectValidSarif(raw);
    expect(text).not.toContain("/repo");
  });

  it("scan and pr write schema-valid SARIF with zero results", async () => {
    const dir = await mkdtemp(join(tmpdir(), "faultline-sarif-cli-"));
    const scanOut = join(dir, "scan-out");
    const prOut = join(dir, "pr-out");
    const io = {
      cwd: dir,
      env: {},
      stdout: () => undefined,
      stderr: () => undefined,
    };
    expect(await runCli(["scan", ".", "--out", scanOut], io)).toBe(0);
    expect(await runCli(["pr", "https://github.com/org/repo/pull/1", "--out", prOut], io)).toBe(0);
    for (const out of [scanOut, prOut]) {
      const raw = JSON.parse(await readFile(join(out, "findings.sarif"), "utf8")) as unknown;
      expectValidSarif(raw);
      const parsed = sarifLogSchema.parse(raw);
      expect(parsed.runs[0].results).toEqual([]);
      expect(parsed.runs[0].tool.driver.name).toBe("faultline");
      expect(parsed.runs[0].tool.driver.version).toBe(TOOL_VERSION);
    }
  });
});

describe("official SARIF schema", () => {
  it("rejects a document that is not SARIF 2.1.0", () => {
    const validate = officialSarifValidator();
    expect(validate({ version: "2.0.0", runs: [] })).toBe(false);
    expect(
      validate({
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "faultline" } },
            results: [{ level: "severe", message: { text: "no" } }],
          },
        ],
      }),
    ).toBe(false);
  });
});
