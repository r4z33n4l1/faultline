import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { executeBench } from "../src/bench/run.js";
import { runCli, type CliIo } from "../src/cli.js";
import { parseModelCandidates } from "../src/schema/candidate.js";
import { coverageFileSchema } from "../src/schema/coverage.js";
import { findingsFileSchema } from "../src/schema/finding.js";
import { candidatesFileSchema } from "../src/schema/candidate.js";
import { FakeProvider, type CompleteInput } from "../src/providers/types.js";
import { validateCandidates } from "../src/validator/index.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const APP = [
  'import express from "express";',
  "const app = express();",
  'app.get("/users", async (req, res) => {',
  "  const name = req.query.name;",
  '  const rows = await db.query("SELECT " + name);',
  "  res.json(rows);",
  "});",
  "export { app };",
  "",
].join("\n");

function quietIo(root: string, provider: FakeProvider): CliIo {
  return {
    cwd: root,
    env: {},
    provider,
    stdout() {},
    stderr() {},
  };
}

async function appRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "faultline-malformed-"));
  roots.push(root);
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(join(root, "src", "app.ts"), APP, "utf8");
  await mkdir(join(root, "routes"), { recursive: true });
  await writeFile(
    join(root, "routes", "users.ts"),
    ["export function show(req, res) {", "  res.send(req.query.q);", "}", ""].join("\n"),
    "utf8",
  );
  await writeFile(
    join(root, "truth.json"),
    `${JSON.stringify({
      schema_version: "1",
      entries: [
        {
          id: "users-query",
          class: "injection",
          cwe: "CWE-89",
          file: "src/app.ts",
          start_line: 5,
          end_line: 5,
          vulnerable: true,
        },
      ],
    })}\n`,
    "utf8",
  );
  return root;
}

it("fills a missing root_cause from the sink and drops other invalid fields", () => {
  const base = {
    class: "injection",
    cwe: "CWE-89",
    severity: "high",
    confidence: { level: "medium", reason: "request text reaches query" },
    location: { file: "src/app.ts", start_line: 5 },
    symbol: "query",
    evidence: [{ file: "src/app.ts", line: 5, note: "string query" }],
  };
  const derived = "GET /users passes request query input into a SQL query built from strings";
  const filled = parseModelCandidates(JSON.stringify({ candidates: [base] }), "injection", derived);
  expect(filled.malformed).toEqual([]);
  expect(filled.candidates[0]?.root_cause).toBe(derived);

  const secret = `ghp_${"d".repeat(20)}`;
  const broken = parseModelCandidates(
    JSON.stringify({
      candidates: [
        {
          class: "injection",
          severity: "high",
          validator_verdict: "confirmed",
          note: secret,
        },
      ],
    }),
    "injection",
    derived,
  );
  expect(broken.candidates).toEqual([]);
  expect(broken.malformed).toHaveLength(1);
  expect(broken.malformed[0]?.source).toBe("hunter");
  expect(broken.malformed[0]?.reason).toContain("location");
  expect(broken.malformed[0]?.reason).not.toContain(secret);

  const fromFindings = parseModelCandidates(
    JSON.stringify({ findings: [{ class: "injection", severity: "high", note: secret }] }),
    "injection",
    derived,
  );
  expect(fromFindings.candidates).toEqual([]);
  expect(fromFindings.malformed).toHaveLength(1);
  expect(fromFindings.malformed[0]?.reason).not.toContain(secret);
});

it("records a malformed validator reply without a provider error", async () => {
  const root = await appRoot();
  const provider = new FakeProvider(
    JSON.stringify({
      validator_verdict: "confirmed",
      class: "injection",
      id: "model-finding",
    }),
  );
  const result = await validateCandidates(
    [
      {
        class: "injection",
        cwe: "CWE-89",
        severity: "high",
        confidence: { level: "medium", reason: "request text reaches query" },
        location: { file: "src/app.ts", start_line: 5 },
        symbol: "query",
        root_cause: "GET /users passes request query input into query",
        evidence: [{ file: "src/app.ts", line: 5, note: "string query" }],
      },
    ],
    { root, provider },
  );
  expect(result.errors).toEqual([]);
  expect(result.findings).toEqual([]);
  expect(result.malformed.length).toBeGreaterThan(0);
  expect(result.malformed.every((item) => item.source === "validator")).toBe(true);
  expect(result.inconclusive[0]?.reason).toBe("Malformed reply or ungrounded evidence.");
});

it("completes a bench run when the model returns a finding missing required fields", async () => {
  const root = await appRoot();
  const secret = `ghp_${"e".repeat(20)}`;
  const badFinding = {
    sites: [{ class: "injection", reason: `uses ${secret}` }],
    candidates: [
      {
        class: "injection",
        severity: "high",
        validator_verdict: "confirmed",
        id: "model-finding",
        note: secret,
      },
    ],
    verdict: "confirmed",
    summary: secret,
    root_cause: undefined,
  };
  const provider = new FakeProvider((input: CompleteInput) => {
    const system = input.messages[0]?.content ?? "";
    if (system.includes("architecture summary")) {
      return "The HTTP edge is the trust boundary.";
    }
    return JSON.stringify(badFinding);
  });
  const out = join(root, "out");
  expect(
    await runCli(
      [
        "bench",
        root,
        "--stage",
        "findings",
        "--out",
        out,
        "--max-sites",
        "4",
        "--discovery-budget",
        "4",
      ],
      quietIo(root, provider),
    ),
  ).toBe(0);

  const findings = findingsFileSchema.parse(
    JSON.parse(await readFile(join(out, "findings.json"), "utf8")) as unknown,
  );
  const candidates = candidatesFileSchema.parse(
    JSON.parse(await readFile(join(out, "candidates.json"), "utf8")) as unknown,
  );
  const coverage = coverageFileSchema.parse(
    JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as unknown,
  );
  const report = await readFile(join(out, "report.md"), "utf8");
  expect(findings.findings).toEqual([]);
  expect(findings.run.provider_error_count).toBe(0);
  expect(findings.run.malformed_count).toBeGreaterThan(0);
  expect(candidates.candidates).toEqual([]);
  expect(coverage.malformed.length).toBeGreaterThan(0);
  expect(coverage.malformed.length).toBeLessThanOrEqual(findings.run.malformed_count ?? 0);
  expect(coverage.malformed.some((item) => item.source === "discovery")).toBe(true);
  expect(coverage.malformed.some((item) => item.source === "hunter")).toBe(true);
  expect(coverage.malformed.some((item) => item.reason.includes("expected"))).toBe(true);
  expect(report).toContain(`Malformed model output: ${findings.run.malformed_count}.`);
  expect(report).toContain("## Malformed model output");
  expect(report).not.toContain(secret);

  const dumped = [
    JSON.stringify(findings),
    JSON.stringify(candidates),
    JSON.stringify(coverage),
    report,
    await readFile(join(out, "architecture.md"), "utf8"),
  ].join("\n");
  expect(dumped).not.toContain(secret);

  const again = await executeBench({
    target: root,
    cwd: root,
    outDir: join(root, "bench-again"),
    stage: "findings",
    truthPath: join(root, "truth.json"),
    model: null,
    provider,
    maxSites: 4,
    discoveryBudget: 4,
  });
  expect(again.run.provider_error_count).toBe(0);
});

it("keeps a model candidate whose only missing field is root_cause", async () => {
  const root = await appRoot();
  const derived = "GET /users passes request query input into a SQL query built from strings";
  const provider = new FakeProvider((input: CompleteInput) => {
    const system = input.messages[0]?.content ?? "";
    if (system.includes("architecture summary")) {
      return "The HTTP edge is the trust boundary.";
    }
    if (system.includes("list candidate security sites")) {
      return '{"sites":[]}';
    }
    if (input.jsonSchema !== undefined) {
      return JSON.stringify({
        verdict: "confirmed",
        summary: "The query is built from the request string.",
        evidence: [{ file: "src/app.ts", line: 5, note: "query call" }],
      });
    }
    if (system.includes("You hunt injection")) {
      return JSON.stringify({
        candidates: [
          {
            class: "injection",
            cwe: "CWE-89",
            severity: "high",
            confidence: { level: "medium", reason: "request text reaches query" },
            location: { file: "src/app.ts", start_line: 5 },
            symbol: "query",
            evidence: [{ file: "src/app.ts", line: 5, note: "string query" }],
          },
        ],
      });
    }
    return '{"candidates":[]}';
  });
  const out = join(root, "out");
  expect(
    await runCli(
      ["scan", root, "--out", out, "--max-sites", "4", "--discovery-budget", "2"],
      quietIo(root, provider),
    ),
  ).toBe(0);
  const findings = findingsFileSchema.parse(
    JSON.parse(await readFile(join(out, "findings.json"), "utf8")) as unknown,
  );
  const candidates = candidatesFileSchema.parse(
    JSON.parse(await readFile(join(out, "candidates.json"), "utf8")) as unknown,
  );
  const kept = candidates.candidates.find((candidate) => candidate.root_cause === derived);
  expect(kept).toBeDefined();
  expect(findings.findings.some((finding) => finding.root_cause === derived)).toBe(true);
  expect(findings.run.provider_error_count).toBe(0);
  const hunterPrompt = provider.calls
    .filter((call) => call.messages[0]?.content.includes("You hunt injection"))
    .map((call) => call.messages.map((message) => message.content).join("\n"))
    .join("\n");
  expect(hunterPrompt).not.toContain(derived);
  const validatorPrompt = provider.calls
    .filter((call) => call.jsonSchema !== undefined)
    .map((call) => call.messages.map((message) => message.content).join("\n"))
    .join("\n");
  expect(validatorPrompt).toContain(derived);
});
