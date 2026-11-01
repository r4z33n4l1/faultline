import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import { executeScan } from "../src/recon/run.js";
import { executePr } from "../src/pr/run.js";
import { parseUnifiedDiff } from "../src/pr/diff.js";
import { sarifLogSchema } from "../src/sarif.js";
import { findingsFileSchema } from "../src/schema/finding.js";
import { FakeProvider } from "../src/providers/types.js";
import type { Candidate } from "../src/schema/candidate.js";
import { findingSchema } from "../src/schema/finding.js";
import { validateCandidates } from "../src/validator/index.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});
async function fixture(source = "function handler(req) { return db.query(req.query.sql); }") {
  const root = await mkdtemp(join(tmpdir(), "faultline-validator-"));
  roots.push(root);
  await writeFile(join(root, "app.ts"), source);
  const candidate: Candidate = {
    class: "injection",
    cwe: "CWE-89",
    severity: "high",
    confidence: { level: "medium", reason: "User input reaches query." },
    location: { file: "app.ts", start_line: 1 },
    symbol: "handler",
    root_cause: "Untrusted query",
    evidence: [{ file: "app.ts", line: 1, note: "Query sink" }],
  };
  return { root, candidate };
}
function reply(verdict = "confirmed", line = 1) {
  return JSON.stringify({
    verdict,
    summary: `Review: ${verdict}`,
    evidence: [{ file: "app.ts", line, note: "Reviewed source" }],
  });
}
it("requires two fresh agreeing confirmations and constructs schema-valid findings", async () => {
  const { root, candidate } = await fixture();
  const provider = new FakeProvider(reply());
  const result = await validateCandidates([candidate], { root, provider });
  expect(result.disproved).toEqual([]);
  expect(result.findings).toHaveLength(1);
  expect(findingSchema.parse(result.findings[0]).disproof_attempts).toHaveLength(2);
  expect(provider.calls).toHaveLength(2);
  expect(provider.calls[0]?.messages).not.toEqual(provider.calls[1]?.messages);
  expect(provider.calls[1]?.messages).toHaveLength(2);
});
it.each(["disproved", "uncertain"])("drops %s with a reason", async (verdict) => {
  const { root, candidate } = await fixture();
  const provider = new FakeProvider(reply(verdict));
  const result = await validateCandidates([candidate], { root, provider });
  expect(result.findings).toEqual([]);
  expect(result.disproved[0]).toMatchObject({
    verdict: verdict === "disproved" ? "rejected" : "inconclusive",
    reason: `Review: ${verdict}`,
  });
  expect(provider.calls).toHaveLength(1);
});
it("drops re-verification disagreement", async () => {
  const { root, candidate } = await fixture();
  let count = 0;
  const provider = new FakeProvider(() => reply(count++ === 0 ? "confirmed" : "uncertain"));
  expect((await validateCandidates([candidate], { root, provider })).findings).toEqual([]);
  expect(provider.calls).toHaveLength(2);
});
it.each([
  reply("confirmed", 100),
  "not json",
  JSON.stringify({ verdict: "confirmed" }),
  reply("invalid"),
])("drops malformed or ungrounded output", async (text) => {
  const { root, candidate } = await fixture();
  const result = await validateCandidates([candidate], { root, provider: new FakeProvider(text) });
  expect(result.findings).toEqual([]);
  expect(result.disproved[0]?.verdict).toBe("inconclusive");
});
it("heuristically promotes medium confidence, drops low confidence, and deduplicates root causes", async () => {
  const { root, candidate } = await fixture();
  const result = await validateCandidates(
    [
      candidate,
      { ...candidate, root_cause: "Different wording" },
      { ...candidate, confidence: { level: "low", reason: "Weak signal" } },
    ],
    { root },
  );
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]?.disproof_attempts[0]?.role).toBe("heuristic-disproof");
  expect(result.disproved.map((item) => item.reason)).toEqual([
    "Duplicate root cause.",
    "Low confidence; heuristic disproof cannot establish the issue.",
  ]);
});
it.each([
  ["authz_idor", "function handler(req) { authorize(req.user); }"],
  ["injection", 'function handler(req) { db.query("select ?", [req.id]); }'],
  ["secrets", 'function handler() { const token = "dummy-token"; }'],
  ["ssrf", "function handler(req) { if (allowedHosts.includes(req.host)) fetch(req.url); }"],
] as const)("heuristically refutes %s", async (klass, source) => {
  const { root, candidate } = await fixture(source);
  const result = await validateCandidates([{ ...candidate, class: klass }], { root });
  expect(result.findings).toEqual([]);
  expect(result.disproved[0]?.verdict).toBe("rejected");
});
it("redacts secrets from source, candidate prose, model summaries and drop reasons", async () => {
  const secret = `ghp_${"aB12".repeat(9)}`;
  const { root, candidate } = await fixture(`function handler() { const token = "${secret}"; }`);
  candidate.class = "secrets";
  candidate.root_cause = `Hardcoded ${secret}`;
  for (const verdict of ["confirmed", "disproved"]) {
    const provider = new FakeProvider(
      JSON.stringify({
        verdict,
        summary: `Credential ${secret}`,
        evidence: [{ file: "app.ts", line: 1, note: secret }],
      }),
    );
    const result = await validateCandidates([candidate], { root, provider });
    expect(JSON.stringify(provider.calls)).not.toContain(secret);
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(result)).toContain("<redacted>");
  }
});

it("does not refute a caller-supplied id lookup, a $where argument, or a session secret literal", async () => {
  const root = await mkdtemp(join(tmpdir(), "faultline-validator-shapes-"));
  roots.push(root);
  await writeFile(
    join(root, "app.ts"),
    [
      "export function edit(req) {",
      "  return db.User.find({ where: { id: req.body.id } });",
      "}",
      "export function render(req) {",
      "  return { userId: req.user.id };",
      "}",
      "export function criteria(threshold) {",
      "  return { $where: `this.stocks > '${threshold}'` };",
      "}",
      "export const session = { secret: 'keyboard cat' };",
      "",
    ].join("\n"),
  );
  const base = {
    severity: "medium" as const,
    confidence: { level: "medium" as const, reason: "Reviewed pattern." },
    evidence: [{ file: "app.ts", line: 2, note: "Cited sink." }],
  };
  const result = await validateCandidates(
    [
      {
        ...base,
        class: "authz_idor",
        cwe: "CWE-639",
        location: { file: "app.ts", start_line: 2, end_line: 2 },
        symbol: "find",
        root_cause: "Lookup uses the caller id",
      },
      {
        ...base,
        class: "injection",
        cwe: "CWE-943",
        location: { file: "app.ts", start_line: 8, end_line: 8 },
        symbol: "$where",
        root_cause: "Dynamic where",
        evidence: [{ file: "app.ts", line: 8, note: "Where clause." }],
      },
      {
        ...base,
        class: "secrets",
        cwe: "CWE-798",
        location: { file: "app.ts", start_line: 10, end_line: 10 },
        symbol: "secret",
        root_cause: "Session secret literal",
        evidence: [{ file: "app.ts", line: 10, note: "Literal." }],
      },
    ],
    { root },
  );
  expect(result.disproved.map((item) => item.reason)).not.toContain(
    "Ownership or authorization check is present.",
  );
  expect(result.disproved.map((item) => item.verdict)).not.toContain("rejected");
  expect(result.findings.map((finding) => finding.class).sort()).toEqual([
    "authz_idor",
    "injection",
    "secrets",
  ]);
});

it.each(["scan", "pr"] as const)(
  "writes validated %s findings and report reasons",
  async (mode) => {
    const { root, candidate } = await fixture(
      'app.get("/items/:id", (req, res) => { const item = prisma.item.findUnique({ where: { id: req.params.id } }); res.json(item); });',
    );
    candidate.class = "authz_idor";
    candidate.cwe = "CWE-639";
    candidate.symbol = "app.get";
    const provider = new FakeProvider((input) => {
      if (input.jsonSchema !== undefined) return reply();
      if (input.messages[0]?.content.includes("authz_idor"))
        return JSON.stringify({ candidates: [candidate] });
      return "";
    });
    const outDir = join(root, "out");
    if (mode === "scan") {
      await executeScan({ target: root, cwd: root, outDir, provider });
    } else {
      await executePr({
        repo: root,
        repoLabel: root,
        diffLabel: "change.diff",
        outDir,
        provider,
        context: 0,
        parsed: parseUnifiedDiff(
          "diff --git a/app.ts b/app.ts\n--- a/app.ts\n+++ b/app.ts\n@@ -1 +1 @@\n-old\n+new\n",
        ),
      });
    }
    const file = findingsFileSchema.parse(
      JSON.parse(await readFile(join(outDir, "findings.json"), "utf8")) as unknown,
    );
    expect(file.findings).toHaveLength(1);
    expect(provider.calls.filter((call) => call.jsonSchema !== undefined)).toHaveLength(2);
    const sarif = sarifLogSchema.parse(
      JSON.parse(await readFile(join(outDir, "findings.sarif"), "utf8")) as unknown,
    );
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(await readFile(join(outDir, "report.md"), "utf8")).toContain("1 confirmed finding.");
  },
);
it.each(["scan", "pr"] as const)(
  "%s --no-validate preserves candidates-only output",
  async (mode) => {
    const { root, candidate } = await fixture(
      'app.get("/items/:id", (req, res) => { const item = prisma.item.findUnique({ where: { id: req.params.id } }); res.json(item); });',
    );
    candidate.class = "authz_idor";
    candidate.cwe = "CWE-639";
    candidate.symbol = "app.get";
    const provider = new FakeProvider((input) =>
      input.messages[0]?.content.includes("authz_idor")
        ? JSON.stringify({ candidates: [candidate] })
        : "",
    );
    const outDir = join(root, "out");
    const stderr: string[] = [];
    const args = mode === "scan" ? ["scan", root] : ["pr", "-", "--repo", root];
    expect(
      await runCli([...args, "--out", outDir, "--no-validate"], {
        cwd: root,
        env: {},
        provider,
        stdout() {},
        stderr(text) {
          stderr.push(text);
        },
        stdin:
          "diff --git a/app.ts b/app.ts\n--- a/app.ts\n+++ b/app.ts\n@@ -1 +1 @@\n-old\n+new\n",
      }),
    ).toBe(0);
    expect(stderr).toEqual([]);
    expect(provider.calls.every((call) => call.jsonSchema === undefined)).toBe(true);
    const file = findingsFileSchema.parse(
      JSON.parse(await readFile(join(outDir, "findings.json"), "utf8")) as unknown,
    );
    expect(file.findings).toEqual([]);
    expect(await readFile(join(outDir, "report.md"), "utf8")).toContain(
      "unvalidated candidates: 1",
    );
  },
);
