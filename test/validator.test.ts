import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { executeBench } from "../src/bench/run.js";
import { benchResultSchema } from "../src/bench/result.js";
import { runCli } from "../src/cli.js";
import { executeScan } from "../src/recon/run.js";
import { executePr } from "../src/pr/run.js";
import { parseUnifiedDiff } from "../src/pr/diff.js";
import { sarifLogSchema } from "../src/sarif.js";
import { findingsFileSchema } from "../src/schema/finding.js";
import { FakeProvider } from "../src/providers/types.js";
import type { Candidate } from "../src/schema/candidate.js";
import { findingSchema } from "../src/schema/finding.js";
import { VALIDATOR_PACK_MAX_CHARS } from "../src/validator/context.js";
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
it("downgrades an uncited disproof to inconclusive", async () => {
  const { root, candidate } = await fixture();
  const provider = new FakeProvider(reply("disproved"));
  const result = await validateCandidates([candidate], { root, provider });
  expect(result.findings).toEqual([]);
  expect(result.disproved).toEqual([]);
  expect(result.inconclusive[0]).toMatchObject({
    kept: false,
    reason: "Disproof omitted a grounded guard. Review: disproved",
  });
  expect(provider.calls).toHaveLength(1);
  expect(provider.calls[0]?.messages[0]?.content).toContain(
    "Without that citation, the verdict cannot be disproved.",
  );
});
it("drops uncertain as inconclusive", async () => {
  const { root, candidate } = await fixture();
  const provider = new FakeProvider(reply("uncertain"));
  const result = await validateCandidates([candidate], { root, provider });
  expect(result.findings).toEqual([]);
  expect(result.disproved).toEqual([]);
  expect(result.inconclusive[0]).toMatchObject({ kept: false, reason: "Review: uncertain" });
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
  expect(result.disproved).toEqual([]);
  expect(result.inconclusive[0]?.reason).toBe("Malformed reply or ungrounded evidence.");
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
  expect(result.disproved.map((item) => item.reason)).toEqual(["Duplicate root cause."]);
  expect(result.inconclusive.map((item) => item.reason)).toEqual([
    "Low confidence; heuristic disproof cannot establish the issue.",
  ]);
  expect(result.inconclusive[0]?.kept).toBe(false);
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
  expect(result.inconclusive).toEqual([]);
  expect(result.disproved[0]?.reason.length).toBeGreaterThan(0);
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
  expect(result.disproved).toEqual([]);
  expect(result.inconclusive).toEqual([]);
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

function guardReply(line: number) {
  return JSON.stringify({
    verdict: "disproved",
    summary: "A host allowlist guards the outbound call.",
    evidence: [{ file: "app.ts", line, note: "Allowlist check." }],
    guard: { file: "app.ts", line, note: "allowedHosts.includes is the guard." },
  });
}

it("accepts a disproof that cites a grounded guard", async () => {
  const { root, candidate } = await fixture(
    "function handler(req) {\n  if (allowedHosts.includes(req.host)) return;\n  return fetch(req.url);\n}\n",
  );
  candidate.class = "ssrf";
  candidate.location = { file: "app.ts", start_line: 1, end_line: 4 };
  const provider = new FakeProvider(guardReply(2));
  const result = await validateCandidates([candidate], { root, provider });
  expect(result.findings).toEqual([]);
  expect(result.inconclusive).toEqual([]);
  expect(result.disproved[0]?.reason).toBe("A host allowlist guards the outbound call.");
  expect(provider.calls).toHaveLength(1);
});

it("downgrades a disproof whose guard line is not in the file", async () => {
  const { root, candidate } = await fixture(
    "function handler(req) {\n  if (allowedHosts.includes(req.host)) return;\n  return fetch(req.url);\n}\n",
  );
  const provider = new FakeProvider(
    JSON.stringify({
      verdict: "disproved",
      summary: "A guard was claimed on a missing line.",
      evidence: [{ file: "app.ts", line: 1, note: "Handler." }],
      guard: { file: "app.ts", line: 40, note: "This line is not in the file." },
    }),
  );
  const result = await validateCandidates([candidate], { root, provider });
  expect(result.disproved).toEqual([]);
  expect(result.inconclusive[0]?.reason).toContain("Disproof omitted a grounded guard.");
  expect(result.inconclusive[0]?.kept).toBe(false);
});

it("keeps inconclusive candidates only when the policy flag is on", async () => {
  const { root, candidate } = await fixture();
  const dropped = await validateCandidates([candidate], {
    root,
    provider: new FakeProvider(reply("uncertain")),
  });
  expect(dropped.findings).toEqual([]);
  expect(dropped.inconclusive[0]?.kept).toBe(false);

  const provider = new FakeProvider(reply("uncertain"));
  const kept = await validateCandidates([candidate], {
    root,
    provider,
    keepInconclusive: true,
  });
  expect(provider.calls).toHaveLength(1);
  expect(kept.inconclusive[0]?.kept).toBe(true);
  expect(kept.findings).toHaveLength(1);
  expect(kept.findings[0]).toMatchObject({
    validator_verdict: "inconclusive",
    confidence: { level: "low" },
  });
  expect(kept.findings[0]?.confidence.reason).toContain("--keep-inconclusive");
  expect(kept.findings[0]?.disproof_attempts[0]?.verdict).toBe("inconclusive");

  const confirming = new FakeProvider(reply());
  const confirmed = await validateCandidates([candidate], {
    root,
    provider: confirming,
    keepInconclusive: true,
  });
  expect(confirming.calls).toHaveLength(2);
  expect(confirmed.findings[0]?.validator_verdict).toBe("confirmed");
  expect(confirmed.inconclusive).toEqual([]);
});

it("sends a bounded redacted context pack with the route chain and local helpers", async () => {
  const secret = `ghp_${"aB12".repeat(9)}`;
  const root = await mkdtemp(join(tmpdir(), "faultline-validator-pack-"));
  roots.push(root);
  const helperPad = Array.from({ length: 60 }, () => "  const pad = 1;").join("\n");
  await writeFile(
    join(root, "app.ts"),
    [
      "function requireAuth(req, res, next) { return next(); }",
      "function loadOwner(id) {",
      "  return db.user.find(id);",
      helperPad,
      '  const marker = "HELPER_TAIL_MARKER";',
      "  return id;",
      "}",
      "function unused() {",
      `  const token = "${secret}";`,
      "  return token;",
      "}",
      "function getItem(req, res) {",
      `  const leaked = "${secret}";`,
      "  const row = loadOwner(req.params.id);",
      "  return res.json(row);",
      "}",
      "",
    ].join("\n"),
  );
  await writeFile(
    join(root, "routes.ts"),
    ["app.use(requireAuth);", 'app.get("/items/:id", requireAuth, getItem);', ""].join("\n"),
  );
  const appLines = (await readFile(join(root, "app.ts"), "utf8")).split("\n");
  const getItemLine = appLines.findIndex((line) => line.startsWith("function getItem")) + 1;
  const candidate: Candidate = {
    class: "authz_idor",
    cwe: "CWE-639",
    severity: "high",
    confidence: { level: "medium", reason: "Object id without an ownership check." },
    location: { file: "app.ts", start_line: getItemLine, end_line: getItemLine + 3 },
    symbol: "getItem",
    root_cause: "getItem loads a stored object by id",
    evidence: [{ file: "app.ts", line: getItemLine + 2, note: "loadOwner uses the request id." }],
  };
  const provider = new FakeProvider(reply());
  await validateCandidates([candidate], {
    root,
    provider,
    inventory: {
      source_files: ["app.ts", "routes.ts"],
      routes: [{ path: "routes.ts", line: 2, note: "GET /items/:id" }],
      auth: [
        { path: "routes.ts", line: 1, note: "requireAuth" },
        { path: "routes.ts", line: 2, note: "requireAuth" },
      ],
    },
  });
  const user = provider.calls[0]?.messages[1]?.content ?? "";
  expect(user).toContain("GET /items/:id");
  expect(user).toContain("requireAuth");
  expect(user).toContain("loadOwner");
  expect(user).toContain("function getItem");
  expect(user).not.toContain("HELPER_TAIL_MARKER");
  expect(user).not.toContain("function unused");
  expect(user).not.toContain(secret);
  expect(user).toContain("<redacted>");
  const fenced = user.split("untrusted\n")[1]?.split("\n```")[0] ?? user;
  expect(fenced.length).toBeLessThanOrEqual(VALIDATOR_PACK_MAX_CHARS);
});

it("attaches a route registration through the resolved handler map", async () => {
  const root = await mkdtemp(join(tmpdir(), "faultline-validator-handler-"));
  roots.push(root);
  await writeFile(
    join(root, "search.ts"),
    [
      "export function search() {",
      "  return (req, res) => {",
      "    return db.query(`SELECT ${req.query.q}`);",
      "  };",
      "}",
      "",
    ].join("\n"),
  );
  await writeFile(join(root, "server.ts"), 'app.get("/rest/search", search());\n');
  const candidate: Candidate = {
    class: "injection",
    cwe: "CWE-89",
    severity: "high",
    confidence: { level: "low", reason: "Request input reaches a query." },
    location: { file: "search.ts", start_line: 3, end_line: 3 },
    symbol: "query",
    root_cause: "search passes request query input into a SQL query",
    evidence: [{ file: "search.ts", line: 3, note: "SQL sink." }],
  };
  const provider = new FakeProvider(reply());
  await validateCandidates([candidate], {
    root,
    provider,
    inventory: {
      source_files: ["search.ts", "server.ts"],
      routes: [{ path: "server.ts", line: 1, note: "GET /rest/search" }],
      auth: [],
      handlers: [
        {
          routeFile: "server.ts",
          routeLine: 1,
          route: "GET /rest/search",
          mountedPath: "/rest/search",
          handlerFile: "search.ts",
          handlerLine: 2,
          handlerEndLine: 4,
          symbol: "search",
        },
      ],
    },
  });
  const user = provider.calls[0]?.messages[1]?.content ?? "";
  expect(user).toContain("GET /rest/search");
  expect(user).toContain("search()");
});

it("records provider, model, commit, and timestamp on findings, SARIF, and bench results", async () => {
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
  provider.model = "stub-model";
  const outDir = join(root, "out");
  await executeScan({ target: root, cwd: root, outDir, provider });
  const file = findingsFileSchema.parse(
    JSON.parse(await readFile(join(outDir, "findings.json"), "utf8")) as unknown,
  );
  expect(file.run.provider).toBe("fake");
  expect(file.run.model).toBe("stub-model");
  expect(file.run.commit).toMatch(/^[0-9a-f]{40}$/);
  expect(file.run.started_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  expect(file.disproved).toEqual([]);
  expect(file.inconclusive).toEqual([]);
  const sarif = sarifLogSchema.parse(
    JSON.parse(await readFile(join(outDir, "findings.sarif"), "utf8")) as unknown,
  );
  expect(sarif.runs[0].properties).toEqual({
    "faultline/provider": "fake",
    "faultline/model": "stub-model",
    "faultline/commit": file.run.commit,
    "faultline/timestamp": file.run.started_at,
  });
  const report = await readFile(join(outDir, "report.md"), "utf8");
  expect(report).toContain("Provider: fake.");
  expect(report).toContain("Model: stub-model.");
  expect(report).toContain(`Commit: ${file.run.commit}.`);
  expect(report).not.toContain("## Disproved or inconclusive");

  await writeFile(
    join(root, "truth.json"),
    `${JSON.stringify({
      schema_version: "1",
      entries: [
        {
          id: "open",
          class: "authz_idor",
          cwe: "CWE-639",
          file: "app.ts",
          start_line: 1,
          end_line: 1,
          vulnerable: true,
        },
      ],
    })}\n`,
  );
  const bench = await executeBench({
    target: root,
    cwd: root,
    outDir: join(root, "bench"),
    stage: "findings",
    truthPath: join(root, "truth.json"),
    model: null,
    provider,
  });
  const recorded = benchResultSchema.parse(bench);
  expect(recorded.run.provider).toBe("fake");
  expect(recorded.run.model).toBe("stub-model");
  expect(recorded.run.commit).toBe(file.run.commit);
  expect(recorded.run.started_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
});

it("splits disproved and inconclusive in the report and keeps them out of SARIF", async () => {
  const { root, candidate } = await fixture(
    'app.get("/items/:id", (req, res) => { const item = prisma.item.findUnique({ where: { id: req.params.id } }); res.json(item); });',
  );
  candidate.class = "authz_idor";
  candidate.cwe = "CWE-639";
  candidate.symbol = "app.get";
  const provider = new FakeProvider((input) => {
    if (input.jsonSchema !== undefined) return reply("uncertain");
    if (input.messages[0]?.content.includes("authz_idor"))
      return JSON.stringify({ candidates: [candidate] });
    return "";
  });
  const dropped = join(root, "dropped");
  expect(
    await runCli(["scan", root, "--out", dropped], {
      cwd: root,
      env: {},
      provider,
      stdout() {},
      stderr() {},
    }),
  ).toBe(0);
  const droppedFile = findingsFileSchema.parse(
    JSON.parse(await readFile(join(dropped, "findings.json"), "utf8")) as unknown,
  );
  expect(droppedFile.findings).toEqual([]);
  expect(droppedFile.inconclusive?.length).toBeGreaterThan(0);
  expect(droppedFile.inconclusive?.[0]?.kept).toBe(false);
  const droppedReport = await readFile(join(dropped, "report.md"), "utf8");
  expect(droppedReport).toContain("## Inconclusive candidates");
  expect(droppedReport).not.toContain("## Disproved candidates");
  expect(droppedReport).not.toContain("## Disproved or inconclusive");

  const keptDir = join(root, "kept");
  expect(
    await runCli(["scan", root, "--out", keptDir, "--keep-inconclusive"], {
      cwd: root,
      env: {},
      provider,
      stdout() {},
      stderr() {},
    }),
  ).toBe(0);
  const keptFile = findingsFileSchema.parse(
    JSON.parse(await readFile(join(keptDir, "findings.json"), "utf8")) as unknown,
  );
  expect(keptFile.findings).toHaveLength(1);
  expect(keptFile.findings[0]?.validator_verdict).toBe("inconclusive");
  expect(keptFile.findings[0]?.confidence.level).toBe("low");
  expect(keptFile.inconclusive?.[0]?.kept).toBe(true);
  const keptReport = await readFile(join(keptDir, "report.md"), "utf8");
  expect(keptReport).toContain("inconclusive finding kept at low confidence");
  expect(keptReport).toContain("## Inconclusive candidates");
  expect(keptReport).toContain(", kept)");
  const sarif = sarifLogSchema.parse(
    JSON.parse(await readFile(join(keptDir, "findings.sarif"), "utf8")) as unknown,
  );
  expect(sarif.runs[0].results).toEqual([]);
});
