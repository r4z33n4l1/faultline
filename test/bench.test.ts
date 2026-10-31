import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { renderBenchMarkdown } from "../src/bench/format.js";
import { benchResultSchema, type BenchResult } from "../src/bench/result.js";
import { scoreBench, type DetectionSpan } from "../src/bench/score.js";
import { runCli, type CliIo } from "../src/cli.js";
import { FakeProvider } from "../src/providers/types.js";
import { truthFileSchema, TRUTH_CLASSES, type TruthEntry } from "../src/schema/truth.js";

function capture(): { io: CliIo; stdout: () => string; stderr: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout: (text) => {
        out.push(text);
      },
      stderr: (text) => {
        err.push(text);
      },
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
  };
}

function entry(
  id: string,
  truthClass: TruthEntry["class"],
  file: string,
  start: number,
  end: number,
  vulnerable: boolean,
): TruthEntry {
  return {
    id,
    class: truthClass,
    cwe: "CWE-1",
    file,
    start_line: start,
    end_line: end,
    vulnerable,
  };
}

function span(truthClass: string, file: string, start: number, end: number): DetectionSpan {
  return { class: truthClass, file, startLine: start, endLine: end };
}

const APP = `import express from "express";

const app = express();
const prisma = { item: { findUnique: (_query: unknown) => Promise.resolve(undefined) } };

app.get("/items/:id", async (req, res) => {
  const row = await prisma.item.findUnique({ where: { id: req.params.id } });
  res.json(row);
});

app.get("/items/:id/mine", async (req, res) => {
  const row = await prisma.item.findUnique({
    where: { id: req.params.id, ownerId: req.user.id },
  });
  res.json(row);
});

export { app };
`;

function syntheticTruth(): string {
  return `${JSON.stringify(
    {
      schema_version: "1",
      entries: [
        entry("open", "authz_idor", "src/app.ts", 6, 9, true),
        entry("mine", "authz_idor", "src/app.ts", 11, 16, false),
      ],
    },
    null,
    2,
  )}\n`;
}

it("scores overlap by class and file, and leaves unmatched detections out of the matrix", () => {
  const truth = [
    entry("a", "authz_idor", "src/file.ts", 10, 20, true),
    entry("b", "authz_idor", "src/file.ts", 30, 40, false),
    entry("c", "injection", "src/file.ts", 10, 20, true),
    entry("d", "secrets", "./other.ts", 1, 1, true),
    entry("e", "ssrf", "src/file.ts", 50, 55, false),
  ];
  const detections = [
    span("authz_idor", "src\\file.ts", 20, 30),
    span("injection", "src/other.ts", 10, 12),
    span("secrets", "other.ts", 1, 2),
    span("authz_idor", "src/file.ts", 100, 100),
    span("ssrf", "src/file.ts", 1, 2),
  ];
  const scored = scoreBench(truth, detections);
  expect(scored.entries.map((item) => [item.id, item.outcome])).toEqual([
    ["a", "tp"],
    ["b", "fp"],
    ["c", "fn"],
    ["d", "tp"],
    ["e", "tn"],
  ]);
  expect(scored.overall).toMatchObject({ tp: 2, fp: 1, fn: 1, tn: 1 });
  expect(scored.overall.recall).toBeCloseTo(2 / 3);
  expect(scored.overall.precision).toBeCloseTo(2 / 3);
  expect(scored.overall.tpr).toBe(scored.overall.recall);
  expect(scored.overall.fpr).toBeCloseTo(1 / 2);
  expect(scored.overall.score).toBeCloseTo(2 / 3 - 1 / 2);
  expect(scored.unmatched).toEqual([
    span("authz_idor", "src/file.ts", 100, 100),
    span("injection", "src/other.ts", 10, 12),
    span("ssrf", "src/file.ts", 1, 2),
  ]);
  const authz = scored.classes.find((item) => item.class === "authz_idor");
  expect(authz).toMatchObject({ tp: 1, fp: 1, fn: 0, tn: 0, tpr: 1, fpr: 1, score: 0 });
});

it("treats a shared endpoint as overlap and a gap as a miss", () => {
  const truth = [entry("site", "injection", "src/app.ts", 10, 12, true)];
  expect(scoreBench(truth, [span("injection", "src/app.ts", 1, 9)]).entries[0]?.outcome).toBe("fn");
  expect(scoreBench(truth, [span("injection", "src/app.ts", 1, 10)]).entries[0]?.outcome).toBe(
    "tp",
  );
  expect(scoreBench(truth, [span("ssrf", "src/app.ts", 10, 12)]).entries[0]?.outcome).toBe("fn");
});

it("counts one hit per label when several detections overlap it", () => {
  const truth = [entry("site", "secrets", "src/app.ts", 4, 4, true)];
  const scored = scoreBench(truth, [
    span("secrets", "src/app.ts", 4, 4),
    span("secrets", "src/app.ts", 4, 6),
  ]);
  expect(scored.overall).toMatchObject({ tp: 1, fp: 0, fn: 0, tn: 0 });
  expect(scored.unmatched).toEqual([]);
  expect(scored.overall.precision).toBe(1);
  expect(scored.overall.score).toBeNull();
});

it("reports a zero score for an empty detection list when both label kinds exist", () => {
  const truth = [
    entry("bug", "ssrf", "src/app.ts", 1, 2, true),
    entry("safe", "ssrf", "src/app.ts", 8, 9, false),
  ];
  const scored = scoreBench(truth, []);
  expect(scored.overall).toMatchObject({
    tp: 0,
    fp: 0,
    fn: 1,
    tn: 1,
    recall: 0,
    precision: null,
    tpr: 0,
    fpr: 0,
    score: 0,
  });
});

it("renders n/a when a rate is undefined and states that the table is not a product result", () => {
  const scored = scoreBench(
    [entry("bug", "authz_idor", "src/app.ts", 1, 2, true)],
    [span("authz_idor", "src/app.ts", 1, 2)],
  );
  const result = benchResultSchema.parse({
    schema_version: "1",
    disclaimer:
      "This file measures one bench run. It is not a Faultline product result. Cite it only when provider, model, and commit are all recorded.",
    citable: false,
    stage: "candidates",
    target: "app",
    truth: "app/truth.json",
    tool: { name: "faultline", version: "0.0.0" },
    run: {
      id: "run",
      started_at: "2026-10-31T00:00:00.000Z",
      provider: null,
      model: null,
      commit: null,
    },
    counts: { truth: 1, vulnerable: 1, safe: 0, detections: 1, unmatched: 0 },
    overall: scored.overall,
    classes: scored.classes,
    entries: scored.entries,
    unmatched: [],
  } satisfies BenchResult);
  const markdown = renderBenchMarkdown(result);
  expect(markdown).toContain("not a Faultline product result");
  expect(markdown).toContain("heuristic pre-pass, no model");
  expect(markdown).toContain("| authz_idor | 1 | 0 | 0 | 0 | 1.000 | 1.000 | n/a | n/a |");
  expect(markdown).toContain("| overall | 1 | 0 | 0 | 0 | 1.000 | 1.000 | n/a | n/a |");
});

it("rejects a duplicate truth id", () => {
  const parsed = truthFileSchema.safeParse({
    schema_version: "1",
    entries: [
      entry("same", "secrets", "src/app.ts", 1, 1, true),
      entry("same", "secrets", "src/app.ts", 2, 2, false),
    ],
  });
  expect(parsed.success).toBe(false);
});

it("seeded truth covers the four classes on real lines and is not a detection rate", () => {
  const root = join(process.cwd(), "bench", "seeded-app");
  const truth = truthFileSchema.parse(
    JSON.parse(readFileSync(join(root, "truth.json"), "utf8")) as unknown,
  );
  const vulnerable = truth.entries.filter((item) => item.vulnerable);
  const safe = truth.entries.filter((item) => !item.vulnerable);
  expect(vulnerable.length).toBeGreaterThanOrEqual(12);
  expect(vulnerable.length).toBeLessThanOrEqual(20);
  expect(safe.length).toBeGreaterThanOrEqual(vulnerable.length);
  for (const name of TRUTH_CLASSES) {
    expect(truth.entries.some((item) => item.class === name && item.vulnerable)).toBe(true);
    expect(truth.entries.some((item) => item.class === name && !item.vulnerable)).toBe(true);
  }
  for (const item of truth.entries) {
    const text = readFileSync(join(root, item.file), "utf8");
    const parts = text.split(/\r?\n/);
    const lines = text.endsWith("\n") || text.endsWith("\r") ? parts.length - 1 : parts.length;
    expect(item.end_line).toBeLessThanOrEqual(lines);
  }
});

it("bench on a tiny app checks harness wiring and scores empty findings as no detections", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-bench-"));
  await mkdir(join(dir, "src"));
  await writeFile(join(dir, "src", "app.ts"), APP);
  await writeFile(join(dir, "truth.json"), syntheticTruth());
  const candidatesOut = join(dir, "candidates-out");
  const candidates = capture();
  expect(
    await runCli(["bench", ".", "--out", candidatesOut, "--stage", "candidates"], {
      ...candidates.io,
      cwd: dir,
      env: {},
    }),
  ).toBe(0);
  const candidatesResult = benchResultSchema.parse(
    JSON.parse(await readFile(join(candidatesOut, "bench-result.json"), "utf8")) as unknown,
  );
  expect(candidates.stdout()).toContain("bench-result.md");
  expect(candidatesResult.citable).toBe(false);
  expect(candidatesResult.run.provider).toBeNull();
  expect(candidatesResult.run.model).toBeNull();
  expect(candidatesResult.stage).toBe("candidates");
  expect(candidatesResult.overall.tp + candidatesResult.overall.fn).toBe(1);
  expect(candidatesResult.overall.fp + candidatesResult.overall.tn).toBe(1);
  expect(await readFile(join(candidatesOut, "bench-result.md"), "utf8")).toContain(
    "not a Faultline product result",
  );

  const findingsOut = join(dir, "findings-out");
  const findings = capture();
  expect(
    await runCli(["bench", ".", "--out", findingsOut, "--stage", "findings"], {
      ...findings.io,
      cwd: dir,
      env: {},
    }),
  ).toBe(0);
  const findingsResult = benchResultSchema.parse(
    JSON.parse(await readFile(join(findingsOut, "bench-result.json"), "utf8")) as unknown,
  );
  expect(findingsResult.counts.detections).toBe(0);
  expect(findingsResult.overall).toMatchObject({
    tp: 0,
    fp: 0,
    fn: 1,
    tn: 1,
    recall: 0,
    precision: null,
    score: 0,
  });
});

it("bench with FakeProvider does not use the network", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-bench-fake-"));
  await mkdir(join(dir, "src"));
  await writeFile(join(dir, "src", "app.ts"), APP);
  await writeFile(join(dir, "truth.json"), syntheticTruth());
  const out = join(dir, "out");
  const captured = capture();
  const provider = new FakeProvider("");
  expect(
    await runCli(["bench", ".", "--out", out], {
      ...captured.io,
      cwd: dir,
      env: {},
      provider,
    }),
  ).toBe(0);
  expect(provider.calls.length).toBeGreaterThan(0);
  const result = benchResultSchema.parse(
    JSON.parse(await readFile(join(out, "bench-result.json"), "utf8")) as unknown,
  );
  expect(result.run.provider).toBe("fake");
  expect(result.run.model).toBeNull();
  expect(result.citable).toBe(false);
  expect(result.overall.tp + result.overall.fn).toBe(1);
  expect(result.overall.fp + result.overall.tn).toBe(1);
});

it("bench exits 1 for a missing truth file, a range past EOF, and a bad stage", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-bench-bad-"));
  const missing = capture();
  expect(await runCli(["bench", "."], { ...missing.io, cwd: dir, env: {} })).toBe(1);
  expect(missing.stderr()).toContain("Cannot read file:");

  await writeFile(join(dir, "note.ts"), "export const value = 1;\n");
  await writeFile(
    join(dir, "truth.json"),
    `${JSON.stringify({
      schema_version: "1",
      entries: [entry("past", "secrets", "note.ts", 1, 40, true)],
    })}\n`,
  );
  const past = capture();
  expect(
    await runCli(["bench", ".", "--truth", "truth.json"], { ...past.io, cwd: dir, env: {} }),
  ).toBe(1);
  expect(past.stderr()).toContain("past line");

  const stage = capture();
  expect(
    await runCli(["bench", ".", "--stage", "confirmed"], { ...stage.io, cwd: dir, env: {} }),
  ).toBe(1);
  expect(stage.stderr().length).toBeGreaterThan(0);
});
