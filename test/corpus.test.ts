import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, it } from "vitest";
import { SARIF_ADAPTERS } from "../src/bench/adapters.js";
import { classForCwes, cweFromTag } from "../src/bench/cwe-map.js";
import { fetchPinnedCommit } from "../src/bench/corpus.js";
import {
  corpusGroupManifest,
  corpusManifestSchema,
  validateCorpusDocuments,
} from "../src/bench/manifest.js";
import { parseFetchArgs } from "../scripts/bench-fetch.js";
import { importSarif } from "../src/bench/sarif-import.js";
import { semgrepScanArgs } from "../src/bench/semgrep.js";
import {
  corpusResultsSchema,
  loadCorpusResultFiles,
  renderCorpusResultsMarkdown,
} from "../src/bench/summary.js";
import { runCli, type CliIo } from "../src/cli.js";

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

function git(args: string[], cwd: string): string {
  return execFileSync(
    "git",
    ["-c", "user.email=test@example.com", "-c", "user.name=Test", ...args],
    {
      cwd,
      encoding: "utf8",
    },
  ).trim();
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

it("maps injection, secrets, SSRF, and authz CWEs and drops XSS", () => {
  expect(cweFromTag("cwe-89")).toBe("CWE-89");
  expect(cweFromTag("CWE-918: Server-Side Request Forgery (SSRF)")).toBe("CWE-918");
  expect(classForCwes(["CWE-89", "CWE-200"])).toBe("injection");
  expect(classForCwes(["CWE-918", "CWE-89"])).toBe("ssrf");
  expect(classForCwes(["CWE-798"])).toBe("secrets");
  expect(classForCwes(["CWE-639"])).toBe("authz_idor");
  expect(classForCwes(["CWE-79", "CWE-611", "CWE-502"])).toBeUndefined();
});

it("imports Semgrep-shaped SARIF and skips rules outside the four classes", () => {
  const document = {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Semgrep OSS",
            semanticVersion: "1.183.0",
            rules: [
              {
                id: "rule.sql",
                properties: { tags: ["cwe-89", "security"] },
              },
              {
                id: "rule.xss",
                properties: { tags: ["CWE-79: Cross-site Scripting"] },
              },
              {
                id: "rule.multi",
                properties: { tags: ["cwe-918", "cwe-89"] },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "rule.sql",
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "core/app.js" },
                  region: { startLine: 10, endLine: 12 },
                },
              },
            ],
          },
          {
            ruleId: "rule.xss",
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "core/app.js" },
                  region: { startLine: 4 },
                },
              },
            ],
          },
          {
            ruleId: "rule.multi",
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "/tmp/app/routes/fetch.js", uriBaseId: "%SRCROOT%" },
                  region: { startLine: 2, endLine: 3 },
                },
              },
            ],
          },
        ],
      },
    ],
  };
  const imported = importSarif(document, "/tmp/app");
  expect(imported.toolName).toBe("Semgrep OSS");
  expect(imported.toolVersion).toBe("1.183.0");
  expect(imported.skipped).toBe(1);
  expect(imported.detections).toEqual([
    { class: "injection", file: "core/app.js", startLine: 10, endLine: 12 },
    { class: "ssrf", file: "routes/fetch.js", startLine: 2, endLine: 3 },
  ]);
});

it("rejects a corpus manifest that is not a pinned https GitHub repo", () => {
  const base = {
    schema_version: "1",
    cache_dir: "bench/.cache",
    semgrep: { version: "1.183.0", rulesets: ["p/javascript"] },
    apps: [
      {
        name: "dvna",
        upstream: "https://github.com/appsecco/dvna",
        commit: "9ba473add536f66ac9007966acb2a775dd31277a",
        license: "MIT",
        license_path: "LICENSE",
      },
    ],
  };
  expect(corpusManifestSchema.safeParse(base).success).toBe(true);
  expect(
    corpusManifestSchema.safeParse({
      ...base,
      apps: [{ ...base.apps[0], upstream: "file:///tmp/dvna" }],
    }).success,
  ).toBe(false);
  expect(
    corpusManifestSchema.safeParse({
      ...base,
      apps: [{ ...base.apps[0], commit: "abc" }],
    }).success,
  ).toBe(false);
  expect(
    corpusManifestSchema.safeParse({
      ...base,
      cache_dir: "../outside",
    }).success,
  ).toBe(false);
  expect(
    corpusManifestSchema.safeParse({
      ...base,
      apps: [base.apps[0], { ...base.apps[0], name: "other" }],
    }).success,
  ).toBe(true);
  expect(
    corpusManifestSchema.safeParse({
      ...base,
      apps: [base.apps[0], base.apps[0]],
    }).success,
  ).toBe(false);
});

it("checks the committed corpus documents without reading a checkout", async () => {
  await validateCorpusDocuments(join(process.cwd(), "bench", "corpus", "manifest.json"));
  await validateCorpusDocuments(corpusGroupManifest("heldout"));
});

it("defaults bench:fetch to the training group and accepts heldout", () => {
  expect(parseFetchArgs([])).toEqual({ group: "corpus", names: [] });
  expect(parseFetchArgs(["--group", "heldout", "pixi"])).toEqual({
    group: "heldout",
    names: ["pixi"],
  });
  expect(() => parseFetchArgs(["--group", "tuned"])).toThrow(/Unknown corpus group/);
});

it("shallow-fetches a local pinned commit and refuses a non-https URL", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-corpus-fetch-"));
  const origin = join(dir, "origin");
  await mkdir(origin);
  git(["init", "-q"], origin);
  await writeFile(join(origin, "note.txt"), "training fixture\n");
  git(["add", "note.txt"], origin);
  git(["commit", "-q", "-m", "pin"], origin);
  const sha = git(["rev-parse", "HEAD"], origin);
  const dest = join(dir, "cache");
  await fetchPinnedCommit({ upstream: pathToFileURL(origin).href, commit: sha }, dest, {
    allowLocal: true,
  });
  expect(git(["rev-parse", "HEAD"], dest)).toBe(sha);
  await fetchPinnedCommit({ upstream: pathToFileURL(origin).href, commit: sha }, dest, {
    allowLocal: true,
  });
  await expect(
    fetchPinnedCommit(
      { upstream: "http://github.com/example/app", commit: sha },
      join(dir, "nope"),
    ),
  ).rejects.toThrow(/Refusing to fetch/);
});

it("builds a semgrep argv from registry ids only", () => {
  expect(semgrepScanArgs(["p/javascript", "p/secrets"])).toEqual([
    "scan",
    "--metrics=off",
    "--disable-version-check",
    "--quiet",
    "--sarif",
    "--config",
    "p/javascript",
    "--config",
    "p/secrets",
    ".",
  ]);
  expect(() => semgrepScanArgs(["../rules.yaml"])).toThrow(/Refusing semgrep ruleset/);
});

it("lists paid SARIF tools as stubs and Semgrep as the baseline", () => {
  const byId = new Map(SARIF_ADAPTERS.map((adapter) => [adapter.id, adapter.status]));
  expect(byId.get("semgrep")).toBe("baseline");
  expect(byId.get("cloudflare-security-audit")).toBe("stub");
  expect(byId.get("strix")).toBe("stub");
  expect(byId.get("vercel-agent")).toBe("stub");
});

it("renders the corpus table with the heuristic model label", () => {
  const file = corpusResultsSchema.parse({
    schema_version: "1",
    label: "pre-validator heuristic",
    note: "Pre-validator heuristic. Not a Faultline product result. No model was called.",
    citable: false,
    date: "2026-11-01",
    tool: { name: "faultline", version: "0.0.0" },
    model: "none, heuristic",
    stage: "candidates",
    commit: "0123456789abcdef0123456789abcdef01234567",
    apps: [
      {
        name: "dvna",
        upstream: "https://github.com/appsecco/dvna",
        license: "MIT",
        corpus_commit: "9ba473add536f66ac9007966acb2a775dd31277a",
        target: "bench/.cache/dvna",
        truth: "bench/corpus/dvna/truth.json",
        inventory_truncated: false,
        counts: { truth: 2, vulnerable: 1, safe: 1, detections: 1, unmatched: 0 },
        overall: {
          class: "overall",
          tp: 1,
          fp: 0,
          fn: 0,
          tn: 1,
          recall: 1,
          precision: 1,
          tpr: 1,
          fpr: 0,
          score: 1,
        },
        classes: [
          {
            class: "authz_idor",
            tp: 0,
            fp: 0,
            fn: 0,
            tn: 0,
            recall: null,
            precision: null,
            tpr: null,
            fpr: null,
            score: null,
          },
        ],
        entries: [],
        unmatched: [],
      },
    ],
  });
  const markdown = renderCorpusResultsMarkdown([file]);
  expect(markdown).toContain("pre-validator heuristic");
  expect(markdown).toContain(
    "| dvna   | faultline | 0.0.0   | none, heuristic | candidates | 0123456789ab | authz_idor | 0   | 0   | 0   | 0   | n/a       | n/a    | n/a   |",
  );
  expect(markdown).toContain(
    "| dvna   | faultline | 0.0.0   | none, heuristic | candidates | 0123456789ab | overall    | 1   | 0   | 0   | 1   | 1.000     | 1.000  | 1.000 |",
  );
});

it("bench --corpus uses a local cache and does not need a network", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "faultline-corpus-cli-"));
  const cache = join(cwd, "bench", ".cache", "tiny");
  await mkdir(join(cache, "src"), { recursive: true });
  await mkdir(join(cwd, "bench", "corpus", "tiny"), { recursive: true });
  await writeFile(join(cache, "src", "app.ts"), APP);
  git(["init", "-q"], cache);
  git(["add", "src/app.ts"], cache);
  git(["commit", "-q", "-m", "pin"], cache);
  const sha = git(["rev-parse", "HEAD"], cache);
  await writeFile(
    join(cwd, "bench", "corpus", "manifest.json"),
    `${JSON.stringify({
      schema_version: "1",
      cache_dir: "bench/.cache",
      semgrep: { version: "1.183.0", rulesets: ["p/javascript"] },
      apps: [
        {
          name: "tiny",
          upstream: "https://github.com/example/tiny",
          commit: sha,
          license: "MIT",
          license_path: "LICENSE",
        },
      ],
    })}\n`,
  );
  await writeFile(
    join(cwd, "bench", "corpus", "tiny", "truth.json"),
    `${JSON.stringify({
      schema_version: "1",
      entries: [
        {
          id: "open",
          class: "authz_idor",
          cwe: "CWE-639",
          file: "src/app.ts",
          start_line: 6,
          end_line: 9,
          vulnerable: true,
        },
        {
          id: "mine",
          class: "authz_idor",
          cwe: "CWE-639",
          file: "src/app.ts",
          start_line: 11,
          end_line: 16,
          vulnerable: false,
        },
      ],
    })}\n`,
  );
  const out = join(cwd, "out");
  const captured = capture();
  expect(
    await runCli(["bench", "--corpus", "tiny", "--cache-only", "--out", out], {
      ...captured.io,
      cwd,
      env: {},
    }),
  ).toBe(0);
  const result = JSON.parse(await readFile(join(out, "bench-result.json"), "utf8")) as {
    stage: string;
    tool: { name: string };
    run: { provider: string | null; model: string | null };
    citable: boolean;
    overall: { tp: number; fp: number; fn: number; tn: number };
  };
  expect(result.stage).toBe("candidates");
  expect(result.tool.name).toBe("faultline");
  expect(result.run.provider).toBeNull();
  expect(result.run.model).toBeNull();
  expect(result.citable).toBe(false);
  expect(result.overall.tp + result.overall.fn).toBe(1);
  expect(result.overall.fp + result.overall.tn).toBe(1);

  const missing = capture();
  expect(
    await runCli(["bench", "--corpus", "absent", "--cache-only"], {
      ...missing.io,
      cwd,
      env: {},
    }),
  ).toBe(1);
  expect(missing.stderr()).toContain("Unknown corpus app");

  const offline = capture();
  await writeFile(join(cache, "src", "app.ts"), APP);
  const other = join(cwd, "bench", "corpus", "manifest.json");
  const manifest = JSON.parse(await readFile(other, "utf8")) as {
    apps: { commit: string }[];
  };
  const pinned = manifest.apps[0];
  if (pinned === undefined) {
    throw new Error("fixture manifest has no app");
  }
  pinned.commit = "0123456789abcdef0123456789abcdef01234567";
  await writeFile(other, `${JSON.stringify(manifest)}\n`);
  expect(
    await runCli(["bench", "--corpus", "tiny", "--cache-only", "--out", join(cwd, "out2")], {
      ...offline.io,
      cwd,
      env: {},
    }),
  ).toBe(1);
  expect(offline.stderr()).toContain("bench:fetch");
});

function loosenTable(text: string): string {
  return text
    .split("\n")
    .map((line) => {
      if (!line.trim().startsWith("|")) {
        return line.trimEnd();
      }
      const cells = line
        .split("|")
        .slice(1, -1)
        .map((cell) => {
          const trimmed = cell.trim();
          return /^:?-+:?$/.test(trimmed) ? "---" : trimmed;
        });
      return `| ${cells.join(" | ")} |`;
    })
    .join("\n")
    .trim();
}

it("keeps a committed results table aligned with the JSON files", async () => {
  const dir = join(process.cwd(), "bench", "results");
  const files = await loadCorpusResultFiles(dir);
  if (files.length === 0) {
    return;
  }
  const readme = await readFile(join(dir, "README.md"), "utf8");
  expect(loosenTable(readme)).toBe(loosenTable(renderCorpusResultsMarkdown(files)));
  expect(readme).toContain("must not drive heuristic changes");
  for (const file of files) {
    expect(file.citable).toBe(false);
    expect(file.model).toBe("none, heuristic");
    expect(file.label).toBe("pre-validator heuristic");
  }
});

it("keeps held-out scores aligned when they are committed", async () => {
  const dir = join(process.cwd(), "bench", "results", "heldout");
  const files = await loadCorpusResultFiles(dir);
  if (files.length === 0) {
    return;
  }
  const readme = await readFile(join(dir, "README.md"), "utf8");
  expect(loosenTable(readme)).toBe(loosenTable(renderCorpusResultsMarkdown(files)));
  expect(readme).toContain("must not drive heuristic changes");
  const stages = new Set(files.map((file) => file.stage));
  expect(stages.has("candidates")).toBe(true);
  expect(stages.has("findings")).toBe(true);
  expect(stages.has("findings-keep-inconclusive")).toBe(true);
  expect(stages.has("scan")).toBe(true);
  for (const file of files) {
    expect(file.citable).toBe(false);
    expect(file.model).toBe("none, heuristic");
  }
});
