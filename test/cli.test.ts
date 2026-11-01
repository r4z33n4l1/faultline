import { mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, it } from "vitest";
import { isCliEntrypoint, runCli, type CliIo } from "../src/cli.js";
import { sarifLogSchema } from "../src/sarif.js";
import { candidatesFileSchema } from "../src/schema/candidate.js";
import { findingsFileSchema } from "../src/schema/finding.js";
import { cloneFixture, loadFixtureText } from "./fixture.js";

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

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "faultline-cli-"));
}

it("treats a bin symlink as the CLI entrypoint", async () => {
  const dir = await tempDir();
  const target = join(dir, "cli.js");
  const link = join(dir, "faultline");
  await writeFile(target, "");
  await symlink("cli.js", link);
  const moduleUrl = pathToFileURL(target).href;
  expect(isCliEntrypoint(link, moduleUrl)).toBe(true);
  expect(isCliEntrypoint(target, moduleUrl)).toBe(true);
  expect(isCliEntrypoint(undefined, moduleUrl)).toBe(false);
  expect(isCliEntrypoint(join(dir, "missing.js"), moduleUrl)).toBe(false);
});

it("validate exits 0 for a valid file and 1 with a path for a bad file", async () => {
  const dir = await tempDir();
  const validPath = join(dir, "findings.json");
  const badPath = join(dir, "bad.json");
  await writeFile(validPath, loadFixtureText());
  const bad = cloneFixture();
  const finding = (bad.findings as { severity: string }[])[0];
  if (finding === undefined) {
    throw new Error("missing finding");
  }
  finding.severity = "severe";
  await writeFile(badPath, JSON.stringify(bad));

  const ok = capture();
  expect(await runCli(["validate", validPath], ok.io)).toBe(0);
  expect(ok.stdout()).toContain("OK");
  expect(ok.stdout()).toContain("2 findings");
  expect(ok.stderr()).toBe("");

  const failed = capture();
  expect(await runCli(["validate", badPath], failed.io)).toBe(1);
  expect(failed.stderr()).toContain("findings.0.severity");
  expect(failed.stdout()).toBe("");
});

it("validate exits 1 for missing files and invalid JSON", async () => {
  const dir = await tempDir();
  const missing = capture();
  expect(await runCli(["validate", join(dir, "missing.json")], missing.io)).toBe(1);
  expect(missing.stderr()).toContain("Cannot read file:");

  const brokenPath = join(dir, "broken.json");
  await writeFile(brokenPath, "{");
  const broken = capture();
  expect(await runCli(["validate", brokenPath], broken.io)).toBe(1);
  expect(broken.stderr()).toContain("Invalid JSON:");
});

it("scan defaults --out to ./faultline-out", async () => {
  const dir = await tempDir();
  await mkdir(join(dir, "src"));
  const io = capture();
  expect(await runCli(["scan", "src"], { ...io.io, cwd: dir, env: {} })).toBe(0);
  const findings = findingsFileSchema.parse(
    JSON.parse(await readFile(join(dir, "faultline-out", "findings.json"), "utf8")) as unknown,
  );
  expect(findings.run.mode).toBe("scan");
  expect(findings.run.target).toBe("src");
  expect(findings.findings).toEqual([]);
  expect(findings.run.provider).toBeNull();
  expect(await readFile(join(dir, "faultline-out", "report.md"), "utf8")).toContain(
    "No confirmed findings.",
  );
  expect(await readFile(join(dir, "faultline-out", "architecture.md"), "utf8")).toContain(
    "Inventory only.",
  );
  const sarif = sarifLogSchema.parse(
    JSON.parse(await readFile(join(dir, "faultline-out", "findings.sarif"), "utf8")) as unknown,
  );
  expect(sarif.runs[0].results).toEqual([]);
  expect(io.stdout()).toContain("findings.sarif");
});

it("scan and pr write a valid empty findings file and report", async () => {
  const dir = await tempDir();
  const scanOut = join(dir, "scan-out");
  const prOut = join(dir, "pr-out");

  const scan = capture();
  expect(await runCli(["scan", ".", "--out", scanOut], { ...scan.io, cwd: dir, env: {} })).toBe(0);
  const scanFindings = findingsFileSchema.parse(
    JSON.parse(await readFile(join(scanOut, "findings.json"), "utf8")) as unknown,
  );
  expect(scanFindings.findings).toEqual([]);
  expect(scanFindings.run.mode).toBe("scan");
  expect(scanFindings.run.target).toBe(".");
  const scanReport = await readFile(join(scanOut, "report.md"), "utf8");
  expect(scanReport).toContain("# Faultline report");
  expect(scanReport).toContain("- critical: 0");
  expect(scanReport).toContain("No confirmed findings.");
  expect(scanReport).toContain("unvalidated candidates: 0, not reported as findings");
  const scanCandidates = candidatesFileSchema.parse(
    JSON.parse(await readFile(join(scanOut, "candidates.json"), "utf8")) as unknown,
  );
  expect(scanCandidates.candidates).toEqual([]);
  expect(scanCandidates.run.id).toBe(scanFindings.run.id);
  const scanSarif = sarifLogSchema.parse(
    JSON.parse(await readFile(join(scanOut, "findings.sarif"), "utf8")) as unknown,
  );
  expect(scanSarif.version).toBe("2.1.0");
  expect(scanSarif.runs[0].results).toEqual([]);
  expect(scan.stdout()).toContain("findings.sarif");

  const diffPath = join(dir, "empty.diff");
  await writeFile(diffPath, "");
  const pr = capture();
  expect(
    await runCli(["pr", diffPath, "--repo", dir, "--out", prOut], { ...pr.io, cwd: dir, env: {} }),
  ).toBe(0);
  const prFindings = findingsFileSchema.parse(
    JSON.parse(await readFile(join(prOut, "findings.json"), "utf8")) as unknown,
  );
  expect(prFindings.findings).toEqual([]);
  expect(prFindings.run.mode).toBe("pr");
  expect(prFindings.run.target).toBe(diffPath);
  const prSarif = sarifLogSchema.parse(
    JSON.parse(await readFile(join(prOut, "findings.sarif"), "utf8")) as unknown,
  );
  expect(prSarif.runs[0].results).toEqual([]);
  expect(prSarif.runs[0].tool.driver.name).toBe("faultline");
  expect(pr.stdout()).toContain("findings.sarif");
  expect(pr.stdout()).toContain("candidates.json");
  const prReport = await readFile(join(prOut, "report.md"), "utf8");
  expect(prReport).toContain("This run is PR-scoped.");
  expect(prReport).toContain("unvalidated candidates: 0, not reported as findings");
  expect(await readFile(join(prOut, "architecture.md"), "utf8")).toContain("## Changed files");
  const prCandidates = candidatesFileSchema.parse(
    JSON.parse(await readFile(join(prOut, "candidates.json"), "utf8")) as unknown,
  );
  expect(prCandidates.candidates).toEqual([]);

  const url = "https://github.com/org/repo/pull/1";
  const refused = capture();
  expect(
    await runCli(["pr", url, "--out", join(dir, "refused")], { ...refused.io, cwd: dir }),
  ).toBe(1);
  expect(refused.stderr()).toContain(`gh pr diff ${url} | faultline pr -`);
  await expect(readFile(join(dir, "refused", "findings.json"), "utf8")).rejects.toThrow();
});
