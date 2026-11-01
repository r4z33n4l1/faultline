import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ensureCorpusCache, resolveCorpusPaths } from "../src/bench/corpus.js";
import { executeSemgrepBench } from "../src/bench/external.js";
import { loadCorpusManifest } from "../src/bench/manifest.js";
import { executeBench, readGitCommit } from "../src/bench/run.js";
import {
  CORPUS_RESULTS_LABEL,
  CORPUS_RESULTS_MODEL,
  CORPUS_RESULTS_NOTE,
  corpusAppResult,
  corpusResultsFilename,
  corpusResultsSchema,
  renderCorpusResultsDir,
  type CorpusAppResult,
  type CorpusResultsFile,
} from "../src/bench/summary.js";
import type { BenchStage } from "../src/bench/result.js";
import { TOOL_VERSION } from "../src/version.js";

const TRUNCATION_NOTE = "Inventory truncated at the file or byte cap.";

function utcDate(now: Date): string {
  return now.toISOString().slice(0, 10);
}

async function inventoryTruncated(outDir: string): Promise<boolean> {
  const text = await readFile(join(outDir, "architecture.md"), "utf8");
  return text.includes(TRUNCATION_NOTE);
}

/**
 * Static Faultline passes (no provider) at the candidates and findings stages,
 * plus Semgrep unless `--faultline-only` is set. Writes bench/results.
 * Does not install or run the apps. The markdown table includes every JSON
 * file in bench/results, so a Semgrep file already on disk stays in the table.
 */
async function main(): Promise<void> {
  const cwd = process.cwd();
  const manifestPath = "bench/corpus/manifest.json";
  const manifest = await loadCorpusManifest(manifestPath);
  const commit = await readGitCommit(cwd);
  if (commit === null) {
    throw new Error("Cannot record a corpus bench without a git commit");
  }
  const now = new Date();
  const date = utcDate(now);
  const faultlineOnly = process.argv.includes("--faultline-only");
  const bin = process.env.SEMGREP_BIN ?? "semgrep";
  const stages: BenchStage[] = ["candidates", "findings"];
  const faultlineByStage = new Map<BenchStage, CorpusAppResult[]>(
    stages.map((stage) => [stage, []]),
  );
  const semgrepApps: CorpusAppResult[] = [];
  const scratch = join(tmpdir(), `faultline-corpus-${commit.slice(0, 12)}`);
  await mkdir(scratch, { recursive: true });
  for (const app of manifest.apps) {
    const paths = await resolveCorpusPaths(cwd, manifestPath, app.name);
    await ensureCorpusCache(paths, false);
    for (const stage of stages) {
      const faultlineOut = join(scratch, `${app.name}-faultline-${stage}`);
      const faultline = await executeBench({
        target: paths.targetLabel,
        cwd,
        outDir: faultlineOut,
        stage,
        truthPath: paths.truthLabel,
        model: null,
      });
      faultlineByStage
        .get(stage)
        ?.push(corpusAppResult(app, faultline, await inventoryTruncated(faultlineOut)));
      process.stdout.write(
        `${app.name} faultline ${stage} recall ${String(faultline.overall.recall)}\n`,
      );
    }
    if (faultlineOnly) {
      continue;
    }
    const semgrepOut = join(scratch, `${app.name}-semgrep`);
    const semgrep = await executeSemgrepBench({
      root: paths.cacheDir,
      targetLabel: paths.targetLabel,
      truthPath: paths.truthPath,
      truthLabel: paths.truthLabel,
      outDir: semgrepOut,
      cwd,
      tool: { name: "semgrep", version: manifest.semgrep.version },
      bin,
      expectedVersion: manifest.semgrep.version,
      rulesets: manifest.semgrep.rulesets,
    });
    semgrepApps.push(corpusAppResult(app, semgrep, null));
    process.stdout.write(`${app.name} semgrep recall ${String(semgrep.overall.recall)}\n`);
  }
  const resultsDir = join(cwd, "bench", "results");
  await mkdir(resultsDir, { recursive: true });
  const written: string[] = [];
  for (const stage of stages) {
    const faultlineFile: CorpusResultsFile = corpusResultsSchema.parse({
      schema_version: "1",
      label: CORPUS_RESULTS_LABEL,
      note: CORPUS_RESULTS_NOTE,
      citable: false,
      date,
      tool: { name: "faultline", version: TOOL_VERSION },
      model: CORPUS_RESULTS_MODEL,
      stage,
      commit,
      apps: faultlineByStage.get(stage) ?? [],
    });
    const faultlineName = corpusResultsFilename(date, commit, "faultline", stage);
    await writeFile(
      join(resultsDir, faultlineName),
      `${JSON.stringify(faultlineFile, null, 2)}\n`,
      "utf8",
    );
    written.push(faultlineName);
  }
  if (!faultlineOnly) {
    const semgrepFile: CorpusResultsFile = corpusResultsSchema.parse({
      schema_version: "1",
      label: CORPUS_RESULTS_LABEL,
      note: CORPUS_RESULTS_NOTE,
      citable: false,
      date,
      tool: { name: "semgrep", version: manifest.semgrep.version },
      model: CORPUS_RESULTS_MODEL,
      stage: "scan",
      commit,
      rulesets: manifest.semgrep.rulesets,
      apps: semgrepApps,
    });
    const semgrepName = corpusResultsFilename(date, commit, "semgrep", "scan");
    await writeFile(
      join(resultsDir, semgrepName),
      `${JSON.stringify(semgrepFile, null, 2)}\n`,
      "utf8",
    );
    written.push(semgrepName);
  }
  const markdown = await renderCorpusResultsDir(resultsDir);
  await writeFile(join(resultsDir, "README.md"), markdown, "utf8");
  process.stdout.write(`Wrote ${written.join(" and ")}\n`);
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
