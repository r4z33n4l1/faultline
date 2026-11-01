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
  renderCorpusResultsMarkdown,
  type CorpusAppResult,
  type CorpusResultsFile,
} from "../src/bench/summary.js";
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
 * One static pass of Faultline (no provider, candidates) and Semgrep over
 * each pinned app. Writes bench/results. Does not install or run the apps.
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
  const bin = process.env.SEMGREP_BIN ?? "semgrep";
  const faultlineApps: CorpusAppResult[] = [];
  const semgrepApps: CorpusAppResult[] = [];
  const scratch = join(tmpdir(), `faultline-corpus-${commit.slice(0, 12)}`);
  await mkdir(scratch, { recursive: true });
  for (const app of manifest.apps) {
    const paths = await resolveCorpusPaths(cwd, manifestPath, app.name);
    await ensureCorpusCache(paths, false);
    const faultlineOut = join(scratch, `${app.name}-faultline`);
    const faultline = await executeBench({
      target: paths.targetLabel,
      cwd,
      outDir: faultlineOut,
      stage: "candidates",
      truthPath: paths.truthLabel,
      model: null,
    });
    faultlineApps.push(corpusAppResult(app, faultline, await inventoryTruncated(faultlineOut)));
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
    process.stdout.write(
      `${app.name} faultline recall ${String(faultline.overall.recall)} semgrep recall ${String(semgrep.overall.recall)}\n`,
    );
  }
  const faultlineFile: CorpusResultsFile = corpusResultsSchema.parse({
    schema_version: "1",
    label: CORPUS_RESULTS_LABEL,
    note: CORPUS_RESULTS_NOTE,
    citable: false,
    date,
    tool: { name: "faultline", version: TOOL_VERSION },
    model: CORPUS_RESULTS_MODEL,
    stage: "candidates",
    commit,
    apps: faultlineApps,
  });
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
  const resultsDir = join(cwd, "bench", "results");
  await mkdir(resultsDir, { recursive: true });
  const faultlineName = corpusResultsFilename(date, commit, "faultline", "candidates");
  const semgrepName = corpusResultsFilename(date, commit, "semgrep", "scan");
  await writeFile(
    join(resultsDir, faultlineName),
    `${JSON.stringify(faultlineFile, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(resultsDir, semgrepName),
    `${JSON.stringify(semgrepFile, null, 2)}\n`,
    "utf8",
  );
  const markdown = renderCorpusResultsMarkdown([faultlineFile, semgrepFile]);
  await writeFile(join(resultsDir, "README.md"), markdown, "utf8");
  process.stdout.write(`Wrote ${faultlineName} and ${semgrepName}\n`);
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
