import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import * as z from "zod";
import { formatZodIssues } from "../schema/finding.js";
import { confusionSchema, scoredEntrySchema, unmatchedSchema, type BenchResult } from "./result.js";
import type { CorpusApp } from "./manifest.js";

export const CORPUS_RESULTS_LABEL = "pre-validator heuristic";
export const CORPUS_RESULTS_NOTE =
  "Pre-validator heuristic. Not a Faultline product result. No model was called.";
export const CORPUS_RESULTS_MODEL = "none, heuristic";

const count = z.number().int().nonnegative();

export const corpusAppResultSchema = z.strictObject({
  name: z.string().min(1),
  upstream: z.string().min(1),
  license: z.string().min(1),
  corpus_commit: z.string().regex(/^[0-9a-f]{40}$/),
  target: z.string().min(1),
  truth: z.string().min(1),
  inventory_truncated: z.boolean().nullable(),
  counts: z.strictObject({
    truth: count,
    vulnerable: count,
    safe: count,
    detections: count,
    unmatched: count,
  }),
  overall: confusionSchema,
  classes: z.array(confusionSchema),
  entries: z.array(scoredEntrySchema),
  unmatched: z.array(unmatchedSchema),
});

export const corpusResultsSchema = z.strictObject({
  schema_version: z.literal("1"),
  label: z.literal(CORPUS_RESULTS_LABEL),
  note: z.literal(CORPUS_RESULTS_NOTE),
  citable: z.literal(false),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  tool: z.strictObject({
    name: z.string().min(1),
    version: z.string().min(1),
  }),
  model: z.literal(CORPUS_RESULTS_MODEL),
  stage: z.enum(["candidates", "scan"]),
  commit: z.string().regex(/^[0-9a-f]{40}$/),
  rulesets: z.array(z.string().min(1)).optional(),
  apps: z.array(corpusAppResultSchema),
});

export type CorpusResultsFile = z.infer<typeof corpusResultsSchema>;
export type CorpusAppResult = z.infer<typeof corpusAppResultSchema>;

export function corpusResultsFilename(
  date: string,
  commit: string,
  tool: string,
  stage: string,
): string {
  return `${date}-${commit}-${tool}-${stage}.json`;
}

export function corpusAppResult(
  app: CorpusApp,
  result: BenchResult,
  inventoryTruncated: boolean | null,
): CorpusAppResult {
  return corpusAppResultSchema.parse({
    name: app.name,
    upstream: app.upstream,
    license: app.license,
    corpus_commit: app.commit,
    target: result.target,
    truth: result.truth,
    inventory_truncated: inventoryTruncated,
    counts: result.counts,
    overall: result.overall,
    classes: result.classes,
    entries: result.entries,
    unmatched: result.unmatched,
  });
}

function formatRate(value: number | null): string {
  if (value === null) {
    return "n/a";
  }
  return value.toFixed(3);
}

function row(cells: readonly string[]): string {
  return `| ${cells.join(" | ")} |`;
}

function confusionCells(
  file: CorpusResultsFile,
  appName: string,
  item: CorpusResultsFile["apps"][number]["overall"],
): string {
  return row([
    appName,
    file.tool.name,
    file.tool.version,
    file.model,
    file.stage,
    file.commit.slice(0, 12),
    item.class,
    String(item.tp),
    String(item.fp),
    String(item.fn),
    String(item.tn),
    formatRate(item.precision),
    formatRate(item.recall),
    formatRate(item.score),
  ]);
}

/**
 * Summary table for committed corpus runs. The full commit is in each JSON
 * file. The table shows the first 12 hex digits so the row stays readable.
 */
export function renderCorpusResultsMarkdown(files: readonly CorpusResultsFile[]): string {
  const lines = [
    "# Corpus bench results",
    "",
    "These numbers are pre-validator heuristic runs. They are not Faultline product results.",
    "Faultline ran with no provider, so the model column is `none, heuristic`.",
    "Semgrep is the free static baseline. Its stage is `scan` because it has no candidate validator.",
    "Precision and recall use the same site-level matrix as `faultline bench`: class, path, and line overlap.",
    "Unmatched detections are not false positives. A rate is `n/a` when its denominator is zero.",
    "The score is TPR minus FPR.",
    "",
    "Raw scanner output is not committed. It can quote corpus source.",
    "",
    row([
      "corpus",
      "tool",
      "version",
      "model",
      "stage",
      "commit",
      "class",
      "TP",
      "FP",
      "FN",
      "TN",
      "precision",
      "recall",
      "score",
    ]),
    row([
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
      "---",
    ]),
  ];
  const ordered = [...files].sort(
    (left, right) =>
      left.tool.name.localeCompare(right.tool.name) || left.stage.localeCompare(right.stage),
  );
  for (const file of ordered) {
    const apps = [...file.apps].sort((left, right) => left.name.localeCompare(right.name));
    for (const app of apps) {
      for (const item of app.classes) {
        lines.push(confusionCells(file, app.name, item));
      }
      lines.push(confusionCells(file, app.name, app.overall));
    }
  }
  lines.push("", "## Runs", "", "Commit prefixes in the table match these files.", "");
  for (const file of ordered) {
    const truncated = file.apps
      .filter((app) => app.inventory_truncated === true)
      .map((app) => app.name);
    const rules = file.rulesets === undefined ? "" : ` Rulesets: ${file.rulesets.join(", ")}.`;
    const cap =
      truncated.length === 0
        ? ""
        : ` Inventory truncated for ${truncated.join(", ")} at Faultline's file and byte caps.`;
    lines.push(
      `- \`${corpusResultsFilename(file.date, file.commit, file.tool.name, file.stage)}\` — ${file.tool.name} ${file.tool.version}, stage ${file.stage}, commit \`${file.commit}\`.${rules}${cap}`,
    );
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

export async function loadCorpusResultFiles(dir: string): Promise<CorpusResultsFile[]> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const files: CorpusResultsFile[] = [];
  for (const name of names.filter((item) => item.endsWith(".json")).sort()) {
    const text = await readFile(join(dir, name), "utf8");
    const parsed = corpusResultsSchema.safeParse(JSON.parse(text) as unknown);
    if (!parsed.success) {
      throw new Error(`${name}: ${formatZodIssues(parsed.error)}`);
    }
    const expected = corpusResultsFilename(
      parsed.data.date,
      parsed.data.commit,
      parsed.data.tool.name,
      parsed.data.stage,
    );
    if (name !== expected) {
      throw new Error(`${name} does not match ${expected}`);
    }
    files.push(parsed.data);
  }
  return files;
}

export async function renderCorpusResultsDir(dir: string): Promise<string> {
  return renderCorpusResultsMarkdown(await loadCorpusResultFiles(dir));
}
