import { execFile } from "node:child_process";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { executeScan } from "../recon/run.js";
import { candidatesFileSchema, type CandidatesFile } from "../schema/candidate.js";
import { findingsFileSchema, formatZodIssues, type FindingsFile } from "../schema/finding.js";
import { truthFileSchema, type TruthEntry, type TruthFile } from "../schema/truth.js";
import { ANTHROPIC_DEFAULT_MODEL } from "../providers/anthropic.js";
import type { ProviderConfig } from "../providers/config.js";
import { OPENAI_DEFAULT_MODEL } from "../providers/openai.js";
import type { ModelProvider } from "../providers/types.js";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";
import { renderBenchMarkdown } from "./format.js";
import {
  BENCH_DISCLAIMER,
  benchResultSchema,
  type BenchResult,
  type BenchStage,
  type ResultStage,
} from "./result.js";
import { normalizeBenchPath, scoreBench, type DetectionSpan } from "./score.js";

export interface BenchRequest {
  target: string;
  cwd: string;
  outDir: string;
  stage: BenchStage;
  /** Path to truth.json. Relative paths are resolved from `cwd`. */
  truthPath: string;
  provider?: ModelProvider;
  /** Model id to record. Null when this run did not call a named model. */
  model: string | null;
  startedAt?: Date;
  runId?: string;
}

/** Model id that would be sent for this config. Fake and unset providers record null. */
export function recordedModel(config: ProviderConfig): string | null {
  if (config.name === undefined || config.name === "fake") {
    return null;
  }
  if (config.model !== undefined) {
    return config.model;
  }
  if (config.name === "openai") {
    return OPENAI_DEFAULT_MODEL;
  }
  if (config.name === "anthropic") {
    return ANTHROPIC_DEFAULT_MODEL;
  }
  return null;
}

export function readGitCommit(cwd: string): Promise<string | null> {
  return new Promise((resolvePromise) => {
    execFile(
      "git",
      ["rev-parse", "HEAD"],
      { cwd, timeout: 5_000 },
      (error, stdout: string | Buffer) => {
        if (error) {
          resolvePromise(null);
          return;
        }
        const sha = stdout.toString().trim();
        resolvePromise(/^[0-9a-f]{40}$/.test(sha) ? sha : null);
      },
    );
  });
}

function lineCount(text: string): number {
  if (text.length === 0) {
    return 0;
  }
  const parts = text.split(/\r?\n/);
  if (text.endsWith("\n") || text.endsWith("\r")) {
    return parts.length - 1;
  }
  return parts.length;
}

function relativePosix(root: string, file: string): string | undefined {
  const abs = resolve(root, file);
  const rel = relative(root, abs);
  if (rel.length === 0 || rel.startsWith("..") || isAbsolute(rel)) {
    return undefined;
  }
  return rel.split(sep).join("/");
}

async function readJson(filePath: string): Promise<unknown> {
  let text: string;
  try {
    text = await readFile(filePath, "utf8");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Cannot read file: ${message}`, { cause: error });
  }
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid JSON: ${message}`, { cause: error });
  }
}

export async function loadTruthFile(truthPath: string, root: string): Promise<TruthFile> {
  const parsed = truthFileSchema.safeParse(await readJson(truthPath));
  if (!parsed.success) {
    throw new Error(formatZodIssues(parsed.error));
  }
  for (const entry of parsed.data.entries) {
    const rel = relativePosix(root, entry.file);
    if (rel === undefined) {
      throw new Error(`Truth entry ${entry.id} file is outside the target: ${entry.file}`);
    }
    const abs = resolve(root, rel);
    let text: string;
    try {
      const info = await stat(abs);
      if (!info.isFile()) {
        throw new Error(`Truth entry ${entry.id} file is not a file: ${rel}`);
      }
      text = await readFile(abs, "utf8");
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Truth entry")) {
        throw error;
      }
      throw new Error(`Truth entry ${entry.id} file cannot be read: ${rel}`, { cause: error });
    }
    const lines = lineCount(text);
    if (entry.end_line > lines) {
      throw new Error(
        `Truth entry ${entry.id} end_line ${entry.end_line} is past line ${lines} of ${rel}`,
      );
    }
  }
  return parsed.data;
}

export function detectionsFromCandidates(file: CandidatesFile): DetectionSpan[] {
  return file.candidates.map((candidate) => ({
    class: candidate.class,
    file: normalizeBenchPath(candidate.location.file),
    startLine: candidate.location.start_line,
    endLine: candidate.location.end_line ?? candidate.location.start_line,
  }));
}

export function detectionsFromFindings(file: FindingsFile): DetectionSpan[] {
  return file.findings.map((finding) => ({
    class: finding.class,
    file: normalizeBenchPath(finding.location.file),
    startLine: finding.location.start_line,
    endLine: finding.location.end_line ?? finding.location.start_line,
  }));
}

export interface BenchResultDraft {
  target: string;
  truthPath: string;
  stage: ResultStage;
  tool: { name: string; version: string };
  runId: string;
  startedAt: string;
  provider: string | null;
  model: string | null;
  commit: string | null;
}

/** Site-level score for one tool run. Does not scan and does not promote candidates. */
export function benchResultFromDetections(
  draft: BenchResultDraft,
  truth: TruthFile,
  detections: readonly DetectionSpan[],
): BenchResult {
  const entries: TruthEntry[] = truth.entries;
  const scored = scoreBench(entries, detections);
  const provider = draft.provider;
  const model = draft.model;
  return benchResultSchema.parse({
    schema_version: "1",
    disclaimer: BENCH_DISCLAIMER,
    citable: provider !== null && provider !== "fake" && model !== null && draft.commit !== null,
    stage: draft.stage,
    target: draft.target,
    truth: draft.truthPath,
    tool: draft.tool,
    run: {
      id: draft.runId,
      started_at: draft.startedAt,
      provider,
      model,
      commit: draft.commit,
    },
    counts: {
      truth: entries.length,
      vulnerable: entries.filter((entry) => entry.vulnerable).length,
      safe: entries.filter((entry) => !entry.vulnerable).length,
      detections: detections.length,
      unmatched: scored.unmatched.length,
    },
    overall: scored.overall,
    classes: scored.classes,
    entries: scored.entries,
    unmatched: scored.unmatched,
  });
}

export async function writeBenchResult(outDir: string, result: BenchResult): Promise<void> {
  await mkdir(outDir, { recursive: true });
  await writeFile(
    resolve(outDir, "bench-result.json"),
    `${JSON.stringify(result, null, 2)}\n`,
    "utf8",
  );
  await writeFile(resolve(outDir, "bench-result.md"), renderBenchMarkdown(result), "utf8");
}

export async function executeBench(request: BenchRequest): Promise<BenchResult> {
  const root = resolve(request.cwd, request.target);
  let rootInfo: Awaited<ReturnType<typeof stat>>;
  try {
    rootInfo = await stat(root);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Cannot read target: ${message}`, { cause: error });
  }
  if (!rootInfo.isDirectory()) {
    throw new Error(`Target is not a directory: ${request.target}`);
  }
  const truthPath = resolve(request.cwd, request.truthPath);
  const truth = await loadTruthFile(truthPath, root);
  const scan: {
    target: string;
    cwd: string;
    outDir: string;
    provider?: ModelProvider;
    validate: boolean;
    startedAt?: Date;
    runId?: string;
  } = {
    target: request.target,
    validate: request.stage === "findings",
    cwd: request.cwd,
    outDir: request.outDir,
  };
  if (request.provider !== undefined) {
    scan.provider = request.provider;
  }
  if (request.startedAt !== undefined) {
    scan.startedAt = request.startedAt;
  }
  if (request.runId !== undefined) {
    scan.runId = request.runId;
  }
  await executeScan(scan);
  const stageName = request.stage === "candidates" ? "candidates.json" : "findings.json";
  const stagePath = resolve(request.outDir, stageName);
  const json = await readJson(stagePath);
  const commit = await readGitCommit(request.cwd);
  let result: BenchResult;
  if (request.stage === "candidates") {
    const parsed = candidatesFileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(formatZodIssues(parsed.error));
    }
    result = benchResultFromDetections(
      draftFromScan(request, parsed.data.run, commit),
      truth,
      detectionsFromCandidates(parsed.data),
    );
  } else {
    const parsed = findingsFileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(formatZodIssues(parsed.error));
    }
    result = benchResultFromDetections(
      draftFromScan(request, parsed.data.run, commit),
      truth,
      detectionsFromFindings(parsed.data),
    );
  }
  await writeBenchResult(request.outDir, result);
  return result;
}

function draftFromScan(
  request: BenchRequest,
  run: { id: string; started_at: string; provider?: string },
  commit: string | null,
): BenchResultDraft {
  return {
    target: request.target,
    truthPath: request.truthPath,
    stage: request.stage,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    runId: run.id,
    startedAt: run.started_at,
    provider: run.provider ?? null,
    model: request.model,
    commit,
  };
}
