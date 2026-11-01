import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { importSarif } from "./sarif-import.js";
import {
  benchResultFromDetections,
  loadTruthFile,
  readGitCommit,
  writeBenchResult,
  type BenchResultDraft,
} from "./run.js";
import type { BenchResult } from "./result.js";
import { assertSemgrepVersion, scanWithSemgrep } from "./semgrep.js";
import type { DetectionSpan } from "./score.js";

export interface ExternalBenchRequest {
  /** Absolute directory the truth paths are relative to. */
  root: string;
  targetLabel: string;
  truthPath: string;
  truthLabel: string;
  outDir: string;
  cwd: string;
  tool: { name: string; version: string };
  startedAt?: Date;
  runId?: string;
}

async function publish(
  request: ExternalBenchRequest,
  detections: readonly DetectionSpan[],
): Promise<BenchResult> {
  const truth = await loadTruthFile(resolve(request.cwd, request.truthPath), request.root);
  const commit = await readGitCommit(request.cwd);
  const draft: BenchResultDraft = {
    target: request.targetLabel,
    truthPath: request.truthLabel,
    stage: "scan",
    tool: request.tool,
    runId: request.runId ?? randomUUID(),
    startedAt: (request.startedAt ?? new Date()).toISOString(),
    provider: null,
    model: null,
    commit,
  };
  const result = benchResultFromDetections(draft, truth, detections);
  await writeBenchResult(request.outDir, result);
  return result;
}

export async function executeSarifBench(
  request: ExternalBenchRequest & { sarifPath: string },
): Promise<BenchResult> {
  let text: string;
  try {
    text = await readFile(resolve(request.cwd, request.sarifPath), "utf8");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Cannot read SARIF: ${message}`, { cause: error });
  }
  let document: unknown;
  try {
    document = JSON.parse(text) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid SARIF JSON: ${message}`, { cause: error });
  }
  const imported = importSarif(document, request.root);
  return publish(request, imported.detections);
}

export async function executeSemgrepBench(
  request: ExternalBenchRequest & {
    bin: string;
    expectedVersion: string;
    rulesets: readonly string[];
  },
): Promise<BenchResult> {
  await assertSemgrepVersion(request.bin, request.expectedVersion);
  const imported = await scanWithSemgrep(request.bin, request.rulesets, request.root);
  return publish(request, imported.detections);
}
