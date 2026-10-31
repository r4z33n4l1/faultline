import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { hunters } from "../hunters/registry.js";
import type { HunterContext } from "../hunters/types.js";
import { writeRunOutput } from "../output.js";
import { runPipeline } from "../pipeline.js";
import type { ModelProvider } from "../providers/types.js";
import { serializeCandidates, type Candidate } from "../schema/candidate.js";
import { renderArchitecture } from "./architecture.js";
import {
  applyCoverageMarks,
  buildCoverage,
  serializeCoverage,
  type CoverageMark,
} from "./coverage.js";
import { collectInventory } from "./inventory.js";

export interface ScanRequest {
  target: string;
  cwd: string;
  outDir: string;
  provider?: ModelProvider;
  startedAt?: Date;
  runId?: string;
}

export async function executeScan(request: ScanRequest): Promise<void> {
  const abs = resolve(request.cwd, request.target);
  const inventory = await collectInventory(abs, { target: request.target });
  const architecture = await renderArchitecture(inventory, request.provider);
  const startedAt = request.startedAt ?? new Date();
  const runId = request.runId ?? randomUUID();
  const marks = new Map<string, CoverageMark>();
  const ctx: HunterContext = {
    root: abs,
    target: request.target,
    inventory,
    markCoverage(unitId, status, reason) {
      marks.set(unitId, { status, reason });
    },
  };
  if (request.provider !== undefined) {
    ctx.provider = request.provider;
  }
  const candidates: Candidate[] = [];
  for (const hunter of hunters) {
    const found = await hunter.run(ctx);
    for (const candidate of found) {
      if (candidate.class === hunter.class) {
        candidates.push(candidate);
      }
    }
  }
  const coverage = applyCoverageMarks(buildCoverage(request.target, inventory), marks);
  const findings = runPipeline({
    mode: "scan",
    target: request.target,
    provider: request.provider,
    startedAt,
    runId,
  });
  await writeRunOutput(request.outDir, findings, {
    scanRoot: abs,
    unvalidatedCandidates: candidates.length,
  });
  await writeFile(join(request.outDir, "architecture.md"), architecture, "utf8");
  await writeFile(join(request.outDir, "coverage.json"), serializeCoverage(coverage), "utf8");
  await writeFile(
    join(request.outDir, "candidates.json"),
    serializeCandidates({
      schema_version: findings.schema_version,
      tool: findings.tool,
      run: findings.run,
      candidates,
    }),
    "utf8",
  );
}
