import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { writeRunOutput } from "../output.js";
import { runPipeline } from "../pipeline.js";
import type { ModelProvider } from "../providers/types.js";
import { renderArchitecture } from "./architecture.js";
import { buildCoverage, serializeCoverage } from "./coverage.js";
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
  const coverage = buildCoverage(request.target, inventory);
  const architecture = await renderArchitecture(inventory, request.provider);
  const findings = runPipeline({
    mode: "scan",
    target: request.target,
    provider: request.provider,
    startedAt: request.startedAt,
    runId: request.runId,
  });
  await writeRunOutput(request.outDir, findings, { scanRoot: abs });
  await writeFile(join(request.outDir, "architecture.md"), architecture, "utf8");
  await writeFile(join(request.outDir, "coverage.json"), serializeCoverage(coverage), "utf8");
}
