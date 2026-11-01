import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { discoverSites } from "../discovery/run.js";
import {
  resolveDiscoveryBudget,
  type DiscoveredSite,
  type DiscoveryRecord,
} from "../discovery/types.js";
import type { ModelProvider } from "../providers/types.js";
import { hunters } from "../hunters/registry.js";
import type { HunterContext } from "../hunters/types.js";
import { writeRunOutput } from "../output.js";
import { provenanceFor, runPipeline } from "../pipeline.js";
import { disprovedEntries, inconclusiveEntries, validateCandidates } from "../validator/index.js";
import { serializeCandidates, type Candidate } from "../schema/candidate.js";
import { renderArchitecture } from "./architecture.js";
import {
  applyCoverageMarks,
  applyDiscoveryRecords,
  buildCoverage,
  serializeCoverage,
  type CoverageMark,
} from "./coverage.js";
import {
  collectInventory,
  inventoryCapNote,
  type CollectOptions,
  type Inventory,
} from "./inventory.js";

export interface ScanRequest {
  target: string;
  cwd: string;
  outDir: string;
  provider?: ModelProvider;
  validate?: boolean;
  /** Promote inconclusive candidates to low-confidence findings. Default off. */
  keepInconclusive?: boolean;
  /** Include and exclude globs, and file or byte caps. Defaults apply when omitted. */
  inventory?: CollectOptions;
  /** Per-hunter site budget. Defaults to the shared cap when omitted. */
  maxSites?: number;
  /** Discovery model calls. Defaults to the discovery budget. Ignored without a provider. */
  discoveryBudget?: number;
  startedAt?: Date;
  runId?: string;
}

async function discoverForProvider(
  root: string,
  inventory: Inventory,
  provider: ModelProvider | undefined,
  budget: number | undefined,
): Promise<{ sites: DiscoveredSite[]; records: DiscoveryRecord[] }> {
  if (provider === undefined) {
    return { sites: [], records: [] };
  }
  return discoverSites({
    root,
    inventory,
    provider,
    budget: resolveDiscoveryBudget(budget),
  });
}

export async function runHunters(ctx: HunterContext): Promise<Candidate[]> {
  const candidates: Candidate[] = [];
  for (const hunter of hunters) {
    const found = await hunter.run(ctx);
    for (const candidate of found) {
      if (candidate.class === hunter.class) {
        candidates.push(candidate);
      }
    }
  }
  return candidates;
}

export async function executeScan(request: ScanRequest): Promise<void> {
  const abs = resolve(request.cwd, request.target);
  const inventory = await collectInventory(abs, {
    target: request.target,
    limits: request.inventory?.limits,
    include: request.inventory?.include,
    exclude: request.inventory?.exclude,
  });
  const architecture = await renderArchitecture(inventory, request.provider);
  const startedAt = request.startedAt ?? new Date();
  const runId = request.runId ?? randomUUID();
  const marks = new Map<string, CoverageMark>();
  const discovered = await discoverForProvider(
    abs,
    inventory,
    request.provider,
    request.discoveryBudget,
  );
  const ctx: HunterContext = {
    root: abs,
    target: request.target,
    inventory,
    ...(request.maxSites === undefined ? {} : { maxSites: request.maxSites }),
    ...(discovered.sites.length === 0 ? {} : { discovered: discovered.sites }),
    markCoverage(unitId, status, reason) {
      marks.set(unitId, { status, reason });
    },
  };
  if (request.provider !== undefined) {
    ctx.provider = request.provider;
  }
  const candidates = await runHunters(ctx);
  const coverage = applyDiscoveryRecords(
    applyCoverageMarks(buildCoverage(request.target, inventory), marks),
    discovered.records,
  );
  const validation =
    request.validate === false
      ? { findings: [], disproved: [], inconclusive: [] }
      : await validateCandidates(candidates, {
          root: abs,
          provider: request.provider,
          inventory,
          keepInconclusive: request.keepInconclusive === true,
        });
  const provenance = await provenanceFor(request.provider);
  const findings = runPipeline({
    mode: "scan",
    target: request.target,
    provider: request.provider,
    model: provenance.model,
    commit: provenance.commit,
    startedAt,
    runId,
    findings: validation.findings,
  });
  await writeRunOutput(request.outDir, findings, {
    scanRoot: abs,
    unvalidatedCandidates: request.validate === false ? candidates.length : 0,
    disproved: disprovedEntries(validation.disproved),
    inconclusive: inconclusiveEntries(validation.inconclusive),
    inventoryNote: inventoryCapNote(inventory),
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
