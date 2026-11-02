import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { discoverSites, type DiscoveryResult } from "../discovery/run.js";
import { resolveDiscoveryBudget } from "../discovery/types.js";
import {
  isProviderFailure,
  isProviderSetupError,
  providerFailureMessage,
} from "../providers/errors.js";
import type { ModelProvider } from "../providers/types.js";
import { hunters } from "../hunters/registry.js";
import type { HunterContext } from "../hunters/types.js";
import { malformedExamples } from "../malformed.js";
import { writeRunOutput } from "../output.js";
import { provenanceFor, runPipeline } from "../pipeline.js";
import {
  disprovedEntries,
  inconclusiveEntries,
  providerErrorEntries,
  validateCandidates,
  type ValidationResult,
} from "../validator/index.js";
import { serializeCandidates, type Candidate } from "../schema/candidate.js";
import { renderArchitecture, renderInventoryArchitecture } from "./architecture.js";
import {
  applyCoverageMarks,
  applyDiscoveryRecords,
  applyMalformed,
  buildCoverage,
  serializeCoverage,
  type CoverageMark,
} from "./coverage.js";
import type { MalformedExample } from "../schema/coverage.js";
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
): Promise<DiscoveryResult> {
  if (provider === undefined) {
    return { sites: [], records: [], malformed: [] };
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

export interface ScanResult {
  providerErrors: number;
}

function emptyValidation(): ValidationResult {
  return { findings: [], disproved: [], inconclusive: [], errors: [], malformed: [] };
}

export async function executeScan(request: ScanRequest): Promise<ScanResult> {
  const abs = resolve(request.cwd, request.target);
  const inventory = await collectInventory(abs, {
    target: request.target,
    limits: request.inventory?.limits,
    include: request.inventory?.include,
    exclude: request.inventory?.exclude,
  });
  let architectureHalt: string | undefined;
  let architecture: string;
  try {
    architecture = await renderArchitecture(inventory, request.provider);
  } catch (error) {
    if (
      request.provider === undefined ||
      !isProviderFailure(error) ||
      isProviderSetupError(error)
    ) {
      throw error;
    }
    architectureHalt = providerFailureMessage(error);
    architecture = `${renderInventoryArchitecture(inventory).trimEnd()}\n\nProvider error: ${architectureHalt}\n`;
  }
  const startedAt = request.startedAt ?? new Date();
  const runId = request.runId ?? randomUUID();
  const marks = new Map<string, CoverageMark>();
  const malformed: MalformedExample[] = [];
  const model = architectureHalt === undefined ? request.provider : undefined;
  const discovered = await discoverForProvider(abs, inventory, model, request.discoveryBudget);
  const halted = architectureHalt ?? discovered.halted;
  const ctx: HunterContext = {
    root: abs,
    target: request.target,
    inventory,
    ...(request.maxSites === undefined ? {} : { maxSites: request.maxSites }),
    ...(discovered.sites.length === 0 ? {} : { discovered: discovered.sites }),
    markCoverage(unitId, status, reason) {
      marks.set(unitId, { status, reason });
    },
    recordMalformed(items) {
      malformed.push(...items);
    },
  };
  if (model !== undefined && halted === undefined) {
    ctx.provider = model;
  }
  let huntHalt: string | undefined;
  let candidates: Candidate[] = [];
  if (halted === undefined) {
    try {
      candidates = await runHunters(ctx);
    } catch (error) {
      if (!isProviderFailure(error) || isProviderSetupError(error)) {
        throw error;
      }
      huntHalt = providerFailureMessage(error);
    }
  }
  const stop = halted ?? huntHalt;
  const validation =
    request.validate === false
      ? emptyValidation()
      : await validateCandidates(candidates, {
          root: abs,
          ...(model === undefined || stop !== undefined ? {} : { provider: model }),
          ...(stop === undefined ? {} : { providerHalt: stop }),
          inventory,
          keepInconclusive: request.keepInconclusive === true,
        });
  malformed.push(...discovered.malformed, ...validation.malformed);
  const examples = malformedExamples(malformed);
  const coverage = applyMalformed(
    applyDiscoveryRecords(
      applyCoverageMarks(buildCoverage(request.target, inventory), marks),
      discovered.records,
    ),
    examples,
  );
  const discoveryErrors = discovered.records.filter((record) => record.status === "error").length;
  let providerErrors = discoveryErrors + validation.errors.length;
  if (stop !== undefined && providerErrors === 0) {
    providerErrors = 1;
  }
  const providerError =
    validation.errors[0]?.reason ??
    discovered.records.find((record) => record.status === "error")?.reason ??
    stop;
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
    providerErrorCount: providerErrors,
    malformedCount: malformed.length,
    ...(providerError === undefined ? {} : { providerError }),
  });
  await writeRunOutput(request.outDir, findings, {
    scanRoot: abs,
    unvalidatedCandidates: request.validate === false ? candidates.length : 0,
    disproved: disprovedEntries(validation.disproved),
    inconclusive: inconclusiveEntries(validation.inconclusive),
    errors: providerErrorEntries(validation.errors),
    inventoryNote: inventoryCapNote(inventory),
    malformed: examples,
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
  return { providerErrors };
}
