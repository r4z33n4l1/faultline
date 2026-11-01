import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { discoverSites } from "../discovery/run.js";
import { resolveDiscoveryBudget } from "../discovery/types.js";
import { runHunters } from "../recon/run.js";
import { writeRunOutput } from "../output.js";
import { provenanceFor, runPipeline } from "../pipeline.js";
import { disprovedEntries, inconclusiveEntries, validateCandidates } from "../validator/index.js";
import type { ModelProvider } from "../providers/types.js";
import { renderArchitecture } from "../recon/architecture.js";
import {
  applyCoverageMarks,
  applyDiscoveryRecords,
  buildCoverage,
  serializeCoverage,
  type CoverageMark,
} from "../recon/coverage.js";
import {
  collectInventory,
  inventoryCapNote,
  type CollectOptions,
  type Inventory,
  type InventoryMatch,
} from "../recon/inventory.js";
import { serializeCandidates } from "../schema/candidate.js";
import type { CoverageFile } from "../schema/coverage.js";
import { coverageFileSchema } from "../schema/coverage.js";
import type { HunterContext } from "../hunters/types.js";
import { candidateOverlapsDiff, rangesOverlap, type ChangedFile, type ParsedDiff } from "./diff.js";

export const OUTSIDE_DIFF_REASON = "outside-diff";

export interface PrRequest {
  /** User-facing diff argument (`-` or the path they passed). Stored on the run. */
  diffLabel: string;
  /** Absolute repository directory after the change. */
  repo: string;
  /** `--repo` value as given. Stored on the coverage file. */
  repoLabel: string;
  outDir: string;
  parsed: ParsedDiff;
  context: number;
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

export async function executePr(request: PrRequest): Promise<void> {
  const inventory = await collectInventory(request.repo, {
    target: request.repoLabel,
    limits: request.inventory?.limits,
    include: request.inventory?.include,
    exclude: request.inventory?.exclude,
  });
  const changed = request.parsed.files;
  const architecture = markChangedFiles(
    await renderArchitecture(inventory, request.provider),
    changed.map((file) => file.path),
  );
  const startedAt = request.startedAt ?? new Date();
  const runId = request.runId ?? randomUUID();
  const marks = new Map<string, CoverageMark>();
  const scoped = scopeInventory(inventory, new Set(changed.map((file) => file.path)));
  const discovered =
    request.provider === undefined
      ? { sites: [], records: [] }
      : await discoverSites({
          root: request.repo,
          inventory: scoped,
          provider: request.provider,
          budget: resolveDiscoveryBudget(request.discoveryBudget),
        });
  const ctx: HunterContext = {
    root: request.repo,
    target: request.repoLabel,
    inventory: scoped,
    ...(request.maxSites === undefined ? {} : { maxSites: request.maxSites }),
    ...(discovered.sites.length === 0 ? {} : { discovered: discovered.sites }),
    markCoverage(unitId, status, reason) {
      marks.set(unitId, { status, reason });
    },
  };
  if (request.provider !== undefined) {
    ctx.provider = request.provider;
  }
  const found = await runHunters(ctx);
  const candidates = found.filter((candidate) =>
    candidateOverlapsDiff(candidate, changed, request.context),
  );
  const coverage = applyOutsideDiff(
    applyDiscoveryRecords(
      applyCoverageMarks(buildCoverage(request.repoLabel, inventory), marks),
      discovered.records,
    ),
    changed,
    request.context,
  );
  const validation =
    request.validate === false
      ? { findings: [], disproved: [], inconclusive: [] }
      : await validateCandidates(candidates, {
          root: request.repo,
          provider: request.provider,
          inventory,
          keepInconclusive: request.keepInconclusive === true,
        });
  const provenance = await provenanceFor(request.provider);
  const findings = runPipeline({
    mode: "pr",
    target: request.diffLabel,
    provider: request.provider,
    model: provenance.model,
    commit: provenance.commit,
    startedAt,
    runId,
    findings: validation.findings,
  });
  await writeRunOutput(request.outDir, findings, {
    scanRoot: request.repo,
    unvalidatedCandidates: request.validate === false ? candidates.length : 0,
    disproved: disprovedEntries(validation.disproved),
    inconclusive: inconclusiveEntries(validation.inconclusive),
    changedFiles: changed.map((file) => file.path),
    hunkContext: request.context,
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

/** Recon still covers the repository. Hunters only see files the diff changed. */
export function scopeInventory(inventory: Inventory, files: ReadonlySet<string>): Inventory {
  const keep = (path: string): boolean => files.has(path);
  const matches = (items: readonly InventoryMatch[]): InventoryMatch[] =>
    items.filter((item) => keep(item.path));
  return {
    ...inventory,
    source_files: inventory.source_files.filter(keep),
    routes: matches(inventory.routes),
    handlers: inventory.handlers.filter(
      (handler) => keep(handler.routeFile) || keep(handler.handlerFile),
    ),
    auth: matches(inventory.auth),
    data_stores: matches(inventory.data_stores),
    outbound_http: matches(inventory.outbound_http),
    env_files: inventory.env_files.filter(keep),
    config_files: inventory.config_files.filter(keep),
    entrypoints: inventory.entrypoints.filter((entry) => keep(entry.path)),
    manifests: inventory.manifests.filter((manifest) => keep(manifest.path)),
  };
}

/**
 * Coverage rows whose file is absent from the diff, and route rows whose line
 * does not overlap a changed hunk, are skipped. Hunter marks on in-diff rows stay.
 */
export function applyOutsideDiff(
  coverage: CoverageFile,
  changed: readonly ChangedFile[],
  context: number,
): CoverageFile {
  const byPath = new Map(changed.map((file) => [file.path, file]));
  return coverageFileSchema.parse({
    ...coverage,
    units: coverage.units.map((unit) => {
      const file = byPath.get(unit.path);
      if (file === undefined) {
        return { ...unit, status: "skipped" as const, reason: OUTSIDE_DIFF_REASON };
      }
      if (unit.kind === "route" && !rangesOverlap(unit.line, unit.line, file.ranges, context)) {
        return { ...unit, status: "skipped" as const, reason: OUTSIDE_DIFF_REASON };
      }
      return unit;
    }),
    discovery: coverage.discovery.map((record) => {
      if (!byPath.has(record.path)) {
        return { ...record, status: "skipped" as const, reason: OUTSIDE_DIFF_REASON };
      }
      return record;
    }),
  });
}

export function markChangedFiles(architecture: string, files: readonly string[]): string {
  const lines = [
    "## Changed files",
    "",
    "PR-scoped run. Recon covered the repository. Hunters run only on these changed files.",
    "",
  ];
  if (files.length === 0) {
    lines.push("None.", "");
  } else {
    for (const file of files) {
      lines.push(`- \`${file}\``);
    }
    lines.push("");
  }
  const base = architecture.endsWith("\n") ? architecture.slice(0, -1) : architecture;
  return `${base}\n\n${lines.join("\n")}`;
}
