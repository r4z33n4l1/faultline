import {
  COVERAGE_CLASSES,
  COVERAGE_SCHEMA_VERSION,
  coverageFileSchema,
  type CoverageClass,
  type CoverageFile,
  type CoverageStatus,
  type CoverageUnit,
  type MalformedExample,
} from "../schema/coverage.js";
import type { Inventory } from "./inventory.js";

export const PENDING_REASON = "not hunted yet";

export function fileCoverageId(path: string, bug: CoverageClass): string {
  return `file:${path}:${bug}`;
}

export function routeCoverageId(
  route: { path: string; line: number; note: string },
  bug: CoverageClass,
): string {
  return `route:${route.path}:${route.line}:${route.note}:${bug}`;
}

export interface CoverageMark {
  status: Extract<CoverageStatus, "hunted" | "skipped">;
  reason: string;
}

export function serializeCoverage(file: CoverageFile): string {
  return `${JSON.stringify(coverageFileSchema.parse(file), null, 2)}\n`;
}

/** Hunters replace pending rows. Unknown ids are left unchanged. */
export function applyCoverageMarks(
  coverage: CoverageFile,
  marks: ReadonlyMap<string, CoverageMark>,
): CoverageFile {
  if (marks.size === 0) {
    return coverage;
  }
  return coverageFileSchema.parse({
    ...coverage,
    units: coverage.units.map((unit) => {
      const mark = marks.get(unit.id);
      if (mark === undefined) {
        return unit;
      }
      return { ...unit, status: mark.status, reason: mark.reason };
    }),
  });
}

/** Recon records every file and route against each bug class as pending. */
export function buildCoverage(target: string, inventory: Inventory): CoverageFile {
  const units: CoverageUnit[] = [];
  for (const path of inventory.source_files) {
    for (const bug of COVERAGE_CLASSES) {
      units.push({
        id: fileCoverageId(path, bug),
        kind: "file",
        path,
        class: bug,
        status: "pending",
        reason: PENDING_REASON,
      });
    }
  }
  for (const route of inventory.routes) {
    for (const bug of COVERAGE_CLASSES) {
      units.push({
        id: routeCoverageId(route, bug),
        kind: "route",
        path: route.path,
        route: route.note,
        line: route.line,
        class: bug,
        status: "pending",
        reason: PENDING_REASON,
      });
    }
  }
  units.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const skipped = [...inventory.skipped].sort(
    (left, right) =>
      (left.path < right.path ? -1 : left.path > right.path ? 1 : 0) ||
      (left.reason < right.reason ? -1 : left.reason > right.reason ? 1 : 0),
  );
  return coverageFileSchema.parse({
    schema_version: COVERAGE_SCHEMA_VERSION,
    target,
    units,
    skipped,
    discovery: [],
    malformed: [],
  });
}

/** Attach capped malformed-reply examples. An empty list leaves the ledger unchanged. */
export function applyMalformed(
  coverage: CoverageFile,
  examples: readonly MalformedExample[],
): CoverageFile {
  if (examples.length === 0) {
    return coverage;
  }
  return coverageFileSchema.parse({ ...coverage, malformed: examples });
}

/** Attach discovery records. An empty list leaves a ledger that already has none. */
export function applyDiscoveryRecords(
  coverage: CoverageFile,
  records: readonly CoverageFile["discovery"][number][],
): CoverageFile {
  if (records.length === 0) {
    return coverage;
  }
  const discovery = [...records].sort((left, right) =>
    left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
  );
  return coverageFileSchema.parse({ ...coverage, discovery });
}
