import {
  COVERAGE_CLASSES,
  COVERAGE_SCHEMA_VERSION,
  coverageFileSchema,
  type CoverageFile,
  type CoverageUnit,
} from "../schema/coverage.js";
import type { Inventory } from "./inventory.js";

export const PENDING_REASON = "not hunted yet";

export function serializeCoverage(file: CoverageFile): string {
  return `${JSON.stringify(coverageFileSchema.parse(file), null, 2)}\n`;
}

/** Recon records every file and route against each bug class as pending. */
export function buildCoverage(target: string, inventory: Inventory): CoverageFile {
  const units: CoverageUnit[] = [];
  for (const path of inventory.source_files) {
    for (const bug of COVERAGE_CLASSES) {
      units.push({
        id: `file:${path}:${bug}`,
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
        id: `route:${route.path}:${route.line}:${route.note}:${bug}`,
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
  return coverageFileSchema.parse({
    schema_version: COVERAGE_SCHEMA_VERSION,
    target,
    units,
  });
}
