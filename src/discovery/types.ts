import type { CoverageClass } from "../schema/coverage.js";
import type { DiscoveryRecord, DiscoveryUnitKind } from "../schema/coverage.js";

export type { DiscoveryRecord, DiscoveryUnitKind };

/** Default number of discovery model calls. `--discovery-budget` overrides it. */
export const DISCOVERY_CALL_BUDGET = 60;
/** A unit whose span is longer than this is split, or skipped when one window is still too dense. */
export const DISCOVERY_UNIT_MAX_LINES = 180;
export const DISCOVERY_UNIT_MAX_CHARS = 8_000;
export const DISCOVERY_MAX_SITES_PER_UNIT = 8;

export const DISCOVERY_REVIEWED = "discovery pass reviewed this unit";
export const DISCOVERY_BUDGET_REASON = "discovery budget exhausted";
export const DISCOVERY_VENDORED = "vendored path";
export const DISCOVERY_TEST = "test path";
export const DISCOVERY_MINIFIED = "minified path";
export const DISCOVERY_TOO_LARGE = "unit exceeds the discovery size cap";
export const DISCOVERY_UNREADABLE = "source could not be read";

/**
 * A site the discovery model named, after the line was checked against the file.
 * Hunters merge these with heuristic sites before the per-class site budget.
 */
export interface DiscoveredSite {
  class: CoverageClass;
  file: string;
  line: number;
  endLine: number;
  symbol: string;
  /** One line, already redacted. */
  reason: string;
  /** Request-object use is visible in the unit window that contains this line. */
  tainted: boolean;
  /** Redacted source for the unit window. Not numbered. */
  source: string;
  startLine: number;
  sourceEndLine: number;
  truncated: boolean;
}

export interface ParsedDiscoverySite {
  class: CoverageClass;
  line: number;
  endLine?: number;
  symbol?: string;
  reason: string;
}

export function resolveDiscoveryBudget(value: number | undefined): number {
  if (value !== undefined && Number.isSafeInteger(value) && value >= 1) {
    return value;
  }
  return DISCOVERY_CALL_BUDGET;
}

export function discoveryRecordId(
  kind: DiscoveryUnitKind,
  path: string,
  start: number,
  end: number,
): string {
  return `discovery:${kind}:${path}:${start}:${end}`;
}

export function hasRequestEvidence(source: string): boolean {
  return (
    /\b(?:req|request)\s*(?:\?\.|\.)\s*(?:params|query|body|headers|files|cookies)\b/.test(
      source,
    ) ||
    /\b(?:ctx|context)\s*(?:\?\.|\.)\s*(?:params|query|body|headers|request)\b/.test(source) ||
    /\bnextUrl\s*(?:\?\.|\.)\s*searchParams\b/.test(source)
  );
}
