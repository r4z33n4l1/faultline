import type { DiscoveredSite } from "../discovery/types.js";
import type { ModelProvider } from "../providers/types.js";
import type { Inventory } from "../recon/inventory.js";
import type { Candidate } from "../schema/candidate.js";
import type { CoverageClass, CoverageStatus, MalformedExample } from "../schema/coverage.js";

export interface HunterContext {
  /** Absolute directory that was inventoried. */
  root: string;
  target: string;
  inventory: Inventory;
  provider?: ModelProvider;
  /** Sites each hunter reviews. Defaults to the shared site budget. */
  maxSites?: number;
  /**
   * Grounded sites from the discovery pass. Hunters union these with
   * heuristic sites before the site budget. Unset when no provider ran.
   */
  discovered?: readonly DiscoveredSite[];
  markCoverage(
    unitId: string,
    status: Extract<CoverageStatus, "hunted" | "skipped">,
    reason: string,
  ): void;
  /** Model objects this hunter rejected. Omitted by unit tests that only inspect candidates. */
  recordMalformed?(items: readonly MalformedExample[]): void;
}

/** One bug class. Register another class by adding a hunter module. */
export interface Hunter {
  readonly name: string;
  readonly class: CoverageClass;
  run(ctx: HunterContext): Promise<Candidate[]>;
}
