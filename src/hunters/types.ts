import type { ModelProvider } from "../providers/types.js";
import type { Inventory } from "../recon/inventory.js";
import type { Candidate } from "../schema/candidate.js";
import type { CoverageClass, CoverageStatus } from "../schema/coverage.js";

export interface HunterContext {
  /** Absolute directory that was inventoried. */
  root: string;
  target: string;
  inventory: Inventory;
  provider?: ModelProvider;
  markCoverage(
    unitId: string,
    status: Extract<CoverageStatus, "hunted" | "skipped">,
    reason: string,
  ): void;
}

/** One bug class. Register another class by adding a hunter module. */
export interface Hunter {
  readonly name: string;
  readonly class: CoverageClass;
  run(ctx: HunterContext): Promise<Candidate[]>;
}
