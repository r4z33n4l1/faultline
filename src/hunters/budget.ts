import { HUNTER_SITE_CAP } from "./shared.js";

/** Higher is reviewed first when the site budget binds. */
export function riskRank(risk: "tainted" | "dynamic" | "constant"): number {
  if (risk === "tainted") {
    return 2;
  }
  if (risk === "dynamic") {
    return 1;
  }
  return 0;
}

export function resolveMaxSites(value: number | undefined): number {
  if (value !== undefined && Number.isSafeInteger(value) && value >= 1) {
    return value;
  }
  return HUNTER_SITE_CAP;
}

/**
 * `overCap` flags aligned with `items`. The budget keeps the highest rank,
 * then `tie`. A lower-ranked site does not take a slot from a higher one.
 */
export function overCapFlags<T>(
  items: readonly T[],
  maxSites: number,
  rank: (item: T) => number,
  tie: (left: T, right: T) => number,
): boolean[] {
  const order = items.map((item, index) => ({ item, index }));
  order.sort(
    (left, right) =>
      rank(right.item) - rank(left.item) || tie(left.item, right.item) || left.index - right.index,
  );
  const dropped = new Set(order.slice(Math.max(0, maxSites)).map((entry) => entry.index));
  return items.map((_, index) => dropped.has(index));
}
