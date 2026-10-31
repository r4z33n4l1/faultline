import { TRUTH_CLASSES, type TruthClass, type TruthEntry } from "../schema/truth.js";

export const BENCH_OUTCOMES = ["tp", "fp", "fn", "tn"] as const;
export type BenchOutcome = (typeof BENCH_OUTCOMES)[number];

/** One detector hit. `class` is the candidate or finding class, which may be outside the truth set. */
export interface DetectionSpan {
  class: string;
  file: string;
  startLine: number;
  endLine: number;
}

export interface Confusion {
  class: string;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  /** True positive rate. Null when the class has no vulnerable labels. */
  recall: number | null;
  /** Null when the class has no positive predictions on labeled sites. */
  precision: number | null;
  tpr: number | null;
  /** False positive rate over labeled safe sites. Null when the class has no safe labels. */
  fpr: number | null;
  /** TPR minus FPR. Null when either rate is undefined. */
  score: number | null;
}

export interface ScoredEntry {
  id: string;
  class: TruthClass;
  cwe: string;
  file: string;
  start_line: number;
  end_line: number;
  vulnerable: boolean;
  outcome: BenchOutcome;
}

export interface BenchScore {
  classes: Confusion[];
  overall: Confusion;
  entries: ScoredEntry[];
  unmatched: DetectionSpan[];
}

export function normalizeBenchPath(file: string): string {
  return file.replaceAll("\\", "/").replace(/^\.\//, "");
}

function rangesOverlap(start: number, end: number, otherStart: number, otherEnd: number): boolean {
  return start <= otherEnd && otherStart <= end;
}

function rate(numerator: number, denominator: number): number | null {
  if (denominator === 0) {
    return null;
  }
  return numerator / denominator;
}

function confusion(name: string, tp: number, fp: number, fn: number, tn: number): Confusion {
  const tpr = rate(tp, tp + fn);
  const fpr = rate(fp, fp + tn);
  return {
    class: name,
    tp,
    fp,
    fn,
    tn,
    recall: tpr,
    precision: rate(tp, tp + fp),
    tpr,
    fpr,
    score: tpr !== null && fpr !== null ? tpr - fpr : null,
  };
}

function compareText(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function outcomeOf(vulnerable: boolean, hit: boolean): BenchOutcome {
  if (vulnerable && hit) {
    return "tp";
  }
  if (!vulnerable && hit) {
    return "fp";
  }
  if (vulnerable) {
    return "fn";
  }
  return "tn";
}

function sameSite(detection: DetectionSpan, entry: TruthEntry): boolean {
  return (
    detection.class === entry.class &&
    normalizeBenchPath(detection.file) === normalizeBenchPath(entry.file) &&
    rangesOverlap(detection.startLine, detection.endLine, entry.start_line, entry.end_line)
  );
}

/**
 * Site-level score. A labeled site is positive when any detection of the same
 * class overlaps its file and line range. Unmatched detections are listed and
 * do not change TP, FP, FN, or TN.
 */
export function scoreBench(
  entries: readonly TruthEntry[],
  detections: readonly DetectionSpan[],
): BenchScore {
  const hits = entries.map((entry) => detections.some((detection) => sameSite(detection, entry)));
  const scored: ScoredEntry[] = entries.map((entry, index) => ({
    id: entry.id,
    class: entry.class,
    cwe: entry.cwe,
    file: normalizeBenchPath(entry.file),
    start_line: entry.start_line,
    end_line: entry.end_line,
    vulnerable: entry.vulnerable,
    outcome: outcomeOf(entry.vulnerable, hits[index] === true),
  }));
  const unmatched = detections.filter(
    (detection) => !entries.some((entry) => sameSite(detection, entry)),
  );
  const classes = TRUTH_CLASSES.map((name) => {
    const rows = scored.filter((entry) => entry.class === name);
    return confusion(
      name,
      rows.filter((entry) => entry.outcome === "tp").length,
      rows.filter((entry) => entry.outcome === "fp").length,
      rows.filter((entry) => entry.outcome === "fn").length,
      rows.filter((entry) => entry.outcome === "tn").length,
    );
  });
  return {
    classes,
    overall: confusion(
      "overall",
      scored.filter((entry) => entry.outcome === "tp").length,
      scored.filter((entry) => entry.outcome === "fp").length,
      scored.filter((entry) => entry.outcome === "fn").length,
      scored.filter((entry) => entry.outcome === "tn").length,
    ),
    entries: [...scored].sort((left, right) => compareText(left.id, right.id)),
    unmatched: unmatched
      .map((detection) => ({
        class: detection.class,
        file: normalizeBenchPath(detection.file),
        startLine: detection.startLine,
        endLine: detection.endLine,
      }))
      .sort(
        (left, right) =>
          compareText(left.class, right.class) ||
          compareText(left.file, right.file) ||
          left.startLine - right.startLine ||
          left.endLine - right.endLine,
      ),
  };
}
