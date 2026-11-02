import type { MalformedExample } from "../schema/coverage.js";
import { parseModelCandidates, type Candidate } from "../schema/candidate.js";
import type { FindingClass } from "../schema/finding.js";
import { normalizeRepoPath, readSourceFile } from "./source.js";

/**
 * Default number of sites one hunter reviews. `--max-sites` overrides it.
 * Sites are ranked before the budget is applied. Sites past it stay in
 * coverage with an explicit reason.
 */
export const HUNTER_SITE_CAP = 40;
export const HUNTER_SITE_MAX_LINES = 80;
export const HUNTER_SITE_MAX_CHARS = 4_000;
export const HUNTER_MAX_CANDIDATES_PER_SITE = 3;

/** Keep schema-valid model candidates. Record the rest. Fill root_cause from the site when it is missing. */
export function acceptModelCandidates(
  ctx: { recordMalformed?(items: readonly MalformedExample[]): void },
  text: string,
  expectedClass: FindingClass,
  rootCause: string,
): Candidate[] {
  const parsed = parseModelCandidates(text, expectedClass, rootCause);
  ctx.recordMalformed?.(parsed.malformed);
  return parsed.candidates.slice(0, HUNTER_MAX_CANDIDATES_PER_SITE);
}

export const HEURISTIC_CONFIDENCE_REASON =
  "Deterministic pre-pass only. A validator has not reviewed this candidate.";

export const SOURCE_TRUNCATED_NOTE = "Handler source in the fence was truncated.";

export function compareString(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

/** Drop comments while keeping newlines. Slashes inside strings and templates stay. */
export function stripComments(source: string): string {
  let result = "";
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const ch = source[index] ?? "";
    const next = source[index + 1] ?? "";
    if (quote !== undefined) {
      result += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = undefined;
      }
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      result += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      index += 1;
      while (index + 1 < source.length && source[index + 1] !== "\n") {
        index += 1;
      }
      continue;
    }
    if (ch === "/" && next === "*") {
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) {
        if (source[index] === "\n") {
          result += "\n";
        }
        index += 1;
      }
      index += 1;
      continue;
    }
    result += ch;
  }
  return result;
}

export function stripQuoted(line: string): string {
  return line.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, '""');
}

export function sliceLines(lines: readonly string[], start: number, end: number): string {
  return lines.slice(start - 1, end).join("\n");
}

export function windowEnd(
  routeLine: number,
  nextLine: number | undefined,
  count: number,
  maxLines: number,
): { end: number; truncated: boolean } {
  const natural = nextLine === undefined ? count : Math.max(routeLine, nextLine - 1);
  const capped = Math.min(natural, routeLine + maxLines - 1, count);
  const end = Math.max(capped, routeLine);
  return { end, truncated: end < natural };
}

export function limitSource(source: string, maxChars: number): string {
  if (source.length > maxChars) {
    return source.slice(0, maxChars);
  }
  return source;
}

export function dedupeCandidates(candidates: readonly Candidate[]): Candidate[] {
  const seen = new Set<string>();
  const kept: Candidate[] = [];
  for (const candidate of candidates) {
    const key = JSON.stringify([
      candidate.class,
      candidate.location.file,
      candidate.location.start_line,
      candidate.location.end_line ?? null,
      candidate.symbol,
      candidate.root_cause,
    ]);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    kept.push(candidate);
  }
  return kept;
}

export async function hydrateCitedFiles(
  root: string,
  allowed: ReadonlySet<string>,
  files: Map<string, string>,
  candidates: readonly Candidate[],
): Promise<void> {
  const needed = new Set<string>();
  for (const candidate of candidates) {
    const location = normalizeRepoPath(candidate.location.file);
    if (location !== undefined) {
      needed.add(location);
    }
    for (const item of candidate.evidence) {
      const file = normalizeRepoPath(item.file);
      if (file !== undefined) {
        needed.add(file);
      }
    }
  }
  for (const rel of needed) {
    if (files.has(rel) || !allowed.has(rel)) {
      continue;
    }
    const text = await readSourceFile(root, rel, allowed);
    if (text !== undefined) {
      files.set(rel, text);
    }
  }
}
