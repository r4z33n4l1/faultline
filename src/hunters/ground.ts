import type { Candidate } from "../schema/candidate.js";
import { normalizeRepoPath } from "./source.js";

function lineCount(text: string): number {
  if (text.length === 0) {
    return 1;
  }
  return text.split(/\r?\n/).length;
}

function lineIn(text: string, line: number): boolean {
  return line >= 1 && line <= lineCount(text);
}

function symbolIn(source: string, symbol: string): boolean {
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(String.raw`(?<![\w$])${escaped}(?![\w$])`).test(source);
}

function groundedCandidate(
  candidate: Candidate,
  files: ReadonlyMap<string, string>,
): Candidate | undefined {
  const file = normalizeRepoPath(candidate.location.file);
  if (file === undefined) {
    return undefined;
  }
  const text = files.get(file);
  if (text === undefined || !lineIn(text, candidate.location.start_line)) {
    return undefined;
  }
  if (candidate.location.end_line !== undefined && !lineIn(text, candidate.location.end_line)) {
    return undefined;
  }
  if (!symbolIn(text, candidate.symbol)) {
    return undefined;
  }

  const evidence: Candidate["evidence"] = [];
  for (const item of candidate.evidence) {
    const evidenceFile = normalizeRepoPath(item.file);
    if (evidenceFile === undefined) {
      return undefined;
    }
    const evidenceText = files.get(evidenceFile);
    if (evidenceText === undefined || !lineIn(evidenceText, item.line)) {
      return undefined;
    }
    evidence.push({ ...item, file: evidenceFile });
  }

  const location: Candidate["location"] = {
    file,
    start_line: candidate.location.start_line,
  };
  if (candidate.location.end_line !== undefined) {
    location.end_line = candidate.location.end_line;
  }
  return { ...candidate, location, evidence };
}

/** Drop candidates whose file, line range, or cited symbol is not in the tree. */
export function groundCandidates(
  candidates: readonly Candidate[],
  files: ReadonlyMap<string, string>,
): Candidate[] {
  const kept: Candidate[] = [];
  for (const candidate of candidates) {
    const grounded = groundedCandidate(candidate, files);
    if (grounded !== undefined) {
      kept.push(grounded);
    }
  }
  return kept;
}
