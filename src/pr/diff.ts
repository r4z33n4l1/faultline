import { normalizeRepoPath } from "../hunters/source.js";
import type { Candidate } from "../schema/candidate.js";

/** Reject diffs larger than this before they are parsed. */
export const MAX_DIFF_BYTES = 1_000_000;

/** Lines added around each changed line when testing overlap. */
export const DEFAULT_HUNK_CONTEXT = 3;

/** Upper bound for `--context`. A wider window would keep bugs the diff did not touch. */
export const MAX_HUNK_CONTEXT = 20;

const MAX_CHANGED_FILES = 2_000;
const MAX_PATH_LENGTH = 512;

const GITHUB_PULL_REQUEST =
  /^https?:\/\/(?:www\.)?github\.com\/[^\s/]+\/[^\s/]+\/pull\/\d+(?:\.diff|\.patch)?(?:\/[^\s]*)?(?:\?[^\s]*)?(?:#[^\s]*)?$/i;

const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

export class DiffError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DiffError";
  }
}

export interface HunkRange {
  /** 1-based inclusive line in the post-change file. */
  start: number;
  /** 1-based inclusive line in the post-change file. */
  end: number;
}

export interface ChangedFile {
  /** Repo-relative path using the post-change name. */
  path: string;
  ranges: HunkRange[];
}

export interface ParsedDiff {
  files: ChangedFile[];
}

/**
 * GitHub PR URLs are not fetched. Returns the message the CLI should print, or
 * undefined when `input` is not a pull request URL.
 */
export function githubPullRequestMessage(input: string): string | undefined {
  const url = input.trim();
  if (!GITHUB_PULL_REQUEST.test(url)) {
    return undefined;
  }
  return [
    "GitHub pull request URLs are not fetched.",
    "Pipe the diff in instead:",
    `gh pr diff ${url} | faultline pr -`,
  ].join("\n");
}

export function parseHunkContext(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new DiffError(`Context window must be an integer from 0 to ${MAX_HUNK_CONTEXT}.`);
  }
  const parsed = Number(value);
  if (parsed > MAX_HUNK_CONTEXT) {
    throw new DiffError(`Context window must be an integer from 0 to ${MAX_HUNK_CONTEXT}.`);
  }
  return parsed;
}

export function assertDiffWithinLimit(bytes: number): void {
  if (bytes > MAX_DIFF_BYTES) {
    throw new DiffError(`Diff exceeds the ${MAX_DIFF_BYTES} byte limit (${bytes} bytes).`);
  }
}

/**
 * Parse a unified diff into post-change paths and changed line ranges.
 * Deleted files, binaries, and pure renames (no hunks) are omitted.
 * Renames keep the new path. The text is untrusted: this function does not
 * execute it, and a path that leaves the repository is rejected.
 */
export function parseUnifiedDiff(text: string): ParsedDiff {
  assertDiffWithinLimit(Buffer.byteLength(text, "utf8"));
  if (text.includes("\0")) {
    throw new DiffError("Diff is not a text unified diff.");
  }
  const body = text
    .replace(/^\uFEFF/, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  const lines = body.split("\n");
  const byPath = new Map<string, number[]>();
  let index = 0;
  while (index < lines.length) {
    const line = lines[index] ?? "";
    if (line.startsWith("diff --git ") || line.startsWith("--- ")) {
      const parsed = readOneFile(lines, index);
      index = parsed.nextIndex;
      if (parsed.path === undefined) {
        continue;
      }
      const existing = byPath.get(parsed.path);
      if (existing === undefined) {
        byPath.set(parsed.path, parsed.changed);
      } else {
        existing.push(...parsed.changed);
      }
      continue;
    }
    index += 1;
  }
  if (byPath.size > MAX_CHANGED_FILES) {
    throw new DiffError(`Diff touches more than ${MAX_CHANGED_FILES} files.`);
  }
  const files: ChangedFile[] = [];
  for (const path of [...byPath.keys()].sort(compareString)) {
    const changed = byPath.get(path) ?? [];
    const ranges = mergeLines(changed);
    if (ranges.length === 0) {
      continue;
    }
    files.push({ path, ranges });
  }
  return { files };
}

export function rangesOverlap(
  start: number,
  end: number,
  ranges: readonly HunkRange[],
  context: number,
): boolean {
  const lo = Math.min(start, end);
  const hi = Math.max(start, end);
  for (const range of ranges) {
    const expandedStart = Math.max(1, range.start - context);
    const expandedEnd = range.end + context;
    if (lo <= expandedEnd && expandedStart <= hi) {
      return true;
    }
  }
  return false;
}

/** True when the candidate location overlaps a changed hunk, expanded by `context`. */
export function candidateOverlapsDiff(
  candidate: Candidate,
  changed: readonly ChangedFile[],
  context: number,
): boolean {
  const file = normalizeRepoPath(candidate.location.file);
  if (file === undefined) {
    return false;
  }
  const match = changed.find((item) => item.path === file);
  if (match === undefined) {
    return false;
  }
  const end = candidate.location.end_line ?? candidate.location.start_line;
  return rangesOverlap(candidate.location.start_line, end, match.ranges, context);
}

function compareString(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function mergeLines(lines: readonly number[]): HunkRange[] {
  const unique = [...new Set(lines)]
    .filter((line) => line >= 1)
    .sort((left, right) => left - right);
  const ranges: HunkRange[] = [];
  for (const line of unique) {
    const last = ranges[ranges.length - 1];
    if (last !== undefined && line <= last.end + 1) {
      last.end = line;
      continue;
    }
    ranges.push({ start: line, end: line });
  }
  return ranges;
}

interface FileParse {
  nextIndex: number;
  path?: string;
  changed: number[];
}

function readOneFile(lines: readonly string[], start: number): FileParse {
  let index = start;
  let deleted = false;
  let binary = false;
  let path: string | undefined;
  let seenPlus = false;
  const changed: number[] = [];
  const first = lines[index] ?? "";
  if (first.startsWith("diff --git ")) {
    index += 1;
  }
  while (index < lines.length) {
    const line = lines[index] ?? "";
    if (line.startsWith("diff --git ")) {
      break;
    }
    if (seenPlus && line.startsWith("--- ")) {
      break;
    }
    if (line.startsWith("deleted file mode")) {
      deleted = true;
      index += 1;
      continue;
    }
    if (line.startsWith("GIT binary patch") || line.startsWith("Binary files ")) {
      binary = true;
      index += 1;
      while (index < lines.length && !(lines[index] ?? "").startsWith("diff --git ")) {
        index += 1;
      }
      break;
    }
    if (line.startsWith("rename to ")) {
      path = normalizeChangedPath(line.slice("rename to ".length), false);
      index += 1;
      continue;
    }
    if (line.startsWith("+++ ")) {
      const plus = headerPath(line);
      seenPlus = true;
      if (plus === "/dev/null") {
        deleted = true;
      } else {
        path = normalizeChangedPath(plus, true);
        deleted = false;
      }
      index += 1;
      continue;
    }
    if (line.startsWith("@@")) {
      const hunk = consumeHunk(lines, index);
      index = hunk.nextIndex;
      changed.push(...hunk.changed);
      continue;
    }
    index += 1;
  }
  if (binary || deleted || path === undefined || path === "/dev/null") {
    return { nextIndex: index, changed: [] };
  }
  return { nextIndex: index, path, changed };
}

function consumeHunk(
  lines: readonly string[],
  start: number,
): { nextIndex: number; changed: number[] } {
  const header = lines[start] ?? "";
  const match = HUNK_HEADER.exec(header);
  if (match === null) {
    throw new DiffError("Diff hunk header is invalid.");
  }
  const oldCount = parseHunkCount(match[2]);
  const newStart = parseHunkStart(match[3]);
  const newCount = parseHunkCount(match[4]);
  let index = start + 1;
  let oldSeen = 0;
  let newSeen = 0;
  let newLine = newStart;
  const changed: number[] = [];
  while (oldSeen < oldCount || newSeen < newCount) {
    const line = lines[index];
    if (line === undefined) {
      throw new DiffError("Diff hunk ended early.");
    }
    index += 1;
    if (line.length === 0) {
      throw new DiffError("Diff hunk ended early.");
    }
    if (line.startsWith("\\")) {
      continue;
    }
    if (line.startsWith("+")) {
      if (newLine >= 1) {
        changed.push(newLine);
      }
      newLine += 1;
      newSeen += 1;
      continue;
    }
    if (line.startsWith("-")) {
      if (newLine >= 1) {
        changed.push(newLine);
      }
      oldSeen += 1;
      continue;
    }
    if (line.startsWith(" ")) {
      newLine += 1;
      oldSeen += 1;
      newSeen += 1;
      continue;
    }
    throw new DiffError("Diff hunk has a line that is not context, an addition, or a deletion.");
  }
  return { nextIndex: index, changed };
}

function parseHunkCount(value: string | undefined): number {
  if (value === undefined) {
    return 1;
  }
  return parseHunkInteger(value);
}

function parseHunkStart(value: string | undefined): number {
  if (value === undefined) {
    throw new DiffError("Diff hunk header is invalid.");
  }
  return parseHunkInteger(value);
}

function parseHunkInteger(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new DiffError("Diff hunk header is invalid.");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new DiffError("Diff hunk header is invalid.");
  }
  return parsed;
}

function headerPath(line: string): string {
  let raw = line.slice(4);
  const tab = raw.indexOf("\t");
  if (tab !== -1) {
    raw = raw.slice(0, tab);
  }
  return unquoteGitPath(raw.trimEnd());
}

function normalizeChangedPath(raw: string, stripPrefix: boolean): string {
  const unquoted = unquoteGitPath(raw.trim());
  if (unquoted === "/dev/null") {
    return unquoted;
  }
  const stripped = stripPrefix ? stripAbPrefix(unquoted) : unquoted;
  const normalized = normalizeRepoPath(stripped);
  if (
    normalized === undefined ||
    normalized.length > MAX_PATH_LENGTH ||
    normalized.includes("`") ||
    hasControlChar(normalized)
  ) {
    throw pathError(stripped);
  }
  return normalized;
}

function hasControlChar(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function pathError(display: string): DiffError {
  const printable =
    /^[\t\x20-\x7e]+$/.test(display) && display.length <= 200 && !display.includes("`");
  if (!printable) {
    return new DiffError("Diff path is outside the repository.");
  }
  return new DiffError(`Diff path is outside the repository: ${display}`);
}

function stripAbPrefix(path: string): string {
  if (path.startsWith("a/") || path.startsWith("b/")) {
    return path.slice(2);
  }
  return path;
}

/** Git quotes paths that contain spaces or non-ASCII bytes. */
function unquoteGitPath(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length < 2 || !trimmed.startsWith('"') || !trimmed.endsWith('"')) {
    return trimmed;
  }
  const inner = trimmed.slice(1, -1);
  let out = "";
  for (let index = 0; index < inner.length; index += 1) {
    const ch = inner[index] ?? "";
    if (ch !== "\\") {
      out += ch;
      continue;
    }
    const next = inner[index + 1];
    if (next === undefined) {
      throw new DiffError("Diff path is outside the repository.");
    }
    if (next === "\\" || next === '"') {
      out += next;
      index += 1;
      continue;
    }
    if (next === "n" || next === "t" || next === "r") {
      throw new DiffError("Diff path is outside the repository.");
    }
    if (next >= "0" && next <= "7") {
      let octal = next;
      let look = index + 2;
      while (octal.length < 3 && look < inner.length) {
        const digit = inner[look];
        if (digit === undefined || digit < "0" || digit > "7") {
          break;
        }
        octal += digit;
        look += 1;
      }
      const code = Number.parseInt(octal, 8);
      if (!Number.isFinite(code) || code <= 0 || code > 0xff) {
        throw new DiffError("Diff path is outside the repository.");
      }
      out += String.fromCharCode(code);
      index += octal.length;
      continue;
    }
    throw new DiffError("Diff path is outside the repository.");
  }
  return out;
}
