import { readFile, realpath, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";

export const MAX_SOURCE_BYTES = 128_000;

/** Repo-relative forward-slash path. Rejects absolute paths and `..`. */
export function normalizeRepoPath(file: string): string | undefined {
  const trimmed = file.trim().replaceAll("\\", "/").replace(/^\.\//, "");
  if (trimmed === "" || trimmed.startsWith("/") || /^[A-Za-z]:/.test(trimmed)) {
    return undefined;
  }
  const parts = trimmed.split("/");
  if (parts.some((part) => part === "" || part === "." || part === "..")) {
    return undefined;
  }
  return parts.join("/");
}

/**
 * Read a source file the inventory already accepted.
 * Env files, config files, and paths outside `root` are not read.
 */
export async function readSourceFile(
  root: string,
  rel: string,
  allowed: ReadonlySet<string>,
): Promise<string | undefined> {
  const normalized = normalizeRepoPath(rel);
  if (normalized === undefined || normalized !== rel || !allowed.has(normalized)) {
    return undefined;
  }
  let rootReal: string;
  try {
    rootReal = await realpath(root);
  } catch {
    return undefined;
  }
  const abs = resolve(rootReal, normalized);
  const prefix = rootReal.endsWith(sep) ? rootReal : `${rootReal}${sep}`;
  if (!abs.startsWith(prefix)) {
    return undefined;
  }
  try {
    const fileReal = await realpath(abs);
    if (!fileReal.startsWith(prefix)) {
      return undefined;
    }
    const info = await stat(fileReal);
    if (!info.isFile() || info.size > MAX_SOURCE_BYTES) {
      return undefined;
    }
    const buffer = await readFile(fileReal);
    if (buffer.includes(0)) {
      return undefined;
    }
    return buffer.toString("utf8");
  } catch {
    return undefined;
  }
}
