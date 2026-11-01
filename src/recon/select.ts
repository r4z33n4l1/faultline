import { open } from "node:fs/promises";
import type { CoverageSkipReason } from "../schema/coverage.js";
import { globToRegExp } from "./gitignore.js";

export type SkipReason = CoverageSkipReason;

export interface InventorySkip {
  path: string;
  reason: SkipReason;
}

export const DEFAULT_SKIP_DIRS = new Set([
  "node_modules",
  "vendor",
  "bower_components",
  "build",
  "dist",
  "coverage",
  "target",
  ".git",
  "__pycache__",
  ".venv",
  "venv",
  ".next",
]);

const PRIORITY_DIRS = new Set([
  "route",
  "routes",
  "controller",
  "controllers",
  "handler",
  "handlers",
  "api",
  "server",
  "servers",
  "model",
  "models",
  "lib",
  "libs",
]);

const SERVER_IMPORT =
  /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)["'](?:node:(?:https|http|child_process)|https|http|mysql2|mysql|express|fastify|koa|sequelize|mongoose|pg|child_process|axios|got|node-fetch|undici|next\/server|next\/dist\/server)(?:\/[^"']*)?["']/;

const SNIFF_BYTES = 8192;
const MINIFIED_SAMPLE_BYTES = 16_384;

export function isDefaultSkipDir(name: string): boolean {
  return DEFAULT_SKIP_DIRS.has(name);
}

/** Frontend asset trees such as `frontend/src/assets`, at any repo prefix. */
export function isFrontendAssetPath(rel: string): boolean {
  return (
    rel === "frontend/src/assets" ||
    rel.startsWith("frontend/src/assets/") ||
    rel.endsWith("/frontend/src/assets") ||
    rel.includes("/frontend/src/assets/")
  );
}

export function isSnapshotPath(rel: string): boolean {
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  if (base.endsWith(".snap") || base.endsWith(".snapshot")) {
    return true;
  }
  return rel.split("/").includes("__snapshots__");
}

export function isMinifiedName(rel: string): boolean {
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  return /\.min\.(?:js|mjs|cjs|ts)$/i.test(base) || /\.bundle\.(?:js|mjs|cjs)$/i.test(base);
}

export function pathUnderDefaultSkip(rel: string): boolean {
  if (isFrontendAssetPath(rel)) {
    return true;
  }
  return rel.split("/").some((part) => DEFAULT_SKIP_DIRS.has(part));
}

function normalizeGlob(pattern: string): string {
  let body = pattern.trim().replace(/\\/g, "/");
  if (body.startsWith("./")) {
    body = body.slice(2);
  }
  while (body.endsWith("/")) {
    body = body.slice(0, -1);
  }
  return body;
}

/** Gitignore-style glob. A match on a directory also matches its children. */
export function pathMatchesGlob(pattern: string, rel: string): boolean {
  const body = normalizeGlob(pattern);
  if (body.length === 0) {
    return false;
  }
  const regex = globToRegExp(body);
  const candidates = [rel];
  if (!body.includes("/")) {
    candidates.push(rel.slice(rel.lastIndexOf("/") + 1));
  }
  const parts = rel.split("/");
  for (let index = 1; index < parts.length; index += 1) {
    candidates.push(parts.slice(0, index).join("/"));
  }
  return candidates.some((item) => regex.test(item));
}

export function matchesAnyGlob(patterns: readonly string[], rel: string): boolean {
  return patterns.some((pattern) => pathMatchesGlob(pattern, rel));
}

/**
 * True when an include glob has a literal prefix inside this directory,
 * so the walk has to enter a path it would otherwise prune.
 * A pattern that starts with `*` does not open `node_modules`.
 */
export function includeForcesDescent(dirRel: string, includes: readonly string[]): boolean {
  for (const pattern of includes) {
    const body = normalizeGlob(pattern);
    const literal = body.split(/[*?]/)[0] ?? "";
    const prefix = literal.replace(/\/$/, "");
    if (prefix.length === 0) {
      continue;
    }
    if (dirRel === prefix || prefix.startsWith(`${dirRel}/`) || dirRel.startsWith(`${prefix}/`)) {
      return true;
    }
  }
  return false;
}

export function pathPriority(
  rel: string,
  entryBasenames: ReadonlySet<string>,
  manifestNames: ReadonlySet<string>,
): number {
  const parts = rel.split("/");
  const base = parts[parts.length - 1] ?? "";
  const dirs = parts.slice(0, -1);
  let score = 0;
  if (dirs.some((part) => PRIORITY_DIRS.has(part.toLowerCase()))) {
    score += 100;
  }
  if (entryBasenames.has(base)) {
    score += 50;
  }
  if (manifestNames.has(base)) {
    score += 40;
  }
  return score;
}

export async function sniffServerImports(abs: string): Promise<boolean> {
  const handle = await open(abs, "r");
  try {
    const buf = Buffer.alloc(SNIFF_BYTES);
    const { bytesRead } = await handle.read(buf, 0, SNIFF_BYTES, 0);
    if (bytesRead === 0) {
      return false;
    }
    return SERVER_IMPORT.test(buf.toString("utf8", 0, bytesRead));
  } finally {
    await handle.close();
  }
}

/** Filename patterns, plus a large JavaScript file whose first bytes are one line. */
export async function looksMinified(abs: string, size: number, rel: string): Promise<boolean> {
  if (isMinifiedName(rel)) {
    return true;
  }
  if (size < MINIFIED_SAMPLE_BYTES) {
    return false;
  }
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  if (!/\.(?:js|mjs|cjs)$/i.test(base)) {
    return false;
  }
  const handle = await open(abs, "r");
  try {
    const buf = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(buf, 0, 4096, 0);
    return !buf.toString("utf8", 0, bytesRead).includes("\n");
  } finally {
    await handle.close();
  }
}
