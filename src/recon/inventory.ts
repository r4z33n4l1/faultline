import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { join } from "node:path";
import type { CoverageSkipReason } from "../schema/coverage.js";
import { isIgnored, parseGitignore, type IgnoreLayer } from "./gitignore.js";
import { resolveRouteHandlers, type ResolvedRouteHandler } from "./handlers.js";
import {
  includeForcesDescent,
  isDefaultSkipDir,
  isFrontendAssetPath,
  isMinifiedName,
  isSnapshotPath,
  looksMinified,
  matchesAnyGlob,
  pathPriority,
  pathUnderDefaultSkip,
  sniffServerImports,
  type InventorySkip,
} from "./select.js";

export type { InventorySkip };
export type { ResolvedRouteHandler };

export interface InventoryLimits {
  maxFiles: number;
  maxBytes: number;
  maxFileBytes: number;
}

export const DEFAULT_LIMITS: InventoryLimits = {
  maxFiles: 5_000,
  maxBytes: 8_000_000,
  maxFileBytes: 128_000,
};

export interface InventoryMatch {
  path: string;
  line: number;
  note: string;
}

export interface Inventory {
  target: string;
  truncated: boolean;
  files_read: number;
  bytes_read: number;
  languages: { name: string; files: number }[];
  manifests: { path: string; kind: string }[];
  frameworks: string[];
  entrypoints: { path: string; reason: string }[];
  source_files: string[];
  routes: InventoryMatch[];
  /** Route registration resolved to the function that handles the request. */
  handlers: ResolvedRouteHandler[];
  auth: InventoryMatch[];
  data_stores: InventoryMatch[];
  outbound_http: InventoryMatch[];
  env_files: string[];
  config_files: string[];
  /** Paths not read, with the reason. Omitted from the model-facing inventory JSON. */
  skipped: InventorySkip[];
  /** Limits used for this run. Omitted from the model-facing inventory JSON. */
  limits: InventoryLimits;
}

export interface CollectOptions {
  /** Label stored on the inventory. Defaults to `root`. */
  target?: string;
  limits?: Partial<InventoryLimits>;
  /** Re-include a path dropped by a default exclude, gitignore, or `--exclude`. */
  include?: readonly string[];
  /** Extra globs to skip. An `--include` match wins. */
  exclude?: readonly string[];
}

const LANGUAGE_BY_EXT: Record<string, string> = {
  ".ts": "TypeScript",
  ".tsx": "TypeScript",
  ".mts": "TypeScript",
  ".cts": "TypeScript",
  ".tf": "Terraform",
  ".tfvars": "Terraform",
  ".js": "JavaScript",
  ".jsx": "JavaScript",
  ".mjs": "JavaScript",
  ".cjs": "JavaScript",
  ".py": "Python",
  ".go": "Go",
  ".rs": "Rust",
  ".rb": "Ruby",
  ".java": "Java",
  ".php": "PHP",
  ".cs": "C#",
  ".kt": "Kotlin",
  ".swift": "Swift",
  ".ex": "Elixir",
  ".exs": "Elixir",
};

const MANIFEST_KINDS: Record<string, string> = {
  "package.json": "node",
  "requirements.txt": "python",
  "pyproject.toml": "python",
  Pipfile: "python",
  "go.mod": "go",
  "Cargo.toml": "rust",
  Gemfile: "ruby",
  "composer.json": "php",
  "pom.xml": "java",
  "build.gradle": "java",
  "build.gradle.kts": "kotlin",
  "mix.exs": "elixir",
};

const LOCKFILES = new Set([
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "poetry.lock",
  "composer.lock",
]);

const CONFIG_BASENAMES = new Set([
  "config.yaml",
  "config.yml",
  "config.json",
  "config.toml",
  "application.yaml",
  "application.yml",
  "appsettings.json",
  "docker-compose.yml",
  "docker-compose.yaml",
]);

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".zip",
  ".gz",
  ".tgz",
  ".tar",
  ".wasm",
  ".so",
  ".dll",
  ".exe",
  ".bin",
  ".class",
  ".jar",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".mp3",
  ".mp4",
  ".mov",
]);

const ENTRY_BASENAMES = new Set([
  "main.go",
  "main.py",
  "main.rs",
  "main.ts",
  "main.js",
  "app.py",
  "manage.py",
  "index.ts",
  "index.tsx",
  "index.js",
  "index.jsx",
  "server.ts",
  "server.js",
  "Program.cs",
  "index.php",
]);

const ENTRY_REASON_ORDER = ["package.json main", "package.json bin", "filename"];

const FRAMEWORK_RULES: { name: string; pattern: RegExp }[] = [
  { name: "django", pattern: /\bdjango\b/i },
  { name: "drizzle", pattern: /\bdrizzle\b/i },
  { name: "echo", pattern: /\becho\b/i },
  { name: "express", pattern: /(?:^|["/\s])express(?:["@\s]|$)/i },
  { name: "fastapi", pattern: /\bfastapi\b/i },
  { name: "fastify", pattern: /\bfastify\b/i },
  { name: "flask", pattern: /\bflask\b/i },
  { name: "gin", pattern: /gin-gonic\/gin/i },
  { name: "hono", pattern: /\bhono\b/i },
  { name: "koa", pattern: /\bkoa\b/i },
  { name: "laravel", pattern: /\blaravel\b/i },
  { name: "nestjs", pattern: /@nestjs\//i },
  { name: "next", pattern: /(?:^|["/\s])next(?:["@\s]|$)/ },
  { name: "prisma", pattern: /prisma/i },
  { name: "rails", pattern: /\brails\b/i },
  { name: "react", pattern: /(?:^|["/\s])react(?:["@\s]|$)/ },
  { name: "spring", pattern: /\bspring\b/i },
  { name: "svelte", pattern: /\bsvelte\b/i },
  { name: "vue", pattern: /(?:^|["/\s])vue(?:["@\s]|$)/ },
  { name: "chi", pattern: /go-chi\/chi/i },
];

const AUTH_KEYWORDS = [
  "requireAuth",
  "authMiddleware",
  "passport",
  "login_required",
  "isAuthenticated",
  "authenticate",
  "authorization",
  "jwt",
];

const DATA_STORE_KEYWORDS = [
  "prisma",
  "mongoose",
  "mongodb",
  "postgres",
  "redis",
  "sqlite",
  "sequelize",
  "knex",
  "typeorm",
  "drizzle",
  "dynamodb",
];

const OUTBOUND_RULES: { pattern: RegExp; note: string }[] = [
  { pattern: /\bfetch\s*\(/, note: "fetch" },
  { pattern: /\baxios\b/, note: "axios" },
  { pattern: /\brequests\.get\s*\(/, note: "requests.get" },
  { pattern: /\brequests\.post\s*\(/, note: "requests.post" },
  { pattern: /\brequests\.put\s*\(/, note: "requests.put" },
  { pattern: /\brequests\.patch\s*\(/, note: "requests.patch" },
  { pattern: /\brequests\.delete\s*\(/, note: "requests.delete" },
  { pattern: /\bhttp\.Get\b/, note: "http.Get" },
  { pattern: /\bhttp\.Post\b/, note: "http.Post" },
  { pattern: /\bhttp\.NewRequest\b/, note: "http.NewRequest" },
  { pattern: /\bhttp\.request\s*\(/, note: "http.request" },
  { pattern: /\bhttps\.request\s*\(/, note: "https.request" },
  { pattern: /\bgot\s*\(/, note: "got" },
];

const ROUTE_RULES: { pattern: RegExp; note: (match: RegExpMatchArray) => string }[] = [
  {
    pattern: /\b(?:app|router|fastify)\.(get|post|put|patch|delete|all)\(\s*["'`]([^"'`]+)["'`]/,
    note: (match) => `${(match[1] ?? "").toUpperCase()} ${match[2] ?? ""}`.trim(),
  },
  {
    pattern: /@(?:app|router)\.(get|post|put|patch|delete)\(\s*["']([^"']+)["']/,
    note: (match) => `${(match[1] ?? "").toUpperCase()} ${match[2] ?? ""}`.trim(),
  },
  {
    pattern: /@app\.route\(\s*["']([^"']+)["']/,
    note: (match) => `ROUTE ${match[1] ?? ""}`.trim(),
  },
  {
    pattern: /http\.HandleFunc\(\s*"([^"]+)"/,
    note: (match) => `HANDLE ${match[1] ?? ""}`.trim(),
  },
  {
    pattern: /\.(GET|POST|PUT|PATCH|DELETE)\(\s*"([^"]+)"/,
    note: (match) => `${match[1] ?? ""} ${match[2] ?? ""}`.trim(),
  },
];

const MAX_MATCHES = 200;

interface CandidateFile {
  abs: string;
  rel: string;
  size: number;
}

interface State {
  limits: InventoryLimits;
  include: readonly string[];
  exclude: readonly string[];
  truncated: boolean;
  reads: number;
  filesRead: number;
  bytesRead: number;
  languages: Map<string, number>;
  manifests: { path: string; kind: string }[];
  frameworks: Set<string>;
  entrypoints: Map<string, Set<string>>;
  sourceFiles: string[];
  sources: Map<string, string>;
  routes: InventoryMatch[];
  auth: InventoryMatch[];
  dataStores: InventoryMatch[];
  outbound: InventoryMatch[];
  envFiles: string[];
  configFiles: string[];
  skipped: InventorySkip[];
  skipKeys: Set<string>;
  candidates: CandidateFile[];
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

function isEnoent(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function basename(rel: string): string {
  const slash = rel.lastIndexOf("/");
  return slash === -1 ? rel : rel.slice(slash + 1);
}

function extension(rel: string): string {
  const base = basename(rel);
  const dot = base.lastIndexOf(".");
  if (dot <= 0) {
    return "";
  }
  return base.slice(dot).toLowerCase();
}

function isEnvFile(rel: string): boolean {
  const base = basename(rel);
  return base === ".env" || base.startsWith(".env.") || base.endsWith(".env");
}

function isConfigFile(rel: string): boolean {
  return CONFIG_BASENAMES.has(basename(rel));
}

function isAuthFilename(base: string): boolean {
  return /(^|[^a-z])(auth|middleware)([^a-z]|$)/i.test(base);
}

function limitsFrom(override: Partial<InventoryLimits> | undefined): InventoryLimits {
  return {
    maxFiles: override?.maxFiles ?? DEFAULT_LIMITS.maxFiles,
    maxBytes: override?.maxBytes ?? DEFAULT_LIMITS.maxBytes,
    maxFileBytes: override?.maxFileBytes ?? DEFAULT_LIMITS.maxFileBytes,
  };
}

function createState(
  limits: InventoryLimits,
  include: readonly string[],
  exclude: readonly string[],
): State {
  return {
    limits,
    include,
    exclude,
    truncated: false,
    reads: 0,
    filesRead: 0,
    bytesRead: 0,
    languages: new Map(),
    manifests: [],
    frameworks: new Set(),
    entrypoints: new Map(),
    sourceFiles: [],
    sources: new Map(),
    routes: [],
    auth: [],
    dataStores: [],
    outbound: [],
    envFiles: [],
    configFiles: [],
    skipped: [],
    skipKeys: new Set(),
    candidates: [],
  };
}

function recordSkip(state: State, path: string, reason: CoverageSkipReason): void {
  const key = `${reason}\0${path}`;
  if (state.skipKeys.has(key)) {
    return;
  }
  state.skipKeys.add(key);
  state.skipped.push({ path, reason });
  if (reason === "max-files" || reason === "max-bytes" || reason === "max-file-bytes") {
    state.truncated = true;
  }
}

function pushMatch(list: InventoryMatch[], match: InventoryMatch, state: State): void {
  const key = `${match.path}:${match.line}:${match.note}`;
  if (list.some((item) => `${item.path}:${item.line}:${item.note}` === key)) {
    return;
  }
  if (list.length >= MAX_MATCHES) {
    state.truncated = true;
    return;
  }
  list.push(match);
}

function addEntrypoint(state: State, path: string, reason: string): void {
  const existing = state.entrypoints.get(path);
  if (existing === undefined) {
    state.entrypoints.set(path, new Set([reason]));
    return;
  }
  existing.add(reason);
}

function keywordOnLine(line: string, keywords: readonly string[]): string | undefined {
  const lower = line.toLowerCase();
  for (const keyword of keywords) {
    const needle = keyword.toLowerCase();
    if (needle.length <= 3) {
      if (new RegExp(`\\b${needle}\\b`, "i").test(line)) {
        return keyword;
      }
      continue;
    }
    if (lower.includes(needle)) {
      return keyword;
    }
  }
  return undefined;
}

function matchRoute(line: string): string | undefined {
  for (const rule of ROUTE_RULES) {
    const match = rule.pattern.exec(line);
    if (match !== null) {
      const note = rule.note(match);
      if (note.length > 0) {
        return note;
      }
    }
  }
  return undefined;
}

function matchOutbound(line: string): string | undefined {
  for (const rule of OUTBOUND_RULES) {
    if (rule.pattern.test(line)) {
      return rule.note;
    }
  }
  return undefined;
}

function frameworksInText(text: string): string[] {
  const found: string[] = [];
  for (const rule of FRAMEWORK_RULES) {
    if (rule.pattern.test(text)) {
      found.push(rule.name);
    }
  }
  return found;
}

function normalizeDeclaredPath(value: string): string | undefined {
  const trimmed = value.trim().replace(/\\/g, "/").replace(/^\.\//, "");
  if (trimmed === "" || trimmed.startsWith("/") || trimmed.includes("://")) {
    return undefined;
  }
  const parts = trimmed.split("/");
  if (parts.some((part) => part === ".." || part === "node_modules")) {
    return undefined;
  }
  return trimmed;
}

function addPackageEntrypoints(text: string, state: State): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return;
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.main === "string") {
    const rel = normalizeDeclaredPath(record.main);
    if (rel !== undefined) {
      addEntrypoint(state, rel, "package.json main");
    }
  }
  const bin = record.bin;
  if (typeof bin === "string") {
    const rel = normalizeDeclaredPath(bin);
    if (rel !== undefined) {
      addEntrypoint(state, rel, "package.json bin");
    }
  } else if (typeof bin === "object" && bin !== null) {
    for (const value of Object.values(bin)) {
      if (typeof value !== "string") {
        continue;
      }
      const rel = normalizeDeclaredPath(value);
      if (rel !== undefined) {
        addEntrypoint(state, rel, "package.json bin");
      }
    }
  }
}

function scanSource(rel: string, text: string, state: State): void {
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const lineNumber = index + 1;
    const route = matchRoute(line);
    if (route !== undefined) {
      pushMatch(state.routes, { path: rel, line: lineNumber, note: route }, state);
    }
    const auth = keywordOnLine(line, AUTH_KEYWORDS);
    if (auth !== undefined) {
      pushMatch(state.auth, { path: rel, line: lineNumber, note: auth }, state);
    }
    const store = keywordOnLine(line, DATA_STORE_KEYWORDS);
    if (store !== undefined) {
      pushMatch(state.dataStores, { path: rel, line: lineNumber, note: store }, state);
    }
    const outbound = matchOutbound(line);
    if (outbound !== undefined) {
      pushMatch(state.outbound, { path: rel, line: lineNumber, note: outbound }, state);
    }
  }
}

const MANIFEST_NAMES = new Set(Object.keys(MANIFEST_KINDS));
const IMPORT_SCORE = 80;
const PATH_SCORE_SNIFF_BELOW = 100;

function included(state: State, rel: string): boolean {
  return state.include.length > 0 && matchesAnyGlob(state.include, rel);
}

async function queueFile(abs: string, rel: string, state: State, forced: boolean): Promise<void> {
  if (!forced) {
    if (isEnvFile(rel)) {
      state.envFiles.push(rel);
      return;
    }
    if (isConfigFile(rel)) {
      state.configFiles.push(rel);
      return;
    }
    const base = basename(rel);
    if (LOCKFILES.has(base)) {
      recordSkip(state, rel, "lockfile");
      return;
    }
    if (isMinifiedName(rel)) {
      recordSkip(state, rel, "minified");
      return;
    }
    if (BINARY_EXTENSIONS.has(extension(rel))) {
      recordSkip(state, rel, "binary");
      return;
    }
  }
  const base = basename(rel);
  const manifestKind = MANIFEST_KINDS[base];
  const language = LANGUAGE_BY_EXT[extension(rel)];
  if (manifestKind === undefined && language === undefined) {
    if (forced && isEnvFile(rel)) {
      state.envFiles.push(rel);
    } else if (forced && isConfigFile(rel)) {
      state.configFiles.push(rel);
    }
    return;
  }
  const info = await stat(abs);
  if (!info.isFile()) {
    return;
  }
  if (info.size > state.limits.maxFileBytes) {
    recordSkip(state, rel, "max-file-bytes");
    return;
  }
  if (!forced && language !== undefined && (await looksMinified(abs, info.size, rel))) {
    recordSkip(state, rel, "minified");
    return;
  }
  state.candidates.push({ abs, rel, size: info.size });
}

async function readCandidate(candidate: CandidateFile, state: State): Promise<void> {
  const buffer = await readFile(candidate.abs);
  state.reads += 1;
  state.bytesRead += buffer.length;
  if (buffer.includes(0)) {
    return;
  }
  state.filesRead += 1;
  const text = buffer.toString("utf8");
  const base = basename(candidate.rel);
  const manifestKind = MANIFEST_KINDS[base];
  const language = LANGUAGE_BY_EXT[extension(candidate.rel)];
  if (manifestKind !== undefined) {
    state.manifests.push({ path: candidate.rel, kind: manifestKind });
    for (const name of frameworksInText(text)) {
      state.frameworks.add(name);
    }
    if (base === "package.json") {
      addPackageEntrypoints(text, state);
    }
  }
  if (language !== undefined) {
    state.languages.set(language, (state.languages.get(language) ?? 0) + 1);
    state.sourceFiles.push(candidate.rel);
    state.sources.set(candidate.rel, text);
    if (ENTRY_BASENAMES.has(base)) {
      addEntrypoint(state, candidate.rel, "filename");
    }
    if (isAuthFilename(base)) {
      pushMatch(state.auth, { path: candidate.rel, line: 1, note: "filename" }, state);
    }
    scanSource(candidate.rel, text, state);
  }
}

async function orderCandidates(
  candidates: readonly CandidateFile[],
  sniff: boolean,
): Promise<CandidateFile[]> {
  const scored: { item: CandidateFile; score: number }[] = [];
  for (const item of candidates) {
    let score = pathPriority(item.rel, ENTRY_BASENAMES, MANIFEST_NAMES);
    if (
      sniff &&
      score < PATH_SCORE_SNIFF_BELOW &&
      LANGUAGE_BY_EXT[extension(item.rel)] !== undefined
    ) {
      if (await sniffServerImports(item.abs)) {
        score += IMPORT_SCORE;
      }
    }
    scored.push({ item, score });
  }
  scored.sort(
    (left, right) => right.score - left.score || compareString(left.item.rel, right.item.rel),
  );
  return scored.map((entry) => entry.item);
}

async function admitCandidates(state: State): Promise<void> {
  const totalBytes = state.candidates.reduce((sum, item) => sum + item.size, 0);
  const overBudget =
    state.candidates.length > state.limits.maxFiles || totalBytes > state.limits.maxBytes;
  // Priority order also applies under the file budget, so the match cap keeps server routes.
  const ordered = await orderCandidates(state.candidates, overBudget);
  for (const candidate of ordered) {
    if (state.reads >= state.limits.maxFiles) {
      recordSkip(state, candidate.rel, "max-files");
      continue;
    }
    if (state.bytesRead + candidate.size > state.limits.maxBytes) {
      recordSkip(state, candidate.rel, "max-bytes");
      continue;
    }
    await readCandidate(candidate, state);
  }
}

async function walk(
  absDir: string,
  relDir: string,
  layers: readonly IgnoreLayer[],
  state: State,
  constrained: boolean,
): Promise<void> {
  let nextLayers = layers;
  try {
    const text = await readFile(join(absDir, ".gitignore"), "utf8");
    nextLayers = [...layers, { dir: relDir, rules: parseGitignore(text) }];
  } catch (error) {
    if (!isEnoent(error)) {
      throw error;
    }
  }
  const entries = await readdir(absDir, { withFileTypes: true });
  entries.sort((left, right) => compareString(left.name, right.name));
  for (const entry of entries) {
    const rel = relDir === "" ? entry.name : `${relDir}/${entry.name}`;
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      await walkDirectory(
        join(absDir, entry.name),
        rel,
        entry.name,
        nextLayers,
        state,
        constrained,
      );
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    await walkFile(join(absDir, entry.name), rel, nextLayers, state, constrained);
  }
}

async function walkDirectory(
  abs: string,
  rel: string,
  name: string,
  layers: readonly IgnoreLayer[],
  state: State,
  constrained: boolean,
): Promise<void> {
  const forced = included(state, rel) || includeForcesDescent(rel, state.include);
  const denylisted = isDefaultSkipDir(name) || isFrontendAssetPath(rel) || isSnapshotPath(rel);
  const ignored = isIgnored(layers, rel, true);
  if (constrained) {
    if (forced) {
      await walk(abs, rel, layers, state, true);
    }
    return;
  }
  if (forced) {
    await walk(abs, rel, layers, state, denylisted || ignored);
    return;
  }
  if (isDefaultSkipDir(name) || isFrontendAssetPath(rel)) {
    recordSkip(state, rel, "default-exclude");
    return;
  }
  if (isSnapshotPath(rel)) {
    recordSkip(state, rel, "snapshot");
    return;
  }
  if (ignored) {
    recordSkip(state, rel, "gitignore");
    return;
  }
  if (matchesAnyGlob(state.exclude, rel)) {
    recordSkip(state, rel, "exclude");
    return;
  }
  await walk(abs, rel, layers, state, false);
}

async function walkFile(
  abs: string,
  rel: string,
  layers: readonly IgnoreLayer[],
  state: State,
  constrained: boolean,
): Promise<void> {
  if (constrained) {
    if (included(state, rel)) {
      await queueFile(abs, rel, state, true);
    }
    return;
  }
  if (included(state, rel)) {
    await queueFile(abs, rel, state, true);
    return;
  }
  if (matchesAnyGlob(state.exclude, rel)) {
    recordSkip(state, rel, "exclude");
    return;
  }
  if (pathUnderDefaultSkip(rel) || isFrontendAssetPath(rel)) {
    recordSkip(state, rel, "default-exclude");
    return;
  }
  if (isSnapshotPath(rel)) {
    recordSkip(state, rel, "snapshot");
    return;
  }
  if (isIgnored(layers, rel, false)) {
    recordSkip(state, rel, "gitignore");
    return;
  }
  await queueFile(abs, rel, state, false);
}

function sortedMatches(list: readonly InventoryMatch[]): InventoryMatch[] {
  return [...list].sort(
    (left, right) =>
      compareString(left.path, right.path) ||
      left.line - right.line ||
      compareString(left.note, right.note),
  );
}

function mergeResolvedRoutes(
  routes: readonly InventoryMatch[],
  handlers: readonly ResolvedRouteHandler[],
): InventoryMatch[] {
  const merged = [...routes];
  const seen = new Set(routes.map((route) => `${route.path}:${route.line}:${route.note}`));
  for (const handler of handlers) {
    const key = `${handler.routeFile}:${handler.routeLine}:${handler.route}`;
    if (seen.has(key) || merged.length >= MAX_MATCHES) {
      continue;
    }
    seen.add(key);
    merged.push({ path: handler.routeFile, line: handler.routeLine, note: handler.route });
  }
  return sortedMatches(merged);
}

function finish(target: string, state: State): Inventory {
  const handlers = resolveRouteHandlers(state.sources);
  const languages = [...state.languages.entries()]
    .map(([name, files]) => ({ name, files }))
    .sort((left, right) => compareString(left.name, right.name));
  const entrypoints = [...state.entrypoints.entries()]
    .map(([path, reasons]) => ({
      path,
      reason: ENTRY_REASON_ORDER.filter((item) => reasons.has(item)).join(", "),
    }))
    .sort((left, right) => compareString(left.path, right.path));
  return {
    target,
    truncated: state.truncated,
    files_read: state.filesRead,
    bytes_read: state.bytesRead,
    languages,
    manifests: [...state.manifests].sort((left, right) => compareString(left.path, right.path)),
    frameworks: [...state.frameworks].sort(compareString),
    entrypoints,
    source_files: [...state.sourceFiles].sort(compareString),
    routes: mergeResolvedRoutes(state.routes, handlers),
    handlers,
    auth: sortedMatches(state.auth),
    data_stores: sortedMatches(state.dataStores),
    outbound_http: sortedMatches(state.outbound),
    env_files: [...state.envFiles].sort(compareString),
    config_files: [...state.configFiles].sort(compareString),
    skipped: [...state.skipped].sort(
      (left, right) =>
        compareString(left.path, right.path) || compareString(left.reason, right.reason),
    ),
    limits: state.limits,
  };
}

/** Inventory JSON passed to a model. Skip paths and limits stay out of that prompt. */
export function serializeInventory(inventory: Inventory): string {
  const publicInventory = {
    target: inventory.target,
    truncated: inventory.truncated,
    files_read: inventory.files_read,
    bytes_read: inventory.bytes_read,
    languages: inventory.languages,
    manifests: inventory.manifests,
    frameworks: inventory.frameworks,
    entrypoints: inventory.entrypoints,
    source_files: inventory.source_files,
    routes: inventory.routes,
    handlers: inventory.handlers,
    auth: inventory.auth,
    data_stores: inventory.data_stores,
    outbound_http: inventory.outbound_http,
    env_files: inventory.env_files,
    config_files: inventory.config_files,
  };
  return JSON.stringify(publicInventory, null, 2);
}

const CAP_REASONS = new Set<CoverageSkipReason>(["max-files", "max-bytes", "max-file-bytes"]);

/** Sentence for report.md when a file or byte cap left paths unread. */
export function inventoryCapNote(inventory: Inventory): string | undefined {
  const capped = inventory.skipped.filter((item) => CAP_REASONS.has(item.reason));
  if (capped.length === 0) {
    return undefined;
  }
  const reasons = [...new Set(capped.map((item) => item.reason))].sort();
  const noun = capped.length === 1 ? "path was" : "paths were";
  return [
    `Inventory caps bound (${reasons.join(", ")}):`,
    `max-files ${inventory.limits.maxFiles},`,
    `max-bytes ${inventory.limits.maxBytes}.`,
    `${capped.length} ${noun} not read.`,
    "Skipped paths and reasons are in coverage.json.",
  ].join(" ");
}

export function capsBound(inventory: Inventory): boolean {
  return inventory.skipped.some(
    (item) => item.reason === "max-files" || item.reason === "max-bytes",
  );
}

export async function collectInventory(root: string, options?: CollectOptions): Promise<Inventory> {
  const target = options?.target ?? root;
  const limits = limitsFrom(options?.limits);
  let abs: string;
  try {
    abs = await realpath(root);
  } catch (error) {
    if (isEnoent(error)) {
      throw new Error(`Target not found: ${target}`, { cause: error });
    }
    throw error;
  }
  const info = await stat(abs);
  if (!info.isDirectory()) {
    throw new Error(`Target is not a directory: ${target}`);
  }
  const state = createState(limits, options?.include ?? [], options?.exclude ?? []);
  await walk(abs, "", [], state, false);
  await admitCandidates(state);
  return finish(target, state);
}
