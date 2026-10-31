import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { join } from "node:path";
import { isIgnored, parseGitignore, type IgnoreLayer } from "./gitignore.js";

export interface InventoryLimits {
  maxFiles: number;
  maxBytes: number;
  maxFileBytes: number;
}

export const DEFAULT_LIMITS: InventoryLimits = {
  maxFiles: 500,
  maxBytes: 1_000_000,
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
  auth: InventoryMatch[];
  data_stores: InventoryMatch[];
  outbound_http: InventoryMatch[];
  env_files: string[];
  config_files: string[];
}

export interface CollectOptions {
  /** Label stored on the inventory. Defaults to `root`. */
  target?: string;
  limits?: Partial<InventoryLimits>;
}

const SKIP_DIRS = new Set([
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

const LANGUAGE_BY_EXT: Record<string, string> = {
  ".ts": "TypeScript",
  ".tsx": "TypeScript",
  ".mts": "TypeScript",
  ".cts": "TypeScript",
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

interface State {
  limits: InventoryLimits;
  truncated: boolean;
  stopped: boolean;
  reads: number;
  filesRead: number;
  bytesRead: number;
  languages: Map<string, number>;
  manifests: { path: string; kind: string }[];
  frameworks: Set<string>;
  entrypoints: Map<string, Set<string>>;
  sourceFiles: string[];
  routes: InventoryMatch[];
  auth: InventoryMatch[];
  dataStores: InventoryMatch[];
  outbound: InventoryMatch[];
  envFiles: string[];
  configFiles: string[];
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

function createState(limits: InventoryLimits): State {
  return {
    limits,
    truncated: false,
    stopped: false,
    reads: 0,
    filesRead: 0,
    bytesRead: 0,
    languages: new Map(),
    manifests: [],
    frameworks: new Set(),
    entrypoints: new Map(),
    sourceFiles: [],
    routes: [],
    auth: [],
    dataStores: [],
    outbound: [],
    envFiles: [],
    configFiles: [],
  };
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

async function considerFile(abs: string, rel: string, state: State): Promise<void> {
  if (state.stopped) {
    return;
  }
  if (isEnvFile(rel)) {
    state.envFiles.push(rel);
    return;
  }
  if (isConfigFile(rel)) {
    state.configFiles.push(rel);
    return;
  }
  const base = basename(rel);
  if (LOCKFILES.has(base) || BINARY_EXTENSIONS.has(extension(rel))) {
    return;
  }
  const manifestKind = MANIFEST_KINDS[base];
  const language = LANGUAGE_BY_EXT[extension(rel)];
  if (manifestKind === undefined && language === undefined) {
    return;
  }
  const info = await stat(abs);
  if (!info.isFile()) {
    return;
  }
  if (info.size > state.limits.maxFileBytes) {
    state.truncated = true;
    return;
  }
  if (state.reads >= state.limits.maxFiles || state.bytesRead + info.size > state.limits.maxBytes) {
    state.truncated = true;
    state.stopped = true;
    return;
  }
  const buffer = await readFile(abs);
  state.reads += 1;
  state.bytesRead += buffer.length;
  if (buffer.includes(0)) {
    return;
  }
  state.filesRead += 1;
  const text = buffer.toString("utf8");
  if (manifestKind !== undefined) {
    state.manifests.push({ path: rel, kind: manifestKind });
    for (const name of frameworksInText(text)) {
      state.frameworks.add(name);
    }
    if (base === "package.json") {
      addPackageEntrypoints(text, state);
    }
  }
  if (language !== undefined) {
    state.languages.set(language, (state.languages.get(language) ?? 0) + 1);
    state.sourceFiles.push(rel);
    if (ENTRY_BASENAMES.has(base)) {
      addEntrypoint(state, rel, "filename");
    }
    if (isAuthFilename(base)) {
      pushMatch(state.auth, { path: rel, line: 1, note: "filename" }, state);
    }
    scanSource(rel, text, state);
  }
}

async function walk(
  absDir: string,
  relDir: string,
  layers: readonly IgnoreLayer[],
  state: State,
): Promise<void> {
  if (state.stopped) {
    return;
  }
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
    if (state.stopped) {
      return;
    }
    const rel = relDir === "" ? entry.name : `${relDir}/${entry.name}`;
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || isIgnored(nextLayers, rel, true)) {
        continue;
      }
      await walk(join(absDir, entry.name), rel, nextLayers, state);
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    if (isIgnored(nextLayers, rel, false)) {
      continue;
    }
    await considerFile(join(absDir, entry.name), rel, state);
  }
}

function sortedMatches(list: readonly InventoryMatch[]): InventoryMatch[] {
  return [...list].sort(
    (left, right) =>
      compareString(left.path, right.path) ||
      left.line - right.line ||
      compareString(left.note, right.note),
  );
}

function finish(target: string, state: State): Inventory {
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
    routes: sortedMatches(state.routes),
    auth: sortedMatches(state.auth),
    data_stores: sortedMatches(state.dataStores),
    outbound_http: sortedMatches(state.outbound),
    env_files: [...state.envFiles].sort(compareString),
    config_files: [...state.configFiles].sort(compareString),
  };
}

export function serializeInventory(inventory: Inventory): string {
  return JSON.stringify(inventory, null, 2);
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
  const state = createState(limits);
  await walk(abs, "", [], state);
  return finish(target, state);
}
