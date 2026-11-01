import { isMinifiedName, SERVER_DIR_NAMES } from "../recon/select.js";
import { readSourceFile } from "../hunters/source.js";
import type { Inventory } from "../recon/inventory.js";
import type { ResolvedRouteHandler } from "../recon/handlers.js";
import type { DiscoveryRecord, DiscoveryUnitKind } from "../schema/coverage.js";
import {
  DISCOVERY_MINIFIED,
  DISCOVERY_TEST,
  DISCOVERY_TOO_LARGE,
  DISCOVERY_UNIT_MAX_CHARS,
  DISCOVERY_UNIT_MAX_LINES,
  DISCOVERY_UNREADABLE,
  DISCOVERY_VENDORED,
  discoveryRecordId,
} from "./types.js";

const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);
const CONFIG_EXT = new Set([...CODE_EXT, ".json", ".yml", ".yaml", ".toml"]);
const VENDOR_SEGMENTS = new Set([
  "node_modules",
  "vendor",
  "vendors",
  "bower_components",
  "third_party",
  "third-party",
]);
const TEST_SEGMENTS = new Set(["test", "tests", "__tests__"]);

const APP_SETUP =
  /\b(?:express\s*\(|fastify\s*\(|new\s+Koa\b|new\s+Hono\b|http\.createServer|https\.createServer|NestFactory\.create)\b/;
const SESSION_JWT =
  /\b(?:jsonwebtoken|express-session|cookie-session|jwt\.sign|jwt\.verify|passport(?:\.|"))\b/;
const DB_CONN =
  /\b(?:createPool|createConnection|mongoose\.connect|new\s+Sequelize|new\s+PrismaClient|new\s+Client\s*\(|\bknex\s*\(|new\s+DataSource\b)\b/;
const LOGGING = /\b(?:winston|createLogger|\bpino\s*\(|\bbunyan\b|\bmorgan\s*\()\b/;

export interface DiscoveryUnit {
  kind: DiscoveryUnitKind;
  path: string;
  startLine: number;
  endLine: number;
  /** Higher is reviewed first inside the same kind. */
  rank: number;
  text: string;
}

export interface UnitSelection {
  units: DiscoveryUnit[];
  skipped: DiscoveryRecord[];
}

interface Loaded {
  path: string;
  text: string;
}

function extensionOf(rel: string): string {
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  if (dot <= 0) {
    return "";
  }
  return base.slice(dot).toLowerCase();
}

function basename(rel: string): string {
  return rel.slice(rel.lastIndexOf("/") + 1);
}

export function pathSkipReason(rel: string): string | undefined {
  const parts = rel.split("/");
  if (parts.some((part) => VENDOR_SEGMENTS.has(part))) {
    return DISCOVERY_VENDORED;
  }
  if (parts.some((part) => TEST_SEGMENTS.has(part))) {
    return DISCOVERY_TEST;
  }
  if (isMinifiedName(rel)) {
    return DISCOVERY_MINIFIED;
  }
  return undefined;
}

function textLooksMinified(text: string): boolean {
  const lines = text.split(/\r?\n/);
  if (lines.length >= 8) {
    return false;
  }
  return text.length >= DISCOVERY_UNIT_MAX_CHARS;
}

function lineCount(text: string): number {
  if (text.length === 0) {
    return 1;
  }
  return text.split(/\r?\n/).length;
}

function sliceText(text: string, start: number, end: number): string {
  const lines = text.split(/\r?\n/);
  return lines.slice(start - 1, end).join("\n");
}

function windows(start: number, end: number, maxLines: number): { start: number; end: number }[] {
  const spans: { start: number; end: number }[] = [];
  for (let cursor = start; cursor <= end; cursor += maxLines) {
    spans.push({ start: cursor, end: Math.min(end, cursor + maxLines - 1) });
  }
  return spans;
}

function windowAround(
  line: number,
  count: number,
  maxLines: number,
): { start: number; end: number } {
  const start = Math.max(1, line - Math.floor(maxLines / 4));
  const end = Math.min(count, start + maxLines - 1);
  return { start, end: Math.max(end, Math.min(line, count)) };
}

function inServerDir(rel: string): boolean {
  return rel.split("/").some((part) => SERVER_DIR_NAMES.has(part.toLowerCase()));
}

function isControllerPath(rel: string): boolean {
  return rel
    .split("/")
    .some((part) => part.toLowerCase() === "controller" || part.toLowerCase() === "controllers");
}

function isMiddlewarePath(rel: string): boolean {
  const base = basename(rel).toLowerCase();
  if (base.includes("middleware")) {
    return true;
  }
  return rel.split("/").some((part) => part.toLowerCase() === "middleware");
}

function requestUses(text: string): number {
  const matches = text.match(
    /\b(?:req|request)\s*(?:\?\.|\.)\s*(?:params|query|body|headers|files|cookies)\b|\b(?:ctx|context)\s*(?:\?\.|\.)\s*(?:params|query|body|headers|request)\b|\bnextUrl\s*(?:\?\.|\.)\s*searchParams\b/g,
  );
  return matches?.length ?? 0;
}

function configRank(text: string): number | undefined {
  let rank = 0;
  if (APP_SETUP.test(text)) {
    rank = Math.max(rank, 4);
  }
  if (SESSION_JWT.test(text)) {
    rank = Math.max(rank, 3);
  }
  if (DB_CONN.test(text)) {
    rank = Math.max(rank, 2);
  }
  if (LOGGING.test(text)) {
    rank = Math.max(rank, 1);
  }
  return rank === 0 ? undefined : rank;
}

function skippedRecord(
  kind: DiscoveryUnitKind,
  path: string,
  start: number,
  end: number,
  reason: string,
): DiscoveryRecord {
  return {
    id: discoveryRecordId(kind, path, start, end),
    path,
    kind,
    start_line: start,
    end_line: end,
    status: "skipped",
    reason,
  };
}

function considerSpan(
  kind: DiscoveryUnitKind,
  path: string,
  text: string,
  start: number,
  end: number,
  rank: number,
  maxLines: number,
  maxChars: number,
  units: DiscoveryUnit[],
  skipped: DiscoveryRecord[],
): void {
  const count = lineCount(text);
  const boundedStart = Math.max(1, Math.min(start, count));
  const boundedEnd = Math.max(boundedStart, Math.min(end, count));
  for (const span of windows(boundedStart, boundedEnd, maxLines)) {
    const body = sliceText(text, span.start, span.end);
    if (body.length > maxChars) {
      skipped.push(skippedRecord(kind, path, span.start, span.end, DISCOVERY_TOO_LARGE));
      continue;
    }
    units.push({
      kind,
      path,
      startLine: span.start,
      endLine: span.end,
      rank,
      text,
    });
  }
}

function handlerCovered(path: string, handlers: readonly ResolvedRouteHandler[]): boolean {
  return handlers.some((handler) => handler.handlerFile === path || handler.routeFile === path);
}

export async function selectDiscoveryUnits(
  root: string,
  inventory: Inventory,
  maxLines = DISCOVERY_UNIT_MAX_LINES,
  maxChars = DISCOVERY_UNIT_MAX_CHARS,
): Promise<UnitSelection> {
  const allowed = new Set([...inventory.source_files, ...inventory.config_files]);
  const units: DiscoveryUnit[] = [];
  const skipped: DiscoveryRecord[] = [];
  const loaded = new Map<string, Loaded>();

  async function load(path: string): Promise<Loaded | undefined> {
    const cached = loaded.get(path);
    if (cached !== undefined) {
      return cached;
    }
    const text = await readSourceFile(root, path, allowed);
    if (text === undefined) {
      return undefined;
    }
    const file = { path, text };
    loaded.set(path, file);
    return file;
  }

  function rejectPath(
    kind: DiscoveryUnitKind,
    path: string,
    start: number,
    end: number,
  ): string | undefined {
    const reason = pathSkipReason(path);
    if (reason !== undefined) {
      skipped.push(skippedRecord(kind, path, start, end, reason));
      return reason;
    }
    return undefined;
  }

  for (const handler of inventory.handlers) {
    const path = handler.handlerFile;
    if (!CODE_EXT.has(extensionOf(path))) {
      continue;
    }
    if (rejectPath("handler", path, handler.handlerLine, handler.handlerEndLine) !== undefined) {
      continue;
    }
    const file = await load(path);
    if (file === undefined) {
      skipped.push(
        skippedRecord(
          "handler",
          path,
          handler.handlerLine,
          handler.handlerEndLine,
          DISCOVERY_UNREADABLE,
        ),
      );
      continue;
    }
    if (textLooksMinified(file.text)) {
      skipped.push(
        skippedRecord(
          "handler",
          path,
          handler.handlerLine,
          handler.handlerEndLine,
          DISCOVERY_MINIFIED,
        ),
      );
      continue;
    }
    considerSpan(
      "handler",
      path,
      file.text,
      handler.handlerLine,
      handler.handlerEndLine,
      0,
      maxLines,
      maxChars,
      units,
      skipped,
    );
  }

  const middlewarePaths = new Set<string>();
  for (const auth of inventory.auth) {
    if (CODE_EXT.has(extensionOf(auth.path))) {
      middlewarePaths.add(auth.path);
    }
  }
  for (const path of inventory.source_files) {
    if (CODE_EXT.has(extensionOf(path)) && isMiddlewarePath(path)) {
      middlewarePaths.add(path);
    }
  }
  for (const path of middlewarePaths) {
    if (rejectPath("middleware", path, 1, 1) !== undefined) {
      continue;
    }
    const file = await load(path);
    if (file === undefined) {
      skipped.push(skippedRecord("middleware", path, 1, 1, DISCOVERY_UNREADABLE));
      continue;
    }
    if (textLooksMinified(file.text)) {
      skipped.push(skippedRecord("middleware", path, 1, 1, DISCOVERY_MINIFIED));
      continue;
    }
    const count = lineCount(file.text);
    const anchor = inventory.auth.find((item) => item.path === path)?.line ?? 1;
    const span = windowAround(anchor, count, maxLines);
    considerSpan(
      "middleware",
      path,
      file.text,
      span.start,
      span.end,
      0,
      maxLines,
      maxChars,
      units,
      skipped,
    );
  }

  for (const path of inventory.source_files) {
    if (!CODE_EXT.has(extensionOf(path)) || !isControllerPath(path)) {
      continue;
    }
    if (handlerCovered(path, inventory.handlers)) {
      continue;
    }
    if (rejectPath("controller", path, 1, 1) !== undefined) {
      continue;
    }
    const file = await load(path);
    if (file === undefined) {
      skipped.push(skippedRecord("controller", path, 1, 1, DISCOVERY_UNREADABLE));
      continue;
    }
    if (textLooksMinified(file.text)) {
      skipped.push(skippedRecord("controller", path, 1, 1, DISCOVERY_MINIFIED));
      continue;
    }
    considerSpan(
      "controller",
      path,
      file.text,
      1,
      lineCount(file.text),
      0,
      maxLines,
      maxChars,
      units,
      skipped,
    );
  }

  const configPaths = new Set<string>([...inventory.source_files, ...inventory.config_files]);
  for (const path of configPaths) {
    if (!CONFIG_EXT.has(extensionOf(path))) {
      continue;
    }
    const pathReason = pathSkipReason(path);
    const file = await load(path);
    if (file === undefined) {
      continue;
    }
    const rank = configRank(file.text);
    if (rank === undefined) {
      continue;
    }
    if (pathReason !== undefined) {
      skipped.push(skippedRecord("config", path, 1, lineCount(file.text), pathReason));
      continue;
    }
    if (textLooksMinified(file.text)) {
      skipped.push(skippedRecord("config", path, 1, lineCount(file.text), DISCOVERY_MINIFIED));
      continue;
    }
    const covered = units.some(
      (unit) => unit.path === path && unit.startLine === 1 && unit.endLine >= lineCount(file.text),
    );
    if (covered) {
      continue;
    }
    considerSpan(
      "config",
      path,
      file.text,
      1,
      lineCount(file.text),
      rank,
      maxLines,
      maxChars,
      units,
      skipped,
    );
  }

  const queued = new Set(units.map((unit) => unit.path));
  for (const path of inventory.source_files) {
    if (!CODE_EXT.has(extensionOf(path)) || !inServerDir(path) || queued.has(path)) {
      continue;
    }
    if (rejectPath("fallback", path, 1, 1) !== undefined) {
      continue;
    }
    const file = await load(path);
    if (file === undefined) {
      skipped.push(skippedRecord("fallback", path, 1, 1, DISCOVERY_UNREADABLE));
      continue;
    }
    if (textLooksMinified(file.text)) {
      skipped.push(skippedRecord("fallback", path, 1, 1, DISCOVERY_MINIFIED));
      continue;
    }
    const uses = requestUses(file.text);
    if (uses === 0) {
      continue;
    }
    considerSpan(
      "fallback",
      path,
      file.text,
      1,
      lineCount(file.text),
      uses,
      maxLines,
      maxChars,
      units,
      skipped,
    );
  }

  return { units, skipped };
}
