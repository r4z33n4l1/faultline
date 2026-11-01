import type { Candidate } from "../schema/candidate.js";
import { stripComments, stripQuoted } from "../hunters/shared.js";
import { normalizeRepoPath, readSourceFile } from "../hunters/source.js";
import type { ResolvedRouteHandler } from "../recon/handlers.js";
import type { InventoryMatch } from "../recon/inventory.js";

/** Character budget for the fenced candidate plus context. Roughly a couple thousand tokens. */
export const VALIDATOR_PACK_MAX_CHARS = 6_000;
export const VALIDATOR_FUNCTION_MAX_LINES = 80;
export const VALIDATOR_FUNCTION_MAX_CHARS = 2_500;
export const VALIDATOR_HELPER_LIMIT = 4;
export const VALIDATOR_HELPER_MAX_LINES = 30;
export const VALIDATOR_HELPER_MAX_CHARS = 700;
export const VALIDATOR_MIDDLEWARE_LIMIT = 6;
export const VALIDATOR_ROUTE_MAX_LINES = 8;
export const VALIDATOR_ROUTE_MAX_CHARS = 800;
const MAX_ROUTE_FILES = 24;

const CALL_SKIP = new Set([
  "if",
  "for",
  "while",
  "switch",
  "catch",
  "function",
  "return",
  "await",
  "new",
  "typeof",
  "void",
  "delete",
  "throw",
  "case",
  "do",
  "else",
  "in",
  "of",
  "try",
  "finally",
  "async",
  "import",
  "export",
  "super",
  "class",
  "yield",
  "require",
  "get",
  "set",
  "from",
  "constructor",
  "console",
  "Object",
  "Array",
  "JSON",
  "Math",
  "Promise",
  "Date",
  "Number",
  "String",
  "Boolean",
  "Error",
  "RegExp",
  "Map",
  "Set",
  "parseInt",
  "parseFloat",
  "isNaN",
  "encodeURIComponent",
  "decodeURIComponent",
]);

export interface ValidatorInventory {
  routes: readonly InventoryMatch[];
  auth: readonly InventoryMatch[];
  source_files?: readonly string[];
  /** Cross-file route registrations. Optional so callers that only pass routes still work. */
  handlers?: readonly ResolvedRouteHandler[];
}

export interface NumberedSlice {
  file: string;
  start_line: number;
  end_line: number;
  source: string;
  truncated: boolean;
}

export interface RouteSlice {
  file: string;
  line: number;
  note: string;
  source: string;
}

export interface HelperSlice {
  name: string;
  file: string;
  start_line: number;
  end_line: number;
  source: string;
  truncated: boolean;
}

export interface ContextPack {
  function: NumberedSlice;
  route: RouteSlice | null;
  middleware: RouteSlice[];
  helpers: HelperSlice[];
  truncated: boolean;
}

interface FnRange {
  name: string;
  start: number;
  end: number;
}

interface PackInput {
  root: string;
  candidate: Candidate;
  files: Map<string, string>;
  inventory?: ValidatorInventory;
  redact: (text: string) => string;
}

function countChar(line: string, ch: string): number {
  let count = 0;
  for (const item of line) {
    if (item === ch) {
      count += 1;
    }
  }
  return count;
}

function functionStartName(structural: string): string | undefined {
  if (/\bfunction\b/.test(structural)) {
    const named = /\bfunction\s+\*?\s*([A-Za-z_$][\w$]*)/.exec(structural);
    return named?.[1] ?? "anonymous";
  }
  if (/=>/.test(structural)) {
    const assigned = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(structural);
    return assigned?.[1] ?? "anonymous";
  }
  return undefined;
}

/** Brace ranges for function and arrow declarations in one file. Not a full parser. */
export function functionRanges(lines: readonly string[]): FnRange[] {
  const ranges: FnRange[] = [];
  const stack: { start: number; name: string; bodyDepth: number }[] = [];
  let depth = 0;
  let pendingName: string | undefined;
  for (let index = 0; index < lines.length; index += 1) {
    const structural = stripQuoted(lines[index] ?? "");
    const started = functionStartName(structural);
    const opens = countChar(structural, "{");
    const closes = countChar(structural, "}");
    if (started !== undefined && opens > 0) {
      stack.push({ start: index + 1, name: started, bodyDepth: depth + 1 });
      pendingName = undefined;
    } else if (started !== undefined) {
      pendingName = started;
    } else if (pendingName !== undefined && structural.trim().startsWith("{")) {
      stack.push({ start: index + 1, name: pendingName, bodyDepth: depth + 1 });
      pendingName = undefined;
    } else if (pendingName !== undefined && structural.trim() !== "") {
      pendingName = undefined;
    }
    depth += opens - closes;
    if (depth < 0) {
      depth = 0;
    }
    while (stack.length > 0 && depth < (stack[stack.length - 1]?.bodyDepth ?? 0)) {
      const fn = stack.pop();
      if (fn !== undefined) {
        ranges.push({ start: fn.start, end: index + 1, name: fn.name });
      }
    }
  }
  while (stack.length > 0) {
    const fn = stack.pop();
    if (fn !== undefined) {
      ranges.push({ start: fn.start, end: lines.length, name: fn.name });
    }
  }
  return ranges;
}

function owningFunction(
  ranges: readonly FnRange[],
  line: number,
  symbol: string,
): FnRange | undefined {
  const containing = ranges.filter((range) => line >= range.start && line <= range.end);
  const named = containing.filter((range) => range.name === symbol);
  const pool = named.length > 0 ? named : containing;
  const ranked = [...pool].sort(
    (left, right) => left.end - left.start - (right.end - right.start) || left.start - right.start,
  );
  return ranked[0];
}

function numbered(
  lines: readonly string[],
  start: number,
  end: number,
  maxLines: number,
  maxChars: number,
): { source: string; end: number; truncated: boolean } {
  const capped = Math.min(end, start + maxLines - 1, lines.length);
  const finalEnd = Math.max(capped, Math.min(start, lines.length));
  const body: string[] = [];
  for (let line = start; line <= finalEnd; line += 1) {
    body.push(`${line} | ${lines[line - 1] ?? ""}`);
  }
  let source = body.join("\n");
  let truncated = finalEnd < end;
  if (source.length > maxChars) {
    source = source.slice(0, maxChars);
    truncated = true;
  }
  return { source, end: finalEnd, truncated };
}

function callsIn(source: string): string[] {
  const names: string[] = [];
  const seen = new Set<string>();
  const pattern = /\b([A-Za-z_$][\w$]*)\s*\(/g;
  for (const match of stripComments(source).matchAll(pattern)) {
    const name = match[1];
    if (name === undefined || CALL_SKIP.has(name) || seen.has(name)) {
      continue;
    }
    seen.add(name);
    names.push(name);
  }
  return names;
}

function mentions(line: string, symbol: string): boolean {
  if (symbol.length === 0) {
    return false;
  }
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(String.raw`(?<![\w$])${escaped}(?![\w$])`).test(line);
}

function linkedRegistration(
  inventory: ValidatorInventory,
  file: string,
  line: number,
): InventoryMatch | undefined {
  const hit = inventory.handlers?.find(
    (handler) =>
      handler.handlerFile === file && line >= handler.handlerLine && line <= handler.handlerEndLine,
  );
  if (hit === undefined) {
    return undefined;
  }
  return { path: hit.routeFile, line: hit.routeLine, note: hit.route };
}

function reconAllows(inventory: ValidatorInventory, rel: string): boolean {
  if (inventory.source_files !== undefined && !inventory.source_files.includes(rel)) {
    return false;
  }
  return (
    inventory.routes.some((route) => route.path === rel) ||
    inventory.auth.some((auth) => auth.path === rel)
  );
}

async function textFor(
  root: string,
  rel: string,
  files: Map<string, string>,
  inventory: ValidatorInventory | undefined,
): Promise<string | undefined> {
  const cached = files.get(rel);
  if (cached !== undefined) {
    return cached;
  }
  if (inventory !== undefined && !reconAllows(inventory, rel)) {
    return undefined;
  }
  const source = await readSourceFile(root, rel, new Set([rel]));
  if (source === undefined) {
    return undefined;
  }
  files.set(rel, source);
  return source;
}

function lineAt(text: string, line: number): string {
  return text.split(/\r?\n/)[line - 1] ?? "";
}

interface RouteHit {
  route: InventoryMatch;
  score: number;
  distance: number;
}

async function matchRoute(
  input: PackInput,
  fn: FnRange,
  file: string,
): Promise<{ route: InventoryMatch; text: string } | undefined> {
  const inventory = input.inventory;
  if (inventory === undefined || inventory.routes.length === 0) {
    return undefined;
  }
  const symbol = input.candidate.symbol;
  const linked = linkedRegistration(inventory, file, input.candidate.location.start_line);
  const preferred = inventory.routes.filter((route) => route.path === file);
  const rest = inventory.routes.filter((route) => route.path !== file);
  const ordered = linked === undefined ? [...preferred, ...rest] : [linked, ...preferred, ...rest];
  const considered = ordered
    .filter(
      (route, index) =>
        ordered.findIndex(
          (item) =>
            item.path === route.path && item.line === route.line && item.note === route.note,
        ) === index,
    )
    .slice(0, MAX_ROUTE_FILES);
  let best: RouteHit | undefined;
  const texts = new Map<string, string>();
  for (const route of considered) {
    const rel = normalizeRepoPath(route.path);
    if (rel === undefined) {
      continue;
    }
    let text = texts.get(rel);
    if (text === undefined) {
      text = await textFor(input.root, rel, input.files, inventory);
      if (text === undefined) {
        continue;
      }
      texts.set(rel, text);
    }
    const registration = lineAt(text, route.line);
    const inside = rel === file && route.line >= fn.start && route.line <= fn.end;
    const near =
      rel === file &&
      route.line < fn.start &&
      fn.start - route.line <= VALIDATOR_FUNCTION_MAX_LINES;
    const named = mentions(registration, symbol);
    const linkedHit =
      linked !== undefined &&
      linked.path === route.path &&
      linked.line === route.line &&
      linked.note === route.note;
    let score = 0;
    if (linkedHit) {
      score += 6;
    }
    if (named) {
      score += 4;
    }
    if (inside) {
      score += 2;
    } else if (near) {
      score += 1;
    }
    if (score === 0) {
      continue;
    }
    const distance = Math.abs(route.line - input.candidate.location.start_line);
    if (
      best === undefined ||
      score > best.score ||
      (score === best.score && distance < best.distance)
    ) {
      best = { route, score, distance };
    }
  }
  if (best === undefined) {
    return undefined;
  }
  const rel = normalizeRepoPath(best.route.path);
  if (rel === undefined) {
    return undefined;
  }
  const text = texts.get(rel);
  if (text === undefined) {
    return undefined;
  }
  return { route: best.route, text };
}

function middlewareFor(
  inventory: ValidatorInventory,
  route: InventoryMatch,
  text: string,
): RouteSlice[] {
  const lines = text.split(/\r?\n/);
  const preceding = inventory.auth
    .filter((auth) => auth.path === route.path && auth.line < route.line && auth.line >= 1)
    .sort((left, right) => right.line - left.line)
    .slice(0, VALIDATOR_MIDDLEWARE_LIMIT)
    .sort((left, right) => left.line - right.line);
  const slices: RouteSlice[] = [];
  for (const auth of preceding) {
    const sourceLine = lines[auth.line - 1];
    if (sourceLine === undefined || sourceLine.trim().length === 0) {
      continue;
    }
    slices.push({
      file: route.path,
      line: auth.line,
      note: auth.note,
      source: `${auth.line} | ${sourceLine}`.slice(0, VALIDATOR_ROUTE_MAX_CHARS),
    });
  }
  return slices;
}

function helpersFor(
  lines: readonly string[],
  fn: FnRange,
  ranges: readonly FnRange[],
): HelperSlice[] {
  const body = lines.slice(fn.start - 1, fn.end).join("\n");
  const helpers: HelperSlice[] = [];
  for (const name of callsIn(body)) {
    if (helpers.length >= VALIDATOR_HELPER_LIMIT || name === fn.name) {
      continue;
    }
    const match = ranges.find(
      (range) =>
        range.name === name &&
        range.name !== "anonymous" &&
        (range.end < fn.start || range.start > fn.end),
    );
    if (match === undefined) {
      continue;
    }
    const slice = numbered(
      lines,
      match.start,
      match.end,
      VALIDATOR_HELPER_MAX_LINES,
      VALIDATOR_HELPER_MAX_CHARS,
    );
    helpers.push({
      name,
      file: "",
      start_line: match.start,
      end_line: slice.end,
      source: slice.source,
      truncated: slice.truncated,
    });
  }
  return helpers;
}

function redactSlice<T extends { source: string }>(slice: T, redact: (text: string) => string): T {
  return { ...slice, source: redact(slice.source) };
}

/** Bounded context for one validator call. Reads only files recon already recorded, plus the candidate file. */
export async function buildContextPack(input: PackInput): Promise<ContextPack> {
  const file = input.candidate.location.file;
  const text = input.files.get(file) ?? "";
  const lines = text.split(/\r?\n/);
  const ranges = functionRanges(lines);
  const owned = owningFunction(ranges, input.candidate.location.start_line, input.candidate.symbol);
  const fn = owned ?? {
    name: input.candidate.symbol,
    start: Math.max(1, input.candidate.location.start_line - 10),
    end: Math.min(
      lines.length,
      Math.max(1, input.candidate.location.start_line - 10) + VALIDATOR_FUNCTION_MAX_LINES - 1,
    ),
  };
  const functionSlice = numbered(
    lines,
    fn.start,
    fn.end,
    VALIDATOR_FUNCTION_MAX_LINES,
    VALIDATOR_FUNCTION_MAX_CHARS,
  );
  const helpers = helpersFor(lines, fn, ranges).map((helper) => ({ ...helper, file }));
  let route: RouteSlice | null = null;
  let middleware: RouteSlice[] = [];
  const matched = await matchRoute(input, fn, file);
  if (matched !== undefined) {
    const routeLines = matched.text.split(/\r?\n/);
    const routeSlice = numbered(
      routeLines,
      matched.route.line,
      Math.min(routeLines.length, matched.route.line + VALIDATOR_ROUTE_MAX_LINES - 1),
      VALIDATOR_ROUTE_MAX_LINES,
      VALIDATOR_ROUTE_MAX_CHARS,
    );
    route = {
      file: matched.route.path,
      line: matched.route.line,
      note: matched.route.note,
      source: routeSlice.source,
    };
    if (input.inventory !== undefined) {
      middleware = middlewareFor(input.inventory, matched.route, matched.text);
    }
  }
  return {
    function: redactSlice(
      {
        file,
        start_line: fn.start,
        end_line: functionSlice.end,
        source: functionSlice.source,
        truncated: functionSlice.truncated || owned === undefined,
      },
      input.redact,
    ),
    route: route === null ? null : redactSlice(route, input.redact),
    middleware: middleware.map((item) => redactSlice(item, input.redact)),
    helpers: helpers.map((helper) => redactSlice(helper, input.redact)),
    truncated: functionSlice.truncated,
  };
}

/** JSON sent inside the fence. Drops helpers, then middleware, then function text to stay inside the cap. */
export function renderContextPayload(candidate: Candidate, pack: ContextPack): string {
  const fitted: ContextPack = {
    ...pack,
    helpers: [...pack.helpers],
    middleware: [...pack.middleware],
    function: { ...pack.function },
    truncated: pack.truncated,
  };
  const payload = (): string => JSON.stringify({ candidate, context: fitted });
  if (payload().length <= VALIDATOR_PACK_MAX_CHARS) {
    return payload();
  }
  fitted.truncated = true;
  while (fitted.helpers.length > 0 && payload().length > VALIDATOR_PACK_MAX_CHARS) {
    fitted.helpers.pop();
  }
  while (fitted.middleware.length > 0 && payload().length > VALIDATOR_PACK_MAX_CHARS) {
    fitted.middleware.pop();
  }
  let text = payload();
  if (text.length <= VALIDATOR_PACK_MAX_CHARS) {
    return text;
  }
  const overflow = text.length - VALIDATOR_PACK_MAX_CHARS;
  fitted.function.truncated = true;
  fitted.function.source = fitted.function.source.slice(
    0,
    Math.max(0, fitted.function.source.length - overflow - 48),
  );
  text = payload();
  if (text.length <= VALIDATOR_PACK_MAX_CHARS) {
    return text;
  }
  return text.slice(0, VALIDATOR_PACK_MAX_CHARS);
}
