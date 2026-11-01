import { stripComments, stripQuoted } from "../hunters/shared.js";

/** One route registration resolved to the function that handles the request. */
export interface ResolvedRouteHandler {
  routeFile: string;
  routeLine: number;
  /** Same text recon stores on the registration, such as `GET /items/:id`. */
  route: string;
  /** Path after Express `Router` mounts. Equals the registered path when nothing mounts it. */
  mountedPath: string;
  handlerFile: string;
  handlerLine: number;
  handlerEndLine: number;
  symbol: string;
}

interface FnRange {
  start: number;
  end: number;
  name: string;
}

interface Imported {
  local: string;
  file: string;
  /** `default`, `*`, or the exported name. */
  exportName: string;
}

interface ExportedHandler {
  handlerLine: number;
  handlerEndLine: number;
  symbol: string;
}

interface Expr {
  kind: "ident" | "member" | "call" | "inline" | "other";
  name?: string;
  object?: string;
  prop?: string;
  args?: Expr[];
}

interface LocalRoute {
  line: number;
  method: string;
  path: string;
  receiver: string;
  expr: Expr;
}

interface Mount {
  prefix: string;
  target: Expr;
}

interface FileModel {
  imports: Imported[];
  handlers: Map<string, ExportedHandler>;
  routes: LocalRoute[];
  mounts: Mount[];
  routers: Set<string>;
  routerExports: Set<string>;
}

const SOURCE_EXT = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const METHODS = new Set(["get", "post", "put", "patch", "delete", "all"]);
const ROUTE_RECEIVERS = new Set(["app", "router", "fastify"]);

function countChar(text: string, char: string): number {
  let count = 0;
  for (const item of text) {
    if (item === char) {
      count += 1;
    }
  }
  return count;
}

function extractCall(source: string, parenIndex: number): { text: string; endIndex: number } {
  let depth = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  const limit = Math.min(source.length, parenIndex + 8_000);
  for (let index = parenIndex; index < limit; index += 1) {
    const ch = source[index] ?? "";
    if (quote !== undefined) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === quote) {
        quote = undefined;
      }
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(") {
      depth += 1;
    } else if (ch === ")") {
      depth -= 1;
      if (depth === 0) {
        return { text: source.slice(parenIndex, index + 1), endIndex: index };
      }
    }
  }
  return { text: source.slice(parenIndex, limit), endIndex: Math.max(parenIndex, limit - 1) };
}

function splitArgs(callInner: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  let start = 0;
  for (let index = 0; index < callInner.length; index += 1) {
    const ch = callInner[index] ?? "";
    if (quote !== undefined) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === quote) {
        quote = undefined;
      }
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") {
      depth += 1;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      depth = Math.max(0, depth - 1);
    } else if (ch === "," && depth === 0) {
      args.push(callInner.slice(start, index));
      start = index + 1;
    }
  }
  args.push(callInner.slice(start));
  return args;
}

function functionStartName(structural: string): string | undefined {
  if (/\bfunction\b/.test(structural)) {
    const named = /\bfunction\s+\*?\s*([A-Za-z_$][\w$]*)/.exec(structural);
    return named?.[1] ?? "anonymous";
  }
  if (/=>/.test(structural)) {
    const assigned = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(structural);
    const exported = /exports\s*\.\s*([A-Za-z_$][\w$]*)\s*=/.exec(structural);
    return assigned?.[1] ?? exported?.[1] ?? "anonymous";
  }
  return undefined;
}

function functionRanges(lines: readonly string[]): FnRange[] {
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

function firstParam(header: string): string | undefined {
  const arrow = header.lastIndexOf("=>");
  let open = arrow === -1 ? -1 : header.lastIndexOf("(", arrow);
  if (open < 0) {
    const fn = header.lastIndexOf("function");
    open = header.indexOf("(", fn === -1 ? 0 : fn);
  }
  if (open < 0) {
    return undefined;
  }
  const extracted = extractCall(header, open);
  const inner = extracted.text.slice(1, extracted.text.endsWith(")") ? -1 : undefined);
  const first = splitArgs(inner)[0]?.trim() ?? "";
  if (/^(?:req|request)\b/.test(first)) {
    return "req";
  }
  return /^([A-Za-z_$][\w$]*)/.exec(first)?.[1];
}

function headerOf(lines: readonly string[], start: number): string {
  return lines.slice(Math.max(0, start - 2), Math.min(lines.length, start + 2)).join("\n");
}

/** The function that reads the request, including a closure returned by a factory. */
function requestSpan(
  range: FnRange,
  ranges: readonly FnRange[],
  lines: readonly string[],
): { start: number; end: number } | undefined {
  const header = headerOf(lines, range.start);
  if (firstParam(header) === "req" || /=>\s*(?:async\s+)?\(\s*(?:req|request)\b/.test(header)) {
    return { start: range.start, end: range.end };
  }
  const nested = ranges.filter((item) => item.start > range.start && item.end <= range.end);
  const returned = nested.filter((item) => {
    const context = headerOf(lines, item.start);
    return firstParam(context) === "req" && (/\breturn\b/.test(context) || /=>/.test(context));
  });
  returned.sort((left, right) => left.start - right.start);
  const pick = returned[0];
  if (pick === undefined) {
    return undefined;
  }
  return { start: pick.start, end: pick.end };
}

function dirname(rel: string): string {
  const slash = rel.lastIndexOf("/");
  return slash === -1 ? "" : rel.slice(0, slash);
}

function joinPath(dir: string, spec: string): string {
  const parts = `${dir}/${spec}`.split("/");
  const stack: string[] = [];
  for (const part of parts) {
    if (part === "" || part === ".") {
      continue;
    }
    if (part === "..") {
      stack.pop();
      continue;
    }
    stack.push(part);
  }
  return stack.join("/");
}

function resolveModule(from: string, spec: string, files: ReadonlySet<string>): string | undefined {
  if (!spec.startsWith(".")) {
    return undefined;
  }
  const base = joinPath(dirname(from), spec.replace(/\.(?:js|jsx|mjs|cjs|ts|tsx)$/, ""));
  const candidates = [base];
  for (const ext of SOURCE_EXT) {
    candidates.push(`${base}${ext}`);
    candidates.push(`${base}/index${ext}`);
  }
  return candidates.find((item) => files.has(item));
}

function lineOfIndex(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < source.length; cursor += 1) {
    if (source[cursor] === "\n") {
      line += 1;
    }
  }
  return line;
}

function calleeExpr(text: string): Pick<Expr, "name" | "object" | "prop"> {
  const member = /^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)$/.exec(text);
  if (member?.[1] !== undefined && member[2] !== undefined) {
    return { object: member[1], prop: member[2] };
  }
  return { name: text };
}

function parseExpr(text: string): Expr {
  const trimmed = text.trim().replace(/;$/, "");
  if (trimmed === "") {
    return { kind: "other" };
  }
  if (
    /^(?:async\s+)?function\b|^(?:async\s+)?\(|^(?:async\s+)?[A-Za-z_$][\w$]*\s*=>/.test(trimmed)
  ) {
    return { kind: "inline" };
  }
  const call = /^([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)?)\s*\(/.exec(trimmed);
  if (call?.[1] !== undefined) {
    const paren = trimmed.indexOf("(");
    const extracted = extractCall(trimmed, paren);
    const inner = extracted.text.slice(1, extracted.text.endsWith(")") ? -1 : undefined);
    const calleeText = call[1].replace(/\s/g, "");
    return {
      kind: "call",
      ...calleeExpr(calleeText),
      args: splitArgs(inner).map((arg) => parseExpr(arg)),
    };
  }
  const member = /^([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)$/.exec(trimmed);
  if (member?.[1] !== undefined && member[2] !== undefined) {
    return { kind: "member", object: member[1], prop: member[2] };
  }
  if (/^[A-Za-z_$][\w$]*$/.test(trimmed)) {
    return { kind: "ident", name: trimmed };
  }
  return { kind: "other" };
}

function asHandler(expr: Expr): Expr | undefined {
  if (expr.kind === "call" && expr.args?.length === 1) {
    const only = expr.args[0];
    if (
      only !== undefined &&
      (only.kind === "call" ||
        only.kind === "ident" ||
        only.kind === "member" ||
        only.kind === "inline")
    ) {
      return asHandler(only);
    }
  }
  if (
    expr.kind === "ident" ||
    expr.kind === "member" ||
    expr.kind === "call" ||
    expr.kind === "inline"
  ) {
    return expr;
  }
  return undefined;
}

function stringLiteral(text: string): string | undefined {
  const match = /^\s*(["'`])([\s\S]*)\1\s*$/.exec(text.trim());
  return match?.[2];
}

function addImport(imports: Imported[], local: string, file: string, exportName: string): void {
  if (!/^[A-Za-z_$][\w$]*$/.test(local)) {
    return;
  }
  imports.push({ local, file, exportName });
}

function parseImportClause(clause: string, file: string, imports: Imported[]): void {
  const body = clause.trim();
  const namespace = /^\*\s+as\s+([A-Za-z_$][\w$]*)$/.exec(body);
  if (namespace?.[1] !== undefined) {
    addImport(imports, namespace[1], file, "*");
    return;
  }
  const named = /^\{([\s\S]*)\}$/.exec(body);
  if (named?.[1] !== undefined) {
    for (const part of named[1].split(",")) {
      const alias = /([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)/.exec(part);
      const plain = /^([A-Za-z_$][\w$]*)/.exec(part.trim());
      if (alias?.[1] !== undefined && alias[2] !== undefined) {
        addImport(imports, alias[2], file, alias[1]);
      } else if (plain?.[1] !== undefined) {
        addImport(imports, plain[1], file, plain[1]);
      }
    }
    return;
  }
  const mixed = /^([A-Za-z_$][\w$]*)\s*,\s*([\s\S]+)$/.exec(body);
  if (mixed?.[1] !== undefined && mixed[2] !== undefined) {
    addImport(imports, mixed[1], file, "default");
    parseImportClause(mixed[2], file, imports);
    return;
  }
  if (/^[A-Za-z_$][\w$]*$/.test(body)) {
    addImport(imports, body, file, "default");
  }
}

function collectImports(source: string, from: string, known: ReadonlySet<string>): Imported[] {
  const imports: Imported[] = [];
  for (const match of source.matchAll(/import\s+([\s\S]*?)\s+from\s*["']([^"']+)["']/g)) {
    const clause = match[1];
    const spec = match[2];
    if (
      clause === undefined ||
      spec === undefined ||
      clause.startsWith("type ") ||
      clause === "type"
    ) {
      continue;
    }
    const file = resolveModule(from, spec, known);
    if (file === undefined) {
      continue;
    }
    parseImportClause(clause.replace(/\s+/g, " "), file, imports);
  }
  for (const match of source.matchAll(
    /(?:const|let|var)\s+(\{[^}]+\}|[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)/g,
  )) {
    const binding = match[1];
    const spec = match[2];
    if (binding === undefined || spec === undefined) {
      continue;
    }
    const file = resolveModule(from, spec, known);
    if (file === undefined) {
      continue;
    }
    if (binding.startsWith("{")) {
      parseImportClause(binding, file, imports);
    } else {
      addImport(imports, binding, file, "default");
    }
  }
  return imports;
}

function rememberHandler(
  handlers: Map<string, ExportedHandler>,
  name: string,
  span: { start: number; end: number },
): void {
  handlers.set(name, { handlerLine: span.start, handlerEndLine: span.end, symbol: name });
}

function collectHandlers(
  lines: readonly string[],
  ranges: readonly FnRange[],
): Map<string, ExportedHandler> {
  const handlers = new Map<string, ExportedHandler>();
  const byStart = new Map<number, FnRange[]>();
  for (const range of ranges) {
    const list = byStart.get(range.start) ?? [];
    list.push(range);
    byStart.set(range.start, list);
  }
  const spanFor = (range: FnRange): { start: number; end: number } | undefined =>
    requestSpan(range, ranges, lines);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const rangesHere = byStart.get(index + 1) ?? [];
    const primary = rangesHere.find((range) => spanFor(range) !== undefined) ?? rangesHere[0];
    const span = primary === undefined ? undefined : spanFor(primary);
    if (span === undefined) {
      continue;
    }
    const named = /export\s+(?:async\s+)?function\s+\*?\s*([A-Za-z_$][\w$]*)/.exec(line);
    if (named?.[1] !== undefined) {
      rememberHandler(handlers, named[1], span);
    }
    if (/export\s+default\s+(?:async\s+)?function\b/.test(line)) {
      rememberHandler(handlers, "default", span);
    }
    const declared = /export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(line);
    if (declared?.[1] !== undefined) {
      rememberHandler(handlers, declared[1], span);
    }
    const common =
      /(?:module\s*\.\s*)?exports\s*(?:\.\s*([A-Za-z_$][\w$]*))?\s*=\s*(?:async\s+)?function\b/.exec(
        line,
      );
    if (common !== null) {
      const name = common[1] ?? "default";
      rememberHandler(handlers, name, span);
      if (common[1] === undefined) {
        const fnName = /\bfunction\s+\*?\s*([A-Za-z_$][\w$]*)/.exec(line)?.[1];
        if (fnName !== undefined) {
          rememberHandler(handlers, fnName, span);
        }
      }
    }
    const assigned = /(?:module\s*\.\s*)?exports\s*\.\s*([A-Za-z_$][\w$]*)\s*=/.exec(line);
    if (assigned?.[1] !== undefined && !handlers.has(assigned[1])) {
      rememberHandler(handlers, assigned[1], span);
    }
  }
  for (const line of lines) {
    const alias = /module\s*\.\s*exports\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$/.exec(line.trim());
    if (alias?.[1] !== undefined && handlers.has(alias[1])) {
      const target = handlers.get(alias[1]);
      if (target !== undefined) {
        handlers.set("default", target);
      }
    }
    if (/export\s+default\s+([A-Za-z_$][\w$]*)\s*;?\s*$/.test(line)) {
      const name = /export\s+default\s+([A-Za-z_$][\w$]*)/.exec(line)?.[1];
      const target = name === undefined ? undefined : handlers.get(name);
      if (target !== undefined) {
        handlers.set("default", target);
      }
    }
    const list = /export\s*\{([^}]+)\}/.exec(line);
    if (list?.[1] === undefined) {
      continue;
    }
    for (const part of list[1].split(",")) {
      const aliasName = /([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)/.exec(part);
      const plain = /^([A-Za-z_$][\w$]*)/.exec(part.trim());
      const local = aliasName?.[1] ?? plain?.[1];
      const exported = aliasName?.[2] ?? plain?.[1];
      if (local === undefined || exported === undefined) {
        continue;
      }
      const target = handlers.get(local);
      if (target !== undefined) {
        handlers.set(exported, target);
      }
    }
  }
  return handlers;
}

function collectRouters(source: string): Set<string> {
  const names = new Set<string>();
  for (const match of source.matchAll(
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?(?:express\s*\.\s*Router|Router)\s*\(/g,
  )) {
    if (match[1] !== undefined) {
      names.add(match[1]);
    }
  }
  return names;
}

function routerExportNames(source: string, routers: ReadonlySet<string>): Set<string> {
  const names = new Set<string>();
  for (const name of routers) {
    if (new RegExp(String.raw`export\s+default\s+${name}\b`).test(source)) {
      names.add("default");
    }
    if (new RegExp(String.raw`module\s*\.\s*exports\s*=\s*${name}\b`).test(source)) {
      names.add("default");
    }
    if (new RegExp(String.raw`export\s*\{[^}]*\b${name}\b[^}]*\}`).test(source)) {
      names.add(name);
    }
  }
  return names;
}

function parseRoutes(
  source: string,
  routers: ReadonlySet<string>,
): { routes: LocalRoute[]; mounts: Mount[] } {
  const routes: LocalRoute[] = [];
  const mounts: Mount[] = [];
  const pattern = /\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(/g;
  for (const match of source.matchAll(pattern)) {
    const receiver = match[1];
    const method = match[2];
    const start = match.index;
    if (receiver === undefined || method === undefined || start === undefined) {
      continue;
    }
    if (!ROUTE_RECEIVERS.has(receiver) && !routers.has(receiver)) {
      continue;
    }
    const paren = start + match[0].lastIndexOf("(");
    const extracted = extractCall(source, paren);
    const inner = extracted.text.slice(1, extracted.text.endsWith(")") ? -1 : undefined);
    const args = splitArgs(inner);
    const path = stringLiteral(args[0] ?? "");
    if (path === undefined || !path.startsWith("/")) {
      continue;
    }
    const line = lineOfIndex(source, start);
    if (method === "use") {
      const target = args
        .slice(1)
        .map((arg) => parseExpr(arg))
        .find((expr) => expr.kind === "ident" || expr.kind === "member");
      if (target !== undefined) {
        mounts.push({ prefix: path, target });
      }
      continue;
    }
    if (!METHODS.has(method)) {
      continue;
    }
    let expr: Expr = { kind: "other" };
    for (let index = args.length - 1; index >= 1; index -= 1) {
      const parsed = asHandler(parseExpr(args[index] ?? ""));
      if (parsed !== undefined) {
        expr = parsed;
        break;
      }
    }
    routes.push({ line, method: method.toUpperCase(), path, receiver, expr });
  }
  return { routes, mounts };
}

function parseFile(rel: string, text: string, known: ReadonlySet<string>): FileModel {
  const stripped = stripComments(text);
  const lines = stripped.split(/\r?\n/);
  const routers = collectRouters(stripped);
  const parsed = parseRoutes(stripped, routers);
  return {
    imports: collectImports(stripped, rel, known),
    handlers: collectHandlers(lines, functionRanges(lines)),
    routes: parsed.routes,
    mounts: parsed.mounts,
    routers,
    routerExports: routerExportNames(stripped, routers),
  };
}

interface Target {
  file: string;
  exportName: string;
}

function resolveIdent(file: string, model: FileModel, name: string): Target | undefined {
  if (model.handlers.has(name)) {
    return { file, exportName: name };
  }
  const imported = model.imports.find((item) => item.local === name);
  if (imported === undefined) {
    return undefined;
  }
  return { file: imported.file, exportName: imported.exportName };
}

function resolveExpr(
  file: string,
  expr: Expr,
  models: ReadonlyMap<string, FileModel>,
): Target | "inline" | undefined {
  const model = models.get(file);
  if (model === undefined) {
    return undefined;
  }
  if (expr.kind === "inline") {
    return "inline";
  }
  if (expr.kind === "ident" && expr.name !== undefined) {
    return resolveIdent(file, model, expr.name);
  }
  if (expr.kind === "member" && expr.object !== undefined && expr.prop !== undefined) {
    const imported = model.imports.find((item) => item.local === expr.object);
    if (imported === undefined) {
      return undefined;
    }
    return { file: imported.file, exportName: imported.exportName === "*" ? expr.prop : expr.prop };
  }
  if (expr.kind === "call") {
    const callee: Expr =
      expr.object !== undefined && expr.prop !== undefined
        ? { kind: "member", object: expr.object, prop: expr.prop }
        : { kind: "ident", name: expr.name };
    return resolveExpr(file, callee, models);
  }
  return undefined;
}

function joinRoute(prefix: string, path: string): string {
  if (prefix === "/" || prefix === "") {
    return path;
  }
  if (path === "/" || path === "") {
    return prefix;
  }
  const left = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  const right = path.startsWith("/") ? path : `/${path}`;
  return `${left}${right}`;
}

function lookupHandler(
  target: Target,
  models: ReadonlyMap<string, FileModel>,
): ExportedHandler | undefined {
  return models.get(target.file)?.handlers.get(target.exportName);
}

function moduleIsRouter(target: Target, model: FileModel): boolean {
  if (target.exportName === "*") {
    return model.routerExports.size > 0 || model.routers.size > 0;
  }
  return model.routerExports.has(target.exportName) || model.routers.has(target.exportName);
}

/**
 * Route registrations in `files`, resolved to the request-handling function.
 * Follows relative import and require, factories that return `(req, res, next)`,
 * single-argument wrappers such as `asyncHandler(fn())`, and Express routers
 * mounted with `app.use(prefix, router)`.
 */
export function resolveRouteHandlers(files: ReadonlyMap<string, string>): ResolvedRouteHandler[] {
  const known = new Set(files.keys());
  const models = new Map<string, FileModel>();
  for (const [rel, text] of files) {
    models.set(rel, parseFile(rel, text, known));
  }
  const prefixes = new Map<string, string[]>();
  const addPrefix = (file: string, receiver: string, prefix: string): void => {
    const key = `${file}\0${receiver}`;
    const list = prefixes.get(key) ?? [];
    list.push(prefix);
    prefixes.set(key, list);
  };
  for (const [rel, model] of models) {
    for (const mount of model.mounts) {
      const target = resolveExpr(rel, mount.target, models);
      if (
        (target === undefined || target === "inline") &&
        mount.target.kind === "ident" &&
        mount.target.name !== undefined &&
        model.routers.has(mount.target.name)
      ) {
        addPrefix(rel, mount.target.name, mount.prefix);
        continue;
      }
      if (target === undefined || target === "inline") {
        continue;
      }
      const mounted = models.get(target.file);
      if (mounted !== undefined && moduleIsRouter(target, mounted)) {
        const names = mounted.routers.size === 0 ? ["router"] : [...mounted.routers];
        for (const name of names) {
          addPrefix(target.file, name, mount.prefix);
        }
      }
    }
  }
  const found: ResolvedRouteHandler[] = [];
  const seen = new Set<string>();
  for (const [rel, model] of models) {
    for (const route of model.routes) {
      const resolved = resolveExpr(rel, route.expr, models);
      if (resolved === undefined || resolved === "inline") {
        continue;
      }
      const span = lookupHandler(resolved, models);
      if (span === undefined) {
        continue;
      }
      const mounted = prefixes.get(`${rel}\0${route.receiver}`) ?? [""];
      for (const prefix of mounted) {
        const mountedPath = prefix === "" ? route.path : joinRoute(prefix, route.path);
        const note = `${route.method} ${route.path}`;
        const symbol = resolved.exportName === "default" ? "default" : resolved.exportName;
        const key = `${rel}:${route.line}:${note}:${resolved.file}:${span.handlerLine}:${mountedPath}`;
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        found.push({
          routeFile: rel,
          routeLine: route.line,
          route: note,
          mountedPath,
          handlerFile: resolved.file,
          handlerLine: span.handlerLine,
          handlerEndLine: span.handlerEndLine,
          symbol,
        });
      }
    }
  }
  found.sort(
    (left, right) =>
      left.routeFile.localeCompare(right.routeFile) ||
      left.routeLine - right.routeLine ||
      left.route.localeCompare(right.route) ||
      left.mountedPath.localeCompare(right.mountedPath) ||
      left.handlerFile.localeCompare(right.handlerFile) ||
      left.handlerLine - right.handlerLine,
  );
  return found;
}
