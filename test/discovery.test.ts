import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { expect, it } from "vitest";
import { CODEX_MAX_CONCURRENCY } from "../src/providers/codex.js";
import { PROVIDER_LIMIT_STOP, ProviderRequestError } from "../src/providers/errors.js";
import { FakeProvider } from "../src/providers/types.js";
import { planAuthz } from "../src/hunters/authz-idor.js";
import { planInjection } from "../src/hunters/injection.js";
import { planSecrets } from "../src/hunters/secrets.js";
import { planSsrf } from "../src/hunters/ssrf.js";
import {
  DISCOVERY_BUDGET_REASON,
  DISCOVERY_MINIFIED,
  DISCOVERY_TEST,
  DISCOVERY_TOO_LARGE,
  DISCOVERY_VENDORED,
  type DiscoveredSite,
} from "../src/discovery/types.js";
import {
  discoverSites,
  groundDiscoverySites,
  parseDiscoveryResponse,
} from "../src/discovery/run.js";
import { executeScan } from "../src/recon/run.js";
import { collectInventory, type Inventory, type InventoryLimits } from "../src/recon/inventory.js";
import type { ResolvedRouteHandler } from "../src/recon/handlers.js";
import { coverageFileSchema } from "../src/schema/coverage.js";
import { runCli, type CliIo } from "../src/cli.js";

const LIMITS: InventoryLimits = { maxFiles: 5000, maxBytes: 8_000_000, maxFileBytes: 128_000 };

async function writeProject(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(root, rel);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, text, "utf8");
  }
}

function emptyInventory(rootLabel: string, source: string[]): Inventory {
  return {
    target: rootLabel,
    truncated: false,
    files_read: source.length,
    bytes_read: 10,
    languages: [],
    manifests: [],
    frameworks: [],
    entrypoints: [],
    source_files: source,
    routes: [],
    handlers: [],
    auth: [],
    data_stores: [],
    outbound_http: [],
    env_files: [],
    config_files: [],
    skipped: [],
    limits: LIMITS,
  };
}

function handler(file: string, start: number, end: number): ResolvedRouteHandler {
  return {
    routeFile: file,
    routeLine: start,
    route: `GET /${file}`,
    mountedPath: `/${file}`,
    handlerFile: file,
    handlerLine: start,
    handlerEndLine: end,
    symbol: "handle",
  };
}

it("drops a discovery site whose line or symbol is not in the shown window", () => {
  const text = ["export function handle(req, res) {", "  return db.query(req.query.q);", "}"].join(
    "\n",
  );
  const parsed = parseDiscoveryResponse(
    JSON.stringify({
      sites: [
        { class: "injection", line: 2, symbol: "query", reason: "query uses the request" },
        { class: "injection", line: 99, symbol: "query", reason: "not a real line" },
        { class: "ssrf", line: 2, symbol: "missingSymbol", reason: "symbol is not in the window" },
        { class: "injection", line: 2, symbol: "query", reason: "duplicate line" },
        { class: "nope", line: 2, reason: "bad class" },
      ],
    }),
  );
  expect(parsed.map((site) => site.class)).toEqual(["injection", "injection", "ssrf", "injection"]);
  const grounded = groundDiscoverySites(parsed, "src/app.ts", text, 1, 3, text);
  expect(grounded).toHaveLength(1);
  expect(grounded[0]).toMatchObject({
    class: "injection",
    file: "src/app.ts",
    line: 2,
    symbol: "query",
    tainted: true,
  });
});

it("rejects a line that exists in the file but was outside the fenced window", () => {
  const text = ["const keep = 1;", "db.query(req.query.q);", "const tail = 2;"].join("\n");
  const parsed = parseDiscoveryResponse(
    JSON.stringify({
      sites: [{ class: "injection", line: 3, symbol: "tail", reason: "outside the fence" }],
    }),
  );
  expect(
    groundDiscoverySites(parsed, "src/app.ts", text, 1, 2, text.split("\n").slice(0, 2).join("\n")),
  ).toEqual([]);
});

it("unions model sites with heuristic sites and lets taint outrank a constant", async () => {
  const root = await mkdtemp(join(tmpdir(), "faultline-discovery-union-"));
  const source = [
    "const app = { get() {} };",
    "app.get('/fixed', (req, res) => {",
    "  db.query('SELECT 1');",
    "});",
    "app.get('/open', (req, res) => {",
    "  res.send(req.query.name);",
    "});",
    "",
  ].join("\n");
  await writeProject(root, { "src/server.ts": source });
  const inventory = await collectInventory(root, { target: "union" });
  const alone = await planInjection(root, inventory, 1);
  const discovered: DiscoveredSite = {
    class: "injection",
    file: "src/server.ts",
    line: 6,
    endLine: 6,
    symbol: "send",
    reason: "response uses the query string",
    tainted: true,
    source: source.trimEnd(),
    startLine: 1,
    sourceEndLine: 7,
    truncated: false,
  };
  const union = await planInjection(root, inventory, 1, [discovered]);
  expect(
    union.sites.some((site) => site.origin === "model" && site.line === 6 && !site.overCap),
  ).toBe(true);
  expect(union.sites.filter((site) => site.line === 6)).toHaveLength(1);
  const seeded = alone.sites[0];
  expect(seeded).toBeDefined();
  if (seeded !== undefined) {
    const again = await planInjection(root, inventory, 5, [
      {
        ...discovered,
        line: seeded.line,
        symbol: seeded.symbol,
        reason: "same line as the heuristic",
      },
    ]);
    expect(
      again.sites.filter((site) => site.line === seeded.line && site.origin === "model"),
    ).toEqual([]);
    expect(again.sites.filter((site) => site.line === seeded.line)).toHaveLength(
      alone.sites.filter((site) => site.line === seeded.line).length,
    );
  }
  const same = await planInjection(root, inventory, 40, []);
  const baseline = await planInjection(root, inventory, 40);
  expect(same.sites).toEqual(baseline.sites);
  expect(await planAuthz(root, inventory, 40, [])).toEqual(await planAuthz(root, inventory, 40));
  expect(await planSsrf(root, inventory, 40, [])).toEqual(await planSsrf(root, inventory, 40));
  expect(await planSecrets(root, inventory, 40, [])).toEqual(
    await planSecrets(root, inventory, 40),
  );
});

it("records budget, vendored, test, minified, and oversized units", async () => {
  const root = await mkdtemp(join(tmpdir(), "faultline-discovery-budget-"));
  const body = ["export function handle(req, res) {", "  res.send(req.query.q);", "}", ""].join(
    "\n",
  );
  await writeProject(root, {
    "src/a.ts": body,
    "src/b.ts": body,
    "src/c.ts": body,
    "vendor/pay.ts": body,
    "test/hidden.ts": body,
    "src/app.min.js": body,
    "src/wide.ts": `export function handle(req, res) { res.send("${"x".repeat(80)}"); }\n`,
  });
  const inventory = emptyInventory("budget", [
    "src/a.ts",
    "src/b.ts",
    "src/c.ts",
    "vendor/pay.ts",
    "test/hidden.ts",
    "src/app.min.js",
    "src/wide.ts",
  ]);
  inventory.handlers = [
    handler("src/a.ts", 1, 3),
    handler("src/b.ts", 1, 3),
    handler("src/c.ts", 1, 3),
    handler("vendor/pay.ts", 1, 3),
    handler("test/hidden.ts", 1, 3),
    handler("src/app.min.js", 1, 3),
    handler("src/wide.ts", 1, 1),
  ];
  const provider = new FakeProvider('{"sites":[]}');
  const result = await discoverSites({
    root,
    inventory,
    provider,
    budget: 1,
    maxChars: 120,
  });
  expect(provider.calls).toHaveLength(1);
  const reasons = new Map(result.records.map((record) => [record.path, record.reason]));
  expect(reasons.get("vendor/pay.ts")).toBe(DISCOVERY_VENDORED);
  expect(reasons.get("test/hidden.ts")).toBe(DISCOVERY_TEST);
  expect(reasons.get("src/app.min.js")).toBe(DISCOVERY_MINIFIED);
  expect(reasons.get("src/wide.ts")).toBe(DISCOVERY_TOO_LARGE);
  expect(result.records.filter((record) => record.reason === DISCOVERY_BUDGET_REASON).length).toBe(
    2,
  );
  expect(result.records.find((record) => record.path === "src/a.ts")?.status).toBe("reviewed");
  expect(result.sites).toEqual([]);
});

it("redacts secrets in the discovery prompt and keeps the Codex concurrency cap", async () => {
  const root = await mkdtemp(join(tmpdir(), "faultline-discovery-secret-"));
  const secret = "jwt-secret-value-should-not-leak";
  await writeProject(root, {
    "src/boot.ts": [
      `const jwtSecret = "${secret}";`,
      "export function boot() {",
      "  return new PrismaClient({ secret: jwtSecret });",
      "}",
      "",
    ].join("\n"),
    "routes/a.ts": "export function one(req, res) { res.send(req.query.a); }\n",
    "routes/b.ts": "export function two(req, res) { res.send(req.query.b); }\n",
    "routes/c.ts": "export function three(req, res) { res.send(req.query.c); }\n",
    "routes/odd.ts": [
      "const verbs = { get: 'get' };",
      "router[verbs.get]('/widgets', (req, res) => {",
      "  return db.query(req.query.q);",
      "});",
      "",
    ].join("\n"),
    "controllers/users.ts": [
      "export class UsersController {",
      "  show(req, res) {",
      "    return db.find(req.params.id);",
      "  }",
      "}",
      "",
    ].join("\n"),
  });
  const inventory = await collectInventory(root, { target: "secret" });
  let active = 0;
  let peak = 0;
  const provider = new FakeProvider(async (input) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((resolve) => {
      setTimeout(resolve, 30);
    });
    active -= 1;
    const user = input.messages.map((message) => message.content).join("\n");
    if (user.includes("controllers/users.ts")) {
      return JSON.stringify({
        sites: [
          { class: "authz_idor", line: 3, symbol: "find", reason: "loads a row from the route id" },
          { class: "authz_idor", line: 40, symbol: "find", reason: "hallucinated" },
        ],
      });
    }
    return '{"sites":[]}';
  });
  const result = await discoverSites({ root, inventory, provider, budget: 10 });
  expect(peak).toBeLessThanOrEqual(CODEX_MAX_CONCURRENCY);
  expect(peak).toBeGreaterThan(1);
  const prompts = provider.calls.map((call) =>
    call.messages.map((message) => message.content).join("\n"),
  );
  expect(prompts.join("\n")).not.toContain(secret);
  expect(prompts.some((prompt) => prompt.includes("<redacted>"))).toBe(true);
  expect(prompts.every((prompt) => prompt.includes("untrusted"))).toBe(true);
  const controller = result.records.find((record) => record.path === "controllers/users.ts");
  const odd = result.records.find((record) => record.path === "routes/odd.ts");
  expect(controller).toMatchObject({ kind: "controller", status: "reviewed" });
  expect(odd?.kind).toBe("fallback");
  expect(odd?.status).toBe("reviewed");
  expect(result.sites).toEqual([
    expect.objectContaining({
      class: "authz_idor",
      file: "controllers/users.ts",
      line: 3,
      symbol: "find",
    }),
  ]);
  expect(result.sites.some((site) => site.line === 40)).toBe(false);
});

it("leaves coverage discovery empty when no provider is configured", async () => {
  const root = await mkdtemp(join(tmpdir(), "faultline-discovery-offline-"));
  const out = await mkdtemp(join(tmpdir(), "faultline-discovery-out-"));
  await writeProject(root, {
    "src/server.ts": "export function handle(req, res) { res.send(req.query.q); }\n",
  });
  await executeScan({ target: root, cwd: root, outDir: out, validate: false });
  const coverage = coverageFileSchema.parse(
    JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as unknown,
  );
  expect(coverage.discovery).toEqual([]);

  const captured = {
    stdout: [] as string[],
    stderr: [] as string[],
  };
  const io: CliIo = {
    cwd: root,
    env: {},
    stdout: (text) => {
      captured.stdout.push(text);
    },
    stderr: (text) => {
      captured.stderr.push(text);
    },
  };
  expect(await runCli(["scan", root, "--out", out, "--discovery-budget", "0"], io)).toBe(1);
  expect(captured.stderr.join("")).toContain("--discovery-budget must be a positive integer");
});

it("records a provider failure on the discovery unit instead of reviewed", async () => {
  const root = await mkdtemp(join(tmpdir(), "faultline-discovery-error-"));
  const body = ["export function handle(req, res) {", "  res.send(req.query.q);", "}", ""].join(
    "\n",
  );
  await writeProject(root, {
    "src/a.ts": body,
    "src/b.ts": body,
    "src/c.ts": body,
  });
  const inventory = emptyInventory("errors", ["src/a.ts", "src/b.ts", "src/c.ts"]);
  inventory.handlers = [
    handler("src/a.ts", 1, 3),
    handler("src/b.ts", 1, 3),
    handler("src/c.ts", 1, 3),
  ];
  const provider = new FakeProvider(() => {
    throw new ProviderRequestError(
      "codex",
      "codex exec exited with status 1: You've hit your usage limit.",
    );
  });
  const result = await discoverSites({ root, inventory, provider, budget: 3 });
  expect(provider.calls.length).toBeGreaterThan(0);
  expect(provider.calls.length).toBeLessThan(3);
  expect(result.halted).toContain("usage limit");
  expect(result.sites).toEqual([]);
  const called = result.records.filter((record) => record.status === "error");
  expect(called).toHaveLength(3);
  expect(result.records.some((record) => record.status === "reviewed")).toBe(false);
  expect(result.records.some((record) => record.reason.includes(PROVIDER_LIMIT_STOP))).toBe(true);

  const out = await mkdtemp(join(tmpdir(), "faultline-discovery-error-out-"));
  await writeProject(root, {
    "routes/items.ts": [
      "export function show(req, res) {",
      "  res.json(req.params.id);",
      "}",
      "",
    ].join("\n"),
  });
  const scanProvider = new FakeProvider((input) => {
    const system = input.messages[0]?.content ?? "";
    if (system.includes("list candidate security sites")) {
      throw new ProviderRequestError(
        "codex",
        "codex exec exited with status 1: You've hit your usage limit.",
      );
    }
    return "Architecture summary.";
  });
  const stderr: string[] = [];
  expect(
    await runCli(["scan", root, "--out", out], {
      cwd: root,
      env: {},
      provider: scanProvider,
      stdout() {},
      stderr(text) {
        stderr.push(text);
      },
    }),
  ).toBe(1);
  expect(stderr.join("")).toContain("provider error");
  const coverage = coverageFileSchema.parse(
    JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as unknown,
  );
  const failed = coverage.discovery.filter((record) => record.status === "error");
  expect(failed.length).toBeGreaterThan(0);
  expect(coverage.discovery.some((record) => record.status === "reviewed")).toBe(false);
  expect(failed.some((record) => record.reason.includes("usage limit"))).toBe(true);
});
