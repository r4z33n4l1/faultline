import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { expect, it } from "vitest";
import { planAuthz } from "../src/hunters/authz-idor.js";
import { injectionHunter, planInjection } from "../src/hunters/injection.js";
import { planSecrets } from "../src/hunters/secrets.js";
import { collectInventory } from "../src/recon/inventory.js";
import { routeCoverageId } from "../src/recon/coverage.js";

async function writeProject(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(root, rel);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, text, "utf8");
  }
}

it("resolves factory handlers, mounted routers, and ranks the site budget", async () => {
  const root = await mkdtemp(join(tmpdir(), "faultline-route-budget-"));
  await writeProject(root, {
    "src/search.ts": [
      "export function search() {",
      "  return (req, res, next) => {",
      "    let criteria: string = req.query.q;",
      "    return models.sequelize.query(`SELECT * FROM products WHERE name LIKE '%${criteria}%'`);",
      "  };",
      "}",
      "",
    ].join("\n"),
    "src/notes.ts": [
      "module.exports = function save() {",
      "  return (req, res, next) => {",
      "    return notes.update({ _id: req.body.id }, { $set: { text: req.body.text } });",
      "  };",
      "};",
      "",
    ].join("\n"),
    "src/safe-notes.ts": [
      "export function saveSafe() {",
      "  return (req, res) => {",
      "    return notes.update({ _id: String(req.params.id) }, { $set: { text: 'fixed' } });",
      "  };",
      "}",
      "",
    ].join("\n"),
    "src/items.ts": [
      "import { Router } from 'express';",
      "const api = Router();",
      "export function readItem() {",
      "  return async (req, res) => {",
      "    const row = await db.query('SELECT ' + req.params.id);",
      "    res.json(row);",
      "  };",
      "}",
      "api.get('/:id', readItem());",
      "export default api;",
      "",
    ].join("\n"),
    "src/owned.ts": [
      "export function loadMine() {",
      "  return async (req, res) => {",
      "    const row = await Basket.findOne({ where: { id: req.user.id } });",
      "    res.json(row);",
      "  };",
      "}",
      "",
    ].join("\n"),
    "src/open.ts": [
      "export function loadRow() {",
      "  return async (req, res) => {",
      "    const id: string = req.params.id;",
      "    const row = await Basket.findOne({ where: { id } });",
      "    res.json(row);",
      "  };",
      "}",
      "",
    ].join("\n"),
    "src/server.ts": [
      "import { search } from './search.js';",
      "import save from './notes.js';",
      "import { saveSafe } from './safe-notes.js';",
      "import items from './items.js';",
      "import { loadMine } from './owned.js';",
      "import { loadRow } from './open.js';",
      "const app = { get() {}, patch() {}, use() {} };",
      "app.get('/rest/search', search());",
      "app.patch('/notes', save());",
      "app.patch('/notes/safe', saveSafe());",
      "app.use('/api/items', items);",
      "app.get('/mine', loadMine());",
      "app.get('/rows/:id', loadRow());",
      "app.get('/live', (req, res) => { db.query('SELECT ' + req.query.name); });",
      "app.get('/fixed', (req, res) => { db.query('SELECT 1'); });",
      "",
    ].join("\n"),
    "src/account.ts": [
      "export class Account {",
      "  public servicePassword = 'HorseBatteryStaple';",
      "}",
      "",
    ].join("\n"),
    "src/sample.ts": [
      "export class Sample {",
      "  public samplePassword = 'changeme';",
      "}",
      "",
    ].join("\n"),
    "infra/network.tf":
      'resource "example" "cert" {\n  private_key = "-----BEGIN RSA PRIVATE KEY-----\\nabc\\n-----END RSA PRIVATE KEY-----"\n}\n',
    "infra/safe.tf": 'resource "example" "cert" {\n  private_key = file("certs/server.key")\n}\n',
  });

  const inventory = await collectInventory(root, { target: root });
  const mounted = inventory.handlers.find((handler) => handler.mountedPath === "/api/items/:id");
  expect(mounted).toMatchObject({
    routeFile: "src/items.ts",
    handlerFile: "src/items.ts",
    route: "GET /:id",
  });
  const search = inventory.handlers.find((handler) => handler.symbol === "search");
  expect(search).toMatchObject({
    routeFile: "src/server.ts",
    handlerFile: "src/search.ts",
    route: "GET /rest/search",
  });

  const plan = await planInjection(root, inventory, 1);
  const fixed = plan.sites.find((site) => site.route === "GET /fixed");
  expect(plan.sites.filter((site) => !site.overCap)).toHaveLength(1);
  expect(plan.sites.find((site) => !site.overCap)?.risk).toBe("tainted");
  expect(fixed).toMatchObject({ risk: "constant", overCap: true });
  expect(plan.sites.some((site) => site.risk === "tainted" && site.overCap)).toBe(true);
  const searched = plan.sites.find((site) => site.file === "src/search.ts");
  expect(searched).toMatchObject({
    risk: "tainted",
    route: "GET /rest/search",
    routeFile: "src/server.ts",
    inputs: ["query"],
  });
  const unsafeUpdate = plan.sites.find((site) => site.file === "src/notes.ts");
  expect(unsafeUpdate).toMatchObject({ kind: "nosql", risk: "tainted", symbol: "update" });
  expect(
    plan.sites.some((site) => site.file === "src/safe-notes.ts" && site.risk === "tainted"),
  ).toBe(false);

  const marks = new Map<string, { status: string; reason: string }>();
  const candidates = await injectionHunter.run({
    root,
    target: root,
    inventory,
    maxSites: 4,
    markCoverage(id, status, reason) {
      marks.set(id, { status, reason });
    },
  });
  expect(candidates.some((candidate) => candidate.location.file === "src/search.ts")).toBe(true);
  expect(candidates.some((candidate) => candidate.location.file === "src/notes.ts")).toBe(true);
  expect(candidates.some((candidate) => candidate.location.file === "src/safe-notes.ts")).toBe(
    false,
  );
  expect(candidates.some((candidate) => candidate.root_cause.includes("GET /fixed"))).toBe(false);
  const fixedRoute = inventory.routes.find((route) => route.note === "GET /fixed");
  expect(fixedRoute).toBeDefined();
  if (fixedRoute !== undefined) {
    expect(marks.get(routeCoverageId(fixedRoute, "injection"))?.reason).toContain("budget");
  }

  const authz = await planAuthz(root, inventory);
  expect(
    authz.handlers.some((handler) => handler.file === "src/open.ts" && !handler.ownershipCheck),
  ).toBe(true);
  expect(
    authz.handlers.some((handler) => handler.file === "src/owned.ts" && !handler.ownershipCheck),
  ).toBe(false);

  const secrets = await planSecrets(root, inventory);
  expect(
    secrets.sites.some(
      (site) => site.file === "src/account.ts" && site.symbol === "servicePassword",
    ),
  ).toBe(true);
  expect(
    secrets.sites.some((site) => site.file === "infra/network.tf" && site.kind === "private-key"),
  ).toBe(true);
  expect(secrets.sites.some((site) => site.file === "src/sample.ts")).toBe(false);
  expect(secrets.sites.some((site) => site.file === "infra/safe.tf")).toBe(false);
});
