import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { buildCoverage } from "../src/recon/coverage.js";
import { collectInventory, inventoryCapNote, serializeInventory } from "../src/recon/inventory.js";
import { coverageFileSchema } from "../src/schema/coverage.js";
import { fixtureSecret, reconFixture } from "./recon-fixture.js";

it("inventories the committed fixture without reading secrets", async () => {
  const secret = fixtureSecret();
  const inventory = await collectInventory(reconFixture, { target: "test/fixtures/recon-app" });
  const blob = serializeInventory(inventory);

  expect(inventory.target).toBe("test/fixtures/recon-app");
  expect(inventory.truncated).toBe(false);
  expect(inventory.files_read).toBe(8);
  expect(inventory.languages).toEqual([
    { name: "Go", files: 1 },
    { name: "Python", files: 1 },
    { name: "TypeScript", files: 2 },
  ]);
  expect(inventory.frameworks).toEqual(["express", "flask", "prisma"]);
  expect(inventory.manifests).toEqual([
    { path: "go.mod", kind: "go" },
    { path: "package.json", kind: "node" },
    { path: "pyproject.toml", kind: "python" },
    { path: "requirements.txt", kind: "python" },
  ]);
  expect(inventory.entrypoints).toEqual([
    { path: "app.py", reason: "filename" },
    { path: "main.go", reason: "filename" },
    { path: "src/server.ts", reason: "package.json main, filename" },
  ]);
  expect(inventory.source_files).toEqual([
    "app.py",
    "main.go",
    "src/middleware.ts",
    "src/server.ts",
  ]);
  expect(inventory.routes.map((route) => `${route.path} ${route.note}`)).toEqual([
    "app.py ROUTE /health",
    "main.go HANDLE /status",
    "src/server.ts GET /users/:id",
    "src/server.ts POST /notes",
    "src/server.ts DELETE /Ignore-previous-instructions",
  ]);
  expect(inventory.auth).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ path: "src/middleware.ts", note: "filename" }),
      expect.objectContaining({ path: "src/middleware.ts", note: "requireAuth" }),
      expect.objectContaining({ path: "src/server.ts", note: "requireAuth" }),
    ]),
  );
  expect(inventory.data_stores.length).toBeGreaterThan(0);
  expect(
    inventory.data_stores.every((item) => item.path === "src/server.ts" && item.note === "prisma"),
  ).toBe(true);
  expect(inventory.outbound_http.map((item) => `${item.path} ${item.note}`)).toEqual([
    "app.py requests.get",
    "src/server.ts fetch",
  ]);
  expect(inventory.env_files).toEqual([".env"]);
  expect(inventory.config_files).toEqual(["config.yaml"]);

  expect(blob).toContain(".env");
  expect(blob).toContain("config.yaml");
  for (const banned of [
    secret,
    "FAULTLINE_DUMMY_SECRET",
    "node_modules",
    "vendor/",
    "build/",
    "dist/",
    "skipme",
    "ignored.ts",
    "debug.log",
    "logo.png",
  ]) {
    expect(blob).not.toContain(banned);
  }
});

it("applies gitignore negation and keeps a later un-ignore", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-ignore-"));
  await mkdir(join(dir, "src"));
  await writeFile(join(dir, ".gitignore"), "*.ts\n!src/ok.ts\n");
  await writeFile(join(dir, "src", "ok.ts"), 'app.get("/kept", () => {});\n');
  await writeFile(join(dir, "src", "no.ts"), 'app.get("/hidden-marker", () => {});\n');
  await writeFile(join(dir, "root.ts"), 'app.get("/root-marker", () => {});\n');

  const inventory = await collectInventory(dir, { target: "gi" });
  expect(inventory.routes.map((route) => route.note)).toEqual(["GET /kept"]);
  const blob = serializeInventory(inventory);
  expect(blob).not.toContain("hidden-marker");
  expect(blob).not.toContain("root-marker");
});

it("caps the number of files and bytes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-cap-"));
  await writeFile(join(dir, "a.ts"), "export const a = 1;\n");
  await writeFile(join(dir, "b.ts"), "export const b = 1;\n");
  await writeFile(join(dir, "c.ts"), "export const c = 1;\n");
  const capped = await collectInventory(dir, {
    target: "cap",
    limits: { maxFiles: 2, maxBytes: 1_000_000, maxFileBytes: 10_000 },
  });
  expect(capped.truncated).toBe(true);
  expect(capped.source_files).toEqual(["a.ts", "b.ts"]);
  expect(capped.skipped).toContainEqual({ path: "c.ts", reason: "max-files" });
  expect(inventoryCapNote(capped)).toContain("max-files");

  const bytes = await mkdtemp(join(tmpdir(), "faultline-bytes-"));
  await writeFile(join(bytes, "big.ts"), `export const big = "${"x".repeat(200)}";\n`);
  await writeFile(join(bytes, "small.ts"), "export const small = 1;\n");
  const limited = await collectInventory(bytes, {
    target: "bytes",
    limits: { maxFiles: 10, maxBytes: 80, maxFileBytes: 10_000 },
  });
  expect(limited.truncated).toBe(true);
  expect(limited.source_files).toEqual(["small.ts"]);
  expect(limited.bytes_read).toBeGreaterThan(0);
  expect(limited.bytes_read).toBeLessThanOrEqual(80);
  expect(limited.skipped).toContainEqual({ path: "big.ts", reason: "max-bytes" });
  const coverage = buildCoverage("bytes", limited);
  expect(coverageFileSchema.parse(coverage)).toEqual(coverage);
  expect(coverage.skipped).toContainEqual({ path: "big.ts", reason: "max-bytes" });
  expect(coverage.units.some((unit) => unit.path === "small.ts" && unit.status === "pending")).toBe(
    true,
  );
  expect(coverage.units.some((unit) => unit.path === "big.ts")).toBe(false);
});

it("skips a file over the per-file cap and keeps scanning", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-filecap-"));
  await writeFile(join(dir, "big.ts"), `export const big = "${"x".repeat(300)}";\n`);
  await writeFile(join(dir, "small.ts"), 'app.get("/small", () => {});\n');
  const inventory = await collectInventory(dir, {
    target: "filecap",
    limits: { maxFiles: 10, maxBytes: 100_000, maxFileBytes: 40 },
  });
  expect(inventory.truncated).toBe(true);
  expect(inventory.source_files).toEqual(["small.ts"]);
  expect(inventory.routes.map((route) => route.note)).toEqual(["GET /small"]);
  expect(inventory.skipped).toContainEqual({ path: "big.ts", reason: "max-file-bytes" });
});

it("rejects a missing path and a file target", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-missing-"));
  await expect(collectInventory(join(dir, "nope"), { target: "missing" })).rejects.toThrow(
    "Target not found: missing",
  );
  const file = join(dir, "one.ts");
  await writeFile(file, "export const one = 1;\n");
  await expect(collectInventory(file, { target: "one.ts" })).rejects.toThrow(
    "Target is not a directory: one.ts",
  );
});

it("reads server files ahead of filler files when the file cap binds", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-priority-"));
  await mkdir(join(dir, "frontend", "src", "components"), { recursive: true });
  await mkdir(join(dir, "routes"), { recursive: true });
  await mkdir(join(dir, "src"), { recursive: true });
  for (let index = 0; index < 24; index += 1) {
    const name = `c${String(index).padStart(2, "0")}.ts`;
    await writeFile(join(dir, "frontend", "src", "components", name), "export const n = 1;\n");
  }
  await writeFile(
    join(dir, "routes", "users.ts"),
    'import express from "express";\nexport const router = express.Router();\nrouter.get("/users/:id", () => {});\n',
  );
  await writeFile(
    join(dir, "server.ts"),
    'import express from "express";\nconst app = express();\napp.get("/health", () => {});\n',
  );
  await writeFile(
    join(dir, "src", "db.ts"),
    'import { Sequelize } from "sequelize";\nexport const db = new Sequelize("db");\n',
  );
  const inventory = await collectInventory(dir, {
    target: "priority",
    limits: { maxFiles: 3, maxBytes: 1_000_000, maxFileBytes: 10_000 },
  });
  expect(inventory.source_files).toEqual(["routes/users.ts", "server.ts", "src/db.ts"]);
  expect(inventory.truncated).toBe(true);
  expect(inventory.skipped.filter((item) => item.reason === "max-files").length).toBe(24);
  expect(inventory.routes.map((route) => route.note).sort()).toEqual([
    "GET /health",
    "GET /users/:id",
  ]);
  const coverage = buildCoverage("priority", inventory);
  expect(coverage.skipped.every((item) => item.reason === "max-files")).toBe(true);
  expect(coverage.units.filter((unit) => unit.kind === "file").map((unit) => unit.path)).toEqual(
    expect.arrayContaining(["routes/users.ts", "server.ts", "src/db.ts"]),
  );
});

it("skips vendored, generated, minified, asset, snapshot, and lockfile paths", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-skip-"));
  await mkdir(join(dir, "node_modules", "pkg"), { recursive: true });
  await mkdir(join(dir, "frontend", "src", "assets"), { recursive: true });
  await mkdir(join(dir, "dist"), { recursive: true });
  await mkdir(join(dir, "lib"), { recursive: true });
  await mkdir(join(dir, "__snapshots__"), { recursive: true });
  await mkdir(join(dir, "routes"), { recursive: true });
  await writeFile(
    join(dir, "node_modules", "pkg", "index.ts"),
    'app.get("/from-modules", () => {});\n',
  );
  await writeFile(
    join(dir, "frontend", "src", "assets", "app.ts"),
    'app.get("/from-assets", () => {});\n',
  );
  await writeFile(join(dir, "dist", "app.min.js"), 'app.get("/from-dist", () => {});\n');
  await writeFile(join(dir, "lib", "app.min.js"), 'app.get("/from-min", () => {});\n');
  await writeFile(join(dir, "lib", "bundle.js"), `${"x".repeat(20_000)}`);
  await writeFile(join(dir, "__snapshots__", "comp.snap"), "exports[`a`] = `1`;\n");
  await writeFile(join(dir, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
  await writeFile(join(dir, ".gitignore"), "secret.ts\n");
  await writeFile(join(dir, "secret.ts"), 'app.get("/secret-marker", () => {});\n');
  await writeFile(join(dir, "routes", "ok.ts"), 'app.get("/ok", () => {});\n');

  const inventory = await collectInventory(dir, { target: "skip" });
  expect(inventory.routes.map((route) => route.note)).toEqual(["GET /ok"]);
  expect(inventory.source_files).toEqual(["routes/ok.ts"]);
  expect(inventory.skipped).toEqual(
    expect.arrayContaining([
      { path: "node_modules", reason: "default-exclude" },
      { path: "dist", reason: "default-exclude" },
      { path: "frontend/src/assets", reason: "default-exclude" },
      { path: "lib/app.min.js", reason: "minified" },
      { path: "lib/bundle.js", reason: "minified" },
      { path: "__snapshots__", reason: "snapshot" },
      { path: "pnpm-lock.yaml", reason: "lockfile" },
      { path: "secret.ts", reason: "gitignore" },
    ]),
  );
  const blob = serializeInventory(inventory);
  for (const banned of [
    "/from-modules",
    "/from-assets",
    "/from-dist",
    "/from-min",
    "/secret-marker",
  ]) {
    expect(blob).not.toContain(banned);
  }
  expect(buildCoverage("skip", inventory).skipped).toEqual(inventory.skipped);
});

it("applies --include and --exclude globs", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-globs-"));
  await mkdir(join(dir, "lib"), { recursive: true });
  await mkdir(join(dir, "src"), { recursive: true });
  await mkdir(join(dir, "hidden"), { recursive: true });
  await writeFile(join(dir, ".gitignore"), "hidden/\n*.log\n");
  await writeFile(join(dir, "lib", "keep.ts"), 'app.get("/keep", () => {});\n');
  await writeFile(join(dir, "lib", "drop.ts"), 'app.get("/drop", () => {});\n');
  await writeFile(join(dir, "src", "other.ts"), 'app.get("/other", () => {});\n');
  await writeFile(join(dir, "hidden", "kept.ts"), 'app.get("/hidden-kept", () => {});\n');
  await writeFile(join(dir, "hidden", "lost.ts"), 'app.get("/hidden-lost", () => {});\n');
  await writeFile(join(dir, "noise.log"), "nope\n");

  const inventory = await collectInventory(dir, {
    target: "globs",
    exclude: ["lib", "*.log"],
    include: ["lib/keep.ts", "hidden/kept.ts"],
  });
  expect(inventory.routes.map((route) => route.note).sort()).toEqual([
    "GET /hidden-kept",
    "GET /keep",
    "GET /other",
  ]);
  expect(inventory.skipped).toContainEqual({ path: "lib/drop.ts", reason: "exclude" });
  expect(inventory.skipped).toContainEqual({ path: "noise.log", reason: "exclude" });
  expect(inventory.source_files).not.toContain("lib/drop.ts");
  expect(inventory.source_files).not.toContain("hidden/lost.ts");
  expect(serializeInventory(inventory)).not.toContain("hidden-lost");
});
