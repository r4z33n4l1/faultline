import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { collectInventory, serializeInventory } from "../src/recon/inventory.js";
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

  const bytes = await mkdtemp(join(tmpdir(), "faultline-bytes-"));
  await writeFile(join(bytes, "big.ts"), `export const big = "${"x".repeat(200)}";\n`);
  await writeFile(join(bytes, "small.ts"), "export const small = 1;\n");
  const limited = await collectInventory(bytes, {
    target: "bytes",
    limits: { maxFiles: 10, maxBytes: 80, maxFileBytes: 10_000 },
  });
  expect(limited.truncated).toBe(true);
  expect(limited.source_files).toEqual([]);
  expect(limited.bytes_read).toBe(0);
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
