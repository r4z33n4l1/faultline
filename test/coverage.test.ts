import { expect, it } from "vitest";
import { buildCoverage, PENDING_REASON } from "../src/recon/coverage.js";
import { collectInventory } from "../src/recon/inventory.js";
import {
  COVERAGE_CLASSES,
  coverageFileSchema,
  coverageUnitSchema,
} from "../src/schema/coverage.js";
import { fixtureSecret, reconFixture } from "./recon-fixture.js";

it("builds a pending ledger for every source file and route", async () => {
  const inventory = await collectInventory(reconFixture, { target: "test/fixtures/recon-app" });
  const coverage = buildCoverage(inventory.target, inventory);
  expect(coverageFileSchema.parse(coverage)).toEqual(coverage);
  expect(coverage.units).toHaveLength(
    (inventory.source_files.length + inventory.routes.length) * COVERAGE_CLASSES.length,
  );
  expect(
    coverage.units.every((unit) => unit.status === "pending" && unit.reason === PENDING_REASON),
  ).toBe(true);

  for (const path of inventory.source_files) {
    for (const bug of COVERAGE_CLASSES) {
      expect(coverage.units).toContainEqual({
        id: `file:${path}:${bug}`,
        kind: "file",
        path,
        class: bug,
        status: "pending",
        reason: PENDING_REASON,
      });
    }
  }
  for (const route of inventory.routes) {
    for (const bug of COVERAGE_CLASSES) {
      expect(coverage.units).toContainEqual({
        id: `route:${route.path}:${route.line}:${route.note}:${bug}`,
        kind: "route",
        path: route.path,
        route: route.note,
        line: route.line,
        class: bug,
        status: "pending",
        reason: PENDING_REASON,
      });
    }
  }

  const blob = JSON.stringify(coverage);
  expect(blob).not.toContain(fixtureSecret());
  expect(blob).not.toContain("FAULTLINE_DUMMY_SECRET");
  const ids = coverage.units.map((unit) => unit.id);
  expect(ids).toEqual([...ids].sort());
});

it("accepts hunted and skipped rows and rejects a bad ledger", () => {
  const fileUnit = {
    id: "file:a.ts:secrets",
    kind: "file",
    path: "a.ts",
    class: "secrets",
    status: "pending",
    reason: PENDING_REASON,
  };
  expect(coverageUnitSchema.parse(fileUnit)).toEqual(fileUnit);
  expect(
    coverageUnitSchema.parse({ ...fileUnit, status: "hunted", reason: "hunter finished" }).status,
  ).toBe("hunted");
  expect(
    coverageUnitSchema.parse({ ...fileUnit, status: "skipped", reason: "out of scope" }).status,
  ).toBe("skipped");
  expect(coverageUnitSchema.safeParse({ ...fileUnit, status: "open" }).success).toBe(false);
  expect(coverageUnitSchema.safeParse({ ...fileUnit, extra: true }).success).toBe(false);
  expect(coverageUnitSchema.safeParse({ ...fileUnit, route: "GET /" }).success).toBe(false);
  expect(coverageUnitSchema.safeParse({ ...fileUnit, reason: "" }).success).toBe(false);

  const routeUnit = {
    id: "route:a.ts:3:GET /:ssrf",
    kind: "route",
    path: "a.ts",
    route: "GET /",
    line: 3,
    class: "ssrf",
    status: "pending",
    reason: PENDING_REASON,
  };
  expect(coverageUnitSchema.parse(routeUnit).kind).toBe("route");
  expect(
    coverageUnitSchema.safeParse({
      id: routeUnit.id,
      kind: "route",
      path: routeUnit.path,
      line: routeUnit.line,
      class: routeUnit.class,
      status: routeUnit.status,
      reason: routeUnit.reason,
    }).success,
  ).toBe(false);
  expect(coverageUnitSchema.safeParse({ ...routeUnit, line: 0 }).success).toBe(false);

  const file = coverageFileSchema.parse({
    schema_version: "1",
    target: ".",
    units: [fileUnit, routeUnit],
    skipped: [{ path: "frontend/src/assets/logo.png", reason: "default-exclude" }],
  });
  expect(file.units).toHaveLength(2);
  expect(file.skipped).toEqual([
    { path: "frontend/src/assets/logo.png", reason: "default-exclude" },
  ]);
  expect(coverageFileSchema.safeParse({ ...file, extra: true }).success).toBe(false);
  expect(
    coverageFileSchema.safeParse({ schema_version: "1", target: ".", units: [fileUnit] }).success,
  ).toBe(false);
  expect(coverageFileSchema.safeParse({ ...file, skipped: [{ path: "a.ts" }] }).success).toBe(
    false,
  );
});
