import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const fixturePath = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "valid-findings.json",
);

export function loadFixtureText(): string {
  return readFileSync(fixturePath, "utf8");
}

export function loadFixture(): unknown {
  return JSON.parse(loadFixtureText()) as unknown;
}

type JsonObject = { [key: string]: unknown };

function asObject(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as JsonObject;
}

export function cloneFixture(): JsonObject {
  return asObject(loadFixture(), "fixture");
}

export function firstFinding(file: JsonObject): JsonObject {
  const findings = file.findings;
  if (!Array.isArray(findings) || findings.length === 0) {
    throw new Error("fixture has no findings");
  }
  return asObject(findings[0], "finding");
}
