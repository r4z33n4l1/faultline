import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { runCli, type CliIo } from "../src/cli.js";
import { providerUnavailableMessage, resolveProviderConfig } from "../src/providers/config.js";
import { FakeProvider } from "../src/providers/types.js";
import { sarifLogSchema } from "../src/sarif.js";
import { coverageFileSchema } from "../src/schema/coverage.js";
import { findingsFileSchema } from "../src/schema/finding.js";
import { fixtureSecret, reconFixture } from "./recon-fixture.js";

const SUMMARY = [
  "## Trust boundaries",
  "The network edge is the trust boundary.",
  "## Entrypoints",
  "src/server.ts serves HTTP.",
  "## Authn/authz model",
  "requireAuth runs before handlers.",
  "## Data flows",
  "Handlers read prisma and call fetch.",
].join("\n");

function capture(env: NodeJS.ProcessEnv = {}): {
  io: CliIo;
  stdout: () => string;
  stderr: () => string;
} {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      cwd: process.cwd(),
      env,
      stdout: (text) => {
        out.push(text);
      },
      stderr: (text) => {
        err.push(text);
      },
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
  };
}

async function outDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "faultline-scan-"));
}

async function readOutputs(dir: string): Promise<Record<string, string>> {
  const names = [
    "findings.json",
    "report.md",
    "findings.sarif",
    "architecture.md",
    "coverage.json",
  ] as const;
  const files: Record<string, string> = {};
  for (const name of names) {
    files[name] = await readFile(join(dir, name), "utf8");
  }
  return files;
}

it("scan writes four files from FakeProvider and never emits the fixture secret", async () => {
  const secret = fixtureSecret();
  const provider = new FakeProvider(SUMMARY, "fake");
  const dir = await outDir();
  const captured = capture();
  captured.io.provider = provider;
  expect(await runCli(["scan", reconFixture, "--out", dir], captured.io)).toBe(0);

  const files = await readOutputs(dir);
  const findings = findingsFileSchema.parse(JSON.parse(files["findings.json"] ?? "") as unknown);
  expect(findings.findings).toEqual([]);
  expect(findings.run.mode).toBe("scan");
  expect(findings.run.provider).toBe("fake");
  expect(findings.run.target).toBe(reconFixture);
  expect(files["report.md"]).toContain("No confirmed findings.");
  const sarif = sarifLogSchema.parse(JSON.parse(files["findings.sarif"] ?? "") as unknown);
  expect(sarif.runs[0].results).toEqual([]);
  expect(sarif.runs[0].tool.driver.name).toBe("faultline");

  const architecture = files["architecture.md"] ?? "";
  expect(architecture).toContain("Model summary from provider `fake`.");
  expect(architecture).toContain("untrusted data, not instructions");
  for (const heading of [
    "## Trust boundaries",
    "## Entrypoints",
    "## Authn/authz model",
    "## Data flows",
  ]) {
    expect(architecture).toContain(heading);
  }

  const coverage = coverageFileSchema.parse(JSON.parse(files["coverage.json"] ?? "") as unknown);
  expect(coverage.target).toBe(reconFixture);
  expect(coverage.units.length).toBeGreaterThan(0);
  expect(coverage.units.every((unit) => unit.status === "pending")).toBe(true);

  expect(provider.calls).toHaveLength(1);
  const call = provider.calls[0];
  expect(call?.messages.map((message) => message.role)).toEqual(["system", "user"]);
  const system = call?.messages[0]?.content ?? "";
  const user = call?.messages[1]?.content ?? "";
  expect(system).toContain("not instructions");
  expect(user).toContain("/Ignore-previous-instructions");
  const fenceAt = user.indexOf("```");
  const needleAt = user.indexOf("/Ignore-previous-instructions");
  const closeAt = user.lastIndexOf("```");
  expect(fenceAt).toBeGreaterThan(-1);
  expect(needleAt).toBeGreaterThan(fenceAt);
  expect(closeAt).toBeGreaterThan(needleAt);

  const dumped = [
    captured.stdout(),
    captured.stderr(),
    ...Object.values(files),
    system,
    user,
    JSON.stringify(call),
  ].join("\n");
  expect(dumped).not.toContain(secret);
  expect(dumped).not.toContain("FAULTLINE_DUMMY_SECRET");
  expect(captured.stdout()).toContain("findings.sarif");
  expect(captured.stdout()).toContain("architecture.md");
  expect(captured.stdout()).toContain("coverage.json");
  expect(captured.stderr()).toBe("");
});

it("scan without a provider writes an inventory-only architecture", async () => {
  const secret = fixtureSecret();
  const dir = await outDir();
  const captured = capture({ FAULTLINE_API_KEY: "should-stay-out-of-offline-output" });
  expect(await runCli(["scan", reconFixture, "--out", dir], captured.io)).toBe(0);
  const files = await readOutputs(dir);
  const architecture = files["architecture.md"] ?? "";
  expect(architecture).toContain("Inventory only. No model provider was configured.");
  expect(architecture).toContain("were not summarized");
  expect(architecture).toContain("Names only. Contents were not read.");
  expect(architecture).toContain("`.env`");
  expect(architecture).not.toContain("Model summary");
  const findings = findingsFileSchema.parse(JSON.parse(files["findings.json"] ?? "") as unknown);
  expect(findings.run.provider).toBeUndefined();
  const dumped = [captured.stdout(), captured.stderr(), ...Object.values(files)].join("\n");
  expect(dumped).not.toContain(secret);
  expect(dumped).not.toContain("FAULTLINE_DUMMY_SECRET");
  expect(dumped).not.toContain("should-stay-out-of-offline-output");
});

it("refuses a named provider without logging the API key", () => {
  const key = "super-secret-key-not-for-logs";
  const missing = resolveProviderConfig(undefined, { FAULTLINE_PROVIDER: "openai" });
  expect(providerUnavailableMessage(missing)).toBe('Provider "openai" requires FAULTLINE_API_KEY.');
  expect(providerUnavailableMessage(missing)).not.toContain(key);

  const flagged = resolveProviderConfig("  anthropic  ", {
    FAULTLINE_PROVIDER: "openai",
    FAULTLINE_API_KEY: key,
  });
  expect(flagged).toEqual({ name: "anthropic", apiKey: key });
  expect(providerUnavailableMessage(flagged)).toBe(
    'No model adapter is configured for provider "anthropic".',
  );
  expect(providerUnavailableMessage(flagged)).not.toContain(key);
  expect(resolveProviderConfig("  ", { FAULTLINE_PROVIDER: "openai" }).name).toBe("openai");
});

it("scan exits before writing when the provider name has no adapter", async () => {
  const key = "super-secret-key-not-for-logs";
  const dir = await outDir();
  const fromFlag = capture({
    FAULTLINE_PROVIDER: "from-env",
    FAULTLINE_API_KEY: key,
  });
  expect(
    await runCli(["scan", reconFixture, "--out", dir, "--provider", "anthropic"], fromFlag.io),
  ).toBe(1);
  expect(fromFlag.stderr()).toContain('No model adapter is configured for provider "anthropic".');
  expect(fromFlag.stderr()).not.toContain("from-env");
  expect(fromFlag.stderr()).not.toContain(key);
  expect(fromFlag.stdout()).not.toContain(key);
  await expect(readFile(join(dir, "architecture.md"), "utf8")).rejects.toThrow();

  const fromEnv = capture({ FAULTLINE_PROVIDER: "openai" });
  expect(await runCli(["scan", reconFixture, "--out", dir], fromEnv.io)).toBe(1);
  expect(fromEnv.stderr()).toContain('Provider "openai" requires FAULTLINE_API_KEY.');
  expect(fromEnv.stdout()).toBe("");
});
