import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { runCli, type CliIo } from "../src/cli.js";
import { providerUnavailableMessage, resolveProviderConfig } from "../src/providers/config.js";
import { FakeProvider } from "../src/providers/types.js";
import { sarifLogSchema } from "../src/sarif.js";
import { candidatesFileSchema } from "../src/schema/candidate.js";
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
    "candidates.json",
    "architecture.md",
    "coverage.json",
  ] as const;
  const files: Record<string, string> = {};
  for (const name of names) {
    files[name] = await readFile(join(dir, name), "utf8");
  }
  return files;
}

it("scan writes recon output from FakeProvider and never emits the fixture secret", async () => {
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
  const authz = coverage.units.filter((unit) => unit.class === "authz_idor");
  const injection = coverage.units.filter((unit) => unit.class === "injection");
  const secrets = coverage.units.filter((unit) => unit.class === "secrets");
  const ssrf = coverage.units.filter((unit) => unit.class === "ssrf");
  expect(authz.length).toBeGreaterThan(0);
  expect(authz.every((unit) => unit.status === "skipped")).toBe(true);
  expect(injection.length).toBeGreaterThan(0);
  expect(injection.every((unit) => unit.status === "skipped")).toBe(true);
  expect(secrets.length).toBeGreaterThan(0);
  expect(secrets.every((unit) => unit.status === "skipped")).toBe(true);
  expect(ssrf.every((unit) => unit.status === "skipped")).toBe(true);
  const candidates = candidatesFileSchema.parse(
    JSON.parse(files["candidates.json"] ?? "") as unknown,
  );
  expect(candidates.candidates.map((candidate) => candidate.location.file)).toEqual([".env"]);
  expect(candidates.candidates[0]).toMatchObject({
    class: "secrets",
    cwe: "CWE-312",
    symbol: "env",
    location: { file: ".env", start_line: 1 },
  });
  expect(candidates.run.id).toBe(findings.run.id);
  expect(files["report.md"]).toContain("unvalidated candidates: 1, not reported as findings");

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
  expect(captured.stdout()).toContain("candidates.json");
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
  const missingMessage = providerUnavailableMessage(missing);
  expect(missingMessage).toBe('Provider "openai" requires FAULTLINE_API_KEY.');
  expect(missingMessage).not.toContain(key);

  const flagged = resolveProviderConfig("  unknown-vendor  ", {
    FAULTLINE_PROVIDER: "openai",
    FAULTLINE_API_KEY: key,
  });
  expect(flagged).toEqual({ name: "unknown-vendor", apiKey: key });
  const flaggedMessage = providerUnavailableMessage(flagged);
  expect(flaggedMessage).toBe('No model adapter is configured for provider "unknown-vendor".');
  expect(flaggedMessage).not.toContain(key);
  expect(resolveProviderConfig("  ", { FAULTLINE_PROVIDER: "openai" }).name).toBe("openai");

  const ready = resolveProviderConfig("openai", { FAULTLINE_API_KEY: key });
  expect(ready).toEqual({ name: "openai", apiKey: key });
  expect(providerUnavailableMessage(ready)).toBeUndefined();
});

it("scan exits before writing when the provider name has no adapter", async () => {
  const key = "super-secret-key-not-for-logs";
  const dir = await outDir();
  const originalFetch = globalThis.fetch;
  let fetched = false;
  const failingFetch: typeof fetch = async () => {
    fetched = true;
    throw new Error("network disabled");
  };
  globalThis.fetch = failingFetch;
  try {
    const fromFlag = capture({
      FAULTLINE_PROVIDER: "from-env",
      FAULTLINE_API_KEY: key,
    });
    expect(
      await runCli(
        ["scan", reconFixture, "--out", dir, "--provider", "unknown-vendor"],
        fromFlag.io,
      ),
    ).toBe(1);
    expect(fromFlag.stderr()).toContain(
      'No model adapter is configured for provider "unknown-vendor".',
    );
    expect(fromFlag.stderr()).not.toContain("from-env");
    expect(fromFlag.stderr()).not.toContain(key);
    expect(fromFlag.stdout()).not.toContain(key);
    await expect(readFile(join(dir, "architecture.md"), "utf8")).rejects.toThrow();

    const fromEnv = capture({ FAULTLINE_PROVIDER: "openai" });
    expect(await runCli(["scan", reconFixture, "--out", dir], fromEnv.io)).toBe(1);
    expect(fromEnv.stderr()).toContain('Provider "openai" requires FAULTLINE_API_KEY.');
    expect(fromEnv.stdout()).toBe("");
    expect(fetched).toBe(false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

it("scan writes the openai architecture summary and keeps the API key out of output", async () => {
  const key = "sk-scan-wiring-secret-value";
  const secret = fixtureSecret();
  const dir = await outDir();
  const originalFetch = globalThis.fetch;
  const calls: { url: string; headers: Headers; body: unknown }[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    calls.push({
      url: String(input),
      headers: new Headers(init?.headers),
      body: JSON.parse(String(init?.body ?? "{}")) as unknown,
    });
    return Response.json({
      choices: [{ message: { role: "assistant", content: "## Trust boundaries\nThe edge." } }],
    });
  };
  globalThis.fetch = fetchImpl;
  try {
    const captured = capture({
      FAULTLINE_API_KEY: key,
      FAULTLINE_BASE_URL: "http://127.0.0.1:11434/v1/",
    });
    expect(
      await runCli(
        ["scan", reconFixture, "--out", dir, "--provider", "openai", "--model", "local-model"],
        captured.io,
      ),
    ).toBe(0);
    const files = await readOutputs(dir);
    const architecture = files["architecture.md"] ?? "";
    expect(architecture).toContain("Model summary from provider `openai`.");
    expect(architecture).toContain("## Trust boundaries");
    expect(architecture).toContain("The edge.");
    const findings = findingsFileSchema.parse(JSON.parse(files["findings.json"] ?? "") as unknown);
    expect(findings.run.provider).toBe("openai");
    const dumped = [captured.stdout(), captured.stderr(), ...Object.values(files)].join("\n");
    expect(dumped).not.toContain(key);
    expect(dumped).not.toContain(secret);
    expect(captured.stderr()).toBe("");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("http://127.0.0.1:11434/v1/chat/completions");
    expect(calls[0]?.headers.get("authorization")).toBe(`Bearer ${key}`);
    const body = calls[0]?.body as {
      model?: string;
      messages?: { role: string; content: string }[];
    };
    expect(body.model).toBe("local-model");
    expect(body.messages?.[0]?.content).toContain("untrusted repository data");
    expect(JSON.stringify(body)).not.toContain(key);
    expect(JSON.stringify(body)).not.toContain(secret);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
