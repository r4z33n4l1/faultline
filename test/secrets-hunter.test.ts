import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runCli, type CliIo } from "../src/cli.js";
import { fenceData } from "../src/recon/architecture.js";
import { fileCoverageId, routeCoverageId } from "../src/recon/coverage.js";
import { collectInventory } from "../src/recon/inventory.js";
import {
  FILE_HUNTED_REASON,
  FILE_SKIPPED_REASON,
  KNOWN_FORMAT_CONFIDENCE_REASON,
  REDACTION_MARKER,
  SECRETS_SITE_CAP,
  SECRETS_SITE_MAX_CHARS,
  SKIP_CAP,
  SKIP_ROUTE,
  SKIP_TEST,
  buildSecretsPrompt,
  planSecrets,
  secretFingerprint,
  secretsHunter,
} from "../src/hunters/secrets.js";
import { HEURISTIC_CONFIDENCE_REASON } from "../src/hunters/shared.js";
import { FakeProvider, type CompleteInput } from "../src/providers/types.js";
import { candidatesFileSchema, candidateSchema } from "../src/schema/candidate.js";
import { coverageFileSchema } from "../src/schema/coverage.js";
import { findingsFileSchema } from "../src/schema/finding.js";
import { sarifLogSchema } from "../src/sarif.js";

const secretsFixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "secrets-app");

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const JWT = "n0t-a-real-jwt-signing-k";
const API_KEY = "q7w8e9r0t1y2u3i4o5p6";
const PASSWORD = "not-a-real-password-value";
const PEM_BODY = "pem-body-do-not-leak-4c91";
const PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
const CONFIG_KEY = "m5n6b7v8c9x0z1l2k3j4hg8";
const FIXTURE_SECRETS = [AWS_KEY, JWT, API_KEY, PASSWORD, PEM_BODY, PEM_HEADER, CONFIG_KEY];

function expectAbsent(text: string, extra: readonly string[] = []): void {
  for (const secret of [...FIXTURE_SECRETS, ...extra]) {
    expect(text).not.toContain(secret);
  }
}

function joinedParts(parts: readonly string[]): string {
  return parts.join("");
}

function githubToken(): string {
  return joinedParts(["gh", "p_"]) + "a".repeat(36);
}

function stripeLiveKey(): string {
  return joinedParts(["sk", "_li", "ve_"]) + "b".repeat(24);
}

function slackToken(): string {
  return joinedParts(["xo", "xb-"]) + "1".repeat(10) + "-" + "2".repeat(12);
}

function googleKey(): string {
  return joinedParts(["AI", "za"]) + "a1".repeat(17) + "b";
}

async function envSentinel(): Promise<string> {
  const text = await readFile(join(secretsFixture, ".env"), "utf8");
  const match = /^SENTINEL_DO_NOT_READ=(.*)$/m.exec(text);
  const secret = match?.[1]?.trim();
  if (secret === undefined || secret.length < 8) {
    throw new Error("secrets fixture .env is missing SENTINEL_DO_NOT_READ");
  }
  return secret;
}

function capture(): { io: CliIo; stdout: () => string; stderr: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      cwd: process.cwd(),
      env: {},
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

function modelCandidate(
  rootCause: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    class: "secrets",
    cwe: "CWE-798",
    severity: "high",
    confidence: { level: "medium", reason: "model suggestion, not validated" },
    location: { file: "src/app.ts", start_line: 1 },
    symbol: "awsAccessKeyId",
    root_cause: rootCause,
    evidence: [{ file: "src/app.ts", line: 1, note: "cited assignment" }],
    ...extra,
  };
}

async function writeProject(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(root, rel);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, text, "utf8");
  }
}

function fingerprintOf(value: string): string {
  const hash = createHash("sha256").update(value, "utf8").digest("hex").slice(0, 8);
  return `${value.slice(0, 4)} len=${value.length} sha256=${hash}`;
}

describe("secrets pre-pass", () => {
  it("selects known formats, entropy, logs, and env names, and skips safe files", async () => {
    const sentinel = await envSentinel();
    const inventory = await collectInventory(secretsFixture, { target: "secrets-app" });
    const plan = await planSecrets(secretsFixture, inventory);
    expect(plan.sites.map((site) => `${site.file}:${site.kind}:${site.symbol}`)).toEqual([
      "config.yaml:high-entropy-assignment:apiKey",
      "src/app.ts:aws-access-key:awsAccessKeyId",
      "src/app.ts:jwt-signing-secret:jwtSecret",
      "src/app.ts:high-entropy-assignment:apiKey",
      "src/app.ts:logged-secret:console.log",
      "src/app.ts:private-key:privateKey",
    ]);
    expect(plan.sites.every((site) => !site.overCap)).toBe(true);
    expect(plan.envSites.map((site) => site.file)).toEqual([".env"]);
    expect(plan.files.has(".env")).toBe(false);
    expect(plan.files.has(".env.example")).toBe(false);
    expect(plan.files.has("test/skipped.ts")).toBe(false);
    expect(plan.files.has("pnpm-lock.yaml")).toBe(false);
    expect([...plan.files.keys()].sort()).toEqual(["config.yaml", "src/app.ts", "src/safe.ts"]);

    const redacted = [...plan.files.values()].join("\n");
    expectAbsent(redacted, [sentinel]);
    expect(redacted).toContain(REDACTION_MARKER);
    expect(redacted).toContain("awsAccessKeyId");
    expect(redacted).toContain("BANANA");

    const aws = plan.sites.find((site) => site.kind === "aws-access-key");
    expect(aws?.knownFormat).toBe(true);
    expect(aws?.cwe).toBe("CWE-798");
    expect(aws?.fingerprint).toBe(secretFingerprint(AWS_KEY));
    expect(aws?.source).toContain(REDACTION_MARKER);
    expect(aws?.source).toContain("BANANA");
  });
});

describe("secrets candidates", () => {
  it("emits heuristic candidates without raw values and updates coverage", async () => {
    const sentinel = await envSentinel();
    const inventory = await collectInventory(secretsFixture, { target: "secrets-app" });
    const marks = new Map<string, { status: string; reason: string }>();
    const candidates = await secretsHunter.run({
      root: secretsFixture,
      target: "secrets-app",
      inventory,
      markCoverage(id, status, reason) {
        marks.set(id, { status, reason });
      },
    });

    expect(candidates.map((candidate) => `${candidate.location.file}:${candidate.cwe}`)).toEqual([
      ".env:CWE-312",
      "config.yaml:CWE-798",
      "src/app.ts:CWE-798",
      "src/app.ts:CWE-798",
      "src/app.ts:CWE-798",
      "src/app.ts:CWE-532",
      "src/app.ts:CWE-798",
    ]);
    expect(candidates.map((candidate) => candidate.confidence.level)).toEqual([
      "low",
      "low",
      "medium",
      "low",
      "low",
      "low",
      "medium",
    ]);
    const dumped = JSON.stringify(candidates);
    expectAbsent(dumped, [sentinel, "SENTINEL_DO_NOT_READ"]);
    expect(dumped).not.toContain("validator_verdict");
    expect(dumped).toContain(fingerprintOf(AWS_KEY));
    expect(dumped).toContain(fingerprintOf(CONFIG_KEY));
    expect(secretFingerprint(AWS_KEY)).toBe(fingerprintOf(AWS_KEY));
    expect(secretFingerprint(AWS_KEY)).not.toContain(AWS_KEY);

    for (const candidate of candidates) {
      expect(candidate.class).toBe("secrets");
      expect(candidateSchema.parse(candidate)).toEqual(candidate);
      if (candidate.location.file === ".env") {
        expect(candidate.confidence.reason).toBe(HEURISTIC_CONFIDENCE_REASON);
        expect(candidate.evidence[0]?.note).toContain("name only");
        expect(candidate.symbol).toBe("env");
      } else if (candidate.confidence.level === "medium") {
        expect(candidate.confidence.reason).toBe(KNOWN_FORMAT_CONFIDENCE_REASON);
      } else {
        expect(candidate.confidence.reason).toBe(HEURISTIC_CONFIDENCE_REASON);
      }
    }
    const privateKey = candidates.find((candidate) => candidate.symbol === "privateKey");
    expect(privateKey?.severity).toBe("critical");
    expect(privateKey?.cwe).toBe("CWE-798");

    expect(marks.get(fileCoverageId("src/app.ts", "secrets"))).toEqual({
      status: "hunted",
      reason: FILE_HUNTED_REASON,
    });
    expect(marks.get(fileCoverageId("src/safe.ts", "secrets"))).toEqual({
      status: "skipped",
      reason: FILE_SKIPPED_REASON,
    });
    expect(marks.get(fileCoverageId("test/skipped.ts", "secrets"))).toEqual({
      status: "skipped",
      reason: SKIP_TEST,
    });
    for (const route of inventory.routes) {
      expect(marks.get(routeCoverageId(route, "secrets"))).toEqual({
        status: "skipped",
        reason: SKIP_ROUTE,
      });
    }
    expect(marks.get(fileCoverageId("src/app.ts", "authz_idor"))).toBeUndefined();
  });

  it("scans a test directory when that directory is the scan root", async () => {
    const root = join(secretsFixture, "test");
    const inventory = await collectInventory(root, { target: "test" });
    const candidates = await secretsHunter.run({
      root,
      target: "test",
      inventory,
      markCoverage() {
        // Coverage is asserted on the parent scan.
      },
    });
    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      location: { file: "skipped.ts" },
      symbol: "awsAccessKeyId",
      confidence: { level: "medium", reason: KNOWN_FORMAT_CONFIDENCE_REASON },
    });
    expectAbsent(JSON.stringify(candidates));
  });

  it("does not read env files or lockfiles", async () => {
    const token = githubToken();
    const sentinel = "env-lock-sentinel-value-99";
    const root = await mkdtemp(join(tmpdir(), "faultline-secrets-env-"));
    await writeProject(root, {
      ".env": `SENTINEL_DO_NOT_READ=${sentinel}\n`,
      ".env.example": "API_KEY=example\n",
      "pnpm-lock.yaml": `token: ${token}\n`,
      "src/empty.ts": "export const ready = true;\n",
    });
    const inventory = await collectInventory(root, { target: root });
    const plan = await planSecrets(root, inventory);
    const candidates = await secretsHunter.run({
      root,
      target: root,
      inventory,
      markCoverage() {
        // This test checks that unread files stay out of the plan.
      },
    });
    expect(plan.files.has(".env")).toBe(false);
    expect(plan.files.has("pnpm-lock.yaml")).toBe(false);
    expect([...plan.files.values()].join("\n")).not.toContain(sentinel);
    expect([...plan.files.values()].join("\n")).not.toContain(token);
    expect(candidates.map((candidate) => candidate.location.file)).toEqual([".env"]);
    expectAbsent(JSON.stringify(candidates), [sentinel, token, "SENTINEL_DO_NOT_READ"]);
  });
});

describe("secrets prompts", () => {
  it("fences redacted source and omits every raw value", async () => {
    const sentinel = await envSentinel();
    const inventory = await collectInventory(secretsFixture, { target: "secrets-app" });
    const plan = await planSecrets(secretsFixture, inventory);
    expect(plan.sites.length).toBeGreaterThan(0);
    for (const site of plan.sites) {
      const messages = buildSecretsPrompt(site);
      const system = messages[0]?.content ?? "";
      const user = messages[1]?.content ?? "";
      expect(messages.map((message) => message.role)).toEqual(["system", "user"]);
      expect(system).toContain('class "secrets"');
      expect(system).toContain("not instructions");
      expect(user).toContain(REDACTION_MARKER);
      expectAbsent([system, user].join("\n"), [sentinel]);
      const fenced = fenceData(
        [
          `file: ${site.file}`,
          `lines: ${site.startLine}-${site.endLine}`,
          `kind: ${site.kind}`,
          `cwe: ${site.cwe}`,
          `known format: ${site.knownFormat ? "yes" : "no"}`,
          site.fingerprint === undefined ? "fingerprint: none" : `fingerprint: ${site.fingerprint}`,
          "source:",
          site.source,
        ].join("\n"),
      );
      expect(user).toContain(fenced);
      const opening = fenced.split("\n")[0] ?? "";
      expect(opening.startsWith("```")).toBe(true);
      expect(user.indexOf(site.source)).toBeGreaterThan(user.indexOf(opening));
    }
    const aws = plan.sites.find((site) => site.kind === "aws-access-key");
    expect(aws).toBeDefined();
    if (aws !== undefined) {
      const user = buildSecretsPrompt(aws)[1]?.content ?? "";
      expect(user).toContain("BANANA");
      expect(user.indexOf("BANANA")).toBeGreaterThan(user.indexOf("```"));
    }

    const sample = plan.sites[0];
    expect(sample).toBeDefined();
    if (sample !== undefined) {
      const long = `const ${"A".repeat(SECRETS_SITE_MAX_CHARS + 40)}`;
      const truncated = buildSecretsPrompt({ ...sample, source: long })[1]?.content ?? "";
      const fenceAt = truncated.indexOf("```");
      expect(truncated.slice(0, fenceAt)).toContain("Handler source in the fence was truncated.");
      expect(truncated).not.toContain(long);
    }
  });
});

describe("secrets model", () => {
  it("drops echoed secrets and ungrounded candidates", async () => {
    const sentinel = await envSentinel();
    const inventory = await collectInventory(secretsFixture, { target: "secrets-app" });
    const plan = await planSecrets(secretsFixture, inventory);
    const aws = plan.sites.find((site) => site.kind === "aws-access-key");
    expect(aws).toBeDefined();
    if (aws === undefined) {
      return;
    }
    const provider = new FakeProvider((input: CompleteInput) => {
      const user = input.messages[1]?.content ?? "";
      if (user.includes("kind: aws-access-key")) {
        return JSON.stringify({
          candidates: [
            modelCandidate("INJECTION_DROPPED", { class: "injection" }),
            modelCandidate("ECHO_DROPPED", { root_cause: `leaked ${AWS_KEY}` }),
            modelCandidate("PEM_ECHO_DROPPED", {
              evidence: [{ file: "src/app.ts", line: aws.line, note: PEM_BODY }],
            }),
            modelCandidate("MODEL_AWS", {
              location: { file: aws.file, start_line: aws.line },
              symbol: aws.symbol,
              evidence: [{ file: aws.file, line: aws.line, note: "cited assignment" }],
            }),
            modelCandidate("HALLUCINATED_SYMBOL", { symbol: "notARealSymbol" }),
            modelCandidate("LINE_OUT_OF_RANGE", {
              location: { file: "src/app.ts", start_line: 99999 },
              evidence: [{ file: "src/app.ts", line: 1, note: "cited assignment" }],
            }),
          ],
        });
      }
      if (user.includes("kind: logged-secret")) {
        return JSON.stringify({
          candidates: [
            modelCandidate("LOGGER_ECHO", { root_cause: PASSWORD, symbol: "console.log" }),
          ],
        });
      }
      return '{"candidates":[]}';
    });
    const candidates = await secretsHunter.run({
      root: secretsFixture,
      target: "secrets-app",
      inventory,
      provider,
      markCoverage() {
        // Model filtering is asserted on the returned candidates.
      },
    });
    expect(candidates.map((candidate) => candidate.root_cause)).toEqual([
      "Committed env file .env may store secrets in cleartext",
      "MODEL_AWS",
    ]);
    expect(provider.calls).toHaveLength(plan.sites.length);
    const dumped = [JSON.stringify(candidates), JSON.stringify(provider.calls)].join("\n");
    expectAbsent(dumped, [sentinel, "SENTINEL_DO_NOT_READ"]);
    for (const dropped of [
      "INJECTION_DROPPED",
      "ECHO_DROPPED",
      "PEM_ECHO_DROPPED",
      "HALLUCINATED_SYMBOL",
      "LINE_OUT_OF_RANGE",
      "LOGGER_ECHO",
      "notARealSymbol",
    ]) {
      expect(JSON.stringify(candidates)).not.toContain(dropped);
    }
    expect(
      candidates
        .filter((candidate) => candidate.location.file !== ".env")
        .every((candidate) => candidate.confidence.reason !== HEURISTIC_CONFIDENCE_REASON),
    ).toBe(true);
  });

  it("caps model calls and heuristic candidates", async () => {
    const root = await mkdtemp(join(tmpdir(), "faultline-secrets-cap-"));
    const files: Record<string, string> = {
      ".env": "TOKEN=cap-env-sentinel-value\n",
    };
    for (let index = 0; index < SECRETS_SITE_CAP + 1; index += 1) {
      const name = `f${index.toString().padStart(2, "0")}.ts`;
      files[name] = `export const apiKey = "${API_KEY}";\n`;
    }
    await writeProject(root, files);
    const inventory = await collectInventory(root, { target: root });
    const provider = new FakeProvider('{"candidates":[]}');
    const marks = new Map<string, { status: string; reason: string }>();
    const fromModel = await secretsHunter.run({
      root,
      target: root,
      inventory,
      provider,
      markCoverage(id, status, reason) {
        marks.set(id, { status, reason });
      },
    });
    expect(provider.calls).toHaveLength(SECRETS_SITE_CAP);
    expect(fromModel.map((candidate) => candidate.location.file)).toEqual([".env"]);
    expectAbsent(JSON.stringify(provider.calls));
    expect(marks.get(fileCoverageId("f00.ts", "secrets"))).toEqual({
      status: "hunted",
      reason: FILE_HUNTED_REASON,
    });
    expect(
      marks.get(fileCoverageId(`f${SECRETS_SITE_CAP.toString().padStart(2, "0")}.ts`, "secrets")),
    ).toEqual({
      status: "skipped",
      reason: SKIP_CAP,
    });

    const fromHeuristic = await secretsHunter.run({
      root,
      target: root,
      inventory,
      markCoverage() {
        // Cap status is asserted on the model pass.
      },
    });
    expect(fromHeuristic).toHaveLength(SECRETS_SITE_CAP + 1);
    expect(fromHeuristic[0]?.location.file).toBe(".env");
    expect(fromHeuristic.some((candidate) => candidate.location.file === "f00.ts")).toBe(true);
    expect(
      fromHeuristic.some(
        (candidate) =>
          candidate.location.file === `f${SECRETS_SITE_CAP.toString().padStart(2, "0")}.ts`,
      ),
    ).toBe(false);
    expectAbsent(JSON.stringify(fromHeuristic), ["cap-env-sentinel-value"]);
  });
});

describe("assembled credential formats", () => {
  it("matches cloud, GitHub, Stripe, and Slack shapes without copying them", async () => {
    const github = githubToken();
    const stripe = stripeLiveKey();
    const slack = slackToken();
    const google = googleKey();
    const root = await mkdtemp(join(tmpdir(), "faultline-secrets-formats-"));
    await writeProject(root, {
      "src/keys.ts": [
        `export const githubToken = "${github}";`,
        `export const stripeKey = "${stripe}";`,
        `export const slackToken = "${slack}";`,
        `export const googleKey = "${google}";`,
        'export const testKey = "sk_test_exampleexampleexample";',
        "",
      ].join("\n"),
      "pnpm-lock.yaml": `githubToken: ${github}\n`,
    });
    const inventory = await collectInventory(root, { target: root });
    const plan = await planSecrets(root, inventory);
    expect(plan.files.has("pnpm-lock.yaml")).toBe(false);
    expect(plan.sites.map((site) => site.kind)).toEqual([
      "github-token",
      "stripe-live-key",
      "slack-token",
      "google-api-key",
    ]);
    expect(plan.sites.every((site) => site.knownFormat && site.cwe === "CWE-798")).toBe(true);
    const secrets = [github, stripe, slack, google];
    expectAbsent([...plan.files.values()].join("\n"), secrets);
    for (const site of plan.sites) {
      expectAbsent(
        buildSecretsPrompt(site)
          .map((message) => message.content)
          .join("\n"),
        secrets,
      );
    }

    const provider = new FakeProvider((input: CompleteInput) => {
      const user = input.messages[1]?.content ?? "";
      const site = plan.sites.find((item) => user.includes(`kind: ${item.kind}`));
      if (site === undefined) {
        return '{"candidates":[]}';
      }
      return JSON.stringify({
        candidates: [
          modelCandidate("ECHO", {
            root_cause: secrets.join(" "),
            symbol: site.symbol,
            location: { file: site.file, start_line: site.line },
          }),
          modelCandidate(`MODEL_${site.kind}`, {
            symbol: site.symbol,
            location: { file: site.file, start_line: site.line },
            evidence: [{ file: site.file, line: site.line, note: "cited assignment" }],
          }),
        ],
      });
    });
    const candidates = await secretsHunter.run({
      root,
      target: root,
      inventory,
      provider,
      markCoverage() {
        // Format coverage is not the assertion here.
      },
    });
    expect(candidates.map((candidate) => candidate.root_cause)).toEqual([
      "MODEL_github-token",
      "MODEL_stripe-live-key",
      "MODEL_slack-token",
      "MODEL_google-api-key",
    ]);
    expectAbsent(JSON.stringify(candidates), secrets);
    expectAbsent(JSON.stringify(provider.calls), secrets);

    const offline = await secretsHunter.run({
      root,
      target: root,
      inventory,
      markCoverage() {
        // Offline confidence is asserted below.
      },
    });
    expect(offline).toHaveLength(4);
    expect(offline.every((candidate) => candidate.confidence.level === "medium")).toBe(true);
    expectAbsent(JSON.stringify(offline), secrets);
  });
});

describe("secrets scan output", () => {
  it("writes candidates.json and keeps findings and SARIF empty", async () => {
    const sentinel = await envSentinel();
    const joined = (
      await Promise.all(
        ["src/app.ts", "src/safe.ts", "config.yaml", "package.json", ".env", "pnpm-lock.yaml"].map(
          (rel) => readFile(join(secretsFixture, rel), "utf8"),
        ),
      )
    ).join("\n");
    expect(joined).not.toContain(".listen(");
    expect(joined).not.toContain("exploit");
    const pkg = JSON.parse(await readFile(join(secretsFixture, "package.json"), "utf8")) as {
      scripts?: unknown;
    };
    expect(pkg.scripts).toBeUndefined();

    const dir = await mkdtemp(join(tmpdir(), "faultline-secrets-scan-"));
    const provider = new FakeProvider((input: CompleteInput) => {
      const system = input.messages[0]?.content ?? "";
      if (!system.includes('class "secrets"')) {
        return "## Trust boundaries\nThe edge.\n";
      }
      const user = input.messages[1]?.content ?? "";
      if (user.includes("kind: aws-access-key")) {
        return JSON.stringify({
          candidates: [
            modelCandidate("MODEL_AWS", {
              evidence: [{ file: "src/app.ts", line: 5, note: "cited assignment" }],
            }),
          ],
        });
      }
      return JSON.stringify({
        candidates: [modelCandidate("ECHO", { root_cause: AWS_KEY })],
      });
    });
    const captured = capture();
    captured.io.provider = provider;
    expect(await runCli(["scan", secretsFixture, "--out", dir], captured.io)).toBe(0);

    const findingsText = await readFile(join(dir, "findings.json"), "utf8");
    const sarifText = await readFile(join(dir, "findings.sarif"), "utf8");
    const report = await readFile(join(dir, "report.md"), "utf8");
    const candidatesText = await readFile(join(dir, "candidates.json"), "utf8");
    const architecture = await readFile(join(dir, "architecture.md"), "utf8");
    const coverageText = await readFile(join(dir, "coverage.json"), "utf8");
    const findings = findingsFileSchema.parse(JSON.parse(findingsText) as unknown);
    const sarif = sarifLogSchema.parse(JSON.parse(sarifText) as unknown);
    const candidates = candidatesFileSchema.parse(JSON.parse(candidatesText) as unknown);
    const coverage = coverageFileSchema.parse(JSON.parse(coverageText) as unknown);

    expect(findings.findings).toEqual([]);
    expect(sarif.runs[0]?.results).toEqual([]);
    expect(candidates.run.id).toBe(findings.run.id);
    expect(candidates.candidates.map((candidate) => candidate.root_cause).sort()).toEqual([
      "Committed env file .env may store secrets in cleartext",
      "MODEL_AWS",
    ]);
    expect(report).toContain("unvalidated candidates: 2, not reported as findings");
    expect(report).toContain("No confirmed findings.");
    expect(report).not.toContain("MODEL_AWS");
    expect(report).not.toContain("hardcoded");
    const outputs = [
      findingsText,
      sarifText,
      report,
      candidatesText,
      architecture,
      coverageText,
      captured.stdout(),
      captured.stderr(),
      JSON.stringify(provider.calls),
    ].join("\n");
    expectAbsent(outputs, [sentinel, "SENTINEL_DO_NOT_READ"]);
    expect(captured.stderr()).toBe("");

    const secrets = coverage.units.filter((unit) => unit.class === "secrets");
    const ssrf = coverage.units.filter((unit) => unit.class === "ssrf");
    expect(secrets.some((unit) => unit.status === "hunted")).toBe(true);
    expect(secrets.every((unit) => unit.status === "hunted" || unit.status === "skipped")).toBe(
      true,
    );
    expect(ssrf.every((unit) => unit.status === "skipped")).toBe(true);

    const offline = await mkdtemp(join(tmpdir(), "faultline-secrets-offline-"));
    const offlineIo = capture();
    expect(await runCli(["scan", secretsFixture, "--out", offline], offlineIo.io)).toBe(0);
    const offlineText = await readFile(join(offline, "candidates.json"), "utf8");
    const offlineCandidates = candidatesFileSchema.parse(JSON.parse(offlineText) as unknown);
    const offlineFindings = await readFile(join(offline, "findings.json"), "utf8");
    const offlineSarif = await readFile(join(offline, "findings.sarif"), "utf8");
    const offlineReport = await readFile(join(offline, "report.md"), "utf8");
    const offlineArchitecture = await readFile(join(offline, "architecture.md"), "utf8");
    const offlineCoverage = await readFile(join(offline, "coverage.json"), "utf8");
    expect(offlineCandidates.candidates).toHaveLength(7);
    expect(
      offlineCandidates.candidates.some((candidate) => candidate.confidence.level === "medium"),
    ).toBe(true);
    expect(offlineReport).toContain("unvalidated candidates: 7, not reported as findings");
    expect(offlineReport).not.toContain("high-entropy");
    const offlineDump = [
      offlineText,
      offlineFindings,
      offlineSarif,
      offlineReport,
      offlineArchitecture,
      offlineCoverage,
      offlineIo.stdout(),
      offlineIo.stderr(),
    ].join("\n");
    expectAbsent(offlineDump, [sentinel, "SENTINEL_DO_NOT_READ"]);
    expect(offlineFindings).not.toContain("CWE-798");
    expect(offlineSarif).not.toContain("CWE-532");
  });
});
