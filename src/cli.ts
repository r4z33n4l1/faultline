#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Command, CommanderError, Option } from "commander";
import { executeBench, recordedModel } from "./bench/run.js";
import type { BenchStage } from "./bench/result.js";
import {
  assertDiffWithinLimit,
  githubPullRequestMessage,
  parseHunkContext,
  parseUnifiedDiff,
} from "./pr/diff.js";
import { executePr } from "./pr/run.js";
import { providerUnavailableMessage, resolveProviderConfig } from "./providers/config.js";
import { createProvider } from "./providers/registry.js";
import type { ModelProvider } from "./providers/types.js";
import { executeScan } from "./recon/run.js";
import { findingsFileSchema, formatZodIssues } from "./schema/finding.js";
import { TOOL_VERSION } from "./version.js";

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** Test seam. When set, the CLI uses this provider instead of constructing one. */
  provider?: ModelProvider;
  /** Test seam for `pr -`. When omitted, `-` reads process.stdin. */
  stdin?: string;
}

const defaultIo: CliIo = {
  stdout: (text) => {
    process.stdout.write(text);
  },
  stderr: (text) => {
    process.stderr.write(text);
  },
};

function messageOf(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

async function validateFile(filePath: string, io: CliIo): Promise<number> {
  let text: string;
  try {
    text = await readFile(filePath, "utf8");
  } catch (error) {
    io.stderr(`Cannot read file: ${messageOf(error)}\n`);
    return 1;
  }

  let json: unknown;
  try {
    json = JSON.parse(text) as unknown;
  } catch (error) {
    io.stderr(`Invalid JSON: ${messageOf(error)}\n`);
    return 1;
  }

  const parsed = findingsFileSchema.safeParse(json);
  if (!parsed.success) {
    io.stderr(`${formatZodIssues(parsed.error)}\n`);
    return 1;
  }

  const count = parsed.data.findings.length;
  const noun = count === 1 ? "finding" : "findings";
  io.stdout(`OK ${filePath} (${count} ${noun})\n`);
  return 0;
}

function wroteLine(outDir: string, names: readonly string[]): string {
  const paths = names.map((name) => resolve(outDir, name));
  if (paths.length < 2) {
    return `Wrote ${paths.join("")}\n`;
  }
  const last = paths[paths.length - 1];
  return `Wrote ${paths.slice(0, -1).join(", ")} and ${last}\n`;
}

const RUN_OUTPUTS = [
  "findings.json",
  "report.md",
  "findings.sarif",
  "candidates.json",
  "architecture.md",
  "coverage.json",
] as const;

async function openProvider(
  providerFlag: string | undefined,
  modelFlag: string | undefined,
  io: CliIo,
): Promise<ModelProvider | undefined> {
  if (io.provider !== undefined) {
    return io.provider;
  }
  const env = io.env ?? process.env;
  const config = resolveProviderConfig(providerFlag, env, modelFlag);
  if (config.name === undefined) {
    return undefined;
  }
  const blocked = providerUnavailableMessage(config);
  if (blocked !== undefined) {
    throw new Error(blocked);
  }
  return createProvider(config.name, {
    apiKey: config.apiKey,
    model: config.model,
    baseUrl: config.baseUrl,
  });
}

async function readDiffText(source: string, io: CliIo): Promise<string> {
  if (source === "-") {
    if (io.stdin !== undefined) {
      assertDiffWithinLimit(Buffer.byteLength(io.stdin, "utf8"));
      return io.stdin;
    }
    return readStdinBounded();
  }
  const cwd = io.cwd ?? process.cwd();
  const abs = resolve(cwd, source);
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    info = await stat(abs);
  } catch (error) {
    throw new Error(`Cannot read diff: ${messageOf(error)}`, { cause: error });
  }
  if (!info.isFile()) {
    throw new Error(`Diff path is not a file: ${source}`);
  }
  assertDiffWithinLimit(info.size);
  return readFile(abs, "utf8");
}

async function readStdinBounded(): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    assertDiffWithinLimit(total);
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function runScan(
  target: string,
  out: string,
  providerFlag: string | undefined,
  modelFlag: string | undefined,
  io: CliIo,
  validate = true,
): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const outDir = resolve(cwd, out);
  let provider: ModelProvider | undefined;
  try {
    provider = await openProvider(providerFlag, modelFlag, io);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  try {
    await executeScan({
      target,
      cwd,
      outDir,
      provider,
      validate,
    });
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  io.stdout(wroteLine(outDir, RUN_OUTPUTS));
  return 0;
}

function isBenchStage(value: string): value is BenchStage {
  return value === "candidates" || value === "findings";
}

async function runBench(
  target: string,
  out: string,
  stage: string,
  truthFlag: string | undefined,
  providerFlag: string | undefined,
  modelFlag: string | undefined,
  io: CliIo,
): Promise<number> {
  if (!isBenchStage(stage)) {
    io.stderr("stage must be candidates or findings\n");
    return 1;
  }
  const cwd = io.cwd ?? process.cwd();
  const env = io.env ?? process.env;
  const config = resolveProviderConfig(providerFlag, env, modelFlag);
  const outDir = resolve(cwd, out);
  let provider: ModelProvider | undefined;
  try {
    provider = await openProvider(providerFlag, modelFlag, io);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  const providerName = provider?.name ?? config.name;
  const model = recordedModel({
    ...(providerName === undefined ? {} : { name: providerName }),
    ...(config.model === undefined ? {} : { model: config.model }),
  });
  const truthPath = truthFlag ?? join(target, "truth.json");
  try {
    await executeBench({
      target,
      cwd,
      outDir,
      stage,
      truthPath,
      model,
      ...(provider === undefined ? {} : { provider }),
    });
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  io.stdout(wroteLine(outDir, ["bench-result.json", "bench-result.md"]));
  return 0;
}

async function runPr(
  source: string,
  out: string,
  repo: string,
  contextFlag: string,
  providerFlag: string | undefined,
  modelFlag: string | undefined,
  io: CliIo,
  validate = true,
): Promise<number> {
  const github = githubPullRequestMessage(source);
  if (github !== undefined) {
    io.stderr(`${github}\n`);
    return 1;
  }
  let context: number;
  try {
    context = parseHunkContext(contextFlag);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  const cwd = io.cwd ?? process.cwd();
  const outDir = resolve(cwd, out);
  const repoRoot = resolve(cwd, repo);
  let diffText: string;
  try {
    diffText = await readDiffText(source, io);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  let parsed: ReturnType<typeof parseUnifiedDiff>;
  try {
    parsed = parseUnifiedDiff(diffText);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  let provider: ModelProvider | undefined;
  try {
    provider = await openProvider(providerFlag, modelFlag, io);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  try {
    const info = await stat(repoRoot);
    if (!info.isDirectory()) {
      io.stderr(`Repository path is not a directory: ${repo}\n`);
      return 1;
    }
  } catch (error) {
    io.stderr(`Cannot read repository: ${messageOf(error)}\n`);
    return 1;
  }
  try {
    await executePr({
      diffLabel: source,
      repo: repoRoot,
      repoLabel: repo,
      outDir,
      parsed,
      context,
      provider,
      validate,
    });
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  io.stdout(wroteLine(outDir, RUN_OUTPUTS));
  return 0;
}

export async function runCli(argv: string[], io: CliIo = defaultIo): Promise<number> {
  let code = 0;
  const program = new Command();
  program
    .name("faultline")
    .description("Security-detector CLI for startup engineering teams")
    .version(TOOL_VERSION);
  program.exitOverride();
  program.configureOutput({
    writeOut: (text) => {
      io.stdout(text);
    },
    writeErr: (text) => {
      io.stderr(text);
    },
  });

  program
    .command("validate")
    .description("Validate a findings JSON file")
    .argument("<findings>", "path to findings.json")
    .action(async (file: string) => {
      code = await validateFile(resolve(io.cwd ?? process.cwd(), file), io);
    });

  program
    .command("scan")
    .option("--no-validate", "skip validation and write candidates only")
    .description(
      "Inventory a directory, hunt authz/IDOR, injection, secrets, and SSRF candidates, and write findings, report, SARIF, candidates, architecture, and coverage",
    )
    .argument("<path>", "target directory")
    .option("-o, --out <dir>", "output directory", "./faultline-out")
    .option("--provider <name>", "model provider name (overrides FAULTLINE_PROVIDER)")
    .option("--model <id>", "model id (overrides FAULTLINE_MODEL)")
    .action(
      async (
        target: string,
        opts: { out: string; provider?: string; model?: string; validate: boolean },
      ) => {
        code = await runScan(target, opts.out, opts.provider, opts.model, io, opts.validate);
      },
    );

  program
    .command("bench")
    .description(
      "Scan a directory and score candidates or findings against truth.json. Findings stage runs validation",
    )
    .argument("<dir>", "directory that contains the app and, by default, truth.json")
    .option("-o, --out <dir>", "output directory", "./faultline-bench")
    .addOption(
      new Option("--stage <stage>", "score candidates.json or findings.json")
        .choices(["candidates", "findings"])
        .default("candidates"),
    )
    .option("--truth <file>", "truth file (default <dir>/truth.json)")
    .option("--provider <name>", "model provider name (overrides FAULTLINE_PROVIDER)")
    .option("--model <id>", "model id (overrides FAULTLINE_MODEL)")
    .action(
      async (
        target: string,
        opts: { out: string; stage: string; truth?: string; provider?: string; model?: string },
      ) => {
        code = await runBench(
          target,
          opts.out,
          opts.stage,
          opts.truth,
          opts.provider,
          opts.model,
          io,
        );
      },
    );

  program
    .command("pr")
    .option("--no-validate", "skip validation and write candidates only")
    .description(
      "Hunt changed lines in a unified diff and write findings, report, SARIF, candidates, architecture, and coverage",
    )
    .argument("<diff>", "unified diff file, or - to read stdin")
    .option("-o, --out <dir>", "output directory", "./faultline-out")
    .option("--repo <path>", "repository root after the change", ".")
    .option("--context <lines>", "lines of context around each changed hunk", "3")
    .option("--provider <name>", "model provider name (overrides FAULTLINE_PROVIDER)")
    .option("--model <id>", "model id (overrides FAULTLINE_MODEL)")
    .action(
      async (
        source: string,
        opts: {
          out: string;
          repo: string;
          context: string;
          provider?: string;
          model?: string;
          validate: boolean;
        },
      ) => {
        code = await runPr(
          source,
          opts.out,
          opts.repo,
          opts.context,
          opts.provider,
          opts.model,
          io,
          opts.validate,
        );
      },
    );

  try {
    await program.parseAsync(argv, { from: "user" });
  } catch (error) {
    if (error instanceof CommanderError) {
      return error.exitCode;
    }
    throw error;
  }
  return code;
}

/** True when this module is the process entry, including a symlink on `bin`. */
export function isCliEntrypoint(argvPath: string | undefined, moduleUrl: string): boolean {
  if (argvPath === undefined) {
    return false;
  }
  let resolved = argvPath;
  try {
    resolved = realpathSync(argvPath);
  } catch {
    // A missing path is compared as given.
  }
  return moduleUrl === pathToFileURL(resolved).href;
}

const entry = process.argv[1];
if (isCliEntrypoint(entry, import.meta.url)) {
  const code = await runCli(process.argv.slice(2));
  process.exit(code);
}
