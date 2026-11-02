#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Command, CommanderError, Option } from "commander";
import { ensureCorpusCache, resolveCorpusPaths } from "./bench/corpus.js";
import { executeSarifBench, executeSemgrepBench } from "./bench/external.js";
import { loadCorpusManifest } from "./bench/manifest.js";
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
import type { CollectOptions, InventoryLimits } from "./recon/inventory.js";
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

function appendGlob(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function parsePositiveInt(flag: string, value: string): number {
  if (!/^[1-9]\d*$/.test(value)) {
    throw new Error(`${flag} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return parsed;
}

interface InventoryFlagInput {
  include?: string[];
  exclude?: string[];
  maxFiles?: string;
  maxBytes?: string;
  maxSites?: string;
  discoveryBudget?: string;
}

function selectionFromFlags(opts: InventoryFlagInput): CollectOptions {
  const limits: Partial<InventoryLimits> = {};
  if (opts.maxFiles !== undefined) {
    limits.maxFiles = parsePositiveInt("--max-files", opts.maxFiles);
  }
  if (opts.maxBytes !== undefined) {
    limits.maxBytes = parsePositiveInt("--max-bytes", opts.maxBytes);
  }
  return {
    ...(opts.include === undefined || opts.include.length === 0 ? {} : { include: opts.include }),
    ...(opts.exclude === undefined || opts.exclude.length === 0 ? {} : { exclude: opts.exclude }),
    ...(opts.maxFiles === undefined && opts.maxBytes === undefined ? {} : { limits }),
  };
}

function addInventoryOptions(command: Command): Command {
  return command
    .option(
      "--include <glob>",
      "re-include a path skipped by a default exclude, gitignore, or --exclude",
      appendGlob,
      [] as string[],
    )
    .option("--exclude <glob>", "skip paths matching this glob", appendGlob, [] as string[])
    .option("--max-files <count>", "maximum source and manifest files to read")
    .option("--max-bytes <count>", "maximum bytes of source and manifests to read")
    .option(
      "--max-sites <count>",
      "maximum sites each hunter reviews, highest risk first (default 40)",
    )
    .option(
      "--discovery-budget <count>",
      "maximum model calls for discovery, before hunters (default 60)",
    );
}

function maxSitesFrom(value: string | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  return parsePositiveInt("--max-sites", value);
}

function discoveryBudgetFrom(value: string | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  return parsePositiveInt("--discovery-budget", value);
}

function exitForProviderErrors(count: number, io: CliIo): number {
  if (count === 0) {
    return 0;
  }
  const noun = count === 1 ? "provider error" : "provider errors";
  io.stderr(`${count} ${noun}. The run failed. See findings.json, report.md, and coverage.json.\n`);
  return 1;
}

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
    codexEnv: env,
    ...(config.codexBin === undefined ? {} : { codexBin: config.codexBin }),
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
  inventory: CollectOptions,
  io: CliIo,
  validate = true,
  keepInconclusive = false,
  maxSites?: number,
  discoveryBudget?: number,
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
    const scan = await executeScan({
      target,
      cwd,
      outDir,
      provider,
      validate,
      keepInconclusive,
      inventory,
      ...(maxSites === undefined ? {} : { maxSites }),
      ...(discoveryBudget === undefined ? {} : { discoveryBudget }),
    });
    io.stdout(wroteLine(outDir, RUN_OUTPUTS));
    return exitForProviderErrors(scan.providerErrors, io);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
}

function isBenchStage(value: string): value is BenchStage {
  return value === "candidates" || value === "findings";
}

async function runCorpus(
  name: string,
  out: string,
  stage: string,
  cacheOnly: boolean,
  baseline: string | undefined,
  sarif: string | undefined,
  toolName: string | undefined,
  toolVersion: string | undefined,
  manifestFlag: string,
  providerFlag: string | undefined,
  modelFlag: string | undefined,
  inventory: CollectOptions,
  io: CliIo,
  keepInconclusive = false,
  maxSites?: number,
  discoveryBudget?: number,
): Promise<number> {
  if (!isBenchStage(stage)) {
    io.stderr("stage must be candidates or findings\n");
    return 1;
  }
  if (baseline !== undefined && sarif !== undefined) {
    io.stderr("Pass either --baseline or --sarif\n");
    return 1;
  }
  if (baseline !== undefined && baseline !== "semgrep") {
    io.stderr("baseline must be semgrep\n");
    return 1;
  }
  const external = baseline !== undefined || sarif !== undefined;
  if (external && stage === "findings") {
    io.stderr("An imported static tool has no findings stage\n");
    return 1;
  }
  if (external && (providerFlag !== undefined || modelFlag !== undefined)) {
    io.stderr("An imported static tool does not take a provider\n");
    return 1;
  }
  const cwd = io.cwd ?? process.cwd();
  const env = io.env ?? process.env;
  let paths: Awaited<ReturnType<typeof resolveCorpusPaths>>;
  try {
    paths = await resolveCorpusPaths(cwd, manifestFlag, name);
    await ensureCorpusCache(paths, cacheOnly);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  const outDir = resolve(cwd, out);
  if (sarif !== undefined) {
    if (toolName === undefined || toolVersion === undefined) {
      io.stderr("Scoring SARIF requires --tool-name and --tool-version\n");
      return 1;
    }
    try {
      await executeSarifBench({
        root: paths.cacheDir,
        targetLabel: paths.targetLabel,
        truthPath: paths.truthPath,
        truthLabel: paths.truthLabel,
        outDir,
        cwd,
        tool: { name: toolName, version: toolVersion },
        sarifPath: sarif,
      });
    } catch (error) {
      io.stderr(`${messageOf(error)}\n`);
      return 1;
    }
    io.stdout(wroteLine(outDir, ["bench-result.json", "bench-result.md"]));
    return 0;
  }
  if (baseline === "semgrep") {
    let manifest: Awaited<ReturnType<typeof loadCorpusManifest>>;
    try {
      manifest = await loadCorpusManifest(paths.manifestPath);
      await executeSemgrepBench({
        root: paths.cacheDir,
        targetLabel: paths.targetLabel,
        truthPath: paths.truthPath,
        truthLabel: paths.truthLabel,
        outDir,
        cwd,
        tool: { name: "semgrep", version: manifest.semgrep.version },
        bin: env.SEMGREP_BIN ?? "semgrep",
        expectedVersion: manifest.semgrep.version,
        rulesets: manifest.semgrep.rulesets,
      });
    } catch (error) {
      io.stderr(`${messageOf(error)}\n`);
      return 1;
    }
    io.stdout(wroteLine(outDir, ["bench-result.json", "bench-result.md"]));
    return 0;
  }
  const config = resolveProviderConfig(providerFlag, env, modelFlag);
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
  try {
    const result = await executeBench({
      target: paths.targetLabel,
      cwd,
      outDir,
      stage,
      truthPath: paths.truthLabel,
      model,
      inventory,
      keepInconclusive,
      ...(maxSites === undefined ? {} : { maxSites }),
      ...(discoveryBudget === undefined ? {} : { discoveryBudget }),
      ...(provider === undefined ? {} : { provider }),
    });
    io.stdout(wroteLine(outDir, ["bench-result.json", "bench-result.md"]));
    return exitForProviderErrors(result.run.provider_error_count, io);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
}

async function runBench(
  target: string,
  out: string,
  stage: string,
  truthFlag: string | undefined,
  providerFlag: string | undefined,
  modelFlag: string | undefined,
  inventory: CollectOptions,
  io: CliIo,
  keepInconclusive = false,
  maxSites?: number,
  discoveryBudget?: number,
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
    const result = await executeBench({
      target,
      cwd,
      outDir,
      stage,
      truthPath,
      model,
      inventory,
      keepInconclusive,
      ...(maxSites === undefined ? {} : { maxSites }),
      ...(discoveryBudget === undefined ? {} : { discoveryBudget }),
      ...(provider === undefined ? {} : { provider }),
    });
    io.stdout(wroteLine(outDir, ["bench-result.json", "bench-result.md"]));
    return exitForProviderErrors(result.run.provider_error_count, io);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
}

async function runPr(
  source: string,
  out: string,
  repo: string,
  contextFlag: string,
  providerFlag: string | undefined,
  modelFlag: string | undefined,
  inventory: CollectOptions,
  io: CliIo,
  validate = true,
  keepInconclusive = false,
  maxSites?: number,
  discoveryBudget?: number,
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
    const pr = await executePr({
      diffLabel: source,
      repo: repoRoot,
      repoLabel: repo,
      outDir,
      parsed,
      context,
      provider,
      validate,
      keepInconclusive,
      inventory,
      ...(maxSites === undefined ? {} : { maxSites }),
      ...(discoveryBudget === undefined ? {} : { discoveryBudget }),
    });
    io.stdout(wroteLine(outDir, RUN_OUTPUTS));
    return exitForProviderErrors(pr.providerErrors, io);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
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
    .option(
      "--keep-inconclusive",
      "promote inconclusive candidates to low-confidence findings (default: drop them)",
    )
    .description(
      "Inventory a directory, hunt authz/IDOR, injection, secrets, and SSRF candidates, and write findings, report, SARIF, candidates, architecture, and coverage",
    )
    .argument("<path>", "target directory")
    .option("-o, --out <dir>", "output directory", "./faultline-out")
    .option("--provider <name>", "model provider name (overrides FAULTLINE_PROVIDER)")
    .option("--model <id>", "model id (overrides FAULTLINE_MODEL)");
  addInventoryOptions(program.commands[program.commands.length - 1] ?? program).action(
    async (
      target: string,
      opts: {
        out: string;
        provider?: string;
        model?: string;
        validate: boolean;
        keepInconclusive?: boolean;
      } & InventoryFlagInput,
    ) => {
      let inventory: CollectOptions;
      let maxSites: number | undefined;
      let discoveryBudget: number | undefined;
      try {
        inventory = selectionFromFlags(opts);
        maxSites = maxSitesFrom(opts.maxSites);
        discoveryBudget = discoveryBudgetFrom(opts.discoveryBudget);
      } catch (error) {
        io.stderr(`${messageOf(error)}\n`);
        code = 1;
        return;
      }
      code = await runScan(
        target,
        opts.out,
        opts.provider,
        opts.model,
        inventory,
        io,
        opts.validate,
        opts.keepInconclusive === true,
        maxSites,
        discoveryBudget,
      );
    },
  );

  program
    .command("bench")
    .description(
      "Scan a directory and score candidates or findings against truth.json. Findings stage runs validation. --corpus checks out a pinned public training app into a gitignored cache and scores that tree",
    )
    .argument("[dir]", "directory that contains the app and, by default, truth.json")
    .option("-o, --out <dir>", "output directory", "./faultline-bench")
    .addOption(
      new Option("--stage <stage>", "score candidates.json or findings.json")
        .choices(["candidates", "findings"])
        .default("candidates"),
    )
    .option("--truth <file>", "truth file (default <dir>/truth.json)")
    .option("--provider <name>", "model provider name (overrides FAULTLINE_PROVIDER)")
    .option("--model <id>", "model id (overrides FAULTLINE_MODEL)")
    .option("--corpus <name>", "pinned app in bench/corpus/manifest.json")
    .option("--manifest <file>", "corpus manifest", "bench/corpus/manifest.json")
    .option("--cache-only", "do not clone; require the pinned cache")
    .option("--baseline <tool>", "score Semgrep OSS instead of a Faultline scan")
    .option("--sarif <file>", "score a SARIF file with the shared importer; does not run a tool")
    .option("--tool-name <name>", "tool name recorded for --sarif")
    .option("--tool-version <version>", "tool version recorded for --sarif")
    .option(
      "--keep-inconclusive",
      "when --stage findings, promote inconclusive candidates to low-confidence findings",
    );
  addInventoryOptions(program.commands[program.commands.length - 1] ?? program).action(
    async (
      target: string | undefined,
      opts: {
        out: string;
        stage: string;
        truth?: string;
        provider?: string;
        model?: string;
        corpus?: string;
        manifest: string;
        cacheOnly?: boolean;
        baseline?: string;
        sarif?: string;
        toolName?: string;
        toolVersion?: string;
        keepInconclusive?: boolean;
      } & InventoryFlagInput,
    ) => {
      let inventory: CollectOptions;
      let maxSites: number | undefined;
      let discoveryBudget: number | undefined;
      try {
        inventory = selectionFromFlags(opts);
        maxSites = maxSitesFrom(opts.maxSites);
        discoveryBudget = discoveryBudgetFrom(opts.discoveryBudget);
      } catch (error) {
        io.stderr(`${messageOf(error)}\n`);
        code = 1;
        return;
      }
      if (opts.corpus !== undefined && target !== undefined) {
        io.stderr("Pass a directory or --corpus, not both\n");
        code = 1;
        return;
      }
      if (opts.corpus !== undefined) {
        code = await runCorpus(
          opts.corpus,
          opts.out,
          opts.stage,
          opts.cacheOnly === true,
          opts.baseline,
          opts.sarif,
          opts.toolName,
          opts.toolVersion,
          opts.manifest,
          opts.provider,
          opts.model,
          inventory,
          io,
          opts.keepInconclusive === true,
          maxSites,
          discoveryBudget,
        );
        return;
      }
      if (target === undefined) {
        io.stderr("Pass a directory or --corpus <name>\n");
        code = 1;
        return;
      }
      if (opts.baseline !== undefined || opts.sarif !== undefined || opts.cacheOnly === true) {
        io.stderr("--baseline, --sarif, and --cache-only require --corpus\n");
        code = 1;
        return;
      }
      code = await runBench(
        target,
        opts.out,
        opts.stage,
        opts.truth,
        opts.provider,
        opts.model,
        inventory,
        io,
        opts.keepInconclusive === true,
        maxSites,
        discoveryBudget,
      );
    },
  );

  program
    .command("pr")
    .option("--no-validate", "skip validation and write candidates only")
    .option(
      "--keep-inconclusive",
      "promote inconclusive candidates to low-confidence findings (default: drop them)",
    )
    .description(
      "Hunt changed lines in a unified diff and write findings, report, SARIF, candidates, architecture, and coverage",
    )
    .argument("<diff>", "unified diff file, or - to read stdin")
    .option("-o, --out <dir>", "output directory", "./faultline-out")
    .option("--repo <path>", "repository root after the change", ".")
    .option("--context <lines>", "lines of context around each changed hunk", "3")
    .option("--provider <name>", "model provider name (overrides FAULTLINE_PROVIDER)")
    .option("--model <id>", "model id (overrides FAULTLINE_MODEL)");
  addInventoryOptions(program.commands[program.commands.length - 1] ?? program).action(
    async (
      source: string,
      opts: {
        out: string;
        repo: string;
        context: string;
        provider?: string;
        model?: string;
        validate: boolean;
        keepInconclusive?: boolean;
      } & InventoryFlagInput,
    ) => {
      let inventory: CollectOptions;
      let maxSites: number | undefined;
      let discoveryBudget: number | undefined;
      try {
        inventory = selectionFromFlags(opts);
        maxSites = maxSitesFrom(opts.maxSites);
        discoveryBudget = discoveryBudgetFrom(opts.discoveryBudget);
      } catch (error) {
        io.stderr(`${messageOf(error)}\n`);
        code = 1;
        return;
      }
      code = await runPr(
        source,
        opts.out,
        opts.repo,
        opts.context,
        opts.provider,
        opts.model,
        inventory,
        io,
        opts.validate,
        opts.keepInconclusive === true,
        maxSites,
        discoveryBudget,
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
