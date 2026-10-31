#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Command, CommanderError } from "commander";
import { writeRunOutput } from "./output.js";
import { runPipeline } from "./pipeline.js";
import { providerUnavailableMessage, resolveProviderConfig } from "./providers/config.js";
import { createProvider } from "./providers/registry.js";
import type { ModelProvider } from "./providers/types.js";
import { executeScan } from "./recon/run.js";
import { findingsFileSchema, formatZodIssues, type RunMode } from "./schema/finding.js";
import { TOOL_VERSION } from "./version.js";

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** Test seam. When set, the CLI uses this provider instead of constructing one. */
  provider?: ModelProvider;
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

async function runStub(mode: RunMode, target: string, out: string, io: CliIo): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const outDir = resolve(cwd, out);
  try {
    const file = runPipeline({ mode, target });
    await writeRunOutput(outDir, file, { scanRoot: resolve(cwd) });
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  io.stdout(wroteLine(outDir, ["findings.json", "report.md", "findings.sarif"]));
  return 0;
}

async function runScan(
  target: string,
  out: string,
  providerFlag: string | undefined,
  modelFlag: string | undefined,
  io: CliIo,
): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const env = io.env ?? process.env;
  const outDir = resolve(cwd, out);
  const config = resolveProviderConfig(providerFlag, env, modelFlag);
  let provider = io.provider;
  if (provider === undefined && config.name !== undefined) {
    const blocked = providerUnavailableMessage(config);
    if (blocked !== undefined) {
      io.stderr(`${blocked}\n`);
      return 1;
    }
    try {
      provider = createProvider(config.name, {
        apiKey: config.apiKey,
        model: config.model,
        baseUrl: config.baseUrl,
      });
    } catch (error) {
      io.stderr(`${messageOf(error)}\n`);
      return 1;
    }
  }
  try {
    await executeScan({
      target,
      cwd,
      outDir,
      provider,
    });
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  io.stdout(
    wroteLine(outDir, [
      "findings.json",
      "report.md",
      "findings.sarif",
      "architecture.md",
      "coverage.json",
    ]),
  );
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
    .description(
      "Inventory a directory and write findings, report, SARIF, architecture, and coverage",
    )
    .argument("<path>", "target directory")
    .option("-o, --out <dir>", "output directory", "./faultline-out")
    .option("--provider <name>", "model provider name (overrides FAULTLINE_PROVIDER)")
    .option("--model <id>", "model id (overrides FAULTLINE_MODEL)")
    .action(async (target: string, opts: { out: string; provider?: string; model?: string }) => {
      code = await runScan(target, opts.out, opts.provider, opts.model, io);
    });

  program
    .command("pr")
    .description("Run an empty pull-request pipeline and write findings, report, and SARIF")
    .argument("<url-or-diff>", "pull request URL or diff path")
    .option("-o, --out <dir>", "output directory", "./faultline-out")
    .action(async (target: string, opts: { out: string }) => {
      code = await runStub("pr", target, opts.out, io);
    });

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

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  const code = await runCli(process.argv.slice(2));
  process.exit(code);
}
