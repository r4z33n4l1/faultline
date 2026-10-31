#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Command, CommanderError } from "commander";
import { writeRunOutput } from "./output.js";
import { runPipeline } from "./pipeline.js";
import { findingsFileSchema, formatZodIssues, type RunMode } from "./schema/finding.js";
import { TOOL_VERSION } from "./version.js";

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  cwd?: string;
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

async function runStub(mode: RunMode, target: string, out: string, io: CliIo): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const outDir = resolve(cwd, out);
  try {
    const file = runPipeline({ mode, target });
    await writeRunOutput(outDir, file);
  } catch (error) {
    io.stderr(`${messageOf(error)}\n`);
    return 1;
  }
  io.stdout(`Wrote ${resolve(outDir, "findings.json")} and ${resolve(outDir, "report.md")}\n`);
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
    .description("Run an empty scan pipeline and write findings.json plus report.md")
    .argument("<path>", "target path")
    .option("-o, --out <dir>", "output directory", "./faultline-out")
    .action(async (target: string, opts: { out: string }) => {
      code = await runStub("scan", target, opts.out, io);
    });

  program
    .command("pr")
    .description("Run an empty pull-request pipeline and write findings.json plus report.md")
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
