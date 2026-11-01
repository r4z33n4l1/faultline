import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { importSarif, type SarifImport } from "./sarif-import.js";

const execFileAsync = promisify(execFile);

/**
 * Semgrep OSS argv. Rules come from registry ids (`p/...`), never from a
 * corpus file. The scan reads the target as data. It does not install or
 * execute the target.
 */
export function semgrepScanArgs(rulesets: readonly string[]): string[] {
  const args = ["scan", "--metrics=off", "--disable-version-check", "--quiet", "--sarif"];
  for (const ruleset of rulesets) {
    if (!/^p\/[A-Za-z0-9][A-Za-z0-9._-]*$/.test(ruleset)) {
      throw new Error(`Refusing semgrep ruleset: ${ruleset}`);
    }
    args.push("--config", ruleset);
  }
  args.push(".");
  return args;
}

export async function readSemgrepVersion(bin: string): Promise<string> {
  let stdout: string;
  try {
    const result = await execFileAsync(bin, ["--version"], {
      timeout: 30_000,
      maxBuffer: 1_000_000,
    });
    stdout = result.stdout.toString();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Cannot run semgrep: ${message}`, { cause: error });
  }
  const version = stdout.trim();
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error(`Unexpected semgrep version output: ${version}`);
  }
  return version;
}

export async function assertSemgrepVersion(bin: string, expected: string): Promise<void> {
  const actual = await readSemgrepVersion(bin);
  if (actual !== expected) {
    throw new Error(`Semgrep ${actual} does not match the pinned version ${expected}`);
  }
}

/** Run the pinned rulesets. SARIF is parsed in-process and not executed. */
export async function scanWithSemgrep(
  bin: string,
  rulesets: readonly string[],
  root: string,
): Promise<SarifImport> {
  const args = semgrepScanArgs(rulesets);
  let stdout: string;
  try {
    const result = await execFileAsync(bin, args, {
      cwd: root,
      timeout: 900_000,
      maxBuffer: 64 * 1024 * 1024,
      env: {
        ...process.env,
        SEMGREP_SEND_METRICS: "off",
      },
    });
    stdout = result.stdout.toString();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`semgrep scan failed: ${message}`, { cause: error });
  }
  let document: unknown;
  try {
    document = JSON.parse(stdout) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`semgrep SARIF was not JSON: ${message}`, { cause: error });
  }
  return importSarif(document, root);
}
