import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

interface PackageJson {
  version: string;
}

const packagePath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
const pkg = JSON.parse(readFileSync(packagePath, "utf8")) as PackageJson;

if (typeof pkg.version !== "string" || pkg.version.length === 0) {
  throw new Error("package.json is missing a version");
}

export const TOOL_NAME = "faultline";
export const TOOL_VERSION: string = pkg.version;

const packageRoot = dirname(packagePath);

/** Commit of this Faultline checkout. Null when git is unavailable. Not the scanned tree. */
export function faultlineCommit(): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: packageRoot, timeout: 5_000 },
      (error, stdout: string | Buffer) => {
        if (error) {
          resolve(null);
          return;
        }
        const sha = stdout.toString().trim();
        resolve(/^[0-9a-f]{40}$/.test(sha) ? sha : null);
      },
    );
  });
}
