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
