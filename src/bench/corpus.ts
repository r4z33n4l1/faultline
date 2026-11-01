import { execFile } from "node:child_process";
import { mkdir, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import {
  findCorpusApp,
  loadCorpusManifest,
  type CorpusApp,
  type CorpusManifest,
} from "./manifest.js";

const execFileAsync = promisify(execFile);

export interface CorpusPaths {
  manifestPath: string;
  app: CorpusApp;
  /** Absolute checkout. Gitignored. */
  cacheDir: string;
  /** Absolute truth.json. Stays in this repo. */
  truthPath: string;
  /** Labels for result files. Relative when they sit under `cwd`. */
  targetLabel: string;
  truthLabel: string;
}

export interface FetchOptions {
  /** Test-only. The CLI never sets this. Manifest URLs are https. */
  allowLocal?: boolean;
}

function assertInside(root: string, target: string): void {
  const rel = relative(root, target);
  if (rel.length === 0 || rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Path escapes the corpus cache: ${target}`);
  }
}

function labelUnder(cwd: string, abs: string): string {
  const rel = relative(cwd, abs);
  if (rel.length === 0 || rel.startsWith("..") || isAbsolute(rel)) {
    return abs;
  }
  return rel.split(sep).join("/");
}

export async function resolveCorpusPaths(
  cwd: string,
  manifestPath: string,
  name: string,
): Promise<CorpusPaths> {
  const absManifest = resolve(cwd, manifestPath);
  const manifest = await loadCorpusManifest(absManifest);
  const app = findCorpusApp(manifest, name);
  const manifestDir = resolve(absManifest, "..");
  const cacheRoot = resolve(cwd, manifest.cache_dir);
  const cacheDir = resolve(cacheRoot, app.name);
  assertInside(cacheRoot, cacheDir);
  const truthPath = resolve(manifestDir, app.name, "truth.json");
  assertInside(manifestDir, truthPath);
  return {
    manifestPath: absManifest,
    app,
    cacheDir,
    truthPath,
    targetLabel: labelUnder(cwd, cacheDir),
    truthLabel: labelUnder(cwd, truthPath),
  };
}

async function git(args: readonly string[], cwd: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", ["-c", "core.hooksPath=/dev/null", ...args], {
      cwd,
      timeout: 180_000,
      maxBuffer: 10_000_000,
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: "0",
      },
    });
    return stdout.toString().trim();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`git ${args.join(" ")} failed: ${message}`, { cause: error });
  }
}

async function headSha(dir: string): Promise<string | undefined> {
  try {
    const info = await stat(dir);
    if (!info.isDirectory()) {
      throw new Error(`Corpus cache is not a directory: ${dir}`);
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Corpus cache")) {
      throw error;
    }
    return undefined;
  }
  try {
    await stat(resolve(dir, ".git"));
  } catch {
    throw new Error(`Corpus cache exists and is not a git checkout: ${dir}`);
  }
  const sha = await git(["rev-parse", "HEAD"], dir);
  return /^[0-9a-f]{40}$/.test(sha) ? sha : undefined;
}

function assertFetchUrl(url: string, allowLocal: boolean): void {
  if (allowLocal && url.startsWith("file://")) {
    return;
  }
  if (!url.startsWith("https://") || url.includes("@")) {
    throw new Error(`Refusing to fetch corpus URL: ${url}`);
  }
}

/**
 * Shallow-fetch one pinned commit. Does not recurse into submodules, run
 * hooks, install dependencies, or execute anything from the tree.
 */
export async function fetchPinnedCommit(
  app: Pick<CorpusApp, "upstream" | "commit">,
  dest: string,
  options?: FetchOptions,
): Promise<void> {
  assertFetchUrl(app.upstream, options?.allowLocal === true);
  const current = await headSha(dest);
  if (current === app.commit) {
    return;
  }
  if (current !== undefined) {
    throw new Error(
      `Corpus cache is ${current}, manifest pins ${app.commit}. Remove the cache and fetch again.`,
    );
  }
  await mkdir(dest, { recursive: true });
  await git(["init", "-q"], dest);
  await git(["remote", "add", "origin", app.upstream], dest);
  await git(["fetch", "--depth", "1", "origin", app.commit], dest);
  await git(["checkout", "--detach", "FETCH_HEAD"], dest);
  const fetched = await git(["rev-parse", "HEAD"], dest);
  if (fetched !== app.commit) {
    throw new Error(`Fetched ${fetched}, manifest pins ${app.commit}`);
  }
}

export async function ensureCorpusCache(
  paths: CorpusPaths,
  cacheOnly: boolean,
  options?: FetchOptions,
): Promise<void> {
  const current = await headSha(paths.cacheDir);
  if (current === paths.app.commit) {
    return;
  }
  if (cacheOnly) {
    throw new Error(
      `Corpus ${paths.app.name} is not checked out at ${paths.app.commit}. Run pnpm bench:fetch. This command was asked not to clone.`,
    );
  }
  await fetchPinnedCommit(paths.app, paths.cacheDir, options);
}

export async function listManifestApps(manifestPath: string): Promise<CorpusManifest> {
  return loadCorpusManifest(resolve(manifestPath));
}
