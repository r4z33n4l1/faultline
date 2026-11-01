import { pathToFileURL } from "node:url";
import { ensureCorpusCache, resolveCorpusPaths } from "../src/bench/corpus.js";
import { CORPUS_GROUPS, corpusGroupManifest, loadCorpusManifest } from "../src/bench/manifest.js";

interface FetchArgs {
  group: string;
  names: string[];
}

export function parseFetchArgs(argv: readonly string[]): FetchArgs {
  let group = "corpus";
  const names: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--group") {
      const value = argv[index + 1];
      if (value === undefined) {
        throw new Error(
          `Missing corpus group after --group. Known groups: ${Object.keys(CORPUS_GROUPS).join(", ")}`,
        );
      }
      group = value;
      index += 1;
      continue;
    }
    if (arg?.startsWith("--group=") === true) {
      group = arg.slice("--group=".length);
      continue;
    }
    if (arg === undefined || arg.startsWith("-")) {
      throw new Error(`Unknown argument: ${String(arg)}`);
    }
    names.push(arg);
  }
  corpusGroupManifest(group);
  return { group, names };
}

/**
 * Shallow-clone pinned corpus commits into the gitignored cache.
 * Does not install, build, or run those apps.
 *
 * `pnpm bench:fetch` fetches the training group. `pnpm bench:fetch --group heldout`
 * fetches the held-out group. Held-out labels must not drive heuristic changes.
 */
async function main(): Promise<void> {
  const cwd = process.cwd();
  const { group, names: requested } = parseFetchArgs(process.argv.slice(2));
  const manifestPath = corpusGroupManifest(group);
  const manifest = await loadCorpusManifest(manifestPath);
  const names = requested.length === 0 ? manifest.apps.map((app) => app.name) : requested;
  for (const name of names) {
    const paths = await resolveCorpusPaths(cwd, manifestPath, name);
    await ensureCorpusCache(paths, false);
    process.stdout.write(`${group} ${name} ${paths.app.commit} ${paths.cacheDir}\n`);
  }
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
