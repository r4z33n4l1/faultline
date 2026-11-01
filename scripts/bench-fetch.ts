import { pathToFileURL } from "node:url";
import { ensureCorpusCache, resolveCorpusPaths } from "../src/bench/corpus.js";
import { loadCorpusManifest } from "../src/bench/manifest.js";

/**
 * Shallow-clone pinned corpus commits into the gitignored cache.
 * Does not install, build, or run those apps.
 */
async function main(): Promise<void> {
  const cwd = process.cwd();
  const manifestPath = "bench/corpus/manifest.json";
  const manifest = await loadCorpusManifest(manifestPath);
  const requested = process.argv.slice(2);
  const names = requested.length === 0 ? manifest.apps.map((app) => app.name) : requested;
  for (const name of names) {
    const paths = await resolveCorpusPaths(cwd, manifestPath, name);
    await ensureCorpusCache(paths, false);
    process.stdout.write(`${name} ${paths.app.commit} ${paths.cacheDir}\n`);
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
