import { readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import * as z from "zod";
import { truthFileSchema, type TruthFile } from "../schema/truth.js";
import { formatZodIssues } from "../schema/finding.js";

export const CORPUS_SCHEMA_VERSION = "1";

const sha = z.string().regex(/^[0-9a-f]{40}$/);
const appName = z.string().regex(/^[a-z][a-z0-9-]*$/);
const githubUrl = z
  .string()
  .regex(
    /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/,
    "must be an https://github.com owner/repo URL",
  );
const ruleset = z.string().regex(/^p\/[A-Za-z0-9][A-Za-z0-9._-]*$/);
const relativePath = z.string().refine(isSafeRelative, "must be a relative path without ..");

function isSafeRelative(value: string): boolean {
  if (value.length === 0 || isAbsolute(value) || value.includes("\\")) {
    return false;
  }
  const parts = value.split("/");
  return parts.every((part) => part.length > 0 && part !== "." && part !== "..");
}

export const corpusAppSchema = z.strictObject({
  name: appName,
  upstream: githubUrl,
  commit: sha,
  license: z.string().min(1),
  /** Path of the license file inside the upstream tree. Not vendored here. */
  license_path: relativePath,
});

export const corpusManifestSchema = z
  .strictObject({
    schema_version: z.literal(CORPUS_SCHEMA_VERSION),
    /** Gitignored checkout root, relative to the process working directory. */
    cache_dir: relativePath,
    semgrep: z.strictObject({
      version: z.string().regex(/^\d+\.\d+\.\d+$/),
      rulesets: z.array(ruleset).min(1),
    }),
    apps: z.array(corpusAppSchema).min(1),
  })
  .superRefine((manifest, ctx) => {
    const seen = new Set<string>();
    manifest.apps.forEach((app, index) => {
      if (seen.has(app.name)) {
        ctx.addIssue({
          code: "custom",
          message: "duplicate app name",
          path: ["apps", index, "name"],
        });
      }
      seen.add(app.name);
    });
  });

export const citationEntrySchema = z.strictObject({
  id: z.string().min(1),
  source: z.string().url(),
  note: z.string().min(1),
});

export const citationFileSchema = z
  .strictObject({
    schema_version: z.literal(CORPUS_SCHEMA_VERSION),
    entries: z.array(citationEntrySchema),
  })
  .superRefine((file, ctx) => {
    const seen = new Set<string>();
    file.entries.forEach((entry, index) => {
      if (seen.has(entry.id)) {
        ctx.addIssue({
          code: "custom",
          message: "duplicate id",
          path: ["entries", index, "id"],
        });
      }
      seen.add(entry.id);
    });
  });

export const excludedEntrySchema = z.strictObject({
  id: z.string().min(1),
  class: z.string().min(1),
  source: z.string().url(),
  note: z.string().min(1),
});

export const excludedFileSchema = z
  .strictObject({
    schema_version: z.literal(CORPUS_SCHEMA_VERSION),
    entries: z.array(excludedEntrySchema),
  })
  .superRefine((file, ctx) => {
    const seen = new Set<string>();
    file.entries.forEach((entry, index) => {
      if (seen.has(entry.id)) {
        ctx.addIssue({
          code: "custom",
          message: "duplicate id",
          path: ["entries", index, "id"],
        });
      }
      seen.add(entry.id);
    });
  });

export type CorpusManifest = z.infer<typeof corpusManifestSchema>;
export type CorpusApp = z.infer<typeof corpusAppSchema>;
export type CitationFile = z.infer<typeof citationFileSchema>;
export type ExcludedFile = z.infer<typeof excludedFileSchema>;

async function readJson(filePath: string): Promise<unknown> {
  let text: string;
  try {
    text = await readFile(filePath, "utf8");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Cannot read file: ${message}`, { cause: error });
  }
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid JSON: ${message}`, { cause: error });
  }
}

function parseWith<T>(
  schema: {
    safeParse: (
      value: unknown,
    ) => { success: true; data: T } | { success: false; error: z.ZodError };
  },
  value: unknown,
  label: string,
): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new Error(`${label}: ${formatZodIssues(parsed.error)}`);
  }
  return parsed.data;
}

export async function loadCorpusManifest(manifestPath: string): Promise<CorpusManifest> {
  return parseWith(corpusManifestSchema, await readJson(manifestPath), manifestPath);
}

export function findCorpusApp(manifest: CorpusManifest, name: string): CorpusApp {
  const app = manifest.apps.find((item) => item.name === name);
  if (app === undefined) {
    const known = manifest.apps.map((item) => item.name).join(", ");
    throw new Error(`Unknown corpus app "${name}". Known apps: ${known}`);
  }
  return app;
}

function sameIds(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  const wanted = new Set(right);
  return left.every((id) => wanted.has(id));
}

/**
 * Check the committed corpus documents. Does not read a checkout and does
 * not use the network. Line ranges are checked only when a bench run loads
 * truth against a cache.
 */
export async function validateCorpusDocuments(manifestPath: string): Promise<void> {
  const manifest = await loadCorpusManifest(manifestPath);
  const root = resolve(manifestPath, "..");
  for (const app of manifest.apps) {
    const dir = resolve(root, app.name);
    const truth = parseWith(
      truthFileSchema,
      await readJson(resolve(dir, "truth.json")),
      `${app.name}/truth.json`,
    );
    const citations = parseWith(
      citationFileSchema,
      await readJson(resolve(dir, "citations.json")),
      `${app.name}/citations.json`,
    );
    const excluded = parseWith(
      excludedFileSchema,
      await readJson(resolve(dir, "excluded.json")),
      `${app.name}/excluded.json`,
    );
    assertIds(app.name, truth, citations, excluded);
  }
}

function assertIds(
  name: string,
  truth: TruthFile,
  citations: CitationFile,
  excluded: ExcludedFile,
): void {
  const truthIds = truth.entries.map((entry) => entry.id);
  const citationIds = citations.entries.map((entry) => entry.id);
  if (!sameIds(truthIds, citationIds)) {
    throw new Error(`${name}: citation ids must match truth ids`);
  }
  const truthSet = new Set(truthIds);
  for (const entry of excluded.entries) {
    if (truthSet.has(entry.id)) {
      throw new Error(`${name}: excluded id ${entry.id} is also a truth id`);
    }
  }
}
