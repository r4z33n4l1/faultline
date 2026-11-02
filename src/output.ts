import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  findingSchema,
  findingsFileSchema,
  formatZodIssues,
  type DisprovedEntry,
  type Finding,
  type FindingsFile,
  type InconclusiveEntry,
  type ProviderErrorEntry,
} from "./schema/finding.js";
import type { MalformedExample } from "./schema/coverage.js";
import { renderReport } from "./report.js";
import { serializeSarif, toSarif } from "./sarif.js";

export interface FindingsDraft {
  schema_version: FindingsFile["schema_version"];
  tool: FindingsFile["tool"];
  run: FindingsFile["run"];
  findings: readonly unknown[];
  disproved?: readonly DisprovedEntry[];
  inconclusive?: readonly InconclusiveEntry[];
  errors?: readonly ProviderErrorEntry[];
}

function verdictOf(value: unknown): unknown {
  if (typeof value !== "object" || value === null || !("validator_verdict" in value)) {
    return undefined;
  }
  return value.validator_verdict;
}

/** Drop anything that is not a confirmed or kept-inconclusive finding. Invalid kept findings throw. */
export function gateFindings(findings: readonly unknown[]): Finding[] {
  const kept: Finding[] = [];
  for (let index = 0; index < findings.length; index += 1) {
    const finding = findings[index];
    if (verdictOf(finding) !== "confirmed" && verdictOf(finding) !== "inconclusive") {
      continue;
    }
    const parsed = findingSchema.safeParse(finding);
    if (!parsed.success) {
      throw new Error(formatZodIssues(parsed.error, `findings.${index}`));
    }
    kept.push(parsed.data);
  }
  return kept;
}

export function serializeFindings(file: FindingsFile): string {
  return `${JSON.stringify(file, null, 2)}\n`;
}

export interface WriteRunOptions {
  /** Directory absolute finding paths are made relative to. Relative paths are left as given. */
  scanRoot?: string;
  /** Included in report.md as a count only. Omitted for commands that do not hunt. */
  unvalidatedCandidates?: number;
  disproved?: readonly DisprovedEntry[];
  inconclusive?: readonly InconclusiveEntry[];
  errors?: readonly ProviderErrorEntry[];
  /** Set for a PR-scoped run. Lists repo-relative changed files. An empty list is still PR-scoped. */
  changedFiles?: readonly string[];
  /** Context window recorded in a PR-scoped report. */
  hunkContext?: number;
  /** Set when a file or byte cap left paths unread. */
  inventoryNote?: string;
  /** Capped examples of model objects rejected before findings assembly. */
  malformed?: readonly MalformedExample[];
}

export async function writeRunOutput(
  outDir: string,
  draft: FindingsDraft,
  options: WriteRunOptions = {},
): Promise<FindingsFile> {
  const file = findingsFileSchema.parse({
    ...draft,
    findings: gateFindings(draft.findings),
    disproved: options.disproved ?? draft.disproved ?? [],
    inconclusive: options.inconclusive ?? draft.inconclusive ?? [],
    errors: options.errors ?? draft.errors ?? [],
  });
  const scanRoot = options.scanRoot ?? process.cwd();
  const findingsText = serializeFindings(file);
  const reportText = renderReport(file, {
    unvalidatedCandidates: options.unvalidatedCandidates,
    disproved: file.disproved,
    inconclusive: file.inconclusive,
    changedFiles: options.changedFiles,
    hunkContext: options.hunkContext,
    inventoryNote: options.inventoryNote,
    ...(options.malformed === undefined ? {} : { malformed: options.malformed }),
  });
  const sarifText = serializeSarif(toSarif(file, scanRoot));
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "findings.json"), findingsText, "utf8");
  await writeFile(join(outDir, "report.md"), reportText, "utf8");
  await writeFile(join(outDir, "findings.sarif"), sarifText, "utf8");
  return file;
}
