import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  findingSchema,
  findingsFileSchema,
  formatZodIssues,
  type Finding,
  type FindingsFile,
} from "./schema/finding.js";
import { renderReport } from "./report.js";
import { serializeSarif, toSarif } from "./sarif.js";

export interface FindingsDraft {
  schema_version: FindingsFile["schema_version"];
  tool: FindingsFile["tool"];
  run: FindingsFile["run"];
  findings: readonly unknown[];
}

function verdictOf(value: unknown): unknown {
  if (typeof value !== "object" || value === null || !("validator_verdict" in value)) {
    return undefined;
  }
  return value.validator_verdict;
}

/** Drop anything that is not a confirmed finding. Invalid confirmed findings throw. */
export function gateFindings(findings: readonly unknown[]): Finding[] {
  const kept: Finding[] = [];
  for (let index = 0; index < findings.length; index += 1) {
    const finding = findings[index];
    if (verdictOf(finding) !== "confirmed") {
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
}

export async function writeRunOutput(
  outDir: string,
  draft: FindingsDraft,
  options: WriteRunOptions = {},
): Promise<FindingsFile> {
  const file = findingsFileSchema.parse({
    ...draft,
    findings: gateFindings(draft.findings),
  });
  const scanRoot = options.scanRoot ?? process.cwd();
  const findingsText = serializeFindings(file);
  const reportText = renderReport(file);
  const sarifText = serializeSarif(toSarif(file, scanRoot));
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "findings.json"), findingsText, "utf8");
  await writeFile(join(outDir, "report.md"), reportText, "utf8");
  await writeFile(join(outDir, "findings.sarif"), sarifText, "utf8");
  return file;
}
