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

export async function writeRunOutput(outDir: string, draft: FindingsDraft): Promise<FindingsFile> {
  const file = findingsFileSchema.parse({
    ...draft,
    findings: gateFindings(draft.findings),
  });
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "findings.json"), serializeFindings(file), "utf8");
  await writeFile(join(outDir, "report.md"), renderReport(file), "utf8");
  return file;
}
