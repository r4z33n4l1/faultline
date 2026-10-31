import { DEFAULT_HUNK_CONTEXT } from "./pr/diff.js";
import {
  SEVERITIES,
  type Finding,
  type FindingClass,
  type FindingsFile,
  type Severity,
} from "./schema/finding.js";

const CLASS_LABELS: Record<FindingClass, string> = {
  authz_idor: "authorization (IDOR)",
  injection: "injection",
  secrets: "secrets",
  ssrf: "SSRF",
  other: "other",
};

function findingCount(count: number): string {
  return count === 1 ? "1 confirmed finding" : `${count} confirmed findings`;
}

function locationLabel(location: Finding["location"]): string {
  if (location.end_line === undefined) {
    return `${location.file}:${location.start_line}`;
  }
  return `${location.file}:${location.start_line}-${location.end_line}`;
}

function fence(code: string): string {
  let ticks = "```";
  while (code.includes(ticks)) {
    ticks += "`";
  }
  return `${ticks}\n${code}\n${ticks}`;
}

function renderFinding(finding: Finding, index: number): string[] {
  const where = locationLabel(finding.location);
  const lines = [
    `### ${index + 1}. ${finding.root_cause}`,
    "",
    `Confirmed ${CLASS_LABELS[finding.class]} finding \`${finding.id}\` at \`${where}\`.`,
    `Severity is ${finding.severity}. Confidence is ${finding.confidence.level}: ${finding.confidence.reason}`,
    `Exploitability is ${finding.exploitability}.`,
  ];

  if (finding.cwe !== undefined) {
    lines.push(`Weakness: ${finding.cwe}.`);
  }

  lines.push("", "Evidence:");
  if (finding.evidence.length === 0) {
    lines.push("None recorded.");
  } else {
    for (const item of finding.evidence) {
      lines.push(`- \`${item.file}:${item.line}\`: ${item.note}`);
    }
  }

  lines.push("", "Disproof attempts:");
  if (finding.disproof_attempts.length === 0) {
    lines.push("None recorded.");
  } else {
    for (const attempt of finding.disproof_attempts) {
      lines.push(`- ${attempt.role} (${attempt.verdict}): ${attempt.summary}`);
    }
  }

  lines.push("", `Suggested fix: ${finding.suggested_fix.summary}`);
  if (finding.suggested_fix.patch !== undefined) {
    lines.push("", fence(finding.suggested_fix.patch));
  }

  lines.push("", "References:");
  if (finding.references.length === 0) {
    lines.push("None.");
  } else {
    for (const reference of finding.references) {
      lines.push(`- ${reference}`);
    }
  }

  lines.push("");
  return lines;
}

export interface ReportOptions {
  /** When set, the report records the count and no candidate details. */
  unvalidatedCandidates?: number;
  /** Set for a PR-scoped run, including when the diff changes no files. */
  changedFiles?: readonly string[];
  /** Lines of context used for hunk overlap. Reported only when `changedFiles` is set. */
  hunkContext?: number;
}

export function renderReport(file: FindingsFile, options: ReportOptions = {}): string {
  const counts = new Map<Severity, number>(SEVERITIES.map((severity) => [severity, 0]));
  for (const finding of file.findings) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  }

  const lines = [
    "# Faultline report",
    "",
    `${file.tool.name} ${file.tool.version} checked \`${file.run.target}\` in ${file.run.mode} mode.`,
    `Run ${file.run.id} started ${file.run.started_at}.`,
  ];

  if (file.run.provider !== undefined) {
    lines.push(`Provider: ${file.run.provider}.`);
  }

  if (options.changedFiles !== undefined) {
    const context = options.hunkContext ?? DEFAULT_HUNK_CONTEXT;
    lines.push(
      "",
      `This run is PR-scoped. Hunters reviewed changed files only. A candidate is kept when its line range overlaps a changed hunk, with a ${context}-line context window.`,
      "",
      "## Changed files",
      "",
    );
    if (options.changedFiles.length === 0) {
      lines.push("None.");
    } else {
      for (const filePath of options.changedFiles) {
        lines.push(`- \`${filePath}\``);
      }
    }
  }

  lines.push("", "## Summary", "");
  for (const severity of SEVERITIES) {
    lines.push(`- ${severity}: ${counts.get(severity) ?? 0}`);
  }
  lines.push("", `${findingCount(file.findings.length)}.`);
  if (options.unvalidatedCandidates !== undefined) {
    lines.push(
      `unvalidated candidates: ${options.unvalidatedCandidates}, not reported as findings`,
    );
  }
  lines.push("", "## Findings", "");

  if (file.findings.length === 0) {
    lines.push("No confirmed findings.", "");
    return lines.join("\n");
  }

  for (const [index, finding] of file.findings.entries()) {
    lines.push(...renderFinding(finding, index));
  }
  return lines.join("\n");
}
