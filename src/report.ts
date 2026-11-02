import type { MalformedExample } from "./schema/coverage.js";
import { DEFAULT_HUNK_CONTEXT } from "./pr/diff.js";
import {
  SEVERITIES,
  type DisprovedEntry,
  type Finding,
  type FindingClass,
  type FindingsFile,
  type InconclusiveEntry,
  type ProviderErrorEntry,
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

function locationLabel(location: { file: string; start_line: number; end_line?: number }): string {
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
  const status = finding.validator_verdict === "inconclusive" ? "Inconclusive" : "Confirmed";
  const lines = [
    `### ${index + 1}. ${finding.root_cause}`,
    "",
    `${status} ${CLASS_LABELS[finding.class]} finding \`${finding.id}\` at \`${where}\`.`,
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
  disproved?: readonly DisprovedEntry[];
  inconclusive?: readonly InconclusiveEntry[];
  errors?: readonly ProviderErrorEntry[];
  /** Set for a PR-scoped run, including when the diff changes no files. */
  changedFiles?: readonly string[];
  /** Lines of context used for hunk overlap. Reported only when `changedFiles` is set. */
  hunkContext?: number;
  /** Set when a file or byte cap left paths unread. */
  inventoryNote?: string;
  /** Capped examples. The count on the run may be higher. */
  malformed?: readonly MalformedExample[];
}

function reviewLine(
  entry: { file: string; start_line: number; end_line?: number; class: string; reason: string },
  suffix = "",
): string {
  return `- \`${locationLabel(entry)}\` (${entry.class}${suffix}): ${entry.reason}`;
}

export function renderReport(file: FindingsFile, options: ReportOptions = {}): string {
  const confirmed = file.findings.filter((finding) => finding.validator_verdict === "confirmed");
  const keptInconclusive = file.findings.filter(
    (finding) => finding.validator_verdict === "inconclusive",
  );
  const counts = new Map<Severity, number>(SEVERITIES.map((severity) => [severity, 0]));
  for (const finding of confirmed) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  }
  const lines = [
    "# Faultline report",
    "",
    `${file.tool.name} ${file.tool.version} checked \`${file.run.target}\` in ${file.run.mode} mode.`,
    `Run ${file.run.id} started ${file.run.started_at}.`,
  ];

  if (file.run.provider !== undefined) {
    lines.push(`Provider: ${file.run.provider ?? "none"}.`);
  }
  if (file.run.model !== undefined) {
    lines.push(`Model: ${file.run.model ?? "none"}.`);
  }
  if (file.run.commit !== undefined) {
    lines.push(`Commit: ${file.run.commit ?? "not recorded"}.`);
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
  lines.push("", `${findingCount(confirmed.length)}.`);
  if (file.run.provider_error_count !== undefined) {
    lines.push(`Provider errors: ${file.run.provider_error_count}.`);
  }
  if (file.run.provider_error !== undefined) {
    lines.push(file.run.provider_error);
  }
  if ((file.run.malformed_count ?? 0) > 0) {
    lines.push(`Malformed model output: ${file.run.malformed_count}.`);
  }
  if (keptInconclusive.length > 0) {
    const noun = keptInconclusive.length === 1 ? "finding" : "findings";
    lines.push(
      `${keptInconclusive.length} inconclusive ${noun} kept at low confidence by --keep-inconclusive.`,
    );
  }
  if (options.unvalidatedCandidates !== undefined) {
    lines.push(
      `unvalidated candidates: ${options.unvalidatedCandidates}, not reported as findings`,
    );
  }
  if (options.inventoryNote !== undefined) {
    lines.push("", "## Inventory", "", options.inventoryNote, "");
  }
  lines.push("", "## Findings", "");

  if (confirmed.length === 0) {
    lines.push("No confirmed findings.", "");
  }

  for (const [index, finding] of confirmed.entries()) {
    lines.push(...renderFinding(finding, index));
  }
  if (keptInconclusive.length > 0) {
    lines.push("", "## Inconclusive findings", "");
    for (const [index, finding] of keptInconclusive.entries()) {
      lines.push(...renderFinding(finding, index));
    }
  }
  const disproved = options.disproved ?? file.disproved ?? [];
  const inconclusive = options.inconclusive ?? file.inconclusive ?? [];
  const providerErrors = options.errors ?? file.errors ?? [];
  if (disproved.length > 0) {
    lines.push("", "## Disproved candidates", "");
    for (const item of disproved) {
      lines.push(reviewLine(item));
    }
    lines.push("");
  }
  if (inconclusive.length > 0) {
    lines.push("", "## Inconclusive candidates", "");
    for (const item of inconclusive) {
      lines.push(reviewLine(item, item.kept ? ", kept" : ""));
    }
    lines.push("");
  }
  if (providerErrors.length > 0) {
    lines.push("", "## Provider errors", "");
    for (const item of providerErrors) {
      lines.push(reviewLine(item));
    }
    lines.push("");
  }
  const malformed = options.malformed ?? [];
  if (malformed.length > 0) {
    lines.push("", "## Malformed model output", "");
    for (const item of malformed) {
      lines.push(`- ${item.source}: ${item.reason}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
