import type { Confusion } from "./score.js";
import type { BenchResult } from "./result.js";

function formatRate(value: number | null): string {
  if (value === null) {
    return "n/a";
  }
  return value.toFixed(3);
}

function formatCell(value: number): string {
  return String(value);
}

function row(cells: readonly string[]): string {
  return `| ${cells.join(" | ")} |`;
}

function confusionRow(item: Confusion): string {
  return row([
    item.class,
    formatCell(item.tp),
    formatCell(item.fp),
    formatCell(item.fn),
    formatCell(item.tn),
    formatRate(item.recall),
    formatRate(item.precision),
    formatRate(item.fpr),
    formatRate(item.score),
  ]);
}

function providerLabel(provider: string | null): string {
  if (provider === null) {
    return "none (heuristic pre-pass, no model)";
  }
  return provider;
}

/**
 * Markdown report for one bench run. The score column is TPR minus FPR.
 * Recall is TPR. Precision is TP / (TP + FP) over labeled sites.
 */
export function renderBenchMarkdown(result: BenchResult): string {
  const header = [
    "# Faultline bench",
    "",
    result.disclaimer,
    "",
    `- stage: ${result.stage}`,
    `- tool: ${result.tool.name} ${result.tool.version}`,
    `- target: ${result.target}`,
    `- truth: ${result.truth}`,
    `- provider: ${providerLabel(result.run.provider)}`,
    `- model: ${result.run.model ?? "none"}`,
    `- commit: ${result.run.commit ?? "not recorded"}`,
    `- provider errors: ${result.run.provider_error_count}`,
    `- started: ${result.run.started_at}`,
    `- citable: ${result.citable ? "yes" : "no"}`,
    `- run: ${result.run.id}`,
    `- detections: ${result.counts.detections}`,
    `- unmatched detections: ${result.counts.unmatched}`,
    "",
    "Unmatched detections are not labeled sites. They are not TP, FP, FN, or TN.",
    "Score is TPR minus FPR. Recall is TPR. `n/a` means the rate's denominator is zero.",
    "",
    row(["class", "TP", "FP", "FN", "TN", "recall", "precision", "FPR", "score"]),
    row(["---", "---", "---", "---", "---", "---", "---", "---", "---"]),
    ...result.classes.map((item) => confusionRow(item)),
    confusionRow(result.overall),
    "",
    "## Labels",
    "",
    row(["id", "class", "vulnerable", "outcome"]),
    row(["---", "---", "---", "---"]),
    ...result.entries.map((entry) =>
      row([entry.id, entry.class, entry.vulnerable ? "true" : "false", entry.outcome]),
    ),
    "",
  ];
  if (result.unmatched.length === 0) {
    header.push("## Unmatched", "", "None.", "");
  } else {
    header.push(
      "## Unmatched",
      "",
      row(["class", "file", "start", "end"]),
      row(["---", "---", "---", "---"]),
      ...result.unmatched.map((item) =>
        row([item.class, item.file, String(item.startLine), String(item.endLine)]),
      ),
      "",
    );
  }
  return `${header.join("\n")}\n`;
}
