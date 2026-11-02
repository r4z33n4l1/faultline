import { redactTokenLike } from "./providers/errors.js";
import type { MalformedExample, MalformedSource } from "./schema/coverage.js";

/** Examples stored on coverage.json. The run count includes every rejection. */
export const MALFORMED_EXAMPLE_CAP = 20;

export function malformedExample(source: MalformedSource, reason: string): MalformedExample {
  const redacted = redactTokenLike(reason).replace(/\s+/g, " ").trim();
  const text = redacted.length === 0 ? "model reply failed validation" : redacted;
  return { source, reason: text.length > 500 ? text.slice(0, 500) : text };
}

/** Stable, capped examples for coverage.json and report.md. */
export function malformedExamples(items: readonly MalformedExample[]): MalformedExample[] {
  return [...items]
    .sort(
      (left, right) =>
        (left.source < right.source ? -1 : left.source > right.source ? 1 : 0) ||
        (left.reason < right.reason ? -1 : left.reason > right.reason ? 1 : 0),
    )
    .slice(0, MALFORMED_EXAMPLE_CAP);
}
