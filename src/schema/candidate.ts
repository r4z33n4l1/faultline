import * as z from "zod";
import { malformedExample } from "../malformed.js";
import type { MalformedExample } from "./coverage.js";
import {
  CONFIDENCE_LEVELS,
  FINDING_CLASSES,
  SCHEMA_VERSION,
  SEVERITIES,
  formatZodIssues,
  locationSchema,
  runSchema,
  type FindingClass,
} from "./finding.js";

const nonEmpty = z.string().min(1);
const positiveLine = z.number().int().min(1);

/** Identifier copied from the cited file. Dots are allowed for member access. */
const SYMBOL = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/;

const evidenceSchema = z.strictObject({
  file: nonEmpty,
  line: positiveLine,
  note: nonEmpty,
});

/**
 * Unvalidated hunter output. Severity is a suggestion.
 * Confirmed findings stay in findings.json and require validator_verdict.
 */
export const candidateSchema = z.strictObject({
  class: z.enum(FINDING_CLASSES),
  cwe: z
    .string()
    .regex(/^CWE-\d+$/, "must match CWE-<digits>")
    .optional(),
  severity: z.enum(SEVERITIES).describe("Suggested severity. Not a confirmed rating."),
  confidence: z.strictObject({
    level: z.enum(CONFIDENCE_LEVELS),
    reason: nonEmpty,
  }),
  location: locationSchema,
  symbol: z.string().regex(SYMBOL, "must be an identifier"),
  root_cause: nonEmpty,
  evidence: z.array(evidenceSchema),
});

export const candidatesFileSchema = z.strictObject({
  schema_version: z.literal(SCHEMA_VERSION),
  tool: z.strictObject({
    name: nonEmpty,
    version: nonEmpty,
  }),
  run: runSchema,
  candidates: z.array(candidateSchema),
});

export type Candidate = z.infer<typeof candidateSchema>;
export type CandidatesFile = z.infer<typeof candidatesFileSchema>;

const MAX_PARSED_ITEMS = 20;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Strip one surrounding markdown fence. Prose around JSON is not scraped. */
function unwrapJson(text: string): string {
  const trimmed = text.trim().replace(/^\uFEFF/, "");
  const fenced = /^```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```[ \t]*$/.exec(trimmed);
  if (fenced?.[1] !== undefined) {
    return fenced[1].trim();
  }
  return trimmed;
}

export interface ModelCandidateParse {
  candidates: Candidate[];
  malformed: MalformedExample[];
}

/**
 * Fill a missing root_cause from the sink the hunter already selected.
 * Other required fields are not invented.
 */
function supplyRootCause(item: unknown, rootCause: string | undefined): unknown {
  if (rootCause === undefined || rootCause.length === 0 || !isRecord(item)) {
    return item;
  }
  const current = item.root_cause;
  if (typeof current === "string" && current.trim().length > 0) {
    return item;
  }
  return { ...item, root_cause: rootCause };
}

/**
 * Parse a model payload into candidates. A missing root_cause is filled from
 * `rootCause` when the caller has one. Other schema failures are returned as
 * malformed examples and are not candidates. Nothing is confirmed.
 */
export function parseModelCandidates(
  text: string,
  expectedClass?: FindingClass,
  rootCause?: string,
): ModelCandidateParse {
  const malformed: MalformedExample[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(unwrapJson(text)) as unknown;
  } catch {
    malformed.push(malformedExample("hunter", "reply was not JSON"));
    return { candidates: [], malformed };
  }

  let items: unknown[];
  if (Array.isArray(parsed)) {
    items = parsed;
  } else if (isRecord(parsed) && Array.isArray(parsed.candidates)) {
    items = parsed.candidates;
  } else if (isRecord(parsed) && Array.isArray(parsed.findings)) {
    items = parsed.findings;
  } else if (isRecord(parsed)) {
    items = [parsed];
  } else {
    malformed.push(malformedExample("hunter", "reply had no candidates"));
    return { candidates: [], malformed };
  }

  const candidates: Candidate[] = [];
  const limit = Math.min(items.length, MAX_PARSED_ITEMS);
  for (let index = 0; index < limit; index += 1) {
    const result = candidateSchema.safeParse(supplyRootCause(items[index], rootCause));
    if (!result.success) {
      malformed.push(
        malformedExample("hunter", formatZodIssues(result.error, `candidates.${index}`)),
      );
      continue;
    }
    if (expectedClass !== undefined && result.data.class !== expectedClass) {
      malformed.push(
        malformedExample("hunter", `candidates.${index}: class did not match ${expectedClass}`),
      );
      continue;
    }
    candidates.push(result.data);
  }
  return { candidates, malformed };
}

/**
 * Parse a model payload into candidates. Malformed JSON, the wrong envelope,
 * and items that fail the schema are discarded. Nothing is confirmed.
 */
export function parseCandidateList(text: string, expectedClass?: FindingClass): Candidate[] {
  return parseModelCandidates(text, expectedClass).candidates;
}

export function serializeCandidates(file: CandidatesFile): string {
  return `${JSON.stringify(candidatesFileSchema.parse(file), null, 2)}\n`;
}

export function renderCandidatesJsonSchema(): string {
  return `${JSON.stringify(z.toJSONSchema(candidatesFileSchema), null, 2)}\n`;
}
