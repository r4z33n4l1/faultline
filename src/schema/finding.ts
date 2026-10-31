import * as z from "zod";

export const SCHEMA_VERSION = "1";

export const FINDING_CLASSES = ["authz_idor", "injection", "secrets", "ssrf", "other"] as const;
export const SEVERITIES = ["informational", "low", "medium", "high", "critical"] as const;
export const CONFIDENCE_LEVELS = ["low", "medium", "high"] as const;
export const EXPLOITABILITIES = ["theoretical", "poc", "demonstrated"] as const;
export const DISPROOF_VERDICTS = ["confirmed", "rejected", "inconclusive"] as const;
export const RUN_MODES = ["scan", "pr"] as const;

export type RunMode = (typeof RUN_MODES)[number];

const CWE_ID = /^CWE-\d+$/;
const nonEmpty = z.string().min(1);
const positiveLine = z.number().int().min(1);

export const locationSchema = z
  .strictObject({
    file: nonEmpty,
    start_line: positiveLine,
    end_line: positiveLine.optional(),
  })
  .refine(
    (location) => location.end_line === undefined || location.end_line >= location.start_line,
    {
      message: "end_line must be >= start_line",
      path: ["end_line"],
    },
  )
  .describe("end_line, when present, must be >= start_line");

export const findingSchema = z.strictObject({
  id: nonEmpty,
  class: z.enum(FINDING_CLASSES),
  cwe: z.string().regex(CWE_ID, "must match CWE-<digits>").optional(),
  severity: z.enum(SEVERITIES),
  confidence: z.strictObject({
    level: z.enum(CONFIDENCE_LEVELS),
    reason: nonEmpty,
  }),
  exploitability: z.enum(EXPLOITABILITIES),
  location: locationSchema,
  root_cause: nonEmpty,
  evidence: z.array(
    z.strictObject({
      file: nonEmpty,
      line: positiveLine,
      note: nonEmpty,
    }),
  ),
  disproof_attempts: z.array(
    z.strictObject({
      role: nonEmpty,
      verdict: z.enum(DISPROOF_VERDICTS),
      summary: nonEmpty,
    }),
  ),
  validator_verdict: z.literal("confirmed"),
  suggested_fix: z.strictObject({
    summary: nonEmpty,
    patch: nonEmpty.optional(),
  }),
  references: z.array(nonEmpty),
});

export const findingsFileSchema = z.strictObject({
  schema_version: z.literal(SCHEMA_VERSION),
  tool: z.strictObject({
    name: nonEmpty,
    version: nonEmpty,
  }),
  run: z.strictObject({
    id: nonEmpty,
    started_at: z.iso.datetime(),
    target: nonEmpty,
    mode: z.enum(RUN_MODES),
    provider: nonEmpty.optional(),
  }),
  findings: z.array(findingSchema),
});

export type Finding = z.infer<typeof findingSchema>;
export type FindingsFile = z.infer<typeof findingsFileSchema>;
export type Severity = (typeof SEVERITIES)[number];
export type FindingClass = (typeof FINDING_CLASSES)[number];

export function formatZodIssues(error: z.ZodError, prefix = ""): string {
  return error.issues
    .map((issue) => {
      const segments = prefix.length > 0 ? prefix.split(".") : [];
      for (const part of issue.path) {
        segments.push(String(part));
      }
      const path = segments.length > 0 ? segments.join(".") : "(root)";
      return `${path}: ${issue.message}`;
    })
    .join("\n");
}

export function renderFindingsJsonSchema(): string {
  const schema = z.toJSONSchema(findingsFileSchema);
  return `${JSON.stringify(schema, null, 2)}\n`;
}
