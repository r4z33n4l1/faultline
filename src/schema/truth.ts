import * as z from "zod";
import { COVERAGE_CLASSES } from "./coverage.js";

export const TRUTH_SCHEMA_VERSION = "1";

/** Bug classes the bench can label. Same set the hunters cover. */
export const TRUTH_CLASSES = COVERAGE_CLASSES;

const nonEmpty = z.string().min(1);
const positiveLine = z.number().int().min(1);

export const truthEntrySchema = z
  .strictObject({
    id: nonEmpty,
    class: z.enum(TRUTH_CLASSES),
    cwe: z.string().regex(/^CWE-\d+$/, "must match CWE-<digits>"),
    file: nonEmpty,
    start_line: positiveLine,
    end_line: positiveLine,
    vulnerable: z.boolean(),
  })
  .refine((entry) => entry.end_line >= entry.start_line, {
    message: "end_line must be >= start_line",
    path: ["end_line"],
  });

export const truthFileSchema = z
  .strictObject({
    schema_version: z.literal(TRUTH_SCHEMA_VERSION),
    entries: z.array(truthEntrySchema),
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

export type TruthEntry = z.infer<typeof truthEntrySchema>;
export type TruthFile = z.infer<typeof truthFileSchema>;
export type TruthClass = (typeof TRUTH_CLASSES)[number];

export function renderTruthJsonSchema(): string {
  return `${JSON.stringify(z.toJSONSchema(truthFileSchema), null, 2)}\n`;
}
