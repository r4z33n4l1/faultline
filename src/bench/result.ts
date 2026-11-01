import * as z from "zod";
import { BENCH_OUTCOMES } from "./score.js";
import { TRUTH_CLASSES } from "../schema/truth.js";

export const BENCH_SCHEMA_VERSION = "1";
export const BENCH_STAGES = ["candidates", "findings"] as const;
export type BenchStage = (typeof BENCH_STAGES)[number];

/**
 * Stages stored in a bench result. `scan` is an external static tool.
 * Faultline's own `--stage` flag stays `candidates` or `findings`.
 */
export const RESULT_STAGES = ["candidates", "findings", "scan"] as const;
export type ResultStage = (typeof RESULT_STAGES)[number];

export const BENCH_DISCLAIMER =
  "This file measures one bench run. It is not a Faultline product result. Cite it only when provider, model, and commit are all recorded.";

const nonEmpty = z.string().min(1);
const count = z.number().int().nonnegative();
const rate = z.number().nullable();

export const confusionSchema = z.strictObject({
  class: nonEmpty,
  tp: count,
  fp: count,
  fn: count,
  tn: count,
  recall: rate,
  precision: rate,
  tpr: rate,
  fpr: rate,
  score: rate,
});

export const scoredEntrySchema = z.strictObject({
  id: nonEmpty,
  class: z.enum(TRUTH_CLASSES),
  cwe: z.string().regex(/^CWE-\d+$/),
  file: nonEmpty,
  start_line: z.number().int().min(1),
  end_line: z.number().int().min(1),
  vulnerable: z.boolean(),
  outcome: z.enum(BENCH_OUTCOMES),
});

export const unmatchedSchema = z.strictObject({
  class: nonEmpty,
  file: nonEmpty,
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
});

export const benchResultSchema = z.strictObject({
  schema_version: z.literal(BENCH_SCHEMA_VERSION),
  disclaimer: z.literal(BENCH_DISCLAIMER),
  citable: z.boolean(),
  stage: z.enum(RESULT_STAGES),
  target: nonEmpty,
  truth: nonEmpty,
  tool: z.strictObject({
    name: nonEmpty,
    version: nonEmpty,
  }),
  run: z.strictObject({
    id: nonEmpty,
    started_at: z.iso.datetime(),
    provider: nonEmpty.nullable(),
    model: nonEmpty.nullable(),
    commit: z
      .string()
      .regex(/^[0-9a-f]{40}$/)
      .nullable(),
  }),
  counts: z.strictObject({
    truth: count,
    vulnerable: count,
    safe: count,
    detections: count,
    unmatched: count,
  }),
  overall: confusionSchema,
  classes: z.array(confusionSchema),
  entries: z.array(scoredEntrySchema),
  unmatched: z.array(unmatchedSchema),
});

export type BenchResult = z.infer<typeof benchResultSchema>;
