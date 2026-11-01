import * as z from "zod";

export const COVERAGE_SCHEMA_VERSION = "1";
export const COVERAGE_CLASSES = ["authz_idor", "injection", "secrets", "ssrf"] as const;
export const COVERAGE_STATUSES = ["pending", "hunted", "skipped"] as const;
export const COVERAGE_SKIP_REASONS = [
  "default-exclude",
  "gitignore",
  "exclude",
  "lockfile",
  "minified",
  "snapshot",
  "binary",
  "max-file-bytes",
  "max-files",
  "max-bytes",
] as const;

const nonEmpty = z.string().min(1);

const fileUnitSchema = z.strictObject({
  id: nonEmpty,
  kind: z.literal("file"),
  path: nonEmpty,
  class: z.enum(COVERAGE_CLASSES),
  status: z.enum(COVERAGE_STATUSES),
  reason: nonEmpty,
});

const routeUnitSchema = z.strictObject({
  id: nonEmpty,
  kind: z.literal("route"),
  path: nonEmpty,
  route: nonEmpty,
  line: z.number().int().min(1),
  class: z.enum(COVERAGE_CLASSES),
  status: z.enum(COVERAGE_STATUSES),
  reason: nonEmpty,
});

export const coverageUnitSchema = z.discriminatedUnion("kind", [fileUnitSchema, routeUnitSchema]);

export const coverageSkipSchema = z.strictObject({
  path: nonEmpty,
  reason: z.enum(COVERAGE_SKIP_REASONS),
});

export const coverageFileSchema = z.strictObject({
  schema_version: z.literal(COVERAGE_SCHEMA_VERSION),
  target: nonEmpty,
  units: z.array(coverageUnitSchema),
  skipped: z.array(coverageSkipSchema),
});

export type CoverageFile = z.infer<typeof coverageFileSchema>;
export type CoverageUnit = z.infer<typeof coverageUnitSchema>;
export type CoverageSkip = z.infer<typeof coverageSkipSchema>;
export type CoverageClass = (typeof COVERAGE_CLASSES)[number];
export type CoverageStatus = (typeof COVERAGE_STATUSES)[number];
export type CoverageSkipReason = (typeof COVERAGE_SKIP_REASONS)[number];

export function renderCoverageJsonSchema(): string {
  return `${JSON.stringify(z.toJSONSchema(coverageFileSchema), null, 2)}\n`;
}
