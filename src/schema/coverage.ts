import * as z from "zod";

export const COVERAGE_SCHEMA_VERSION = "1";
export const COVERAGE_CLASSES = ["authz_idor", "injection", "secrets", "ssrf"] as const;
export const COVERAGE_STATUSES = ["pending", "hunted", "skipped"] as const;

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

export const coverageFileSchema = z.strictObject({
  schema_version: z.literal(COVERAGE_SCHEMA_VERSION),
  target: nonEmpty,
  units: z.array(coverageUnitSchema),
});

export type CoverageFile = z.infer<typeof coverageFileSchema>;
export type CoverageUnit = z.infer<typeof coverageUnitSchema>;
export type CoverageClass = (typeof COVERAGE_CLASSES)[number];
export type CoverageStatus = (typeof COVERAGE_STATUSES)[number];

export function renderCoverageJsonSchema(): string {
  return `${JSON.stringify(z.toJSONSchema(coverageFileSchema), null, 2)}\n`;
}
