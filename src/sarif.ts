import { createHash } from "node:crypto";
import * as z from "zod";
import {
  CONFIDENCE_LEVELS,
  EXPLOITABILITIES,
  type Finding,
  type FindingClass,
  type FindingsFile,
  type Severity,
} from "./schema/finding.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

/**
 * SARIF 2.1.0 export for confirmed findings.
 *
 * Artifact URIs are relative to the scan root (forward slashes, never absolute).
 * `originalUriBaseIds` is omitted. `fixes` from `suggested_fix.patch` are deferred.
 */
export const SARIF_VERSION = "2.1.0" as const;

export const SARIF_SCHEMA_URI =
  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/** Stable across re-runs. Bump if the hash input changes. */
export const FINGERPRINT_KEY = "faultline/v1" as const;

const SARIF_LEVELS = ["error", "warning", "note"] as const;

const LEVEL_BY_SEVERITY: Record<Severity, (typeof SARIF_LEVELS)[number]> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  informational: "note",
};

const CLASS_SUMMARY: Record<FindingClass, string> = {
  authz_idor: "Authorization or insecure direct object reference.",
  injection: "Injection.",
  secrets: "Exposed secret.",
  ssrf: "Server-side request forgery.",
  other: "Other confirmed weakness.",
};

const textMessageSchema = z.strictObject({
  text: z.string().min(1),
});

const relativeUriSchema = z
  .string()
  .min(1)
  .refine(
    (uri) =>
      !uri.startsWith("/") &&
      !/^[A-Za-z]:/.test(uri) &&
      !uri.includes("\\") &&
      !uri.includes("://") &&
      !/\s/.test(uri),
    { message: "artifact uri must be a relative forward-slash URI" },
  );

const regionSchema = z
  .strictObject({
    startLine: z.number().int().min(1),
    endLine: z.number().int().min(1).optional(),
  })
  .refine((region) => region.endLine === undefined || region.endLine >= region.startLine, {
    message: "endLine must be >= startLine",
    path: ["endLine"],
  });

const resultPropertiesSchema = z.strictObject({
  "ai/origin": z.literal("faultline"),
  "ai/exploitability": z.enum(EXPLOITABILITIES),
  confidence: z.enum(CONFIDENCE_LEVELS),
  validator_verdict: z.literal("confirmed"),
});

const resultSchema = z.strictObject({
  ruleId: z.string().min(1),
  level: z.enum(SARIF_LEVELS),
  message: textMessageSchema,
  locations: z
    .array(
      z.strictObject({
        physicalLocation: z.strictObject({
          artifactLocation: z.strictObject({
            uri: relativeUriSchema,
          }),
          region: regionSchema,
        }),
      }),
    )
    .min(1),
  partialFingerprints: z.strictObject({
    [FINGERPRINT_KEY]: z.string().regex(/^[0-9a-f]{64}$/),
  }),
  properties: resultPropertiesSchema,
});

const ruleSchema = z.strictObject({
  id: z.string().min(1),
  shortDescription: textMessageSchema,
});

const runSchema = z.strictObject({
  tool: z.strictObject({
    driver: z.strictObject({
      name: z.literal(TOOL_NAME),
      version: z.string().min(1),
      rules: z.array(ruleSchema),
    }),
  }),
  results: z.array(resultSchema),
});

export const sarifLogSchema = z.strictObject({
  $schema: z.literal(SARIF_SCHEMA_URI),
  version: z.literal(SARIF_VERSION),
  runs: z.tuple([runSchema]),
});

export type SarifLog = z.infer<typeof sarifLogSchema>;

interface AbsolutePath {
  /** Uppercase drive letter, or "" for a POSIX absolute path. */
  drive: string;
  parts: string[];
}

function absoluteParts(pathAfterRoot: string): string[] {
  const parts: string[] = [];
  for (const part of pathAfterRoot.split("/")) {
    if (part === "" || part === ".") {
      continue;
    }
    if (part === "..") {
      parts.pop();
      continue;
    }
    parts.push(part);
  }
  return parts;
}

function splitAbsolute(file: string): AbsolutePath | undefined {
  const slashed = file.replaceAll("\\", "/");
  const windows = /^([A-Za-z]):\/(.*)$/.exec(slashed);
  if (windows !== null) {
    const letter = windows[1];
    const rest = windows[2];
    if (letter === undefined || rest === undefined) {
      return undefined;
    }
    return { drive: letter.toUpperCase(), parts: absoluteParts(rest) };
  }
  if (slashed.startsWith("/")) {
    return { drive: "", parts: absoluteParts(slashed.slice(1)) };
  }
  return undefined;
}

function normalizeRelative(file: string): string {
  const parts: string[] = [];
  for (const part of file.replaceAll("\\", "/").split("/")) {
    if (part === "" || part === ".") {
      continue;
    }
    if (part === "..") {
      if (parts.length > 0 && parts[parts.length - 1] !== "..") {
        parts.pop();
      } else {
        parts.push("..");
      }
      continue;
    }
    parts.push(part);
  }
  return parts.length === 0 ? "." : parts.join("/");
}

function relativeAbsolute(from: AbsolutePath, to: AbsolutePath): string {
  if (from.drive !== to.drive) {
    const prefix = to.drive === "" ? [] : [to.drive];
    const joined = [...prefix, ...to.parts].join("/");
    return joined.length === 0 ? "." : joined;
  }
  let index = 0;
  while (
    index < from.parts.length &&
    index < to.parts.length &&
    from.parts[index] === to.parts[index]
  ) {
    index += 1;
  }
  const parts = [
    ...Array.from({ length: from.parts.length - index }, () => ".."),
    ...to.parts.slice(index),
  ];
  return parts.length === 0 ? "." : parts.join("/");
}

/** Scan-root-relative path. Relative finding paths are not joined onto scanRoot. */
function logicalArtifactPath(file: string, scanRoot: string): string {
  const absolute = splitAbsolute(file);
  if (absolute === undefined) {
    return normalizeRelative(file);
  }
  const root = splitAbsolute(scanRoot);
  if (root === undefined) {
    const prefix = absolute.drive === "" ? [] : [absolute.drive];
    const joined = [...prefix, ...absolute.parts].join("/");
    return joined.length === 0 ? "." : joined;
  }
  return relativeAbsolute(root, absolute);
}

function encodeSarifUri(relativePath: string): string {
  return relativePath
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

function ruleIdFor(finding: Finding): string {
  if (finding.cwe !== undefined) {
    return `${finding.cwe}/${finding.class}`;
  }
  return `faultline/${finding.class}`;
}

function ruleText(finding: Finding): string {
  const summary = CLASS_SUMMARY[finding.class];
  if (finding.cwe !== undefined) {
    return `${finding.cwe} ${summary}`;
  }
  return summary;
}

/** sha256 of JSON `[class, scan-root-relative file, root_cause]`. Lines are not included. */
function fingerprintFor(findingClass: string, file: string, rootCause: string): string {
  return createHash("sha256")
    .update(JSON.stringify([findingClass, file, rootCause]), "utf8")
    .digest("hex");
}

function regionFor(location: Finding["location"]): { startLine: number; endLine?: number } {
  if (location.end_line === undefined) {
    return { startLine: location.start_line };
  }
  return { startLine: location.start_line, endLine: location.end_line };
}

/** Confirmed findings to a SARIF log. Does not read the tree or include unconfirmed results. */
export function toSarif(file: FindingsFile, scanRoot: string): SarifLog {
  const rules: z.infer<typeof ruleSchema>[] = [];
  const seen = new Set<string>();
  const results: z.infer<typeof resultSchema>[] = [];

  for (const finding of file.findings) {
    const ruleId = ruleIdFor(finding);
    if (!seen.has(ruleId)) {
      seen.add(ruleId);
      rules.push({
        id: ruleId,
        shortDescription: { text: ruleText(finding) },
      });
    }

    const logicalPath = logicalArtifactPath(finding.location.file, scanRoot);
    // suggested_fix.patch is not copied into SARIF fixes; that mapping is deferred.
    results.push({
      ruleId,
      level: LEVEL_BY_SEVERITY[finding.severity],
      message: { text: finding.root_cause },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: encodeSarifUri(logicalPath) },
            region: regionFor(finding.location),
          },
        },
      ],
      partialFingerprints: {
        [FINGERPRINT_KEY]: fingerprintFor(finding.class, logicalPath, finding.root_cause),
      },
      properties: {
        "ai/origin": "faultline",
        "ai/exploitability": finding.exploitability,
        confidence: finding.confidence.level,
        validator_verdict: finding.validator_verdict,
      },
    });
  }

  return sarifLogSchema.parse({
    $schema: SARIF_SCHEMA_URI,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            rules,
          },
        },
        results,
      },
    ],
  });
}

export function serializeSarif(log: SarifLog): string {
  return `${JSON.stringify(log, null, 2)}\n`;
}
