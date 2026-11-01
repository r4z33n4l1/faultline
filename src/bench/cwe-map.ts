import type { TruthClass } from "../schema/truth.js";

/**
 * CWE to a Faultline class. Rules with no entry here are out of the four
 * classes and are not detections. XSS, XXE, CSRF, open redirect, and
 * deserialization stay unmapped on purpose.
 *
 * When one rule lists several CWEs, the first matching class in
 * `CWE_CLASS_PRECEDENCE` wins.
 */
export const CWE_CLASS: Readonly<Record<string, TruthClass>> = {
  "CWE-918": "ssrf",
  "CWE-74": "injection",
  "CWE-77": "injection",
  "CWE-78": "injection",
  "CWE-88": "injection",
  "CWE-89": "injection",
  "CWE-90": "injection",
  "CWE-91": "injection",
  "CWE-94": "injection",
  "CWE-95": "injection",
  "CWE-96": "injection",
  "CWE-643": "injection",
  "CWE-917": "injection",
  "CWE-943": "injection",
  "CWE-1336": "injection",
  "CWE-256": "secrets",
  "CWE-259": "secrets",
  "CWE-311": "secrets",
  "CWE-312": "secrets",
  "CWE-321": "secrets",
  "CWE-522": "secrets",
  "CWE-532": "secrets",
  "CWE-540": "secrets",
  "CWE-798": "secrets",
  "CWE-284": "authz_idor",
  "CWE-285": "authz_idor",
  "CWE-306": "authz_idor",
  "CWE-566": "authz_idor",
  "CWE-639": "authz_idor",
  "CWE-862": "authz_idor",
  "CWE-863": "authz_idor",
};

export const CWE_CLASS_PRECEDENCE: readonly TruthClass[] = [
  "ssrf",
  "injection",
  "secrets",
  "authz_idor",
];

const CWE_TAG = /cwe-(\d+)/i;

/** Pull `CWE-<digits>` out of a tag such as `cwe-89` or `CWE-89: SQL Injection`. */
export function cweFromTag(tag: string): string | undefined {
  const match = CWE_TAG.exec(tag);
  if (match?.[1] === undefined) {
    return undefined;
  }
  return `CWE-${match[1]}`;
}

export function classForCwes(cwes: readonly string[]): TruthClass | undefined {
  const classes = new Set<TruthClass>();
  for (const cwe of cwes) {
    const mapped = CWE_CLASS[cwe];
    if (mapped !== undefined) {
      classes.add(mapped);
    }
  }
  for (const name of CWE_CLASS_PRECEDENCE) {
    if (classes.has(name)) {
      return name;
    }
  }
  return undefined;
}
