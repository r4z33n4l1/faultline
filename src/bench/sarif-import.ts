import { isAbsolute, relative, resolve, sep } from "node:path";
import { classForCwes, cweFromTag } from "./cwe-map.js";
import { normalizeBenchPath, type DetectionSpan } from "./score.js";

/**
 * SARIF 2.1.0 to bench detections.
 *
 * CWEs are read from rule tags (`cwe-89`, `CWE-89: ...`) and from result
 * `taxa` ids. Message text is not scanned. A result whose CWEs do not map
 * to authz/IDOR, injection, secrets, or SSRF is skipped.
 * Paths are relative to `root`. Absolute URIs outside `root` are skipped.
 */

export interface SarifImport {
  detections: DetectionSpan[];
  skipped: number;
  toolName: string | null;
  toolVersion: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringOf(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0) {
    return undefined;
  }
  return value;
}

function cwesFromTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) {
    return [];
  }
  const found: string[] = [];
  for (const tag of tags) {
    if (typeof tag !== "string") {
      continue;
    }
    const cwe = cweFromTag(tag);
    if (cwe !== undefined) {
      found.push(cwe);
    }
  }
  return found;
}

function cwesFromRule(rule: unknown): string[] {
  if (!isRecord(rule)) {
    return [];
  }
  const properties = isRecord(rule.properties) ? rule.properties : undefined;
  const fromTags = cwesFromTags(properties?.tags);
  const fromCwe = cwesFromTags(properties?.cwe);
  return [...fromTags, ...fromCwe];
}

function ruleCwes(run: Record<string, unknown>): Map<string, string[]> {
  const map = new Map<string, string[]>();
  const tool = isRecord(run.tool) ? run.tool : undefined;
  const driver = tool !== undefined && isRecord(tool.driver) ? tool.driver : undefined;
  const rules = driver !== undefined && Array.isArray(driver.rules) ? driver.rules : [];
  for (const rule of rules) {
    if (!isRecord(rule)) {
      continue;
    }
    const cwes = cwesFromRule(rule);
    const id = stringOf(rule.id);
    const name = stringOf(rule.name);
    if (id !== undefined) {
      map.set(id, cwes);
    }
    if (name !== undefined) {
      map.set(name, cwes);
    }
  }
  return map;
}

function toolIdentity(run: Record<string, unknown>): {
  name: string | null;
  version: string | null;
} {
  const tool = isRecord(run.tool) ? run.tool : undefined;
  const driver = tool !== undefined && isRecord(tool.driver) ? tool.driver : undefined;
  if (driver === undefined) {
    return { name: null, version: null };
  }
  return {
    name: stringOf(driver.name) ?? null,
    version: stringOf(driver.semanticVersion) ?? stringOf(driver.version) ?? null,
  };
}

function resultCwes(result: Record<string, unknown>, rules: Map<string, string[]>): string[] {
  const found: string[] = [];
  const ruleId = stringOf(result.ruleId);
  if (ruleId !== undefined) {
    const mapped = rules.get(ruleId);
    if (mapped !== undefined) {
      found.push(...mapped);
    }
  }
  if (Array.isArray(result.taxa)) {
    for (const taxon of result.taxa) {
      if (!isRecord(taxon)) {
        continue;
      }
      const id = stringOf(taxon.id);
      if (id === undefined) {
        continue;
      }
      const cwe = cweFromTag(id);
      if (cwe !== undefined) {
        found.push(cwe);
      }
    }
  }
  const properties = isRecord(result.properties) ? result.properties : undefined;
  found.push(...cwesFromTags(properties?.tags));
  found.push(...cwesFromTags(properties?.cwe));
  return found;
}

function relativeToRoot(root: string, uri: string): string | undefined {
  const cleaned = uri.replaceAll("\\", "/");
  if (!isAbsolute(cleaned) && !/^[A-Za-z]:/.test(cleaned)) {
    const normalized = normalizeBenchPath(cleaned);
    if (normalized.startsWith("..") || normalized === "") {
      return undefined;
    }
    return normalized;
  }
  const rel = relative(root, resolve(cleaned));
  if (rel.length === 0 || rel.startsWith("..") || isAbsolute(rel)) {
    return undefined;
  }
  return normalizeBenchPath(rel.split(sep).join("/"));
}

function spanFromResult(
  result: Record<string, unknown>,
  rules: Map<string, string[]>,
  root: string,
): DetectionSpan | undefined {
  const truthClass = classForCwes(resultCwes(result, rules));
  if (truthClass === undefined) {
    return undefined;
  }
  if (!Array.isArray(result.locations) || result.locations.length === 0) {
    return undefined;
  }
  const location = result.locations[0];
  if (!isRecord(location) || !isRecord(location.physicalLocation)) {
    return undefined;
  }
  const physical = location.physicalLocation;
  const artifact = isRecord(physical.artifactLocation) ? physical.artifactLocation : undefined;
  const region = isRecord(physical.region) ? physical.region : undefined;
  const uri = artifact === undefined ? undefined : stringOf(artifact.uri);
  const start = region === undefined ? undefined : region.startLine;
  if (uri === undefined || typeof start !== "number" || !Number.isInteger(start) || start < 1) {
    return undefined;
  }
  const file = relativeToRoot(root, uri);
  if (file === undefined) {
    return undefined;
  }
  const endRaw = region?.endLine;
  const end =
    typeof endRaw === "number" && Number.isInteger(endRaw) && endRaw >= start ? endRaw : start;
  return { class: truthClass, file, startLine: start, endLine: end };
}

export function importSarif(document: unknown, root: string): SarifImport {
  if (!isRecord(document) || !Array.isArray(document.runs)) {
    throw new Error("SARIF document has no runs array");
  }
  const detections: DetectionSpan[] = [];
  let skipped = 0;
  let toolName: string | null = null;
  let toolVersion: string | null = null;
  for (const run of document.runs) {
    if (!isRecord(run)) {
      skipped += 1;
      continue;
    }
    const identity = toolIdentity(run);
    toolName = toolName ?? identity.name;
    toolVersion = toolVersion ?? identity.version;
    const rules = ruleCwes(run);
    const results = Array.isArray(run.results) ? run.results : [];
    for (const result of results) {
      if (!isRecord(result)) {
        skipped += 1;
        continue;
      }
      const span = spanFromResult(result, rules, root);
      if (span === undefined) {
        skipped += 1;
        continue;
      }
      detections.push(span);
    }
  }
  return { detections, skipped, toolName, toolVersion };
}
