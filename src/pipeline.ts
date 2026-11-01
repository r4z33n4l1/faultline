import { randomUUID } from "node:crypto";
import type { ModelProvider } from "./providers/types.js";
import {
  SCHEMA_VERSION,
  findingsFileSchema,
  type FindingsFile,
  type Finding,
  type RunMode,
} from "./schema/finding.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

export interface PipelineInput {
  mode: RunMode;
  target: string;
  provider?: ModelProvider;
  startedAt?: Date;
  runId?: string;
  findings?: readonly Finding[];
}

/** Assemble the run envelope for confirmed findings. */
export function runPipeline(input: PipelineInput): FindingsFile {
  const run: FindingsFile["run"] = {
    id: input.runId ?? randomUUID(),
    started_at: (input.startedAt ?? new Date()).toISOString(),
    target: input.target,
    mode: input.mode,
  };
  if (input.provider !== undefined) {
    run.provider = input.provider.name;
  }

  return findingsFileSchema.parse({
    schema_version: SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    run,
    findings: input.findings ?? [],
  });
}
