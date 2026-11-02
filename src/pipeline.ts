import { randomUUID } from "node:crypto";
import { resolveRunModel, type ModelProvider } from "./providers/types.js";
import {
  SCHEMA_VERSION,
  findingsFileSchema,
  type FindingsFile,
  type Finding,
  type RunMode,
} from "./schema/finding.js";
import { TOOL_NAME, TOOL_VERSION, faultlineCommit } from "./version.js";

export interface PipelineInput {
  mode: RunMode;
  target: string;
  provider?: ModelProvider;
  /** Resolved model id. Null when this run did not call a named model. */
  model?: string | null;
  /** Faultline checkout commit. Null when git cannot answer. */
  commit?: string | null;
  startedAt?: Date;
  runId?: string;
  findings?: readonly Finding[];
  /** Provider or transport failures recorded for this run. */
  providerErrorCount?: number;
  /** First provider failure message, already secret-redacted. */
  providerError?: string;
}

export async function provenanceFor(
  provider: ModelProvider | undefined,
  configuredModel: string | null = null,
): Promise<{ model: string | null; commit: string | null }> {
  const [model, commit] = await Promise.all([
    resolveRunModel(provider, configuredModel),
    faultlineCommit(),
  ]);
  return { model, commit };
}

/** Assemble the run envelope for confirmed findings. */
export function runPipeline(input: PipelineInput): FindingsFile {
  const run: FindingsFile["run"] = {
    id: input.runId ?? randomUUID(),
    started_at: (input.startedAt ?? new Date()).toISOString(),
    target: input.target,
    mode: input.mode,
    provider: input.provider?.name ?? null,
    model: input.model ?? input.provider?.model ?? null,
    commit: input.commit ?? null,
    provider_error_count: input.providerErrorCount ?? 0,
    ...(input.providerError === undefined || input.providerError.length === 0
      ? {}
      : { provider_error: input.providerError }),
  };

  return findingsFileSchema.parse({
    schema_version: SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    run,
    findings: input.findings ?? [],
  });
}
