export interface ModelMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface CompleteInput {
  messages: readonly ModelMessage[];
  jsonSchema?: unknown;
  signal?: AbortSignal;
}

export interface ModelProvider {
  readonly name: string;
  /** Resolved model id when the provider already knows one. */
  readonly model?: string;
  complete(input: CompleteInput): Promise<string>;
  /**
   * Fill a model id that is still unknown after the run.
   * Codex uses this to record `codex-cli-default` plus the CLI version.
   */
  resolveModel?(): Promise<string | undefined>;
}

/** Model id to store on a run. Prefers the provider, then the configured fallback. */
export async function resolveRunModel(
  provider: ModelProvider | undefined,
  configured: string | null,
): Promise<string | null> {
  if (provider?.model !== undefined && provider.model.length > 0) {
    return provider.model;
  }
  if (provider?.resolveModel !== undefined) {
    const resolved = await provider.resolveModel();
    if (resolved !== undefined && resolved.length > 0) {
      return resolved;
    }
  }
  return configured;
}

export class FakeProvider implements ModelProvider {
  readonly name: string;
  model?: string;
  readonly calls: CompleteInput[] = [];

  constructor(
    private readonly reply: string | ((input: CompleteInput) => string | Promise<string>) = "",
    name = "fake",
  ) {
    this.name = name;
  }

  async complete(input: CompleteInput): Promise<string> {
    this.calls.push(input);
    if (input.signal?.aborted) {
      throw new Error("aborted");
    }
    return this.reply instanceof Function ? this.reply(input) : this.reply;
  }
}
