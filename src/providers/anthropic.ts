import type { ProviderCreateOptions, ProviderDefinition } from "./definition.js";
import { ProviderResponseError, requireApiKey } from "./errors.js";
import {
  boundedRetries,
  boundedTimeout,
  isRecord,
  requestJson,
  resolveEndpoint,
  sleep,
  textFromContent,
  type Sleep,
} from "./http.js";
import type { CompleteInput, ModelMessage, ModelProvider } from "./types.js";

export const ANTHROPIC_DEFAULT_MODEL = "claude-3-5-haiku-latest";
export const ANTHROPIC_DEFAULT_BASE_URL = "https://api.anthropic.com";
export const ANTHROPIC_VERSION = "2023-06-01";
export const ANTHROPIC_MAX_TOKENS = 4096;

/**
 * Anthropic Messages API. Returns text only. `jsonSchema` is not sent.
 * Tool-use blocks are ignored and never executed.
 */
export class AnthropicProvider implements ModelProvider {
  readonly name = "anthropic";
  readonly #apiKey: string;
  readonly #model: string;
  readonly #baseUrl: string;
  readonly #timeoutMs: number;
  readonly #maxRetries: number;
  readonly #fetchImpl: typeof fetch;
  readonly #sleep: Sleep;

  constructor(options: ProviderCreateOptions & { apiKey: string }) {
    this.#apiKey = options.apiKey;
    this.#model = options.model ?? ANTHROPIC_DEFAULT_MODEL;
    this.#baseUrl = options.baseUrl ?? ANTHROPIC_DEFAULT_BASE_URL;
    this.#timeoutMs = boundedTimeout(options.timeoutMs);
    this.#maxRetries = boundedRetries(options.maxRetries);
    this.#fetchImpl = options.fetch ?? globalThis.fetch;
    this.#sleep = options.sleep ?? sleep;
  }

  get model(): string {
    return this.#model;
  }

  async complete(input: CompleteInput): Promise<string> {
    const payload = await requestJson({
      providerName: this.name,
      url: resolveEndpoint(this.#baseUrl, "v1/messages", this.name, this.#apiKey),
      headers: {
        "x-api-key": this.#apiKey,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: anthropicBody(this.#model, input.messages),
      apiKey: this.#apiKey,
      timeoutMs: this.#timeoutMs,
      maxRetries: this.#maxRetries,
      signal: input.signal,
      fetchImpl: this.#fetchImpl,
      sleep: this.#sleep,
    });
    return textFromAnthropic(payload);
  }
}

export const anthropicProviderDefinition: ProviderDefinition = {
  name: "anthropic",
  requiresApiKey: true,
  create(options) {
    return new AnthropicProvider({
      ...options,
      apiKey: requireApiKey("anthropic", options.apiKey),
    });
  },
};

interface AnthropicBody {
  model: string;
  max_tokens: number;
  stream: false;
  system?: string;
  messages: { role: "user" | "assistant"; content: string }[];
}

function anthropicBody(model: string, messages: readonly ModelMessage[]): AnthropicBody {
  const system = messages
    .filter((message) => message.role === "system")
    .map((message) => message.content)
    .join("\n\n");
  const chat: AnthropicBody["messages"] = [];
  for (const message of messages) {
    if (message.role === "system") {
      continue;
    }
    chat.push({ role: message.role, content: message.content });
  }
  const body: AnthropicBody = {
    model,
    max_tokens: ANTHROPIC_MAX_TOKENS,
    stream: false,
    messages: chat,
  };
  if (system.length > 0) {
    body.system = system;
  }
  return body;
}

function textFromAnthropic(payload: unknown): string {
  if (!isRecord(payload)) {
    throw new ProviderResponseError("anthropic", "response was not a JSON object");
  }
  const text = textFromContent(payload["content"]);
  if (text === undefined) {
    throw new ProviderResponseError("anthropic", "response did not include text");
  }
  return text;
}
