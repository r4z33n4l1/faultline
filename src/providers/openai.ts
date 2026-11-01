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
import type { CompleteInput, ModelProvider } from "./types.js";

export const OPENAI_DEFAULT_MODEL = "gpt-4o-mini";
export const OPENAI_DEFAULT_BASE_URL = "https://api.openai.com/v1";

/**
 * OpenAI-compatible Chat Completions. `baseUrl` defaults to the OpenAI API
 * and can point at OpenRouter, Ollama, vLLM, or another compatible server.
 * Returns text only. `jsonSchema` is not sent. Tool calls are not executed.
 */
export class OpenAIProvider implements ModelProvider {
  readonly name = "openai";
  readonly #apiKey: string;
  readonly #model: string;
  readonly #baseUrl: string;
  readonly #timeoutMs: number;
  readonly #maxRetries: number;
  readonly #fetchImpl: typeof fetch;
  readonly #sleep: Sleep;

  constructor(options: ProviderCreateOptions & { apiKey: string }) {
    this.#apiKey = options.apiKey;
    this.#model = options.model ?? OPENAI_DEFAULT_MODEL;
    this.#baseUrl = options.baseUrl ?? OPENAI_DEFAULT_BASE_URL;
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
      url: resolveEndpoint(this.#baseUrl, "chat/completions", this.name, this.#apiKey),
      headers: {
        authorization: `Bearer ${this.#apiKey}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: {
        model: this.#model,
        messages: input.messages.map((message) => ({
          role: message.role,
          content: message.content,
        })),
        stream: false,
      },
      apiKey: this.#apiKey,
      timeoutMs: this.#timeoutMs,
      maxRetries: this.#maxRetries,
      signal: input.signal,
      fetchImpl: this.#fetchImpl,
      sleep: this.#sleep,
    });
    return textFromOpenAI(payload);
  }
}

export const openaiProviderDefinition: ProviderDefinition = {
  name: "openai",
  requiresApiKey: true,
  create(options) {
    return new OpenAIProvider({
      ...options,
      apiKey: requireApiKey("openai", options.apiKey),
    });
  },
};

function textFromOpenAI(payload: unknown): string {
  if (!isRecord(payload)) {
    throw new ProviderResponseError("openai", "response did not include choices");
  }
  const choices = payload["choices"];
  if (!Array.isArray(choices) || choices.length === 0) {
    throw new ProviderResponseError("openai", "response did not include choices");
  }
  const first = choices[0];
  if (!isRecord(first)) {
    throw new ProviderResponseError("openai", "response did not include a message");
  }
  const message = first["message"];
  if (!isRecord(message)) {
    throw new ProviderResponseError("openai", "response did not include a message");
  }
  const text = textFromContent(message["content"]);
  if (text === undefined) {
    throw new ProviderResponseError("openai", "response did not include text");
  }
  return text;
}
