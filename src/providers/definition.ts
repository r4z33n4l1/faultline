import type { Sleep } from "./http.js";
import type { ModelProvider } from "./types.js";

export interface ProviderCreateOptions {
  apiKey?: string;
  model?: string;
  baseUrl?: string;
  timeoutMs?: number;
  maxRetries?: number;
  fetch?: typeof fetch;
  sleep?: Sleep;
}

export interface ProviderDefinition {
  readonly name: string;
  readonly requiresApiKey: boolean;
  create(options: ProviderCreateOptions): ModelProvider;
}
