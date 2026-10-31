import { missingApiKeyMessage, unknownProviderMessage } from "./errors.js";
import { getProviderDefinition } from "./registry.js";

export interface ProviderConfig {
  name?: string;
  /** Present only in memory. Do not interpolate this into logs or errors. */
  apiKey?: string;
  model?: string;
  baseUrl?: string;
}

function cleanName(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function cleanKey(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * `--provider` wins over `FAULTLINE_PROVIDER`.
 * `--model` wins over `FAULTLINE_MODEL`.
 * The key is `FAULTLINE_API_KEY`. The base URL is `FAULTLINE_BASE_URL`.
 */
export function resolveProviderConfig(
  flag: string | undefined,
  env: NodeJS.ProcessEnv,
  modelFlag?: string,
): ProviderConfig {
  const name = cleanName(flag) ?? cleanName(env.FAULTLINE_PROVIDER);
  if (name === undefined) {
    return {};
  }
  const config: ProviderConfig = { name: name.toLowerCase() };
  const apiKey = cleanKey(env.FAULTLINE_API_KEY);
  const model = cleanName(modelFlag) ?? cleanName(env.FAULTLINE_MODEL);
  const baseUrl = cleanName(env.FAULTLINE_BASE_URL);
  if (apiKey !== undefined) {
    config.apiKey = apiKey;
  }
  if (model !== undefined) {
    config.model = model;
  }
  if (baseUrl !== undefined) {
    config.baseUrl = baseUrl;
  }
  return config;
}

/** Why this config cannot build a provider. Undefined when it can. */
export function providerUnavailableMessage(config: ProviderConfig): string | undefined {
  if (config.name === undefined) {
    return undefined;
  }
  const definition = getProviderDefinition(config.name);
  if (definition === undefined) {
    return unknownProviderMessage(config.name);
  }
  if (definition.requiresApiKey && config.apiKey === undefined) {
    return missingApiKeyMessage(config.name);
  }
  return undefined;
}
