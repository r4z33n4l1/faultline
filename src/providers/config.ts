export interface ProviderConfig {
  name?: string;
  /** Present only in memory. Do not interpolate this into logs or errors. */
  apiKey?: string;
}

function cleanName(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/** `--provider` wins over FAULTLINE_PROVIDER. The key is FAULTLINE_API_KEY. */
export function resolveProviderConfig(
  flag: string | undefined,
  env: NodeJS.ProcessEnv,
): ProviderConfig {
  const name = cleanName(flag) ?? cleanName(env.FAULTLINE_PROVIDER);
  if (name === undefined) {
    return {};
  }
  const apiKey = env.FAULTLINE_API_KEY;
  return {
    name,
    apiKey: apiKey !== undefined && apiKey.length > 0 ? apiKey : undefined,
  };
}

/** Safe to print. The API key is never included. */
export function providerUnavailableMessage(config: ProviderConfig): string {
  const name = config.name ?? "provider";
  if (config.apiKey === undefined) {
    return `Provider "${name}" requires FAULTLINE_API_KEY.`;
  }
  return `No model adapter is configured for provider "${name}".`;
}
