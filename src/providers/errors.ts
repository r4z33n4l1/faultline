export type ProviderErrorCode =
  "missing_api_key" | "unknown_provider" | "timeout" | "aborted" | "http" | "network" | "response";

export function missingApiKeyMessage(name: string): string {
  return `Provider "${name}" requires FAULTLINE_API_KEY.`;
}

export function unknownProviderMessage(name: string): string {
  return `No model adapter is configured for provider "${name}".`;
}

export class ProviderError extends Error {
  readonly code: ProviderErrorCode;
  readonly providerName: string;
  readonly status?: number;

  constructor(
    message: string,
    init: { code: ProviderErrorCode; providerName: string; status?: number },
  ) {
    super(message);
    this.name = new.target.name;
    this.code = init.code;
    this.providerName = init.providerName;
    if (init.status !== undefined) {
      this.status = init.status;
    }
  }
}

export class MissingApiKeyError extends ProviderError {
  constructor(providerName: string) {
    super(missingApiKeyMessage(providerName), {
      code: "missing_api_key",
      providerName,
    });
  }
}

export class UnknownProviderError extends ProviderError {
  constructor(providerName: string) {
    super(unknownProviderMessage(providerName), {
      code: "unknown_provider",
      providerName,
    });
  }
}

export class ProviderTimeoutError extends ProviderError {
  constructor(providerName: string, timeoutMs: number) {
    super(`${providerName} request timed out after ${timeoutMs}ms.`, {
      code: "timeout",
      providerName,
    });
  }
}

export class ProviderAbortedError extends ProviderError {
  constructor(providerName: string) {
    super(`${providerName} request was aborted.`, {
      code: "aborted",
      providerName,
    });
  }
}

export class ProviderHttpError extends ProviderError {
  constructor(providerName: string, status: number, detail: string) {
    super(`${providerName} request failed with HTTP ${status}: ${detail}`, {
      code: "http",
      providerName,
      status,
    });
  }
}

export class ProviderRequestError extends ProviderError {
  constructor(providerName: string, detail: string) {
    super(`${providerName} request failed: ${detail}`, {
      code: "network",
      providerName,
    });
  }
}

export class ProviderResponseError extends ProviderError {
  constructor(providerName: string, detail: string) {
    super(`${providerName} response was invalid: ${detail}`, {
      code: "response",
      providerName,
    });
  }
}

/** The value actually sent. Empty and whitespace-only keys are missing. */
export function requireApiKey(providerName: string, apiKey: string | undefined): string {
  const trimmed = apiKey?.trim() ?? "";
  if (trimmed.length === 0) {
    throw new MissingApiKeyError(providerName);
  }
  return trimmed;
}

const REDACTED = "[redacted]";

/**
 * Strip the API key and credential headers from text that might be copied
 * into an error. Request headers are not logged; this is the backstop when
 * a transport error or response body echoes them.
 */
export function redactSensitive(text: string, secret: string | undefined): string {
  let out = text;
  if (secret !== undefined && secret.length > 0) {
    out = out.split(secret).join(REDACTED);
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret) {
      out = out.split(encoded).join(REDACTED);
    }
  }
  out = out.replace(/Bearer\s+\S+/gi, `Bearer ${REDACTED}`);
  out = out.replace(/((?:x-api-key|authorization)\s*[:=]\s*)\S+/gi, `$1${REDACTED}`);
  return out;
}
