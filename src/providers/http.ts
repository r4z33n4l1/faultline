import { setTimeout as delay } from "node:timers/promises";
import {
  ProviderAbortedError,
  ProviderError,
  ProviderHttpError,
  ProviderRequestError,
  ProviderResponseError,
  ProviderTimeoutError,
  redactSensitive,
} from "./errors.js";

export const DEFAULT_TIMEOUT_MS = 60_000;
export const DEFAULT_MAX_RETRIES = 2;

const MAX_RETRY_ATTEMPTS = 5;
const BASE_DELAY_MS = 200;
const MAX_BACKOFF_MS = 5_000;
const MAX_RETRY_AFTER_MS = 30_000;
const SNIPPET_CHARS = 300;

export type Sleep = (ms: number, signal?: AbortSignal) => Promise<void>;

export interface JsonRequest {
  providerName: string;
  url: string;
  headers: Readonly<Record<string, string>>;
  body: unknown;
  /** Used only to redact error text. Never written into an error or log. */
  apiKey: string;
  timeoutMs: number;
  maxRetries: number;
  signal?: AbortSignal;
  fetchImpl: typeof fetch;
  sleep: Sleep;
}

export function boundedTimeout(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value) || value <= 0) {
    return DEFAULT_TIMEOUT_MS;
  }
  return Math.min(value, 10 * 60 * 1000);
}

export function boundedRetries(value: number | undefined): number {
  if (value === undefined || !Number.isInteger(value) || value < 0) {
    return DEFAULT_MAX_RETRIES;
  }
  return Math.min(value, MAX_RETRY_ATTEMPTS);
}

export async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
  }
  if (ms <= 0) {
    return;
  }
  await delay(ms, undefined, { signal });
}

export function retryDelayMs(attempt: number, retryAfter: string | null): number {
  if (retryAfter !== null) {
    const fromHeader = retryAfterToMs(retryAfter);
    if (fromHeader !== undefined) {
      return fromHeader;
    }
  }
  return Math.min(BASE_DELAY_MS * 2 ** attempt, MAX_BACKOFF_MS);
}

export function resolveEndpoint(
  base: string,
  path: string,
  providerName: string,
  apiKey: string,
): string {
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    throw new ProviderRequestError(
      providerName,
      `base URL is invalid: ${snippet(redactSensitive(base, apiKey))}`,
    );
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ProviderRequestError(providerName, "base URL must use http or https");
  }
  if (url.username !== "" || url.password !== "" || urlContainsSecret(url, apiKey)) {
    throw new ProviderRequestError(
      providerName,
      "base URL must not include credentials or the API key",
    );
  }
  const extra = path.replace(/^\/+/, "");
  const prefix = url.pathname.replace(/\/+$/, "");
  url.pathname = `${prefix}/${extra}`.replace(/\/{2,}/g, "/");
  url.hash = "";
  return url.toString();
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Text parts only. Tool calls and other block types are dropped. */
export function textFromContent(content: unknown): string | undefined {
  if (typeof content === "string") {
    return content;
  }
  if (!Array.isArray(content)) {
    return undefined;
  }
  const parts: string[] = [];
  for (const part of content) {
    if (typeof part === "string") {
      parts.push(part);
      continue;
    }
    if (isRecord(part) && part["type"] === "text" && typeof part["text"] === "string") {
      parts.push(part["text"]);
    }
  }
  return parts.length > 0 ? parts.join("") : undefined;
}

export async function requestJson(request: JsonRequest): Promise<unknown> {
  const timeoutSignal = AbortSignal.timeout(request.timeoutMs);
  const signals: AbortSignal[] = [timeoutSignal];
  if (request.signal !== undefined) {
    signals.push(request.signal);
  }
  const signal = AbortSignal.any(signals);
  const attempts = request.maxRetries + 1;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    throwIfStopped(request, timeoutSignal);
    let response: Response;
    try {
      response = await request.fetchImpl(request.url, {
        method: "POST",
        headers: { ...request.headers },
        body: JSON.stringify(request.body),
        signal,
      });
    } catch (error) {
      throw transportError(error, request, timeoutSignal);
    }

    const text = await readBody(response, request, timeoutSignal);
    if (response.ok) {
      return parseBody(request, text);
    }

    const retryable = response.status === 429 || (response.status >= 500 && response.status <= 599);
    if (retryable && attempt < attempts - 1) {
      await sleepOrStop(
        request,
        timeoutSignal,
        retryDelayMs(attempt, response.headers.get("retry-after")),
        signal,
      );
      continue;
    }

    throw new ProviderHttpError(
      request.providerName,
      response.status,
      snippet(redactSensitive(text, request.apiKey)),
    );
  }

  throw new ProviderRequestError(request.providerName, "request failed");
}

function retryAfterToMs(header: string): number | undefined {
  const trimmed = header.trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, MAX_RETRY_AFTER_MS);
  }
  const when = Date.parse(trimmed);
  if (Number.isNaN(when)) {
    return undefined;
  }
  return Math.min(Math.max(0, when - Date.now()), MAX_RETRY_AFTER_MS);
}

function urlContainsSecret(url: URL, secret: string): boolean {
  // Short dummy keys (local servers) can be substrings of a normal host.
  // Longer secrets are refused anywhere in the URL so they are not sent.
  if (secret.length < 12) {
    return false;
  }
  const haystack = url.href;
  if (haystack.includes(secret)) {
    return true;
  }
  const encoded = encodeURIComponent(secret);
  return encoded !== secret && haystack.includes(encoded);
}

function snippet(text: string): string {
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return "(empty body)";
  }
  if (trimmed.length <= SNIPPET_CHARS) {
    return trimmed;
  }
  return `${trimmed.slice(0, SNIPPET_CHARS)}…`;
}

function messageOf(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function isTimeoutError(error: unknown): boolean {
  return error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError");
}

function throwIfStopped(request: JsonRequest, timeoutSignal: AbortSignal): void {
  if (request.signal?.aborted) {
    throw new ProviderAbortedError(request.providerName);
  }
  if (timeoutSignal.aborted) {
    throw new ProviderTimeoutError(request.providerName, request.timeoutMs);
  }
}

function transportError(
  error: unknown,
  request: JsonRequest,
  timeoutSignal: AbortSignal,
): ProviderError {
  if (error instanceof ProviderError) {
    return error;
  }
  if (request.signal?.aborted) {
    return new ProviderAbortedError(request.providerName);
  }
  if (timeoutSignal.aborted || isTimeoutError(error)) {
    return new ProviderTimeoutError(request.providerName, request.timeoutMs);
  }
  return new ProviderRequestError(
    request.providerName,
    snippet(redactSensitive(messageOf(error), request.apiKey)),
  );
}

async function readBody(
  response: Response,
  request: JsonRequest,
  timeoutSignal: AbortSignal,
): Promise<string> {
  try {
    return await response.text();
  } catch (error) {
    throw transportError(error, request, timeoutSignal);
  }
}

function parseBody(request: JsonRequest, text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ProviderResponseError(
      request.providerName,
      snippet(redactSensitive(text, request.apiKey)),
    );
  }
}

async function sleepOrStop(
  request: JsonRequest,
  timeoutSignal: AbortSignal,
  ms: number,
  signal: AbortSignal,
): Promise<void> {
  try {
    await request.sleep(ms, signal);
  } catch (error) {
    throw transportError(error, request, timeoutSignal);
  }
}
