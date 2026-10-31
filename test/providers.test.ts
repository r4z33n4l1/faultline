import { inspect } from "node:util";
import { expect, it } from "vitest";
import { ANTHROPIC_DEFAULT_MODEL, ANTHROPIC_VERSION } from "../src/providers/anthropic.js";
import { resolveProviderConfig } from "../src/providers/config.js";
import {
  MissingApiKeyError,
  ProviderAbortedError,
  ProviderHttpError,
  ProviderRequestError,
  ProviderResponseError,
  ProviderTimeoutError,
  UnknownProviderError,
} from "../src/providers/errors.js";
import { retryDelayMs, type Sleep } from "../src/providers/http.js";
import { OPENAI_DEFAULT_MODEL } from "../src/providers/openai.js";
import { createProvider, listProviderNames } from "../src/providers/registry.js";
import type { CompleteInput, ModelMessage } from "../src/providers/types.js";

const messages: ModelMessage[] = [
  { role: "system", content: "one" },
  { role: "system", content: "two" },
  { role: "user", content: "hello" },
  { role: "assistant", content: "prior" },
];

const input: CompleteInput = {
  messages,
  jsonSchema: { type: "object", properties: { tools: { type: "array" } } },
};

interface Captured {
  url: string;
  method: string;
  headers: Headers;
  body: Record<string, unknown>;
}

function mockFetch(handler: (call: number) => Response | Promise<Response>): {
  fetchImpl: typeof fetch;
  calls: Captured[];
} {
  const calls: Captured[] = [];
  const fetchImpl: typeof fetch = async (url, init) => {
    calls.push({
      url: String(url),
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>,
    });
    return handler(calls.length);
  };
  return { fetchImpl, calls };
}

function immediateSleep(): Sleep {
  return async () => undefined;
}

function dumpError(error: unknown): string {
  const parts: string[] = [String(error), inspect(error, { depth: 8, showHidden: true })];
  const seen = new Set<unknown>();
  const walk = (value: unknown): void => {
    if (typeof value === "string") {
      parts.push(value);
      return;
    }
    if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
      parts.push(String(value));
      return;
    }
    if (value === null || value === undefined || typeof value === "function") {
      return;
    }
    if (typeof value !== "object") {
      return;
    }
    if (seen.has(value)) {
      return;
    }
    seen.add(value);
    if (value instanceof Error) {
      parts.push(value.name, value.message, value.stack ?? "");
      walk((value as { cause?: unknown }).cause);
    }
    const record = value as Record<string | symbol, unknown>;
    for (const key of [
      ...Object.getOwnPropertyNames(value),
      ...Object.getOwnPropertySymbols(value),
    ]) {
      walk(record[key]);
    }
  };
  walk(error);
  return parts.join("\n");
}

function openaiResponse(content: unknown): Response {
  return Response.json({ choices: [{ message: { role: "assistant", content } }] });
}

function anthropicResponse(content: unknown): Response {
  return Response.json({ content });
}

it("registers fake, openai, and anthropic", async () => {
  expect(listProviderNames()).toEqual(["fake", "openai", "anthropic"]);
  const fake = createProvider("fake");
  expect(fake.name).toBe("fake");
  await expect(fake.complete(input)).resolves.toBe("");
  expect(createProvider(" OpenAI ", { apiKey: "sk-test" }).name).toBe("openai");
});

it("throws a typed error when the API key is missing", () => {
  expect(() => createProvider("openai", {})).toThrow(MissingApiKeyError);
  expect(() => createProvider("openai", { apiKey: "   " })).toThrow(
    'Provider "openai" requires FAULTLINE_API_KEY.',
  );
  expect(() => createProvider("anthropic", { apiKey: "" })).toThrow(MissingApiKeyError);
  expect(() => createProvider("anthropic", {})).toThrow(
    'Provider "anthropic" requires FAULTLINE_API_KEY.',
  );
});

it("reads provider, model, and base URL with flag precedence", () => {
  expect(
    resolveProviderConfig(
      undefined,
      {
        FAULTLINE_PROVIDER: "OpenAI",
        FAULTLINE_API_KEY: "  sk-from-env  ",
        FAULTLINE_MODEL: "env-model",
        FAULTLINE_BASE_URL: " http://127.0.0.1:11434/v1/ ",
      },
      "flag-model",
    ),
  ).toEqual({
    name: "openai",
    apiKey: "sk-from-env",
    model: "flag-model",
    baseUrl: "http://127.0.0.1:11434/v1/",
  });
  expect(resolveProviderConfig(undefined, {})).toEqual({});
});

it("sends an OpenAI chat completions request and drops tool calls", async () => {
  const { fetchImpl, calls } = mockFetch(() =>
    openaiResponse([
      { type: "text", text: "summary" },
      { type: "tool_use", id: "call-1", name: "shell", input: { cmd: "rm -rf /" } },
    ]),
  );
  const provider = createProvider("openai", {
    apiKey: "sk-openai",
    fetch: fetchImpl,
    sleep: immediateSleep(),
  });
  await expect(provider.complete(input)).resolves.toBe("summary");
  expect(calls).toHaveLength(1);
  const call = calls[0];
  expect(call?.method).toBe("POST");
  expect(call?.url).toBe("https://api.openai.com/v1/chat/completions");
  expect(call?.headers.get("authorization")).toBe("Bearer sk-openai");
  expect(call?.headers.get("content-type")).toBe("application/json");
  expect(Object.keys(call?.body ?? {}).sort()).toEqual(["messages", "model", "stream"]);
  expect(call?.body["model"]).toBe(OPENAI_DEFAULT_MODEL);
  expect(call?.body["stream"]).toBe(false);
  expect(call?.body["messages"]).toEqual(messages);
  expect(call?.body["tools"]).toBeUndefined();
  expect(call?.body["response_format"]).toBeUndefined();
  expect(JSON.stringify(call?.body)).not.toContain("jsonSchema");
});

it("sends an Anthropic messages request and returns text only", async () => {
  const { fetchImpl, calls } = mockFetch(() =>
    anthropicResponse([
      { type: "tool_use", id: "toolu_1", name: "shell", input: { cmd: "rm -rf /" } },
      { type: "text", text: "summary" },
    ]),
  );
  const provider = createProvider("anthropic", {
    apiKey: "sk-ant-test",
    fetch: fetchImpl,
    sleep: immediateSleep(),
  });
  const text = await provider.complete(input);
  expect(text).toBe("summary");
  expect(text).not.toContain("rm -rf");
  expect(text).not.toContain("shell");
  const call = calls[0];
  expect(call?.method).toBe("POST");
  expect(call?.url).toBe("https://api.anthropic.com/v1/messages");
  expect(call?.headers.get("x-api-key")).toBe("sk-ant-test");
  expect(call?.headers.get("anthropic-version")).toBe(ANTHROPIC_VERSION);
  expect(call?.headers.get("authorization")).toBeNull();
  expect(Object.keys(call?.body ?? {}).sort()).toEqual([
    "max_tokens",
    "messages",
    "model",
    "stream",
    "system",
  ]);
  expect(call?.body["model"]).toBe(ANTHROPIC_DEFAULT_MODEL);
  expect(call?.body["max_tokens"]).toBe(4096);
  expect(call?.body["stream"]).toBe(false);
  expect(call?.body["system"]).toBe("one\n\ntwo");
  expect(call?.body["messages"]).toEqual([
    { role: "user", content: "hello" },
    { role: "assistant", content: "prior" },
  ]);
  expect(call?.body["tools"]).toBeUndefined();
});

it("uses FAULTLINE_BASE_URL for an OpenAI-compatible server", async () => {
  const { fetchImpl, calls } = mockFetch(() => openaiResponse("local"));
  const provider = createProvider("openai", {
    apiKey: "ollama",
    model: "llama3.2",
    baseUrl: "http://127.0.0.1:11434/v1/",
    fetch: fetchImpl,
    sleep: immediateSleep(),
  });
  await expect(provider.complete(input)).resolves.toBe("local");
  expect(calls[0]?.url).toBe("http://127.0.0.1:11434/v1/chat/completions");
  expect(calls[0]?.body["model"]).toBe("llama3.2");
  expect(calls[0]?.headers.get("authorization")).toBe("Bearer ollama");
});

it("honors an Anthropic base URL override", async () => {
  const { fetchImpl, calls } = mockFetch(() => anthropicResponse([{ type: "text", text: "ok" }]));
  const provider = createProvider("anthropic", {
    apiKey: "sk-ant-test",
    baseUrl: "https://gateway.example",
    fetch: fetchImpl,
    sleep: immediateSleep(),
  });
  await expect(provider.complete(input)).resolves.toBe("ok");
  expect(calls[0]?.url).toBe("https://gateway.example/v1/messages");
});

it("retries a 429 and then returns the completion", async () => {
  let calls = 0;
  const sleeps: number[] = [];
  const { fetchImpl } = mockFetch(() => {
    calls += 1;
    if (calls === 1) {
      return new Response("slow down", { status: 429, headers: { "retry-after": "0" } });
    }
    return openaiResponse("done");
  });
  const provider = createProvider("openai", {
    apiKey: "sk-test",
    fetch: fetchImpl,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  await expect(provider.complete(input)).resolves.toBe("done");
  expect(calls).toBe(2);
  expect(sleeps).toEqual([0]);
});

it("retries 5xx with exponential backoff and stops after the budget", async () => {
  const sleeps: number[] = [];
  const { fetchImpl, calls } = mockFetch((call) => {
    if (call < 3) {
      return new Response("unavailable", { status: 503 });
    }
    return anthropicResponse([{ type: "text", text: "recovered" }]);
  });
  const provider = createProvider("anthropic", {
    apiKey: "sk-ant-test",
    fetch: fetchImpl,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  await expect(provider.complete(input)).resolves.toBe("recovered");
  expect(calls).toHaveLength(3);
  expect(sleeps).toEqual([200, 400]);

  const persistent = mockFetch(() => new Response("still limited", { status: 429 }));
  const limited = createProvider("openai", {
    apiKey: "sk-test",
    fetch: persistent.fetchImpl,
    sleep: immediateSleep(),
  });
  const error = await limited.complete(input).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderHttpError);
  expect((error as ProviderHttpError).status).toBe(429);
  expect(persistent.calls).toHaveLength(3);
  expect(retryDelayMs(0, null)).toBe(200);
  expect(retryDelayMs(1, null)).toBe(400);
  expect(retryDelayMs(0, "0")).toBe(0);
  expect(retryDelayMs(0, "45")).toBe(30_000);
});

it("does not retry a 400", async () => {
  const { fetchImpl, calls } = mockFetch(
    () => new Response('{"error":"bad request"}', { status: 400 }),
  );
  const provider = createProvider("openai", {
    apiKey: "sk-test",
    fetch: fetchImpl,
    sleep: async () => {
      throw new Error("sleep should not run");
    },
  });
  const error = await provider.complete(input).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderHttpError);
  expect((error as ProviderHttpError).status).toBe(400);
  expect(calls).toHaveLength(1);
});

it("times out without retrying", async () => {
  const key = "sk-timeout-secret-value";
  let calls = 0;
  const fetchImpl: typeof fetch = (_url, init) => {
    calls += 1;
    return new Promise((_resolve, reject) => {
      const signal = init?.signal;
      if (signal == null) {
        reject(new Error("missing abort signal"));
        return;
      }
      const onAbort = () => {
        reject(signal.reason ?? new DOMException("The operation was aborted", "AbortError"));
      };
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });
    });
  };
  const provider = createProvider("openai", {
    apiKey: key,
    timeoutMs: 30,
    fetch: fetchImpl,
    sleep: async () => {
      throw new Error("sleep should not run");
    },
  });
  const error = await provider.complete(input).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderTimeoutError);
  expect((error as ProviderTimeoutError).code).toBe("timeout");
  expect(calls).toBe(1);
  expect(dumpError(error)).not.toContain(key);
});

it("keeps the API key out of thrown error messages", async () => {
  const key = "sk-live-NEVER-LOG-THIS-KEY-9f3a";
  const network: typeof fetch = async () => {
    throw new Error(
      `connect failed Authorization: Bearer ${key} x-api-key: ${key} secret=${encodeURIComponent(key)}`,
    );
  };
  const provider = createProvider("anthropic", {
    apiKey: key,
    fetch: network,
    sleep: immediateSleep(),
  });
  const error = await provider.complete(input).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderRequestError);
  const dumped = dumpError(error);
  expect(dumped).not.toContain(key);
  expect(dumped).not.toContain(encodeURIComponent(key));
  expect(dumped).toContain("[redacted]");
  expect(inspect(provider)).not.toContain(key);

  const echoed = mockFetch(
    () => new Response(`{"error":"invalid","api_key":"${key}"}`, { status: 400 }),
  );
  const httpProvider = createProvider("openai", {
    apiKey: key,
    fetch: echoed.fetchImpl,
    sleep: async () => {
      throw new Error("sleep should not run");
    },
  });
  const httpError = await httpProvider.complete(input).catch((caught: unknown) => caught);
  expect(httpError).toBeInstanceOf(ProviderHttpError);
  expect((httpError as ProviderHttpError).status).toBe(400);
  expect(echoed.calls).toHaveLength(1);
  const httpDump = dumpError(httpError);
  expect(httpDump).not.toContain(key);
  expect(httpDump).toContain("[redacted]");

  let unknown: unknown;
  try {
    createProvider("nope", { apiKey: key });
  } catch (caught) {
    unknown = caught;
  }
  expect(unknown).toBeInstanceOf(UnknownProviderError);
  expect(dumpError(unknown)).not.toContain(key);
});

it("does not send a base URL that contains the API key", async () => {
  const key = "sk-base-url-secret-value";
  let fetched = false;
  const fetchImpl: typeof fetch = async () => {
    fetched = true;
    throw new Error(`fetched ${key}`);
  };
  const cases = [
    `https://user:${key}@example.com/v1`,
    `https://example.com/v1?access_token=${key}`,
    `http://${key}`,
    `not a url ${key}`,
  ];
  for (const baseUrl of cases) {
    const provider = createProvider("openai", {
      apiKey: key,
      baseUrl,
      fetch: fetchImpl,
      sleep: immediateSleep(),
    });
    const error = await provider.complete(input).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ProviderRequestError);
    expect(dumpError(error)).not.toContain(key);
  }
  expect(fetched).toBe(false);
});

it("does not copy an abort reason that contains the API key", async () => {
  const key = "sk-abort-reason-secret";
  let fetched = false;
  const fetchImpl: typeof fetch = async () => {
    fetched = true;
    return openaiResponse("nope");
  };
  const provider = createProvider("openai", {
    apiKey: key,
    fetch: fetchImpl,
    sleep: immediateSleep(),
  });
  const controller = new AbortController();
  controller.abort(key);
  const error = await provider
    .complete({ ...input, signal: controller.signal })
    .catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderAbortedError);
  expect(dumpError(error)).not.toContain(key);
  expect(fetched).toBe(false);
});

it("rejects a completion that has no text", async () => {
  const { fetchImpl } = mockFetch(() =>
    Response.json({
      choices: [
        {
          message: {
            role: "assistant",
            content: null,
            tool_calls: [
              { id: "1", type: "function", function: { name: "shell", arguments: "{}" } },
            ],
          },
        },
      ],
    }),
  );
  const provider = createProvider("openai", {
    apiKey: "sk-test",
    fetch: fetchImpl,
    sleep: immediateSleep(),
  });
  const error = await provider.complete(input).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderResponseError);
  expect(dumpError(error)).not.toContain("shell");
});
