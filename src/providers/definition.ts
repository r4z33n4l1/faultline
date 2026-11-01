import type { Readable, Writable } from "node:stream";
import type { Sleep } from "./http.js";
import type { ModelProvider } from "./types.js";

/** Options passed to `spawn` for the Codex CLI. `shell` is always false. */
export interface CodexSpawnOptions {
  cwd: string;
  shell: false;
  windowsHide: true;
  stdio: ["pipe", "pipe", "pipe"];
  env: NodeJS.ProcessEnv;
}

export interface CodexChild {
  stdin: Writable;
  stdout: Readable;
  stderr: Readable;
  kill(signal?: NodeJS.Signals): boolean;
  once(event: "error", listener: (error: Error) => void): void;
  once(
    event: "close",
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): void;
}

export type CodexSpawn = (
  bin: string,
  args: readonly string[],
  options: CodexSpawnOptions,
) => CodexChild;

export interface ProviderCreateOptions {
  apiKey?: string;
  model?: string;
  baseUrl?: string;
  timeoutMs?: number;
  maxRetries?: number;
  fetch?: typeof fetch;
  sleep?: Sleep;
  /** Codex executable. `FAULTLINE_CODEX_BIN` when omitted by the CLI. */
  codexBin?: string;
  /** Environment the Codex child is filtered from. Defaults to `process.env`. */
  codexEnv?: NodeJS.ProcessEnv;
  /** Test seam. Production uses `spawn` with `shell: false`. */
  codexSpawn?: CodexSpawn;
  /** Test seam for the stdout, stderr, and final-message cap. */
  codexMaxOutputBytes?: number;
}

export interface ProviderDefinition {
  readonly name: string;
  readonly requiresApiKey: boolean;
  create(options: ProviderCreateOptions): ModelProvider;
}
