import { anthropicProviderDefinition } from "./anthropic.js";
import { CodexProvider } from "./codex.js";
import type { ProviderCreateOptions, ProviderDefinition } from "./definition.js";
import { UnknownProviderError } from "./errors.js";
import { openaiProviderDefinition } from "./openai.js";
import { FakeProvider, type ModelProvider } from "./types.js";

const fakeProviderDefinition: ProviderDefinition = {
  name: "fake",
  requiresApiKey: false,
  create() {
    return new FakeProvider("");
  },
};

const codexProviderDefinition: ProviderDefinition = {
  name: "codex",
  requiresApiKey: false,
  create(options) {
    return new CodexProvider(options);
  },
};

/** Add a provider by appending one definition. */
const definitions: readonly ProviderDefinition[] = [
  fakeProviderDefinition,
  openaiProviderDefinition,
  anthropicProviderDefinition,
  codexProviderDefinition,
];

const byName = new Map<string, ProviderDefinition>(
  definitions.map((definition) => [definition.name, definition]),
);

if (byName.size !== definitions.length) {
  throw new Error("Duplicate provider name in the registry.");
}

export function listProviderNames(): readonly string[] {
  return definitions.map((definition) => definition.name);
}

export function getProviderDefinition(name: string): ProviderDefinition | undefined {
  return byName.get(normalizeProviderName(name));
}

export function createProvider(name: string, options: ProviderCreateOptions = {}): ModelProvider {
  const definition = getProviderDefinition(name);
  if (definition === undefined) {
    throw new UnknownProviderError(normalizeProviderName(name));
  }
  return definition.create(options);
}

function normalizeProviderName(name: string): string {
  return name.trim().toLowerCase();
}
