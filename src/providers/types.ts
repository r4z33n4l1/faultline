export interface ModelMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface CompleteInput {
  messages: readonly ModelMessage[];
  jsonSchema?: unknown;
  signal?: AbortSignal;
}

export interface ModelProvider {
  readonly name: string;
  complete(input: CompleteInput): Promise<string>;
}

export class FakeProvider implements ModelProvider {
  readonly name: string;
  readonly calls: CompleteInput[] = [];

  constructor(
    private readonly reply: string | ((input: CompleteInput) => string | Promise<string>) = "",
    name = "fake",
  ) {
    this.name = name;
  }

  async complete(input: CompleteInput): Promise<string> {
    this.calls.push(input);
    if (input.signal?.aborted) {
      throw new Error("aborted");
    }
    return this.reply instanceof Function ? this.reply(input) : this.reply;
  }
}
