import { expect, it } from "vitest";
import { runPipeline } from "../src/pipeline.js";
import { FakeProvider, type ModelProvider } from "../src/providers/types.js";
import { findingsFileSchema } from "../src/schema/finding.js";

it("runs an empty pipeline without calling the provider", () => {
  const provider: ModelProvider = new FakeProvider("unused", "fake");
  const file = runPipeline({
    mode: "pr",
    target: "diff.patch",
    provider,
    startedAt: new Date("2026-10-31T12:00:00.000Z"),
    runId: "run_test",
  });
  expect(findingsFileSchema.parse(file)).toEqual(file);
  expect(file.findings).toEqual([]);
  expect(file.run.provider).toBe("fake");
  expect(file.run.id).toBe("run_test");
  expect(provider).toBeInstanceOf(FakeProvider);
  if (provider instanceof FakeProvider) {
    expect(provider.calls).toEqual([]);
  }
});

it("FakeProvider returns its canned completion", async () => {
  const provider = new FakeProvider("ok");
  await expect(
    provider.complete({
      messages: [{ role: "user", content: "hi" }],
      jsonSchema: { type: "object" },
    }),
  ).resolves.toBe("ok");
  expect(provider.calls).toHaveLength(1);
});
