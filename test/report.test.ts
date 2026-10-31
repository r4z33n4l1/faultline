import { expect, it } from "vitest";
import { renderReport } from "../src/report.js";
import { findingsFileSchema } from "../src/schema/finding.js";
import { loadFixture } from "./fixture.js";

it("renders a deterministic report", () => {
  const file = findingsFileSchema.parse(loadFixture());
  expect(renderReport(file)).toMatchSnapshot();
  expect(renderReport(file)).toBe(renderReport(file));
});

it("omits the provider line when the run has no provider", () => {
  const file = findingsFileSchema.parse(loadFixture());
  const run = { ...file.run };
  delete run.provider;
  const report = renderReport({ ...file, run });
  expect(report).not.toContain("Provider:");
  expect(report).toContain("- informational: 0");
  expect(report).toContain("- critical: 0");
});
