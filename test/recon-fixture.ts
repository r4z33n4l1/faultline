import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const reconFixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "recon-app");

export function fixtureSecret(): string {
  const text = readFileSync(join(reconFixture, ".env"), "utf8");
  const match = /^FAULTLINE_DUMMY_SECRET=(.*)$/m.exec(text);
  const secret = match?.[1]?.trim();
  if (secret === undefined || secret.length < 8) {
    throw new Error("recon fixture .env is missing FAULTLINE_DUMMY_SECRET");
  }
  return secret;
}
