/**
 * Static-tool adapters. Semgrep is the free baseline and is actually run.
 * The other three need paid model calls. This repo does not invoke them.
 * Their SARIF can be scored later with `faultline bench --corpus <name> --sarif <file>`.
 */
export const SARIF_ADAPTERS = [
  {
    id: "semgrep",
    status: "baseline",
    summary:
      "Semgrep OSS CLI with the pinned free registry rulesets. Mapped to the four classes by CWE and scored with the bench harness.",
  },
  {
    id: "cloudflare-security-audit",
    status: "stub",
    summary:
      "Cloudflare security-audit skill. Not run: it needs a paid model call. Import a SARIF file; do not start it from this repo.",
  },
  {
    id: "strix",
    status: "stub",
    summary:
      "Strix. Not run: it needs a paid model call. Import a SARIF file; do not start it from this repo.",
  },
  {
    id: "vercel-agent",
    status: "stub",
    summary:
      "Vercel Agent. Not run: it needs a paid model call. Import a SARIF file; do not start it from this repo.",
  },
] as const;

export type SarifAdapterId = (typeof SARIF_ADAPTERS)[number]["id"];
export type SarifAdapterStatus = (typeof SARIF_ADAPTERS)[number]["status"];

export function sarifAdapter(id: string): (typeof SARIF_ADAPTERS)[number] | undefined {
  return SARIF_ADAPTERS.find((adapter) => adapter.id === id);
}
