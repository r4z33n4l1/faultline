# Faultline design inspiration

Access dates: **2026-10-29** (initial research); **2026-10-31** (recent-tools sweep). Zone: America/Toronto.  
Faultline is an open-source security-detector CLI for startup eng teams
(`faultline scan .`, `faultline pr <url|diff>`). It emits only findings that
survived a disproof attempt, as `findings.json` + `report.md`. Stack:
TypeScript / Node 20, commander, zod findings schema, vitest, pluggable
`ModelProvider`. This note records what we studied on the public web and what
we take (or refuse) from each source. Numbers below are attributed to their
publishers; they are **not** Faultline benchmarks.

---

## 1. Cloudflare security-audit-skill + vulnerability harness

**What it is.** Cloudflare open-sourced `cloudflare/security-audit-skill`, an
MIT-licensed coding-agent skill that runs a multi-phase audit: recon →
coverage-led hunting → adversarial validation → schema-checked
`findings.json` → independent re-verification → target-neutral reports. The
same ideas seed their fleet harness described in the June 18, 2026 blog post
“Build your own vulnerability harness.”

**Sources**

- Repo: https://github.com/cloudflare/security-audit-skill  
- LICENSE (MIT, Copyright 2025–2026 Cloudflare, Inc.):  
  https://raw.githubusercontent.com/cloudflare/security-audit-skill/main/LICENSE  
- README: https://github.com/cloudflare/security-audit-skill/blob/main/README.md  
- Blog (exact URL): https://blog.cloudflare.com/build-your-own-vulnerability-harness/  
- Schema:  
  https://raw.githubusercontent.com/cloudflare/security-audit-skill/main/skills/security-audit/report-schema.json  
- Validation / reporting:  
  https://raw.githubusercontent.com/cloudflare/security-audit-skill/main/skills/security-audit/VALIDATION-AND-REPORTING.md  
- Recon / ledger:  
  https://raw.githubusercontent.com/cloudflare/security-audit-skill/main/skills/security-audit/RECONNAISSANCE.md  

**Pipeline (from README + blog)**

1. **Recon** — parallel research agents; write `architecture.md` plus a
   deterministic `coverage-ledger.json` (units = surface × boundary ×
   subsystem × attack_class; stable `coverage_id` / `canonical_refs`).
2. **Hunt** — one hunter (or ledger-unit assignment) per bug / attack class;
   hunters try to break code, not “review” it; coverage critics reopen gaps.
3. **Validate** — every unique candidate goes to a **fresh** verifier that
   tries to **disprove** it; verifier cannot file findings of its own.
4. **Structured output** — `confirmed` | `needs_validation` | `rejected` in
   `findings.json`, mechanically checked against `report-schema.json`
   (`validate-findings.cjs`).
5. **Independent re-verification** — another fresh agent rechecks final
   source claims; material replacements need yet another independent pass.
6. **Report** — derive prose (`REPORT.md`, detail / needs-validation docs)
   from verified records + ledger; blog also stresses dedup by **root cause**
   and (at fleet scale) a separate validation system on a **different model**.

**Concrete details worth borrowing**

- Verdict triad and the rule that unvalidated candidates stay in the ledger,
  not in user-facing “findings.”
- Schema fields for confirmed records (from `report-schema.json`):
  `fingerprint`, `title`, `description`, `root_cause`, `intended_behavior`,
  `trace[]` (`entrypoint` | `propagation` | `sink` + file/line/scope),
  `evidence[]`, `conditions[]`, `execution` (attacker_perspective, payloads,
  instructions, observed_result), `remediation` (strategy, optional
  code_changes), `severity` (likelihood/impact/overall + reasons),
  `confidence` (score + reason).
- Validator rules: separate hunter vs verifier; schema `additionalProperties:
  false`; mechanical path/line checks; require a stated threat model /
  boundary before confirmation; reject vacuous “if you have write access you
  can write” findings.
- Prompt shape: verifier gets the candidate + schema branch, not peer
  conclusions; returns one JSON object `{decision, record}`.
- Blog advice for a **minimal** harness: Recon + Hunt + Validate in durable
  state; skip cross-repo tracing and a dedicated Dedup agent until noise
  forces it; keep the harness **model-agnostic**.

**Faultline borrows**

- Disproof-first gate before any finding is emitted.
- Schema-validated `findings.json` + human `report.md`.
- Root-cause / fingerprint key for dedup across runs.
- Per-class hunting + fresh validator separation.
- Pluggable models (aligns with Cloudflare’s model-agnostic thesis).

**Faultline deliberately doesn’t**

- Fleet orchestration, cross-repo Trace, Wishlist, SQLite stage DB, or
  Cloudflare’s VVS triage product surface.
- Full coverage-ledger critic machinery in PR1 (optional later).
- Shipping Cloudflare’s attack-class prompt corpora or validators verbatim
  (MIT allows reuse; we re-implement a smaller startup-focused subset).
- Claiming Cloudflare’s published funnel stats (e.g. blog lifetime
  candidate → validated counts) as ours.

---

## 2. OpenAI Daybreak and Codex Security

**What it is.** Daybreak is OpenAI’s cyber-defense program framing an agentic
loop: inventory → discover → validate → assign → remediate → prove, with
human control on consequential steps. Codex Security is the productized
scan / validate / patch / verify workflow (UI, plugin, CLI) that proposes
patches but does not auto-merge or auto-close findings.

**Sources**

- Daybreak: https://openai.com/daybreak/  
- Codex Security overview: https://developers.openai.com/codex/security  
- Fix / verify: https://developers.openai.com/codex/security/plugin/fix-findings  
- Help Center: https://help.openai.com/en/articles/20001107-codex-security  
- CLI reference: https://developers.openai.com/codex/security/cli/reference  

**Faultline borrows**

- Explicit stages: discover → **validate** → (optional) patch → **prove**,
  with human approval before applying patches or closing findings.
- Separate validate vs patch commands as a UX pattern for `faultline pr`
  and later remediation.
- “Verification doesn’t automatically close a finding” — keep an explicit
  human / CI gate.

**Faultline deliberately doesn’t**

- Hosted GitHub App, threat-model cloud workspace, or Daybreak partner
  network / Access program.
- Auto-create draft PRs in v1 (optional later behind an explicit flag).
- OpenAI’s product-specific finding IDs / occurrence APIs.
- Daybreak marketing metrics ($ commits, patch counts on openai.com/daybreak)
  as Faultline claims.

---

## 3. Anthropic Mythos and Project Glasswing

**What it is.** Claude Mythos Preview is Anthropic’s unreleased frontier
model with strong cyber capability. Project Glasswing is the partner program
to use that capability defensively on critical software. Anthropic also
published a defending-code reference harness (recon → find → verify →
dedupe → report → patch) and Claude Security as a managed product. Public
Glasswing updates emphasize that **finding** outpaces **verify / disclose /
patch** capacity.

**Sources**

- Glasswing home: https://www.anthropic.com/glasswing  
- Initial update (2026-05-22): https://www.anthropic.com/news/glasswing-initial-update  
- Expanding Glasswing: https://www.anthropic.com/news/expanding-project-glasswing  
- Mythos preview research: https://www.anthropic.com/research/mythos-preview  
- Reference harness: https://github.com/anthropics/defending-code-reference-harness  

**Faultline borrows**

- Core takeaway: **keep the pipeline model-independent** so Anthropic /
  OpenAI / xAI (or whatever is best that week) can swap under
  `ModelProvider`.
- Separate find vs verify agents; prefer execution- or evidence-backed
  confirmation over static “looks bad” notes.
- Sandbox discipline when running target-controlled checks (harness docs
  stress isolation; Faultline should refuse elevating to `confirmed` when
  sandbox controls are missing — map to `needs_validation` / omit).

**Faultline deliberately doesn’t**

- Depend on Mythos Preview or any single frontier model.
- Adopt Glasswing partner disclosure / CVE workflows as product scope.
- Copy Glasswing aggregate vulnerability counts or partner false-positive
  claims into Faultline docs as our performance.
- Ship Anthropic’s C/C++ ASAN Docker harness as-is (wrong default target for
  TypeScript startup apps; shape only).

**Could not fully verify from public pages alone:** Anthropic harness SPDX /
LICENSE text was not fetched here (repo exists and README describes the
pipeline; treat license as unchecked until read from the repo LICENSE file).

---

## 4. Factory, Devin, and Lovable security scans

### Factory (Droid Automated Security Review)

**What it is.** Factory’s Droid posts STRIDE / OWASP / LLM-Top-10 security
review on non-draft PRs: candidate generation, validation against the diff,
then inline comments with severity, CWE, plain-language explanation, and
suggested fix. Also supports deep full-repo audits via missions / CLI.

**Sources**

- Announcement: https://factory.com/news/automated-security-review  
- Docs: https://docs.factory.com/automations/security-review  

**Borrows:** PR-native surface for `faultline pr`; severity + suggested fix
next to the changed lines; validate-before-post; one deduped summary per PR.  
**Doesn’t:** Require Factory’s GitHub Action, missions product, or
`.factory/skills` layout.

### Devin Review (security scanning)

**What it is.** Cognition’s Devin Review includes a security pass (injection,
auth, secrets, SSRF, crypto, etc.) with Critical / Warning severity, CWE
when applicable, fix recommendation, and optional posting as PR comments
(`/devin review` or auto-review).

**Sources**

- https://docs.devin.ai/work-with-devin/devin-review  

**Borrows:** Diff-scoped security categories useful for startup web/API
stacks; post-as-comment pattern; allow repo instruction files to steer
checks.  
**Doesn’t:** Full Devin Review product (bug catcher, autoapprover, ACU
billing, multi-provider Review UI).

### Lovable security scans

**What it is.** Lovable ships Quick scan (auto on publish: RLS / deps / MCP)
and Deep scan (app-logic: authz, injection, secrets, payments, etc.) with
Critical / Warning / Info, plain-language fixes aimed at non-security
builders, optional publish blocking on criticals, and auto-fix for some
Quick findings.

**Sources**

- Overview: https://docs.lovable.dev/features/security  
- Earlier product post: https://lovable.dev/blog/secure-vibe-coding  

**Borrows:** Plain-language remediation copy in `report.md`; severity
labels non-experts can act on; gate “ship / merge” on surviving criticals
as an optional CI mode later.  
**Doesn’t:** Supabase-RLS-specific Quick scan as Faultline’s core (keep
checks stack-agnostic); publish dialog UX; Wiz / Aikido connectors.

---

---

## Recent tools & guides (Oct 2026)

Sweep weighted to ~Jul–Oct 2026. Verified via fetch/search on **2026-10-31**. Publisher
numbers are theirs, not Faultline’s.

### Guides / harness patterns (high leverage)

- **OpenSSF — Finding and Fixing Vulnerabilities Using AI** (announced 2026-10-20):  
  https://openssf.org/blog/2026/10/20/new-openssf-guide-finding-and-fixing-vulnerabilities-using-ai/  
  Validate chapter: https://best.openssf.org/Finding-and-Fixing-Vulnerabilities-Using-AI/validate-findings.html  
  Tool-agnostic: separate find vs validate; independent disproof verifier (fresh context,
  finding + codebase only); PoC must trigger claimed failure on vulnerable build, not on
  benign input, and fail after fix; AI consensus ≠ proof; sandbox PoCs.
- **AWS Security — AI vulnerability harness, Part 2 (steering file)** (2026-10-07):  
  https://aws.amazon.com/blogs/security/configuring-your-ai-vulnerability-harness-part-2-the-steering-file/  
  Structural verification before trust (file/function/dataflow/call path exist); evidence-
  based confidence; don’t file low-confidence noise as tickets.
- **Microsoft SARIF SDK — SARIF for AI-generated findings** (draft conventions on SARIF 2.1.0):  
  https://raw.githubusercontent.com/microsoft/sarif-sdk/main/docs/ai/generating-sarif.md  
  Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html  
  Core: `$schema` + `version: "2.1.0"`; `run.properties.ai/origin` (`generated|annotated|synthesized`);
  `ruleId` as `CWE-<n>/<kebab-sub>` or `NOVEL-<kebab>`; `result.properties.ai/exploitability`
  (`demonstrated|poc|theoretical`); optional `ai/attackerPosition`; `rank` as confidence;
  `message.markdown` for exploit/fix narrative; `fixes[]` for machine patches.

### OpenAI / Anthropic / Google (updated)

- **Aardvark → Codex Security** (research preview; rename noted Mar 2026):  
  https://openai.com/index/introducing-aardvark/ ·  
  https://openai.com/index/codex-security-now-in-research-preview/  
  Daybreak expansion (2026-06-22) documents SARIF / CodeQL export from Codex Security:  
  https://openai.com/index/daybreak-securing-the-world/
- **Anthropic**: Glasswing folded into expanded **Cyber Verification Program** (Oct 2026);
  Claude Security can run Mythos-class scans for Enterprise (human-reviewed patches).  
  https://www.anthropic.com/news/cyber-verification-program ·  
  https://claude.com/resources/articles/bringing-claude-mythos-5-to-more-defenders ·  
  https://support.claude.com/en/articles/14604842-cyber-verification-program
- **Google Big Sleep** (LLM bug-finding; Project Zero compared to Fuzzilli on V8, Apr–Sep 2026):  
  https://projectzero.google/2026/10/fuzzing-v-AI.html — fuzzing and agents are complementary.
- **Google CodeMender** (find/verify/patch agent; Cloud preview; human review before upstream):  
  https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/ ·  
  https://cloud.google.com/security/codemender ·  
  https://cloud.google.com/blog/products/identity-security/find-and-fix-software-vulnerabilities-with-codemender

### Cloudflare skill (status)

- Main still last merged **2026-09-14** (guidance vs full-audit). Oct 2026 open PRs (not
  verified merged): treat target content as untrusted, move fix design out of discovery,
  Windows `O_NOFOLLOW` validator fixes, plugin.json.  
  https://github.com/cloudflare/security-audit-skill/pulls

### Commercial / product AI scanners (PR-native / autofix)

- **Factory Droid**, **Devin Review**, **Lovable** — see §4 (still current).
- **DryRun Security**: adversarial PR review, exploit-path evidence, merge thresholds, agent
  fix guidance (MCP/API/skills). https://www.dryrun.security/
- **ZeroPath**: agentic SAST/SCA/secrets/IaC/PR reviews + autofix; repo-context triage posts.  
  https://zeropath.com/
- **Corgea AI SAST**: business-logic / auth flaws + PR/IDE fixes.  
  https://corgea.com/products/ai-sast
- **Endor Labs AI SAST**: LLM agent over first-party code; source→sink + attack vector;
  CI `--ai-sast`, PR baseline scans, local `--diff-scope`.  
  https://docs.endorlabs.com/scan/ai-sast
- **GitHub Copilot Autofix** (+ agentic autofix for CodeQL alerts):  
  https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning
- **Semgrep Autofix** (public beta 2026): LLM fixes for Semgrep Code/SCA findings.  
  https://semgrep.dev/blog/2026/semgrep-autofix-public-beta
- **Snyk Agent Fix** (agentic retry loop after May 2026):  
  https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-code/manage-code-vulnerabilities/fix-code-vulnerabilities-automatically
- **Socket**: primarily dependency / malicious-package SCA (not a peer first-party AI SAST
  in fetched materials). Treat as supply-chain adjacent, not Faultline’s core loop.

### Benchmarks usable for step-7 fixtures

- **OWASP Benchmark** (Java/Python known-vuln + decoy cases; SARIF-friendly scoring):  
  https://owasp.org/www-project-benchmark/
- **CyberGym** (1,507 real vulns / 188 projects; PoC reproduction; mostly C/C++ sanitizer):  
  https://arxiv.org/abs/2506.02548 · https://github.com/sunblaze-ucb/cybergym
- **CVE-Bench** (web-app CVE exploit outcomes): https://github.com/uiuc-kang-lab/cve-bench
- **SEC-bench** (real-world security tasks; NeurIPS 2025): https://github.com/SEC-bench/SEC-bench

For Faultline’s TypeScript startup CLI, prefer **small curated fixtures** (authz miss,
injection sink, secret leak) scored like OWASP Benchmark TP/FP, plus optional later
runs against public harnesses. Do not treat CyberGym C/C++ memory-safety scores as
Faultline product metrics.

### Unverified / partial

- Anthropic defending-code harness LICENSE text still not fetched this pass.
- Cloudflare Oct PRs: existence verified on pulls page; merge state not re-checked per PR.
- Vendor marketing FP-reduction / accuracy percentages: cite only; never copy as ours.

## Cross-cutting decisions for Faultline

| Idea | Keep | Drop / defer |
|------|------|--------------|
| Disproof validator before emit | Yes (core promise) | — |
| Schema-checked JSON + MD report | Yes | Cloudflare’s three prose files → one `report.md` for v1 |
| ModelProvider swap | Yes | Lock-in to one vendor |
| Per-class hunters | Yes (PR2+) | Full companion attack-class library on day one |
| Coverage ledger | Defer | PR1 can use a thin work queue |
| PR inline comments | PR2+ for `faultline pr` | Hosted bot as a service |
| Auto-patch / prove | Later, human-gated | Auto-merge |
| Fleet / cross-repo | Out of scope | — |

