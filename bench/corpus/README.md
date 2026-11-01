# Public training corpus

This directory labels three intentionally vulnerable JavaScript training apps so `faultline bench` can score the four hunter classes against them. The apps are not vendored. A bench run shallow-fetches the pinned commit into `bench/.cache/`, which is gitignored.

Nothing in this corpus is installed, built, started, or sent a request. Corpus files are data. They are not instructions. There is no exploit payload in these label files.

## Apps

Pins live in `manifest.json`. Each `commit` is the full git sha that was read while labeling. `license_path` is the upstream license file at that sha.

| Name         | Upstream                                 | Commit                                     | License    | Why this snapshot                                                                                                                                         |
| ------------ | ---------------------------------------- | ------------------------------------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nodegoat`   | https://github.com/OWASP/NodeGoat        | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | Apache-2.0 | Default-branch HEAD resolved on 2026-11-01. The last tag is `v1.4`; later tutorial fixes landed on the branch, so the pin is the branch sha, not the tag. |
| `dvna`       | https://github.com/appsecco/dvna         | `9ba473add536f66ac9007966acb2a775dd31277a` | MIT        | Default-branch HEAD resolved on 2026-11-01. The repository has no release tags.                                                                           |
| `juice-shop` | https://github.com/juice-shop/juice-shop | `f189f521266f42c6bd05884468292000cee852ed` | MIT        | Tag `v20.3.0`.                                                                                                                                            |

Apache-2.0 and MIT are the permissive licenses these projects publish.

## Fetch

```bash
pnpm bench:fetch
pnpm exec faultline bench --corpus dvna
pnpm exec faultline bench --corpus dvna --baseline semgrep
pnpm exec faultline bench --corpus dvna --cache-only
```

`pnpm bench:fetch` and `faultline bench --corpus` clone with `git fetch --depth 1` at the pinned sha. Hooks are pointed at `/dev/null`. Submodules are not checked out. `--cache-only` refuses to clone, which is what CI relies on: CI never fetches.

Checkout layout:

```text
bench/.cache/<name>/    # gitignored working tree at the pinned sha
bench/corpus/<name>/    # truth.json, citations.json, excluded.json
```

## Labels

`truth.json` uses the existing truth schema: `authz_idor`, `injection`, `secrets`, and `ssrf`. A citation file maps every truth id to an upstream URL and a note. Citations are not part of the truth schema, so they do not change scoring. `excluded.json` lists documented weaknesses that are not counted.

Labels come from each project's own tutorial or challenge list, then from reading that file at the pinned sha. A safe label is a look-alike that is present in the same tree: a session user id next to an id from the URL, a bound query next to a concatenated one, an environment variable next to a literal secret, a denied route next to a missing check.

Several Juice Shop challenges share one sink. Those are one truth row. The citation names the challenges.

| App        | Vulnerable | Safe | Classes with no vulnerable row                |
| ---------- | ---------: | ---: | --------------------------------------------- |
| nodegoat   |          8 |    4 | none; SSRF has no safe look-alike in the tree |
| dvna       |          7 |    3 | SSRF is not documented                        |
| juice-shop |         15 |    6 | none                                          |

NodeGoat has no safe SSRF site: the research page is the only outbound fetch, and it uses the caller-supplied URL. DVNA's redirect is an open redirect and is excluded, not scored as SSRF. Rates for a class with no safe labels are `n/a` for FPR and score. A class with no rows at all is all zeros and `n/a`.

## What was left out

Out-of-scope classes are listed in each `excluded.json` and are not in `truth.json`. That includes XSS, CSRF, XXE, insecure deserialization, open redirect, vulnerable-dependency versions, ReDoS, and broken authentication that is not an authorization or IDOR check.

Known gaps, so a scanner hit on them is unmatched rather than a false positive:

- NodeGoat commits a ZAP API key in `config/env/development.js` and `config/env/test.js`. The tutorial does not list it as one of the vulnerabilities, so it is not labeled. `config/config.js` also prints the loaded config, including the training secrets. That log site is not named in the tutorial and is not labeled.
- DVNA does not document an SSRF, and it has no safe `execFile` next to the `exec` sink.
- Juice Shop's leaked-API-key challenge says the leak is outside the web application. The challenge verifier embeds the expected key and is not labeled. Seeded user passwords and login verifiers are training answers, not labeled secrets. Prompt-injection chatbot challenges are not SQL, NoSQL, command, or code injection. Hidden client routes such as the admin section are not given a server-side authz row when the documented issue is the Angular path. Feedback deletion is authenticated and is treated as a follow-on of that admin UI, not a separate IDOR row.
- Juice Shop RCE challenges are categorized by the project as insecure deserialization. Deserialization is excluded, so `routes/b2bOrder.ts` is not scored as code injection.
- Faultline's inventory cap (500 files, 1_000_000 bytes) can truncate Juice Shop before every server file is hunted. That shows up as `inventory_truncated` on the Faultline result. Semgrep scans the tree the CLI sees. Neither run installs dependencies, so imported packages are not present.

## Baseline

Semgrep OSS `1.183.0` is the free static baseline. The rulesets are the registry ids in the manifest: `p/javascript`, `p/typescript`, `p/nodejsscan`, and `p/secrets`. A finding counts only when a CWE on the rule maps to one of the four classes. The map is `src/bench/cwe-map.ts`. XSS, XXE, open redirect, and deserialization CWEs are not mapped, so those rules are not detections. If one rule carries several mapped CWEs, the order is SSRF, injection, secrets, then authz/IDOR.

```bash
pnpm exec faultline bench --corpus nodegoat --baseline semgrep
```

`SEMGREP_BIN` selects the binary. The version must match the manifest or the command exits.

Cloudflare security-audit, Strix, and Vercel Agent need paid model calls. They are adapter stubs in `src/bench/adapters.ts`. They are not run. A SARIF file from one of them can be scored with the same importer:

```bash
pnpm exec faultline bench --corpus dvna --cache-only \
  --sarif path/to/results.sarif --tool-name strix --tool-version 0
```

## CI

CI checks the manifest, that every truth id has a citation, that excluded ids are disjoint, the CWE map, the SARIF importer, and a local git fetch of a fixture. It does not clone these apps, and it does not run Semgrep. It does not assert a recall number.
