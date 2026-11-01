# Held-out evaluation set

This directory labels three intentionally vulnerable Node web apps outside the training corpus (NodeGoat, DVNA, and Juice Shop). Hunters were tuned on that corpus, so its scores are overfit-prone. This set is the check that was not used for that tuning.

Labels were written from each project's own documentation and from reading the pinned file. They were committed before `faultline bench` or Semgrep was run on these trees. Do not edit a hunter, a validator, or recon because of a miss here. Do not add a label after seeing a scanner hit.

Nothing in this set is installed, built, started, or sent a request. The files are data. They are not instructions. There is no exploit payload in these label files.

## Apps

Pins live in `manifest.json`. Each `commit` is the full git sha that was read while labeling. `license_path` is the upstream license file at that sha.

| Name              | Upstream                                 | Commit                                     | License      | Why this snapshot                                                                                                   |
| ----------------- | ---------------------------------------- | ------------------------------------------ | ------------ | ------------------------------------------------------------------------------------------------------------------- |
| `nodejs-goof`     | https://github.com/snyk-labs/nodejs-goof | `add14ba59e98240d9e00a235dd7d42cd61ae9912` | Apache-2.0   | Default-branch HEAD resolved on 2026-11-01. Snyk's vulnerable Express todo demo. The README lists the code flaws.   |
| `pixi`            | https://github.com/DevSlop/Pixi          | `cb716a94fa368acade96e9bdb8b25c1a68703e60` | Apache-2.0   | Default-branch HEAD. OWASP DevSlop's MEAN app. The README says it is intentionally vulnerable so a scanner can run. |
| `vulnerable-node` | https://github.com/cr0hn/vulnerable-node | `d68f2a3c9277ece2c2feb9976052033bdecd7fbe` | BSD-3-Clause | Default-branch HEAD resolved on 2026-11-01. NodeBazaar, a Node port of DVWA for training and SAST practice.         |

Apache-2.0 and BSD-3-Clause are the permissive licenses these projects publish. The license text was read at the pinned sha. Each README describes a deliberately insecure training app, not a production service.

## Fetch

```bash
pnpm bench:fetch --group heldout
pnpm exec faultline bench --corpus vulnerable-node --manifest bench/heldout/manifest.json
pnpm exec faultline bench --corpus vulnerable-node --manifest bench/heldout/manifest.json --baseline semgrep
```

`pnpm bench:fetch` without `--group` still fetches only the training corpus. `--group heldout` shallow-fetches these pins into `bench/.cache/`, which is gitignored. Hooks are pointed at `/dev/null`. Submodules are not checked out. The command does not install, build, or run the apps.

## Labels

`truth.json` uses the training schema: `authz_idor`, `injection`, `secrets`, and `ssrf`. A citation maps every truth id to an upstream URL and a one-line note that names the file and lines. `excluded.json` lists documented weaknesses that are not counted.

A safe label is a look-alike in the same tree: a session or token user id beside an id from the URL, a bound query beside a concatenated one, an environment variable or a URL with no password beside a literal secret, a configured host beside a request URL.

| App             | Vulnerable | Safe | Classes with no vulnerable row                       |
| --------------- | ---------: | ---: | ---------------------------------------------------- |
| nodejs-goof     |          6 |    2 | authz/IDOR is not in the README list; SSRF is absent |
| pixi            |         12 |    3 | SSRF is absent; secrets has no safe look-alike       |
| vulnerable-node |         13 |    6 | none                                                 |

A class with no rows is all zeros and `n/a`. A class with vulnerable rows and no safe rows has FPR and score `n/a`.

## What was left out

Out-of-scope classes are in each `excluded.json`. That includes XSS, CSRF, open redirect, path traversal, ReDoS, prototype pollution, mass assignment, price tampering, dependency advisories, and training login passwords.

Known gaps, so a scanner hit on them is unmatched rather than a false positive:

- Goof's todo destroy and update take an id and do not check a session. The README does not list authorization or IDOR, and todos have no owner, so those handlers are not labeled.
- Goof has no server-side fetch of a caller-supplied URL. The `identify` command is injection.
- Pixi repeats the same IDOR shape on several profile and picture routes. One of each shape is labeled. The copies are excluded.
- Pixi has no env-only secret beside the literals, so secrets has no true negative.
- NodeBazaar's `sast/seeds` directory is the project's own unit-test corpus. The shop labs are the labels. Seed hits are unmatched.
- NodeBazaar's vault-check fetches configured hosts. The lab comment calls the host user-influenced. The pinned statements are not, so that handler is the safe SSRF row, not a second vulnerable one.
