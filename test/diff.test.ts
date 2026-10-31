import { describe, expect, it } from "vitest";
import {
  DEFAULT_HUNK_CONTEXT,
  MAX_DIFF_BYTES,
  MAX_HUNK_CONTEXT,
  assertDiffWithinLimit,
  candidateOverlapsDiff,
  githubPullRequestMessage,
  parseHunkContext,
  parseUnifiedDiff,
  rangesOverlap,
  DiffError,
} from "../src/pr/diff.js";
import { candidateSchema, type Candidate } from "../src/schema/candidate.js";

function candidate(file: string, start: number, end?: number): Candidate {
  return candidateSchema.parse({
    class: "authz_idor",
    severity: "low",
    confidence: { level: "low", reason: "test" },
    location:
      end === undefined ? { file, start_line: start } : { file, start_line: start, end_line: end },
    symbol: "findUnique",
    root_cause: "lookup",
    evidence: [{ file, line: start, note: "call" }],
  });
}

describe("github pull request URLs", () => {
  it("tells the user to pipe gh pr diff and does not fetch", () => {
    const url = "https://github.com/org/repo/pull/1";
    const message = githubPullRequestMessage(url);
    expect(message).toContain("are not fetched");
    expect(message).toContain(`gh pr diff ${url} | faultline pr -`);
    expect(githubPullRequestMessage("https://www.github.com/org/repo/pull/2/")).toContain(
      "gh pr diff",
    );
    expect(githubPullRequestMessage("http://github.com/org/repo/pull/3.diff")).toContain(
      "gh pr diff",
    );
    expect(githubPullRequestMessage("https://github.com/org/repo/pull/4.patch")).toContain(
      "gh pr diff",
    );
    expect(githubPullRequestMessage("  https://github.com/org/repo/pull/5  ")).toContain(
      "https://github.com/org/repo/pull/5",
    );
  });

  it("leaves local paths and other hosts alone", () => {
    expect(githubPullRequestMessage("change.diff")).toBeUndefined();
    expect(githubPullRequestMessage("-")).toBeUndefined();
    expect(githubPullRequestMessage("https://github.com/org/repo/issues/1")).toBeUndefined();
    expect(githubPullRequestMessage("https://gitlab.com/org/repo/pull/1")).toBeUndefined();
  });
});

describe("unified diff parser", () => {
  it("records added lines and ignores a deleted file, a binary, and a pure rename", () => {
    const parsed = parseUnifiedDiff(`diff --git a/src/app.ts b/src/app.ts
--- a/src/app.ts
+++ b/src/app.ts
@@ -30,4 +30,11 @@
   res.send(req.params.id);
 });
 
+app.get("/notes/:noteId", async (req, res) => {
+  const note = await prisma.note.findUnique({
+    where: { id: req.params.noteId },
+  });
+  res.json(note);
+});
+
 export { app };
diff --git a/src/gone.ts b/src/gone.ts
deleted file mode 100644
--- a/src/gone.ts
+++ /dev/null
@@ -1,2 +0,0 @@
-export const a = 1;
-export const b = 2;
diff --git a/src/blob.bin b/src/blob.bin
index 1111111..2222222
GIT binary patch
literal 4
abcd
diff --git a/pic.png b/pic.png
Binary files a/pic.png and b/pic.png differ
diff --git a/src/old.ts b/src/renamed.ts
similarity index 100%
rename from src/old.ts
rename to src/renamed.ts
`);
    expect(parsed.files.map((file) => file.path)).toEqual(["src/app.ts"]);
    expect(parsed.files[0]?.ranges).toEqual([{ start: 33, end: 39 }]);
  });

  it("uses the new path of a rename that also edits lines", () => {
    const parsed = parseUnifiedDiff(`diff --git a/src/old.ts b/src/new.ts
similarity index 80%
rename from src/old.ts
rename to src/new.ts
--- a/src/old.ts
+++ b/src/new.ts
@@ -1,2 +1,3 @@
 const keep = 1;
+const added = 2;
 const tail = 3;
`);
    expect(parsed.files).toEqual([{ path: "src/new.ts", ranges: [{ start: 2, end: 2 }] }]);
  });

  it("keeps a modified file whose hunk only deletes lines", () => {
    const parsed = parseUnifiedDiff(`diff --git a/src/app.ts b/src/app.ts
--- a/src/app.ts
+++ b/src/app.ts
@@ -4,3 +4,2 @@
 keep
-removed
 keep
`);
    expect(parsed.files).toEqual([{ path: "src/app.ts", ranges: [{ start: 5, end: 5 }] }]);
  });

  it("accepts a quoted path and rejects traversal", () => {
    const parsed = parseUnifiedDiff(`diff --git "a/src/my file.ts" "b/src/my file.ts"
--- "a/src/my file.ts"
+++ "b/src/my file.ts"
@@ -0,0 +1,1 @@
+const added = 1;
`);
    expect(parsed.files.map((file) => file.path)).toEqual(["src/my file.ts"]);

    expect(() =>
      parseUnifiedDiff(`diff --git a/src/app.ts b/../../etc/passwd
--- a/src/app.ts
+++ b/../../etc/passwd
@@ -0,0 +1 @@
+x
`),
    ).toThrow(/outside the repository/);
    expect(() =>
      parseUnifiedDiff(`--- a/src/app.ts
+++ /etc/passwd
@@ -0,0 +1 @@
+x
`),
    ).toThrow(DiffError);
  });

  it("rejects a binary-looking diff, a truncated hunk, and an oversize payload", () => {
    expect(() => parseUnifiedDiff("diff --git a/a b/a\n\0")).toThrow(/not a text unified diff/);
    expect(() =>
      parseUnifiedDiff("--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1,3 +1,3 @@\n context\n"),
    ).toThrow(/hunk ended early/);
    expect(() => parseUnifiedDiff("a".repeat(MAX_DIFF_BYTES + 1))).toThrow(/byte limit/);
    expect(() => assertDiffWithinLimit(MAX_DIFF_BYTES)).not.toThrow();
    expect(() => assertDiffWithinLimit(MAX_DIFF_BYTES + 1)).toThrow(DiffError);
  });
});

describe("hunk overlap", () => {
  const ranges = [{ start: 40, end: 42 }];

  it("expands a changed hunk by the context window", () => {
    expect(rangesOverlap(36, 37, ranges, 3)).toBe(true);
    expect(rangesOverlap(36, 37, ranges, 2)).toBe(false);
    expect(rangesOverlap(43, 44, ranges, DEFAULT_HUNK_CONTEXT)).toBe(true);
    expect(rangesOverlap(46, 46, ranges, DEFAULT_HUNK_CONTEXT)).toBe(false);
  });

  it("keeps a candidate only when its location overlaps the changed file", () => {
    const changed = [{ path: "src/app.ts", ranges }];
    expect(candidateOverlapsDiff(candidate("src/app.ts", 36, 37), changed, 3)).toBe(true);
    expect(candidateOverlapsDiff(candidate("src/app.ts", 36, 37), changed, 2)).toBe(false);
    expect(candidateOverlapsDiff(candidate("src/other.ts", 41, 41), changed, 3)).toBe(false);
    expect(candidateOverlapsDiff(candidate("../src/app.ts", 41, 41), changed, 3)).toBe(false);
  });

  it("bounds the context window", () => {
    expect(parseHunkContext("0")).toBe(0);
    expect(parseHunkContext(String(MAX_HUNK_CONTEXT))).toBe(MAX_HUNK_CONTEXT);
    expect(() => parseHunkContext("-1")).toThrow(/0 to 20/);
    expect(() => parseHunkContext("3.5")).toThrow(DiffError);
    expect(() => parseHunkContext(String(MAX_HUNK_CONTEXT + 1))).toThrow(DiffError);
  });
});
