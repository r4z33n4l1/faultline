import { chmod, mkdir, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import process from "node:process";

// pnpm does not put this package's own bin on PATH. `prepare` runs after tsc,
// so dist/cli.js exists and this link makes `pnpm exec faultline` work.
// npm's git install links the bin from package.json itself; this is extra.
const root = process.cwd();
const target = join(root, "dist", "cli.js");
const binDir = join(root, "node_modules", ".bin");
const linkPath = join(binDir, "faultline");

await chmod(target, 0o755);
await mkdir(binDir, { recursive: true });
await rm(linkPath, { force: true });
await symlink(join("..", "..", "dist", "cli.js"), linkPath);
