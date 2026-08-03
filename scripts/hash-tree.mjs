import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";

const root = process.argv[2];
if (!root) throw new Error("usage: node scripts/hash-tree.mjs <directory>");

async function files(path) {
  const result = [];
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const child = join(path, entry.name);
    if (entry.isDirectory()) result.push(...await files(child));
    else if (entry.isFile()) result.push(child);
  }
  return result;
}

const hash = createHash("sha256");
for (const path of (await files(root)).sort()) {
  hash.update(relative(root, path).replaceAll("\\", "/"));
  hash.update("\0");
  hash.update(await readFile(path));
  hash.update("\0");
}
process.stdout.write(hash.digest("hex") + "\n");
