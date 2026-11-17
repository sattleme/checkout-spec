// manifest.json: this repository's version, the protocol's, and the SHA-256 of every file an
// implementation copies (PORTING.md, "The pinned copy of the specification"): SPEC.md, PORTING.md,
// currencies.json and everything under vectors/.
//
//   node scripts/manifest.mjs --check            fails unless manifest.json is the files'
//   node scripts/manifest.mjs [--version X.Y.Z]  writes manifest.json (keeps the version otherwise)
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = join(import.meta.dirname, "..");
const ROOT_FILES = ["SPEC.md", "PORTING.md", "currencies.json"];
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/** The files under `dir` (relative to the root, with "/"), sorted. */
export function filesUnder(dir) {
  const out = [];
  const walk = (relative) => {
    for (const entry of readdirSync(join(ROOT, relative), { withFileTypes: true })) {
      const child = `${relative}/${entry.name}`;
      if (entry.isDirectory()) walk(child);
      else out.push(child);
    }
  };
  walk(dir);
  return out.sort();
}

/** The pinned files, sorted, with their SHA-256. */
export function pinnedFiles() {
  const names = [...ROOT_FILES, ...filesUnder("vectors")].sort();
  return Object.fromEntries(
    names.map((name) => [
      name,
      createHash("sha256")
        .update(readFileSync(join(ROOT, name)))
        .digest("hex")
    ])
  );
}

function main(argv) {
  const file = join(ROOT, "manifest.json");
  const current = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
  const files = pinnedFiles();
  if (argv.includes("--check")) {
    const problems = [];
    if (!current) problems.push("manifest.json is missing.");
    else {
      if (!VERSION.test(current.version ?? "")) problems.push("Invalid version.");
      if (!Number.isSafeInteger(current.protocol) || current.protocol < 1) {
        problems.push("Invalid protocol.");
      }
      for (const [name, hash] of Object.entries(files)) {
        if (!current.files?.[name]) problems.push(`${name} is not in manifest.json.`);
        else if (current.files[name] !== hash) problems.push(`${name} differs from manifest.json.`);
      }
      for (const name of Object.keys(current.files ?? {})) {
        if (!files[name]) problems.push(`${name} is in manifest.json, not in the repository.`);
      }
      if (JSON.stringify(Object.keys(current.files ?? {})) !== JSON.stringify(Object.keys(files))) {
        problems.push("manifest.json's files are not sorted.");
      }
    }
    if (problems.length > 0) {
      for (const problem of problems) console.error(problem);
      console.error("Run: npm run manifest");
      process.exitCode = 1;
      return;
    }
    console.log(`manifest.json (${current.version}) is the ${Object.keys(files).length} files'.`);
    return;
  }
  const at = argv.indexOf("--version");
  const version = at === -1 ? current?.version : argv[at + 1];
  if (!VERSION.test(version ?? "")) throw new Error("No version: give --version X.Y.Z.");
  const manifest = {
    description:
      current?.description ??
      'The files a repository that depends on this specification copies, with their SHA-256 (PORTING.md, "The pinned copy of the specification").',
    version,
    protocol: current?.protocol ?? 1,
    files
  };
  writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Wrote manifest.json (${version}, ${Object.keys(files).length} files).`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
