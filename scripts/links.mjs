// Checks the links of every Markdown file: a relative link, and a link to this repository on
// github.com, names a file or directory that exists, and its #anchor a heading of that file. The
// files implementations copy (manifest.json) link to each other only, or to an absolute URL: their
// relative links must still work in a copy.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, normalize, relative } from "node:path";

import { pinnedFiles } from "./manifest.mjs";

const ROOT = join(import.meta.dirname, "..");
const REPOSITORY = "https://github.com/sattleme/checkout-spec/";

function markdownFiles(dir = "") {
  const out = [];
  for (const entry of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const path = dir ? `${dir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...markdownFiles(path));
    else if (entry.name.endsWith(".md")) out.push(path);
  }
  return out;
}

/** The anchors of a Markdown file's headings, as GitHub writes them. */
function anchors(file) {
  const seen = new Map();
  const out = new Set();
  let fenced = false;
  for (const line of readFileSync(join(ROOT, file), "utf8").split("\n")) {
    if (line.startsWith("```")) fenced = !fenced;
    const heading = !fenced && /^#{1,6} (.+)$/.exec(line);
    if (!heading) continue;
    const slug = heading[1]
      .trim()
      .toLowerCase()
      .replace(/[^\p{L}\p{M}\p{N} _-]/gu, "")
      .replace(/ /g, "-");
    const count = seen.get(slug) ?? 0;
    seen.set(slug, count + 1);
    out.add(count === 0 ? slug : `${slug}-${count}`);
  }
  return out;
}

/** The link targets of a Markdown file, outside code. */
function links(file) {
  const text = readFileSync(join(ROOT, file), "utf8")
    .replace(/^```[\s\S]*?^```/gm, "")
    .replace(/`[^`\n]*`/g, "");
  return [...text.matchAll(/\]\(([^)\s]+)\)/g)].map((match) => match[1]);
}

const pinned = new Set(Object.keys(pinnedFiles()));
/** Whether `path` (relative to the root) is a pinned file, or a directory of pinned files. */
const isPinned = (path) =>
  pinned.has(path) || [...pinned].some((file) => file.startsWith(`${path}/`));

const problems = [];
let count = 0;
for (const file of markdownFiles()) {
  for (const target of links(file)) {
    count++;
    let path;
    let anchor;
    if (target.startsWith(REPOSITORY)) {
      const rest = /^(?:blob|tree)\/main\/([^#]*)(?:#(.*))?$/.exec(target.slice(REPOSITORY.length));
      if (!rest) {
        problems.push(`${file}: ${target} is not a file of the default branch.`);
        continue;
      }
      [, path, anchor] = rest;
    } else if (/^[a-z][a-z0-9+.-]*:/i.test(target)) {
      continue; // Another site, or mailto:.
    } else {
      const [relativePath, hash] = target.split("#");
      path = relativePath
        ? relative(ROOT, normalize(join(ROOT, dirname(file), relativePath)))
        : file;
      anchor = hash;
      if (path.startsWith("..")) {
        problems.push(`${file}: ${target} is outside the repository.`);
        continue;
      }
      if (pinned.has(file) && !isPinned(path)) {
        problems.push(
          `${file}: ${target} is not a copied file: link to ${REPOSITORY}blob/main/${path}.`
        );
      }
    }
    path = path.replace(/\/$/, "");
    if (!existsSync(join(ROOT, path))) {
      problems.push(`${file}: ${target}: ${path} does not exist.`);
    } else if (anchor !== undefined) {
      if (statSync(join(ROOT, path)).isDirectory() || !path.endsWith(".md")) {
        problems.push(`${file}: ${target}: an anchor in a file that is not Markdown.`);
      } else if (!anchors(path).has(anchor)) {
        problems.push(`${file}: ${target}: no heading #${anchor} in ${path}.`);
      }
    }
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(problem);
  process.exitCode = 1;
} else {
  console.log(`${count} links resolve.`);
}
