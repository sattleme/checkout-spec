// Checks every JSON file of the specification against its schema (schemas/). A JSON file without a
// schema fails too: a new vector file comes with its schema.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import Ajv2020 from "ajv/dist/2020.js";

import { filesUnder } from "./manifest.mjs";

const ROOT = join(import.meta.dirname, "..");

/** Each JSON file, and its schema in schemas/. */
const SCHEMAS = {
  "manifest.json": "manifest",
  "currencies.json": "currencies",
  "vectors/app/app.json": "app",
  "vectors/app/implementation-declaration.json": "implementation-declaration",
  "vectors/app/checkout-link.json": "checkout-link",
  "vectors/app/onchain-lot.json": "onchain-lot",
  "vectors/app/checkout-rest.json": "checkout-rest",
  "vectors/app/merchant-acceptance.json": "merchant-acceptance",
  "vectors/nip44/nip44.vectors.json": "nip44"
};

/** vectors/<name>.json: schemas/<name>.schema.json. */
function schemaOf(file) {
  return SCHEMAS[file] ?? /^vectors\/([a-z0-9-]+)\.json$/.exec(file)?.[1] ?? null;
}

const read = (file) => JSON.parse(readFileSync(join(ROOT, file), "utf8"));

const ajv = new Ajv2020({ strict: true, allErrors: true });
for (const name of readdirSync(join(ROOT, "schemas"))) {
  ajv.addSchema(read(`schemas/${name}`), name);
}

const files = ["manifest.json", "currencies.json", ...filesUnder("vectors")];
const problems = [];
for (const file of files) {
  if (!file.endsWith(".json")) {
    problems.push(`${file}: not a JSON file.`);
    continue;
  }
  const schema = schemaOf(file);
  const validate = schema && ajv.getSchema(`${schema}.schema.json`);
  if (!validate) {
    problems.push(`${file}: no schema (schemas/${schema ?? "?"}.schema.json).`);
    continue;
  }
  if (!validate(read(file))) {
    for (const error of validate.errors) {
      problems.push(`${file}${error.instancePath}: ${error.message}`);
    }
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(problem);
  process.exitCode = 1;
} else {
  console.log(`${files.length} files match their schemas.`);
}
