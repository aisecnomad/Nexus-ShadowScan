// Static site build: render content/*.md into site/*.html with a shared
// layout. No client-side code; the pages pipeline uploads site/ as-is.
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

import _ from "lodash";
import { marked } from "marked";

const CONTENT_DIR = "content";
const SITE_DIR = "site";

const layout = _.template(
  '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    "<title><%- title %></title>" +
    '<link rel="stylesheet" href="site.css"></head>' +
    "<body><main><%= body %></main></body></html>",
);

const files = await readdir(CONTENT_DIR);
await mkdir(SITE_DIR, { recursive: true });
for (const file of files.filter((name) => name.endsWith(".md"))) {
  const source = await readFile(path.join(CONTENT_DIR, file), "utf8");
  const title = _.startCase(path.basename(file, ".md"));
  const body = marked.parse(source);
  const target = path.join(SITE_DIR, `${path.basename(file, ".md")}.html`);
  await writeFile(target, layout({ title, body }));
}
