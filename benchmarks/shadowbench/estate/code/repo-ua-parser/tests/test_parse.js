import { readFileSync } from "node:fs";

import test from "tape";

import { parse } from "../src/index.js";

const fixtures = readFileSync(new URL("./fixtures/agents.txt", import.meta.url), "utf8")
  .split("\n")
  .filter(Boolean);

test("every fixture line parses", (t) => {
  for (const line of fixtures) {
    const result = parse(line);
    t.ok(typeof result.robot === "boolean", line.slice(0, 40));
  }
  t.end();
});

test("desktop chrome is not a robot", (t) => {
  const result = parse(fixtures[0]);
  t.equal(result.robot, false);
  t.equal(result.browser, "chrome");
  t.end();
});

test("crawler fixtures classify as robots", (t) => {
  const bots = fixtures.filter((line) => /bot|spider|externalagent/i.test(line));
  for (const line of bots) {
    t.equal(parse(line).robot, true, line.slice(0, 40));
  }
  t.end();
});
