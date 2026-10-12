// Classify a User-Agent string: browser family, OS family and robot flag.
// Robot detection is heuristic (token patterns) plus the curated list in
// data/crawlers.json; the fixture corpus under tests/fixtures keeps the
// heuristics honest against real-world strings.

import crawlers from "../data/crawlers.json" with { type: "json" };

const ROBOT_HINT = /\b(bot|crawl(er)?|spider|slurp|fetcher|archiver|preview|monitor(ing)?)\b/i;
const BROWSERS = [
  ["edge", /edg(e|a|ios)?\/(\d+)/i],
  ["chrome", /chrome\/(\d+)/i],
  ["firefox", /firefox\/(\d+)/i],
  ["safari", /version\/(\d+).*safari/i],
];
const SYSTEMS = [
  ["windows", /windows nt (\d+\.\d+)/i],
  ["macos", /mac os x (\d+[._]\d+)/i],
  ["android", /android (\d+)/i],
  ["ios", /(iphone|ipad).* os (\d+)/i],
  ["linux", /linux/i],
];

export function parse(userAgent) {
  const ua = String(userAgent || "");
  const robotName = classifyRobot(ua);
  return {
    browser: pick(BROWSERS, ua),
    os: pick(SYSTEMS, ua),
    robot: robotName !== null,
    robotName,
  };
}

function classifyRobot(ua) {
  const lowered = ua.toLowerCase();
  for (const { token, name } of crawlers) {
    if (lowered.includes(token)) {
      return name;
    }
  }
  const hint = ua.match(ROBOT_HINT);
  if (hint) {
    const product = ua.match(/([a-z0-9._-]+)\/(\d[\w.]*)/i);
    return product ? product[1] : hint[0];
  }
  return null;
}

function pick(table, ua) {
  for (const [family, pattern] of table) {
    if (pattern.test(ua)) {
      return family;
    }
  }
  return "other";
}
