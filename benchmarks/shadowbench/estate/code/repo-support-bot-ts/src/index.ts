import { createServer } from "node:http";

import { answer } from "./agent.js";

const server = createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/ask") {
    res.writeHead(404).end();
    return;
  }
  let body = "";
  for await (const chunk of req) {
    body += chunk;
  }
  const { question } = JSON.parse(body) as { question: string };
  const text = await answer(question);
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ text }));
});

server.listen(8787);
