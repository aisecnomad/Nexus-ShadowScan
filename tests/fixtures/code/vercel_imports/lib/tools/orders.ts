import { tool } from "ai";

export const lookupOrder = tool({
  description: "Return a fixed fixture status without accessing an external system",
  execute: async ({ orderNumber }) => ({ orderNumber, status: "fixture" }),
});
