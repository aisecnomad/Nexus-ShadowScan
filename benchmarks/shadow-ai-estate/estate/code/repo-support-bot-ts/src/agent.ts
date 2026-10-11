import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
import { z } from "zod";

import { lookupShipment } from "./shipments.js";

export async function answer(question: string): Promise<string> {
  const result = await generateText({
    model: openai("gpt-4o-mini"),
    system:
      "You are the Vantor Logistics support assistant. Answer questions " +
      "about shipments, quotes and delivery windows. Cite the tracking id.",
    prompt: question,
    tools: {
      shipment: tool({
        description: "Look up a shipment by its tracking id",
        parameters: z.object({ trackingId: z.string() }),
        execute: async ({ trackingId }) => lookupShipment(trackingId),
      }),
    },
    maxSteps: 4,
  });
  return result.text;
}
