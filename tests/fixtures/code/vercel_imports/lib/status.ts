import { generateText } from "ai";
import { lookupOrder } from "@/lib/tools/orders";

// Inert scanner input: this source is never imported or executed by the tests.
export async function status(question: string) {
  return generateText({ model, prompt: question, tools: { lookupOrder } });
}
