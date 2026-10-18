import { generateText } from 'ai';
import { lookupOrder } from '@/lib/tools/orders';

export async function status(question: string) {
  return generateText({model, prompt: question, tools: {lookupOrder}});
}
