import { tool } from 'ai';

export const lookupOrder = tool({
  execute: async ({orderId}) => ({orderId, status: 'packed'}),
});
