import { Agent } from '@openai/agents';
class LocalAgent {}

export function fromObject() {
  const { Agent } = { Agent: LocalAgent };
  return new Agent();
}

export function fromArray() {
  const [Agent] = [LocalAgent];
  return new Agent();
}
