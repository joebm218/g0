import type { AttackPayload, AttackCategory } from '../../types/test.js';
import { promptInjectionPayloads } from './prompt-injection.js';
import { dataExfiltrationPayloads } from './data-exfiltration.js';
import { toolAbusePayloads } from './tool-abuse.js';
import { jailbreakPayloads } from './jailbreak.js';
import { goalHijackingPayloads } from './goal-hijacking.js';
import { authorizationPayloads } from './authorization.js';
import { indirectInjectionPayloads } from './indirect-injection.js';
import { encodingBypassPayloads } from './encoding-bypass.js';

const allPayloads: AttackPayload[] = [
  ...promptInjectionPayloads,
  ...dataExfiltrationPayloads,
  ...toolAbusePayloads,
  ...jailbreakPayloads,
  ...goalHijackingPayloads,
  ...authorizationPayloads,
  ...indirectInjectionPayloads,
  ...encodingBypassPayloads,
];

export function getAllPayloads(): AttackPayload[] {
  return allPayloads;
}

export function getPayloadsByCategory(category: AttackCategory): AttackPayload[] {
  return allPayloads.filter(p => p.category === category);
}

export function getPayloadById(id: string): AttackPayload | undefined {
  return allPayloads.find(p => p.id === id);
}

export function getPayloadsByCategories(categories: AttackCategory[]): AttackPayload[] {
  return allPayloads.filter(p => categories.includes(p.category));
}

export function getPayloadsByIds(ids: string[]): AttackPayload[] {
  return allPayloads.filter(p => ids.includes(p.id));
}
