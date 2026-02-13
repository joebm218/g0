import type { InventoryResult, RiskLevel } from '../types/inventory.js';
import type { InventoryDiff, InventoryDiffItem, InventoryDiffSummary } from '../types/inventory-diff.js';

type KeyExtractor<T> = (item: T) => string;

function diffArrays<T>(
  current: T[],
  previous: T[],
  keyFn: KeyExtractor<T>,
  compareFn: (a: T, b: T) => string[],
): InventoryDiffItem<T>[] {
  const result: InventoryDiffItem<T>[] = [];
  const prevMap = new Map(previous.map(item => [keyFn(item), item]));
  const currMap = new Map(current.map(item => [keyFn(item), item]));

  for (const [key, curr] of currMap) {
    const prev = prevMap.get(key);
    if (!prev) {
      result.push({ status: 'added', current: curr });
    } else {
      const changes = compareFn(curr, prev);
      if (changes.length > 0) {
        result.push({ status: 'changed', current: curr, previous: prev, changes });
      }
    }
  }

  for (const [key, prev] of prevMap) {
    if (!currMap.has(key)) {
      result.push({ status: 'removed', previous: prev });
    }
  }

  return result;
}

export function diffInventory(current: InventoryResult, baseline: InventoryResult): InventoryDiff {
  const models = diffArrays(
    current.models, baseline.models,
    m => `${m.name}:${m.provider}`,
    (a, b) => {
      const changes: string[] = [];
      if (a.framework !== b.framework) changes.push(`framework: ${b.framework} → ${a.framework}`);
      if (a.file !== b.file) changes.push(`file: ${b.file} → ${a.file}`);
      return changes;
    },
  );

  const frameworks = diffArrays(
    current.frameworks, baseline.frameworks,
    f => f.name,
    (a, b) => {
      const changes: string[] = [];
      if (a.version !== b.version) changes.push(`version: ${b.version ?? 'unknown'} → ${a.version ?? 'unknown'}`);
      return changes;
    },
  );

  const tools = diffArrays(
    current.tools, baseline.tools,
    t => `${t.name}:${t.framework}`,
    (a, b) => {
      const changes: string[] = [];
      if (a.hasSideEffects !== b.hasSideEffects) changes.push(`sideEffects: ${b.hasSideEffects} → ${a.hasSideEffects}`);
      if (a.hasValidation !== b.hasValidation) changes.push(`validation: ${b.hasValidation} → ${a.hasValidation}`);
      if (a.capabilities.join(',') !== b.capabilities.join(',')) changes.push('capabilities changed');
      return changes;
    },
  );

  const agents = diffArrays(
    current.agents, baseline.agents,
    a => `${a.name}:${a.framework}`,
    (a, b) => {
      const changes: string[] = [];
      if (a.toolCount !== b.toolCount) changes.push(`tools: ${b.toolCount} → ${a.toolCount}`);
      if (a.model !== b.model) changes.push(`model: ${b.model ?? 'none'} → ${a.model ?? 'none'}`);
      if (a.hasDelegation !== b.hasDelegation) changes.push(`delegation: ${b.hasDelegation} → ${a.hasDelegation}`);
      return changes;
    },
  );

  const mcpServers = diffArrays(
    current.mcpServers, baseline.mcpServers,
    s => s.name,
    (a, b) => {
      const changes: string[] = [];
      if (a.command !== b.command) changes.push(`command: ${b.command} → ${a.command}`);
      if (a.hasSecrets !== b.hasSecrets) changes.push(`secrets: ${b.hasSecrets} → ${a.hasSecrets}`);
      return changes;
    },
  );

  const vectorDBs = diffArrays(
    current.vectorDBs, baseline.vectorDBs,
    v => `${v.name}:${v.framework}`,
    (a, b) => {
      const changes: string[] = [];
      if (a.file !== b.file) changes.push(`file: ${b.file} → ${a.file}`);
      return changes;
    },
  );

  const risks = diffArrays(
    current.risks, baseline.risks,
    r => `${r.category}:${r.description}`,
    (a, b) => {
      const changes: string[] = [];
      if (a.level !== b.level) changes.push(`level: ${b.level} → ${a.level}`);
      return changes;
    },
  );

  const allDiffs = [...models, ...frameworks, ...tools, ...agents, ...mcpServers, ...vectorDBs, ...risks];
  const totalAdded = allDiffs.filter(d => d.status === 'added').length;
  const totalRemoved = allDiffs.filter(d => d.status === 'removed').length;
  const totalChanged = allDiffs.filter(d => d.status === 'changed').length;

  const riskLevels: RiskLevel[] = ['critical', 'high', 'medium', 'low'];
  const riskDelta = {} as Record<RiskLevel, number>;
  for (const level of riskLevels) {
    const currCount = current.risks.filter(r => r.level === level).length;
    const prevCount = baseline.risks.filter(r => r.level === level).length;
    riskDelta[level] = currCount - prevCount;
  }

  const summary: InventoryDiffSummary = { totalAdded, totalRemoved, totalChanged, riskDelta };

  return { models, frameworks, tools, agents, mcpServers, vectorDBs, risks, summary };
}
