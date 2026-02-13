import type { InventoryResult, RiskLevel } from './inventory.js';

export type DiffStatus = 'added' | 'removed' | 'changed';

export interface InventoryDiffItem<T> {
  status: DiffStatus;
  current?: T;
  previous?: T;
  changes?: string[];
}

export interface InventoryDiff {
  models: InventoryDiffItem<InventoryResult['models'][number]>[];
  frameworks: InventoryDiffItem<InventoryResult['frameworks'][number]>[];
  tools: InventoryDiffItem<InventoryResult['tools'][number]>[];
  agents: InventoryDiffItem<InventoryResult['agents'][number]>[];
  mcpServers: InventoryDiffItem<InventoryResult['mcpServers'][number]>[];
  vectorDBs: InventoryDiffItem<InventoryResult['vectorDBs'][number]>[];
  risks: InventoryDiffItem<InventoryResult['risks'][number]>[];
  summary: InventoryDiffSummary;
}

export interface InventoryDiffSummary {
  totalAdded: number;
  totalRemoved: number;
  totalChanged: number;
  riskDelta: Record<RiskLevel, number>;
}
