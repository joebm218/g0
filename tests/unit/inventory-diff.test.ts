import { describe, it, expect } from 'vitest';
import { diffInventory } from '../../src/inventory/differ.js';
import type { InventoryResult } from '../../src/types/inventory.js';

function makeInventory(overrides?: Partial<InventoryResult>): InventoryResult {
  return {
    models: [],
    frameworks: [],
    tools: [],
    agents: [],
    mcpServers: [],
    vectorDBs: [],
    risks: [],
    summary: {
      totalModels: 0,
      totalFrameworks: 0,
      totalTools: 0,
      totalAgents: 0,
      totalMCPServers: 0,
      totalVectorDBs: 0,
      totalRisks: 0,
      riskBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
    },
    ...overrides,
  };
}

describe('Inventory Differ', () => {
  it('detects added models', () => {
    const current = makeInventory({
      models: [{ name: 'gpt-4', provider: 'openai', framework: 'langchain', file: 'agent.py', line: 1 }],
    });
    const baseline = makeInventory();
    const diff = diffInventory(current, baseline);

    expect(diff.models).toHaveLength(1);
    expect(diff.models[0].status).toBe('added');
    expect(diff.summary.totalAdded).toBe(1);
  });

  it('detects removed frameworks', () => {
    const current = makeInventory();
    const baseline = makeInventory({
      frameworks: [{ name: 'langchain', version: '0.1.0', file: 'requirements.txt' }],
    });
    const diff = diffInventory(current, baseline);

    expect(diff.frameworks).toHaveLength(1);
    expect(diff.frameworks[0].status).toBe('removed');
    expect(diff.summary.totalRemoved).toBe(1);
  });

  it('detects changed tools', () => {
    const current = makeInventory({
      tools: [{
        name: 'search', framework: 'langchain', description: 'search', capabilities: ['web'],
        hasSideEffects: true, hasValidation: false, file: 'agent.py', line: 1,
      }],
    });
    const baseline = makeInventory({
      tools: [{
        name: 'search', framework: 'langchain', description: 'search', capabilities: ['web'],
        hasSideEffects: false, hasValidation: false, file: 'agent.py', line: 1,
      }],
    });
    const diff = diffInventory(current, baseline);

    expect(diff.tools).toHaveLength(1);
    expect(diff.tools[0].status).toBe('changed');
    expect(diff.tools[0].changes).toContain('sideEffects: false → true');
    expect(diff.summary.totalChanged).toBe(1);
  });

  it('detects unchanged items (no diff entries)', () => {
    const inv = makeInventory({
      models: [{ name: 'gpt-4', provider: 'openai', framework: 'langchain', file: 'agent.py', line: 1 }],
    });
    const diff = diffInventory(inv, inv);

    expect(diff.models).toHaveLength(0);
    expect(diff.summary.totalAdded).toBe(0);
    expect(diff.summary.totalRemoved).toBe(0);
    expect(diff.summary.totalChanged).toBe(0);
  });

  it('calculates risk delta', () => {
    const current = makeInventory({
      risks: [
        { level: 'critical', category: 'shell', description: 'Shell tool' },
        { level: 'high', category: 'sql', description: 'SQL injection' },
      ],
    });
    const baseline = makeInventory({
      risks: [
        { level: 'critical', category: 'shell', description: 'Shell tool' },
      ],
    });
    const diff = diffInventory(current, baseline);

    expect(diff.summary.riskDelta.critical).toBe(0);
    expect(diff.summary.riskDelta.high).toBe(1);
  });
});
