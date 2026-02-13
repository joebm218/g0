import { describe, it, expect } from 'vitest';
import { reportInventoryCycloneDX } from '../../src/reporters/inventory-cyclonedx.js';
import type { InventoryResult } from '../../src/types/inventory.js';

function makeInventory(): InventoryResult {
  return {
    models: [
      { name: 'gpt-4', provider: 'openai', framework: 'langchain', file: 'agent.py', line: 5 },
    ],
    frameworks: [
      { name: 'langchain', version: '0.1.0', file: 'requirements.txt' },
    ],
    tools: [
      {
        name: 'search_tool', framework: 'langchain', description: 'Web search',
        capabilities: ['web'], hasSideEffects: false, hasValidation: true,
        file: 'agent.py', line: 10,
      },
    ],
    mcpServers: [
      { name: 'test-server', command: 'node', args: ['server.js'], hasSecrets: false, isPinned: false, file: 'config.json' },
    ],
    agents: [
      { name: 'researcher', framework: 'langchain', toolCount: 1, model: 'gpt-4', hasDelegation: false, file: 'agent.py', line: 20 },
    ],
    vectorDBs: [],
    risks: [
      { level: 'high', category: 'shell', description: 'Shell tool detected' },
    ],
    summary: {
      totalModels: 1, totalFrameworks: 1, totalTools: 1, totalAgents: 1,
      totalMCPServers: 1, totalVectorDBs: 0, totalRisks: 1,
      riskBreakdown: { critical: 0, high: 1, medium: 0, low: 0 },
    },
  };
}

describe('CycloneDX Reporter', () => {
  it('generates valid CycloneDX 1.6 structure', () => {
    const json = reportInventoryCycloneDX(makeInventory());
    const bom = JSON.parse(json);

    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.version).toBe(1);
    expect(bom.serialNumber).toMatch(/^urn:uuid:/);
  });

  it('maps models to machine-learning-model components', () => {
    const json = reportInventoryCycloneDX(makeInventory());
    const bom = JSON.parse(json);

    const mlComponents = bom.components.filter((c: { type: string }) => c.type === 'machine-learning-model');
    expect(mlComponents).toHaveLength(1);
    expect(mlComponents[0].name).toBe('gpt-4');
    expect(mlComponents[0].group).toBe('openai');
  });

  it('maps frameworks to framework components', () => {
    const json = reportInventoryCycloneDX(makeInventory());
    const bom = JSON.parse(json);

    const fwComponents = bom.components.filter((c: { type: string }) => c.type === 'framework');
    expect(fwComponents).toHaveLength(1);
    expect(fwComponents[0].name).toBe('langchain');
    expect(fwComponents[0].version).toBe('0.1.0');
  });

  it('maps tools to library components', () => {
    const json = reportInventoryCycloneDX(makeInventory());
    const bom = JSON.parse(json);

    const libComponents = bom.components.filter((c: { type: string }) => c.type === 'library');
    expect(libComponents).toHaveLength(1);
    expect(libComponents[0].name).toBe('search_tool');
  });

  it('maps MCP servers to services', () => {
    const json = reportInventoryCycloneDX(makeInventory());
    const bom = JSON.parse(json);

    expect(bom.services).toHaveLength(1);
    expect(bom.services[0].name).toBe('test-server');
  });

  it('generates agent dependencies', () => {
    const json = reportInventoryCycloneDX(makeInventory());
    const bom = JSON.parse(json);

    expect(bom.dependencies.length).toBeGreaterThan(0);
  });

  it('includes metadata with tool info', () => {
    const json = reportInventoryCycloneDX(makeInventory());
    const bom = JSON.parse(json);

    expect(bom.metadata.tools[0].name).toBe('g0');
    expect(bom.metadata.timestamp).toBeDefined();
  });
});
