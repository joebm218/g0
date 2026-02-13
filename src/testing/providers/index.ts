import type { TestProvider, TestTarget } from '../../types/test.js';
import { createHttpProvider } from './http.js';
import { createMcpProvider } from './mcp.js';

export function createProvider(target: TestTarget): TestProvider {
  switch (target.type) {
    case 'http':
      return createHttpProvider(target);
    case 'mcp-stdio':
      return createMcpProvider(target);
    default:
      throw new Error(`Unknown target type: ${(target as TestTarget).type}`);
  }
}
