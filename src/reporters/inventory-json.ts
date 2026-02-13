import * as fs from 'node:fs';
import type { InventoryResult } from '../types/inventory.js';

export function reportInventoryJson(
  inventory: InventoryResult,
  outputPath?: string,
): string {
  const json = JSON.stringify(inventory, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
