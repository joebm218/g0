import * as fs from 'node:fs';
import type { MCPScanResult } from '../types/mcp-scan.js';

export function reportMCPJson(
  result: MCPScanResult,
  outputPath?: string,
): string {
  const json = JSON.stringify(result, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
