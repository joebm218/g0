import * as fs from 'node:fs';
import type { FlowAnalysisResult } from '../types/flow.js';

export function reportFlowsJson(
  result: FlowAnalysisResult,
  outputPath?: string,
): string {
  const json = JSON.stringify(result, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
