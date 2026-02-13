import * as fs from 'node:fs';
import type { TestRunResult } from '../types/test.js';

export function reportTestJson(
  result: TestRunResult,
  outputPath?: string,
): string {
  const json = JSON.stringify(result, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
