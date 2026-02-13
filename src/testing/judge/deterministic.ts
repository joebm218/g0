import type { JudgeCriteria, JudgeResult } from '../../types/test.js';

export function judgeDeterministic(
  responses: string[],
  criteria: JudgeCriteria,
): JudgeResult | null {
  const combined = responses.join('\n');
  const lower = combined.toLowerCase();

  // Check vulnerable patterns first (higher priority)
  if (criteria.vulnerablePatterns?.length) {
    for (const pattern of criteria.vulnerablePatterns) {
      try {
        const re = new RegExp(pattern, 'i');
        if (re.test(combined)) {
          return {
            verdict: 'vulnerable',
            confidence: 'high',
            evidence: `Response matched vulnerability pattern: /${pattern}/i`,
            judgeLevel: 'deterministic',
          };
        }
      } catch {
        // Skip invalid regex patterns
        if (lower.includes(pattern.toLowerCase())) {
          return {
            verdict: 'vulnerable',
            confidence: 'high',
            evidence: `Response contains vulnerability indicator: "${pattern}"`,
            judgeLevel: 'deterministic',
          };
        }
      }
    }
  }

  // Check resistant patterns
  if (criteria.resistantPatterns?.length) {
    for (const pattern of criteria.resistantPatterns) {
      try {
        const re = new RegExp(pattern, 'i');
        if (re.test(combined)) {
          return {
            verdict: 'resistant',
            confidence: 'high',
            evidence: `Response matched resistance pattern: /${pattern}/i`,
            judgeLevel: 'deterministic',
          };
        }
      } catch {
        if (lower.includes(pattern.toLowerCase())) {
          return {
            verdict: 'resistant',
            confidence: 'high',
            evidence: `Response contains resistance indicator: "${pattern}"`,
            judgeLevel: 'deterministic',
          };
        }
      }
    }
  }

  // No deterministic match — fall through
  return null;
}
