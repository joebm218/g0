import type { AgentGraph } from '../types/agent-graph.js';
import type { Finding } from '../types/finding.js';
import type { StaticContext, AttackPayload, AttackCategory } from '../types/test.js';
import { getAllPayloads, getPayloadsByCategories } from './payloads/index.js';

export function buildStaticContext(graph: AgentGraph, findings: Finding[]): StaticContext {
  return {
    tools: graph.tools.map(t => ({
      name: t.name,
      capabilities: [...t.capabilities],
      hasValidation: t.hasInputValidation,
    })),
    models: graph.models.map(m => ({
      name: m.name,
      provider: m.provider,
    })),
    prompts: graph.prompts.map(p => ({
      type: p.type,
      hasGuarding: p.hasInstructionGuarding,
      scopeClarity: p.scopeClarity,
    })),
    findings: findings.map(f => ({
      ruleId: f.ruleId,
      domain: f.domain,
      severity: f.severity,
    })),
  };
}

interface ScoredPayload {
  payload: AttackPayload;
  score: number;
}

export function selectPayloads(
  context: StaticContext,
  categories?: AttackCategory[],
): AttackPayload[] {
  const pool = categories ? getPayloadsByCategories(categories) : getAllPayloads();
  const toolCapabilities = new Set(context.tools.flatMap(t => t.capabilities));
  const toolNames = new Set(context.tools.map(t => t.name.toLowerCase()));

  // Filter out payloads requiring tools the target doesn't have
  const eligible = pool.filter(p => {
    if (!p.requiresTools?.length) return true;
    return p.requiresTools.some(req =>
      toolCapabilities.has(req) || toolNames.has(req.toLowerCase())
    );
  });

  // Score each payload based on static context
  const scored: ScoredPayload[] = eligible.map(payload => {
    let score = 1; // Base score

    switch (payload.category) {
      case 'prompt-injection':
        // Boost if prompts lack guarding or have vague scope
        if (context.prompts.some(p => !p.hasGuarding)) score += 3;
        if (context.prompts.some(p => p.scopeClarity === 'vague' || p.scopeClarity === 'missing')) score += 2;
        break;

      case 'data-exfiltration':
        // Boost if data-leakage findings exist
        if (context.findings.some(f => f.domain === 'data-leakage')) score += 3;
        if (context.findings.some(f => f.severity === 'critical' && f.domain === 'data-leakage')) score += 2;
        break;

      case 'tool-abuse':
        // Boost if tools lack validation
        if (context.tools.some(t => !t.hasValidation)) score += 3;
        // Extra boost for dangerous capabilities
        const dangerousCaps = ['shell', 'code-execution', 'database', 'filesystem'];
        const hasDangerous = context.tools.some(t =>
          t.capabilities.some(c => dangerousCaps.includes(c))
        );
        if (hasDangerous) score += 2;
        break;

      case 'jailbreak':
        // Boost if prompts lack guarding
        if (context.prompts.some(p => !p.hasGuarding)) score += 2;
        if (context.findings.some(f => f.domain === 'goal-integrity')) score += 1;
        break;

      case 'goal-hijacking':
        // Boost when goal-integrity findings exist
        if (context.findings.some(f => f.domain === 'goal-integrity')) score += 3;
        if (context.prompts.some(p => p.scopeClarity === 'missing')) score += 2;
        break;

      case 'authorization':
        // Boost on identity-access findings + database tools
        if (context.findings.some(f => f.domain === 'identity-access')) score += 3;
        if (context.tools.some(t => t.capabilities.some(c => c === 'database' || c === 'user-management'))) score += 2;
        if (context.findings.some(f => f.severity === 'critical' && f.domain === 'identity-access')) score += 2;
        break;

      case 'indirect-injection':
        // Boost on fetch/http/rag tools + unguarded prompts
        if (context.tools.some(t => t.capabilities.some(c =>
          ['http', 'fetch', 'web', 'rag', 'retrieval', 'search'].includes(c)
        ))) score += 3;
        if (context.prompts.some(p => !p.hasGuarding)) score += 2;
        if (context.findings.some(f => f.domain === 'tool-safety')) score += 1;
        break;

      case 'encoding-bypass':
        // Boost on goal-integrity findings (suggests weak input filtering)
        if (context.findings.some(f => f.domain === 'goal-integrity')) score += 3;
        if (context.prompts.some(p => !p.hasGuarding)) score += 2;
        break;
    }

    // Severity boost
    if (payload.severity === 'critical') score += 1;

    return { payload, score };
  });

  // Sort by score descending, then by severity
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return severityRank(b.payload.severity) - severityRank(a.payload.severity);
  });

  return scored.map(s => s.payload);
}

function severityRank(severity: string): number {
  switch (severity) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
}
