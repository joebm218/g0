import type { FlowNode, FlowPath, ToxicFlow, ToxicFlowSeverity } from '../types/flow.js';

export function scorePaths(
  paths: FlowPath[],
  nodes: FlowNode[],
): ToxicFlow[] {
  const toxicFlows: ToxicFlow[] = [];
  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  for (const path of paths) {
    const toxic = analyzePath(path, nodeMap);
    if (toxic) {
      toxicFlows.push(toxic);
    }
  }

  // Sort by severity then risk score
  const severityOrder: Record<ToxicFlowSeverity, number> = { critical: 0, high: 1, medium: 2 };
  toxicFlows.sort((a, b) =>
    severityOrder[a.severity] - severityOrder[b.severity] || b.riskScore - a.riskScore,
  );

  return toxicFlows;
}

function analyzePath(path: FlowPath, nodeMap: Map<string, FlowNode>): ToxicFlow | null {
  const hasUntrustedInput = path.nodes.some(id => {
    const n = nodeMap.get(id);
    return n?.type === 'user_input' || (n?.trust === 'untrusted' && n?.type !== 'tool');
  });

  if (!hasUntrustedInput) return null;

  const terminalId = path.nodes[path.nodes.length - 1];
  const terminal = nodeMap.get(terminalId);
  if (!terminal) return null;

  // CRITICAL: untrusted input -> shell/code-exec without validation
  if (terminal.scope === 'execute' && terminal.trust !== 'trusted') {
    return {
      severity: 'critical',
      title: 'Untrusted input reaches code execution',
      description: `User input flows to "${terminal.label}" which has ${terminal.scope} scope without adequate validation`,
      path: path.nodes.map(id => nodeMap.get(id)?.label ?? id),
      riskScore: path.riskScore,
    };
  }

  // CRITICAL: untrusted input -> external side-effect (email, API)
  if (terminal.scope === 'external' && terminal.access === 'write') {
    return {
      severity: 'critical',
      title: 'Untrusted input triggers external side-effect',
      description: `User input flows to "${terminal.label}" which can perform external writes (email, API calls) without approval`,
      path: path.nodes.map(id => nodeMap.get(id)?.label ?? id),
      riskScore: path.riskScore,
    };
  }

  // HIGH: untrusted input -> database write without validation
  if (terminal.scope === 'database' && terminal.access === 'write' && terminal.trust !== 'trusted') {
    return {
      severity: 'high',
      title: 'Untrusted input reaches database write',
      description: `User input flows to "${terminal.label}" which writes to database without parameterization`,
      path: path.nodes.map(id => nodeMap.get(id)?.label ?? id),
      riskScore: path.riskScore,
    };
  }

  // HIGH: cross-agent delegation passes input without re-validation
  const agentNodes = path.nodes.filter(id => nodeMap.get(id)?.type === 'agent');
  if (agentNodes.length > 1 && terminal.scope && terminal.scope !== 'internal') {
    return {
      severity: 'high',
      title: 'Cross-agent delegation without re-validation',
      description: `Input passes through ${agentNodes.length} agents before reaching "${terminal.label}" without re-validation`,
      path: path.nodes.map(id => nodeMap.get(id)?.label ?? id),
      riskScore: path.riskScore,
    };
  }

  // MEDIUM: read-only tools with external scope (SSRF risk)
  if (terminal.scope === 'external' && terminal.access === 'read') {
    return {
      severity: 'medium',
      title: 'External read from untrusted input (SSRF risk)',
      description: `User input flows to "${terminal.label}" which performs external reads — potential SSRF vector`,
      path: path.nodes.map(id => nodeMap.get(id)?.label ?? id),
      riskScore: path.riskScore,
    };
  }

  // MEDIUM: file write without path validation
  if (terminal.scope === 'filesystem' && terminal.access === 'write') {
    return {
      severity: 'medium',
      title: 'File write from untrusted input',
      description: `User input flows to "${terminal.label}" which can write to filesystem without path validation`,
      path: path.nodes.map(id => nodeMap.get(id)?.label ?? id),
      riskScore: path.riskScore,
    };
  }

  return null;
}
