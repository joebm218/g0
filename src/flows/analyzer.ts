import type { AgentGraph } from '../types/agent-graph.js';
import type { FlowAnalysisResult } from '../types/flow.js';
import { buildFlowGraph } from './graph-builder.js';
import { enumeratePaths } from './path-finder.js';
import { scorePaths } from './scorer.js';

export function analyzeFlows(graph: AgentGraph): FlowAnalysisResult {
  const { nodes, edges } = buildFlowGraph(graph);
  const paths = enumeratePaths(nodes, edges);
  const toxicFlows = scorePaths(paths, nodes);

  const maxRiskScore = paths.length > 0
    ? Math.max(...paths.map(p => p.riskScore))
    : 0;

  let riskLevel: 'safe' | 'warning' | 'critical';
  if (toxicFlows.some(t => t.severity === 'critical')) {
    riskLevel = 'critical';
  } else if (toxicFlows.length > 0) {
    riskLevel = 'warning';
  } else {
    riskLevel = 'safe';
  }

  return {
    nodes,
    edges,
    paths,
    toxicFlows,
    summary: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      totalPaths: paths.length,
      toxicFlowCount: toxicFlows.length,
      maxRiskScore,
      riskLevel,
    },
  };
}
