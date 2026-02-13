import type { FlowNode, FlowEdge, FlowPath } from '../types/flow.js';

const MAX_HOPS = 10;
const MAX_PATHS = 100;

export function enumeratePaths(
  nodes: FlowNode[],
  edges: FlowEdge[],
): FlowPath[] {
  const paths: FlowPath[] = [];
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const adjacency = new Map<string, FlowEdge[]>();

  for (const edge of edges) {
    if (!adjacency.has(edge.from)) adjacency.set(edge.from, []);
    adjacency.get(edge.from)!.push(edge);
  }

  // Start DFS from all user_input nodes
  const startNodes = nodes.filter(n => n.type === 'user_input');

  for (const start of startNodes) {
    dfs(
      start.id,
      [start.id],
      [],
      new Set([start.id]),
      adjacency,
      nodeMap,
      paths,
    );
    if (paths.length >= MAX_PATHS) break;
  }

  return paths;
}

function dfs(
  current: string,
  pathNodes: string[],
  pathEdges: FlowEdge[],
  visited: Set<string>,
  adjacency: Map<string, FlowEdge[]>,
  nodeMap: Map<string, FlowNode>,
  results: FlowPath[],
): void {
  if (results.length >= MAX_PATHS) return;

  const outEdges = adjacency.get(current) ?? [];

  // If this is a leaf (no outgoing edges) or we've reached a tool, record the path
  if (outEdges.length === 0 || nodeMap.get(current)?.type === 'tool') {
    if (pathNodes.length >= 2) {
      results.push({
        nodes: [...pathNodes],
        edges: [...pathEdges],
        riskScore: calculatePathRisk(pathNodes, nodeMap),
        description: describePath(pathNodes, nodeMap),
      });
    }
    // For tool nodes, don't continue (tools are terminal)
    if (nodeMap.get(current)?.type === 'tool') return;
  }

  if (pathNodes.length >= MAX_HOPS) return;

  for (const edge of outEdges) {
    if (visited.has(edge.to)) continue;

    visited.add(edge.to);
    pathNodes.push(edge.to);
    pathEdges.push(edge);

    dfs(edge.to, pathNodes, pathEdges, visited, adjacency, nodeMap, results);

    pathNodes.pop();
    pathEdges.pop();
    visited.delete(edge.to);
  }
}

function calculatePathRisk(pathNodes: string[], nodeMap: Map<string, FlowNode>): number {
  let risk = 0;

  const hasUntrustedInput = pathNodes.some(id => nodeMap.get(id)?.trust === 'untrusted');
  const terminalNode = nodeMap.get(pathNodes[pathNodes.length - 1]);

  if (!terminalNode) return 0;

  if (hasUntrustedInput) {
    // Untrusted input reaching dangerous scopes
    if (terminalNode.scope === 'execute') risk += 40;
    else if (terminalNode.scope === 'external') risk += 30;
    else if (terminalNode.scope === 'database') risk += 25;
    else if (terminalNode.scope === 'filesystem') risk += 15;
    else risk += 5;

    // Write access amplifies risk
    if (terminalNode.access === 'write' || terminalNode.access === 'execute') risk += 20;
  }

  // Delegation adds risk (more hops = less control)
  const agentCount = pathNodes.filter(id => nodeMap.get(id)?.type === 'agent').length;
  if (agentCount > 1) risk += (agentCount - 1) * 10;

  // Lack of validation
  if (terminalNode.trust === 'untrusted') risk += 10;

  return Math.min(risk, 100);
}

function describePath(pathNodes: string[], nodeMap: Map<string, FlowNode>): string {
  return pathNodes
    .map(id => nodeMap.get(id)?.label ?? id)
    .join(' -> ');
}
