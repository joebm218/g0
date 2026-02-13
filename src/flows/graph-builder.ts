import type { AgentGraph, ToolCapability } from '../types/agent-graph.js';
import type { FlowNode, FlowEdge, TrustLevel, ScopeType, AccessLevel } from '../types/flow.js';

export function buildFlowGraph(agentGraph: AgentGraph): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const nodes: FlowNode[] = [];
  const edges: FlowEdge[] = [];

  // Create user_input source node
  const userNode: FlowNode = {
    id: 'user_input',
    label: 'User Input',
    type: 'user_input',
    trust: 'untrusted',
  };
  nodes.push(userNode);

  // Create agent nodes
  for (const agent of agentGraph.agents) {
    const agentNode: FlowNode = {
      id: agent.id,
      label: agent.name,
      type: 'agent',
      trust: 'semi-trusted',
      file: agent.file,
      line: agent.line,
    };
    nodes.push(agentNode);

    // Edge from user input to each top-level agent
    edges.push({
      from: 'user_input',
      to: agent.id,
      label: 'user request',
      dataFlow: 'user_input',
    });

    // Create tool nodes for each tool bound to this agent
    for (const toolId of agent.tools) {
      const tool = agentGraph.tools.find(t => t.id === toolId);
      if (!tool) continue;

      // Only add tool node if it doesn't exist yet
      if (!nodes.find(n => n.id === tool.id)) {
        const scope = deriveScope(tool.capabilities);
        const access = deriveAccess(tool.hasSideEffects);

        const toolNode: FlowNode = {
          id: tool.id,
          label: tool.name,
          type: 'tool',
          trust: tool.hasInputValidation ? 'semi-trusted' : 'untrusted',
          scope,
          access,
          file: tool.file,
          line: tool.line,
        };
        nodes.push(toolNode);
      }

      // Edge from agent to tool
      edges.push({
        from: agent.id,
        to: tool.id,
        label: 'invokes',
        dataFlow: 'agent_input',
      });
    }

    // Add delegation edges
    if (agent.delegationTargets) {
      for (const targetName of agent.delegationTargets) {
        const targetAgent = agentGraph.agents.find(
          a => a.name === targetName || a.id === targetName,
        );
        if (targetAgent) {
          edges.push({
            from: agent.id,
            to: targetAgent.id,
            label: 'delegates',
            dataFlow: 'delegation',
          });
        }
      }
    }

    // If delegation is enabled generically (crewai), add edges to all other agents
    if (agent.delegationEnabled && !agent.delegationTargets) {
      for (const other of agentGraph.agents) {
        if (other.id !== agent.id) {
          edges.push({
            from: agent.id,
            to: other.id,
            label: 'may delegate',
            dataFlow: 'delegation',
          });
        }
      }
    }
  }

  return { nodes, edges };
}

function deriveScope(capabilities: ToolCapability[]): ScopeType {
  if (capabilities.includes('shell') || capabilities.includes('code-execution')) return 'execute';
  if (capabilities.includes('network') || capabilities.includes('email') || capabilities.includes('api')) return 'external';
  if (capabilities.includes('database')) return 'database';
  if (capabilities.includes('filesystem')) return 'filesystem';
  return 'internal';
}

function deriveAccess(hasSideEffects: boolean): AccessLevel {
  return hasSideEffects ? 'write' : 'read';
}
