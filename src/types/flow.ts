export type TrustLevel = 'untrusted' | 'semi-trusted' | 'trusted';
export type ScopeType = 'internal' | 'filesystem' | 'database' | 'external' | 'execute';
export type AccessLevel = 'read' | 'write' | 'execute';

export interface FlowNode {
  id: string;
  label: string;
  type: 'user_input' | 'agent' | 'tool' | 'model' | 'external';
  trust: TrustLevel;
  scope?: ScopeType;
  access?: AccessLevel;
  file?: string;
  line?: number;
}

export interface FlowEdge {
  from: string;
  to: string;
  label?: string;
  dataFlow?: string;
}

export interface FlowPath {
  nodes: string[];
  edges: FlowEdge[];
  riskScore: number;
  description: string;
}

export type ToxicFlowSeverity = 'critical' | 'high' | 'medium';

export interface ToxicFlow {
  severity: ToxicFlowSeverity;
  title: string;
  description: string;
  path: string[];
  riskScore: number;
}

export interface FlowAnalysisResult {
  nodes: FlowNode[];
  edges: FlowEdge[];
  paths: FlowPath[];
  toxicFlows: ToxicFlow[];
  summary: FlowSummary;
}

export interface FlowSummary {
  totalNodes: number;
  totalEdges: number;
  totalPaths: number;
  toxicFlowCount: number;
  maxRiskScore: number;
  riskLevel: 'safe' | 'warning' | 'critical';
}
