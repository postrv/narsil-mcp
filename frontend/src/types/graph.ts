// Graph types matching the backend Rust structures

export interface GraphMetadata {
  repo: string;
  view: ViewType;
  generated_at: string;
  node_count: number;
  edge_count: number;
}

export interface NodeMetrics {
  loc: number;
  cyclomatic: number;
  cognitive: number;
  call_count: number;
  caller_count: number;
}

export interface NodeSecurity {
  has_vulnerabilities: boolean;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  taint_source: boolean;
  taint_sink: boolean;
}

export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  file_path: string;
  line: number;
  metrics?: NodeMetrics;
  security?: NodeSecurity;
  excerpt?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  label?: string;
  call_type?: CallType;
  weight?: number;
  is_cycle?: boolean;
}

export interface Cluster {
  id: string;
  label: string;
  nodes: string[];
  parent?: string;
}

export interface CodeGraph {
  metadata: GraphMetadata;
  nodes: GraphNode[];
  edges: GraphEdge[];
  clusters?: Cluster[];
}

// Enums
export type ViewType = 'call' | 'import' | 'symbol' | 'hybrid' | 'flow';
export type NodeKind = 'function' | 'class' | 'struct' | 'file' | 'reference' | 'entry' | 'block';
export type EdgeType = 'call' | 'import' | 'reference' | 'flow';
export type CallType = 'direct' | 'method' | 'static' | 'closure' | 'async' | 'spawn' | 'unknown';

// API Request/Response types
export interface GraphRequest {
  repo: string;
  view: ViewType;
  root?: string;
  depth?: number;
  direction?: 'callers' | 'callees' | 'both';
  include_metrics?: boolean;
  include_security?: boolean;
  include_excerpts?: boolean;
  cluster_by?: 'none' | 'file' | 'module';
  max_nodes?: number;
  filter?: {
    min_complexity?: number;
    file_pattern?: string;
  };
}

export interface GraphResponse {
  success: boolean;
  graph?: CodeGraph;
  error?: string;
}

export interface ToolCallRequest {
  tool: string;
  args: Record<string, unknown>;
}

export interface ToolCallResponse {
  success: boolean;
  result?: unknown;
  error?: string;
}

// UI State types
export interface GraphState {
  graph: CodeGraph | null;
  loading: boolean;
  error: string | null;
  selectedNode: GraphNode | null;
  highlightedNodes: Set<string>;
  view: ViewType;
  depth: number;
  showMetrics: boolean;
  showSecurity: boolean;
  clustered: boolean;
}

// Cytoscape element types
export interface CytoscapeNode {
  group: 'nodes';
  data: {
    id: string;
    label: string;
    kind: NodeKind;
    file_path: string;
    line: number;
    metrics?: NodeMetrics;
    security?: NodeSecurity;
    parent?: string;
  };
  classes?: string;
}

export interface CytoscapeEdge {
  group: 'edges';
  data: {
    id: string;
    source: string;
    target: string;
    type: EdgeType;
    label?: string;
    call_type?: CallType;
    weight?: number;
    is_cycle?: boolean;
  };
  classes?: string;
}

export type CytoscapeElement = CytoscapeNode | CytoscapeEdge;

// Utility functions
export function nodeToCytoscape(node: GraphNode, cluster?: string): CytoscapeNode {
  const classes: string[] = [node.kind];

  if (node.security?.has_vulnerabilities) {
    classes.push('vulnerable');
    if (node.security.severity) {
      classes.push(`severity-${node.security.severity}`);
    }
  }

  if (node.security?.taint_source) classes.push('taint-source');
  if (node.security?.taint_sink) classes.push('taint-sink');

  if (node.metrics) {
    const cc = node.metrics.cyclomatic;
    if (cc > 20) classes.push('complexity-critical');
    else if (cc > 15) classes.push('complexity-high');
    else if (cc > 10) classes.push('complexity-medium');
    else classes.push('complexity-low');
  }

  return {
    group: 'nodes',
    data: {
      id: node.id,
      label: node.label,
      kind: node.kind,
      file_path: node.file_path,
      line: node.line,
      metrics: node.metrics,
      security: node.security,
      parent: cluster,
    },
    classes: classes.join(' '),
  };
}

export function edgeToCytoscape(edge: GraphEdge): CytoscapeEdge {
  const classes: string[] = [edge.type];

  if (edge.is_cycle) classes.push('cycle');
  if (edge.call_type) classes.push(`call-${edge.call_type}`);

  return {
    group: 'edges',
    data: {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: edge.type,
      label: edge.label,
      call_type: edge.call_type,
      weight: edge.weight,
      is_cycle: edge.is_cycle,
    },
    classes: classes.join(' '),
  };
}

export function graphToCytoscape(graph: CodeGraph): CytoscapeElement[] {
  const elements: CytoscapeElement[] = [];

  // Create cluster parent nodes if present
  if (graph.clusters) {
    for (const cluster of graph.clusters) {
      elements.push({
        group: 'nodes',
        data: {
          id: cluster.id,
          label: cluster.label,
          kind: 'file' as NodeKind,
          file_path: cluster.label,
          line: 0,
          parent: cluster.parent,
        },
        classes: 'cluster',
      });
    }
  }

  // Create node map for cluster lookup
  const nodeToCluster = new Map<string, string>();
  if (graph.clusters) {
    for (const cluster of graph.clusters) {
      for (const nodeId of cluster.nodes) {
        nodeToCluster.set(nodeId, cluster.id);
      }
    }
  }

  // Build a set of valid node IDs for edge validation
  const validNodeIds = new Set<string>(graph.nodes.map(n => n.id));

  // Also include cluster IDs as valid targets
  if (graph.clusters) {
    for (const cluster of graph.clusters) {
      validNodeIds.add(cluster.id);
    }
  }

  // Add nodes
  for (const node of graph.nodes) {
    elements.push(nodeToCytoscape(node, nodeToCluster.get(node.id)));
  }

  // Add edges (only if both source and target exist, and no self-loops)
  for (const edge of graph.edges) {
    if (
      validNodeIds.has(edge.source) &&
      validNodeIds.has(edge.target) &&
      edge.source !== edge.target // Filter out self-loops which can confuse dagre
    ) {
      elements.push(edgeToCytoscape(edge));
    }
  }

  return elements;
}
