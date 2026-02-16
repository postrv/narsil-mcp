import { describe, it, expect } from 'vitest';
import {
  nodeToCytoscape,
  edgeToCytoscape,
  graphToCytoscape,
  type GraphNode,
  type GraphEdge,
  type CodeGraph,
  type CytoscapeNode,
} from './graph';

describe('nodeToCytoscape', () => {
  const baseNode: GraphNode = {
    id: 'fn_main',
    label: 'main',
    kind: 'function',
    file_path: 'src/main.rs',
    line: 42,
  };

  it('converts a basic node to Cytoscape format', () => {
    const result = nodeToCytoscape(baseNode);
    expect(result.group).toBe('nodes');
    expect(result.data.id).toBe('fn_main');
    expect(result.data.label).toBe('main');
    expect(result.data.kind).toBe('function');
    expect(result.data.file_path).toBe('src/main.rs');
    expect(result.data.line).toBe(42);
    expect(result.classes).toBe('function');
  });

  it('sets parent when cluster is provided', () => {
    const result = nodeToCytoscape(baseNode, 'cluster_src');
    expect(result.data.parent).toBe('cluster_src');
  });

  it('adds complexity-low class for low cyclomatic complexity', () => {
    const node: GraphNode = {
      ...baseNode,
      metrics: { loc: 10, cyclomatic: 5, cognitive: 3, call_count: 2, caller_count: 1 },
    };
    const result = nodeToCytoscape(node);
    expect(result.classes).toContain('complexity-low');
  });

  it('adds complexity-medium class for moderate complexity', () => {
    const node: GraphNode = {
      ...baseNode,
      metrics: { loc: 50, cyclomatic: 12, cognitive: 8, call_count: 5, caller_count: 3 },
    };
    const result = nodeToCytoscape(node);
    expect(result.classes).toContain('complexity-medium');
  });

  it('adds complexity-high class for high complexity', () => {
    const node: GraphNode = {
      ...baseNode,
      metrics: { loc: 100, cyclomatic: 18, cognitive: 15, call_count: 10, caller_count: 5 },
    };
    const result = nodeToCytoscape(node);
    expect(result.classes).toContain('complexity-high');
  });

  it('adds complexity-critical class for very high complexity', () => {
    const node: GraphNode = {
      ...baseNode,
      metrics: { loc: 200, cyclomatic: 25, cognitive: 20, call_count: 15, caller_count: 8 },
    };
    const result = nodeToCytoscape(node);
    expect(result.classes).toContain('complexity-critical');
  });

  it('adds vulnerable class for nodes with security findings', () => {
    const node: GraphNode = {
      ...baseNode,
      security: { has_vulnerabilities: true, severity: 'high', taint_source: false, taint_sink: false },
    };
    const result = nodeToCytoscape(node);
    expect(result.classes).toContain('vulnerable');
    expect(result.classes).toContain('severity-high');
  });

  it('adds taint classes for taint source and sink', () => {
    const node: GraphNode = {
      ...baseNode,
      security: { has_vulnerabilities: false, taint_source: true, taint_sink: true },
    };
    const result = nodeToCytoscape(node);
    expect(result.classes).toContain('taint-source');
    expect(result.classes).toContain('taint-sink');
  });

  it('handles node with no metrics or security', () => {
    const result = nodeToCytoscape(baseNode);
    expect(result.classes).toBe('function');
    expect(result.data.metrics).toBeUndefined();
    expect(result.data.security).toBeUndefined();
  });
});

describe('edgeToCytoscape', () => {
  it('converts a basic call edge', () => {
    const edge: GraphEdge = {
      id: 'e1',
      source: 'fn_a',
      target: 'fn_b',
      type: 'call',
    };
    const result = edgeToCytoscape(edge);
    expect(result.group).toBe('edges');
    expect(result.data.source).toBe('fn_a');
    expect(result.data.target).toBe('fn_b');
    expect(result.classes).toBe('call');
  });

  it('adds call type class', () => {
    const edge: GraphEdge = {
      id: 'e2',
      source: 'fn_a',
      target: 'fn_b',
      type: 'call',
      call_type: 'async',
    };
    const result = edgeToCytoscape(edge);
    expect(result.classes).toContain('call');
    expect(result.classes).toContain('call-async');
  });

  it('adds cycle class for cycle edges', () => {
    const edge: GraphEdge = {
      id: 'e3',
      source: 'fn_a',
      target: 'fn_b',
      type: 'call',
      is_cycle: true,
    };
    const result = edgeToCytoscape(edge);
    expect(result.classes).toContain('cycle');
  });

  it('handles import edge type', () => {
    const edge: GraphEdge = {
      id: 'e4',
      source: 'file_a',
      target: 'file_b',
      type: 'import',
    };
    const result = edgeToCytoscape(edge);
    expect(result.classes).toBe('import');
  });
});

describe('graphToCytoscape', () => {
  const minimalGraph: CodeGraph = {
    metadata: {
      repo: 'test-repo',
      view: 'call',
      generated_at: '2025-01-01T00:00:00Z',
      node_count: 2,
      edge_count: 1,
    },
    nodes: [
      { id: 'a', label: 'a', kind: 'function', file_path: 'a.rs', line: 1 },
      { id: 'b', label: 'b', kind: 'function', file_path: 'b.rs', line: 2 },
    ],
    edges: [
      { id: 'e1', source: 'a', target: 'b', type: 'call' },
    ],
  };

  it('converts a minimal graph correctly', () => {
    const elements = graphToCytoscape(minimalGraph);
    expect(elements).toHaveLength(3); // 2 nodes + 1 edge
    const nodes = elements.filter(e => e.group === 'nodes');
    const edges = elements.filter(e => e.group === 'edges');
    expect(nodes).toHaveLength(2);
    expect(edges).toHaveLength(1);
  });

  it('filters out self-loops', () => {
    const graph: CodeGraph = {
      ...minimalGraph,
      edges: [
        { id: 'e1', source: 'a', target: 'a', type: 'call' }, // self-loop
        { id: 'e2', source: 'a', target: 'b', type: 'call' },
      ],
    };
    const elements = graphToCytoscape(graph);
    const edges = elements.filter(e => e.group === 'edges');
    expect(edges).toHaveLength(1);
    expect(edges[0].data.id).toBe('e2');
  });

  it('filters out edges with missing nodes', () => {
    const graph: CodeGraph = {
      ...minimalGraph,
      edges: [
        { id: 'e1', source: 'a', target: 'nonexistent', type: 'call' },
        { id: 'e2', source: 'a', target: 'b', type: 'call' },
      ],
    };
    const elements = graphToCytoscape(graph);
    const edges = elements.filter(e => e.group === 'edges');
    expect(edges).toHaveLength(1);
    expect(edges[0].data.id).toBe('e2');
  });

  it('creates cluster parent nodes', () => {
    const graph: CodeGraph = {
      ...minimalGraph,
      clusters: [
        { id: 'cluster_src', label: 'src/', nodes: ['a', 'b'] },
      ],
    };
    const elements = graphToCytoscape(graph);
    const clusterNodes = elements.filter(
      e => e.group === 'nodes' && e.classes?.includes('cluster')
    );
    expect(clusterNodes).toHaveLength(1);
    expect(clusterNodes[0].data.id).toBe('cluster_src');
    // Child nodes should reference parent
    const childNodes = elements.filter(
      e => e.group === 'nodes' && e.data.id === 'a'
    );
    expect((childNodes[0] as CytoscapeNode).data.parent).toBe('cluster_src');
  });

  it('handles empty graph', () => {
    const graph: CodeGraph = {
      metadata: { repo: 'test', view: 'call', generated_at: '', node_count: 0, edge_count: 0 },
      nodes: [],
      edges: [],
    };
    const elements = graphToCytoscape(graph);
    expect(elements).toHaveLength(0);
  });
});
