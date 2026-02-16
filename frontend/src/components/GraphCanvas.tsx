import { useRef, useEffect, useCallback, useState } from 'react';
import cytoscape from 'cytoscape';
import type { Core, NodeSingular, EventObject } from 'cytoscape';
// @ts-ignore - no type definitions available
import dagre from 'cytoscape-dagre';
// @ts-ignore - no type definitions available
import coseBilkent from 'cytoscape-cose-bilkent';
import type { CodeGraph, GraphNode } from '../types/graph';
import { graphToCytoscape } from '../types/graph';

// Register layout extensions (guard against multiple registrations in HMR)
try {
  cytoscape.use(dagre);
} catch {
  // Already registered - this is fine
}

try {
  cytoscape.use(coseBilkent);
} catch {
  // Already registered - this is fine
}

// Premium Cytoscape style definitions
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const cytoscapeStyles: any[] = [
  // Node styles - refined, modern look
  {
    selector: 'node',
    style: {
      'background-color': '#64748b',
      'label': 'data(label)',
      'color': '#ffffff',
      'text-valign': 'center',
      'text-halign': 'center',
      'font-size': '11px',
      'font-weight': '500',
      'width': 100,
      'height': 36,
      'padding': '10px',
      'shape': 'round-rectangle',
      'text-wrap': 'ellipsis',
      'text-max-width': '90px',
      'border-width': 0,
      'overlay-opacity': 0,
    },
  },
  // Function nodes - color based on complexity when metrics available
  {
    selector: 'node.function',
    style: {
      'background-color': '#64748b', // Default slate when no metrics
    },
  },
  // Class nodes
  {
    selector: 'node.class, node.struct',
    style: {
      'background-color': '#8b5cf6',
      'shape': 'round-rectangle',
    },
  },
  // File nodes
  {
    selector: 'node.file',
    style: {
      'background-color': '#0ea5e9',
      'shape': 'round-rectangle',
    },
  },
  // Reference nodes
  {
    selector: 'node.reference',
    style: {
      'background-color': '#a855f7',
      'shape': 'ellipse',
      'width': 28,
      'height': 28,
      'font-size': '9px',
    },
  },
  // Entry/block nodes (CFG)
  {
    selector: 'node.entry, node.block',
    style: {
      'background-color': '#f59e0b',
      'shape': 'round-rectangle',
    },
  },
  // Cluster/compound parent nodes
  {
    selector: 'node.cluster',
    style: {
      'background-color': '#f1f5f9',
      'background-opacity': 0.85,
      'border-width': 2,
      'border-color': '#94a3b8',
      'border-style': 'dashed',
      'text-valign': 'top',
      'text-halign': 'center',
      'text-margin-y': -8,
      'color': '#475569',
      'font-size': '10px',
      'font-weight': '600',
      'padding': '24px',
      'shape': 'round-rectangle',
      // Compound node specific
      'compound-sizing-wrt-labels': 'include',
      'min-width': '80px',
      'min-height': '60px',
    },
  },
  // Parent nodes with children
  {
    selector: ':parent',
    style: {
      'background-color': '#f8fafc',
      'background-opacity': 0.9,
      'border-width': 1,
      'border-color': '#e2e8f0',
      'border-style': 'solid',
      'padding': '20px',
    },
  },
  // Children inside compound nodes
  {
    selector: ':child',
    style: {
      // Reduce size slightly when inside a cluster
      'width': 90,
      'height': 32,
    },
  },
  // Complexity coloring - full background color coding
  {
    selector: 'node.complexity-low',
    style: {
      'background-color': '#22c55e', // Green - simple code
      'border-width': 0,
    },
  },
  {
    selector: 'node.complexity-medium',
    style: {
      'background-color': '#eab308', // Yellow - moderate complexity
      'border-width': 0,
    },
  },
  {
    selector: 'node.complexity-high',
    style: {
      'background-color': '#f97316', // Orange - complex
      'border-width': 0,
    },
  },
  {
    selector: 'node.complexity-critical',
    style: {
      'background-color': '#dc2626', // Red - very complex
      'border-width': 0,
    },
  },
  // Security: vulnerable nodes override complexity colors
  {
    selector: 'node.vulnerable',
    style: {
      'background-color': '#dc2626',
      'border-width': 3,
      'border-color': '#7f1d1d',
      'border-style': 'double',
      'color': '#ffffff',
    },
  },
  {
    selector: 'node.severity-critical',
    style: {
      'background-color': '#991b1b',
      'border-width': 3,
      'border-color': '#450a0a',
      'color': '#ffffff',
    },
  },
  {
    selector: 'node.severity-high',
    style: {
      'background-color': '#c2410c',
      'border-width': 3,
      'border-color': '#7c2d12',
      'color': '#ffffff',
    },
  },
  // Taint source/sink
  {
    selector: 'node.taint-source',
    style: {
      'border-style': 'dashed',
      'border-width': 3,
      'border-color': '#fbbf24',
    },
  },
  {
    selector: 'node.taint-sink',
    style: {
      'border-style': 'dashed',
      'border-width': 3,
      'border-color': '#ef4444',
    },
  },
  // Hover state
  {
    selector: 'node:active',
    style: {
      'overlay-opacity': 0.15,
      'overlay-color': '#000000',
    },
  },
  // Selected node
  {
    selector: 'node:selected',
    style: {
      'border-width': 3,
      'border-color': '#1e3a8a',
      'border-style': 'solid',
    },
  },
  // Edge styles - base
  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': '#94a3b8',
      'target-arrow-color': '#94a3b8',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'arrow-scale': 1,
      'opacity': 0.8,
    },
  },
  // Call edges - blue solid arrows
  {
    selector: 'edge.call',
    style: {
      'width': 2.5,
      'line-color': '#3b82f6',
      'target-arrow-color': '#3b82f6',
      'target-arrow-shape': 'triangle',
      'line-style': 'solid',
      'opacity': 0.9,
    },
  },
  // Direct calls - thicker
  {
    selector: 'edge.call-direct',
    style: {
      'width': 3,
    },
  },
  // Method calls - with circle at source
  {
    selector: 'edge.call-method',
    style: {
      'source-arrow-shape': 'circle',
      'source-arrow-color': '#3b82f6',
    },
  },
  // Async calls - dashed blue
  {
    selector: 'edge.call-async, edge.call-spawn',
    style: {
      'line-style': 'dashed',
      'line-dash-pattern': [6, 3],
      'line-color': '#6366f1',
      'target-arrow-color': '#6366f1',
    },
  },
  // Closure calls - dotted
  {
    selector: 'edge.call-closure',
    style: {
      'line-style': 'dotted',
      'line-color': '#8b5cf6',
      'target-arrow-color': '#8b5cf6',
    },
  },
  // Import edges - green dashed with diamond arrow
  {
    selector: 'edge.import',
    style: {
      'width': 2,
      'line-color': '#10b981',
      'target-arrow-color': '#10b981',
      'target-arrow-shape': 'diamond',
      'line-style': 'dashed',
      'line-dash-pattern': [8, 4],
      'opacity': 0.85,
    },
  },
  // Reference edges - purple dotted
  {
    selector: 'edge.reference',
    style: {
      'width': 1.5,
      'line-color': '#a855f7',
      'target-arrow-color': '#a855f7',
      'target-arrow-shape': 'vee',
      'line-style': 'dotted',
      'opacity': 0.6,
    },
  },
  // Flow edges (CFG) - orange with chevron arrows
  {
    selector: 'edge.flow',
    style: {
      'width': 2.5,
      'line-color': '#f59e0b',
      'target-arrow-color': '#f59e0b',
      'target-arrow-shape': 'chevron',
      'line-style': 'solid',
      'opacity': 0.9,
    },
  },
  // Cycle edges - red bold dashed
  {
    selector: 'edge.cycle',
    style: {
      'width': 3,
      'line-color': '#dc2626',
      'target-arrow-color': '#dc2626',
      'target-arrow-shape': 'triangle',
      'line-style': 'dashed',
      'line-dash-pattern': [5, 5],
      'opacity': 1,
    },
  },
  // Selected edge
  {
    selector: 'edge:selected',
    style: {
      'width': 4,
      'line-color': '#1e3a8a',
      'target-arrow-color': '#1e3a8a',
      'opacity': 1,
    },
  },
];

export type LayoutType = 'dagre' | 'breadthfirst' | 'circle' | 'concentric' | 'cose-bilkent' | 'grid';

export interface GraphCanvasProps {
  graph: CodeGraph | null;
  onNodeSelect?: (node: GraphNode | null) => void;
  onNodeDoubleClick?: (node: GraphNode) => void;
  layout?: LayoutType;
  className?: string;
}

export function GraphCanvas({
  graph,
  onNodeSelect,
  onNodeDoubleClick,
  layout = 'dagre',
  className = '',
}: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [isReady, setIsReady] = useState(false);

  // Initialize Cytoscape - only once when container is available
  useEffect(() => {
    if (!containerRef.current || cyRef.current) return;

    cyRef.current = cytoscape({
      container: containerRef.current,
      style: cytoscapeStyles,
      minZoom: 0.1,
      maxZoom: 3,
      wheelSensitivity: 0.3,
    });
    setIsReady(true);

    return () => {
      cyRef.current?.destroy();
      cyRef.current = null;
      setIsReady(false);
    };
  }, []);

  // Update graph data - only when cytoscape is ready AND we have graph data
  useEffect(() => {
    if (!isReady || !cyRef.current || !graph) return;

    const cy = cyRef.current;

    // Extra safety check
    if (!cy.container()) {
      console.warn('Cytoscape container not available');
      return;
    }

    // Convert graph to Cytoscape elements
    const elements = graphToCytoscape(graph);

    // Clear existing elements
    cy.elements().remove();

    if (elements.length === 0) {
      console.warn('No elements to display in graph');
      return;
    }

    // Add elements in batch
    cy.batch(() => {
      cy.add(elements as unknown as cytoscape.ElementDefinition[]);
    });

    // Apply layout with fallback
    const applyLayout = (name: string, options: cytoscape.LayoutOptions): boolean => {
      try {
        const layoutInstance = cy.layout(options);
        layoutInstance.run();
        return true;
      } catch (err) {
        console.warn(`Layout '${name}' failed:`, err);
        return false;
      }
    };

    // Determine the best layout based on graph size
    const nodeCount = elements.filter(e => e.group === 'nodes').length;

    // For very large graphs (>300 nodes), use force-directed cose-bilkent
    // For medium graphs (50-300), allow hierarchical layouts
    // For small graphs (<50), any layout works well
    const layoutToUse = nodeCount > 300 && layout === 'dagre' ? 'cose-bilkent' : layout;

    // Build layout options with size-appropriate settings
    const layoutOptions = getLayoutOptions(layoutToUse, graph, nodeCount);

    if (!applyLayout(layoutToUse, layoutOptions)) {
      // Fallback chain: cose-bilkent -> breadthfirst -> grid
      if (!applyLayout('cose-bilkent', getLayoutOptions('cose-bilkent', graph, nodeCount))) {
        if (!applyLayout('breadthfirst', { name: 'breadthfirst', directed: true, spacingFactor: 1.25, animate: false })) {
          applyLayout('grid', { name: 'grid', animate: false });
        }
      }
    }

    // Fit to viewport after layout settles (guard against destroyed instance)
    const fitTimeout = setTimeout(() => {
      if (cyRef.current?.container()) {
        cyRef.current.fit(undefined, 50);
      }
    }, 150);

    return () => clearTimeout(fitTimeout);
  }, [isReady, graph, layout]);

  // Handle node selection
  const handleSelect = useCallback(
    (event: EventObject) => {
      if (!onNodeSelect) return;

      const node = event.target as NodeSingular;
      if (node.isNode()) {
        const data = node.data();
        onNodeSelect({
          id: data.id,
          label: data.label,
          kind: data.kind,
          file_path: data.file_path,
          line: data.line,
          metrics: data.metrics,
          security: data.security,
        });
      }
    },
    [onNodeSelect]
  );

  const handleUnselect = useCallback(() => {
    onNodeSelect?.(null);
  }, [onNodeSelect]);

  const handleDoubleClick = useCallback(
    (event: EventObject) => {
      if (!onNodeDoubleClick) return;

      const node = event.target as NodeSingular;
      if (node.isNode()) {
        const data = node.data();
        onNodeDoubleClick({
          id: data.id,
          label: data.label,
          kind: data.kind,
          file_path: data.file_path,
          line: data.line,
          metrics: data.metrics,
          security: data.security,
        });
      }
    },
    [onNodeDoubleClick]
  );

  // Set up event handlers - only when cytoscape is ready
  useEffect(() => {
    if (!isReady || !cyRef.current) return;

    const cy = cyRef.current;
    cy.on('select', 'node', handleSelect);
    cy.on('unselect', 'node', handleUnselect);
    cy.on('dbltap', 'node', handleDoubleClick);

    return () => {
      cy.off('select', 'node', handleSelect);
      cy.off('unselect', 'node', handleUnselect);
      cy.off('dbltap', 'node', handleDoubleClick);
    };
  }, [isReady, handleSelect, handleUnselect, handleDoubleClick]);

  return (
    <div
      ref={containerRef}
      className={`w-full h-full min-h-[400px] bg-slate-50 dark:bg-slate-950 ${className}`}
    />
  );
}

function getLayoutOptions(
  layout: string,
  _graph: CodeGraph,
  nodeCount: number = 50
): cytoscape.LayoutOptions {
  // Disable animation for larger graphs for performance
  const animate = nodeCount < 100;
  const animationDuration = animate ? 400 : 0;

  switch (layout) {
    case 'dagre':
      return {
        name: 'dagre',
        rankDir: 'TB', // Top to bottom - hierarchical
        nodeSep: nodeCount > 100 ? 30 : 50, // Tighter spacing for larger graphs
        rankSep: nodeCount > 100 ? 60 : 100,
        edgeSep: 10,
        ranker: 'tight-tree', // Better for call graphs - alternatives: 'network-simplex', 'longest-path'
        animate,
        animationDuration,
        fit: true,
        padding: 30,
      } as cytoscape.LayoutOptions;

    case 'breadthfirst':
      return {
        name: 'breadthfirst',
        directed: true,
        circle: false,
        grid: false,
        spacingFactor: nodeCount > 100 ? 1.0 : 1.5,
        avoidOverlap: true,
        animate,
        animationDuration,
        fit: true,
        padding: 30,
      };

    case 'circle':
      return {
        name: 'circle',
        spacingFactor: nodeCount > 50 ? 1.0 : 1.5,
        avoidOverlap: true,
        animate,
        animationDuration,
        fit: true,
        padding: 30,
      };

    case 'concentric':
      return {
        name: 'concentric',
        minNodeSpacing: nodeCount > 100 ? 20 : 50,
        avoidOverlap: true,
        animate,
        animationDuration,
        fit: true,
        padding: 30,
        concentric: (node: cytoscape.NodeSingular) => {
          // Put nodes with more connections in the center
          return node.degree(false);
        },
      };

    case 'cose-bilkent':
      return {
        name: 'cose-bilkent',
        quality: nodeCount > 200 ? 'draft' : 'default',
        nodeDimensionsIncludeLabels: true,
        animate: animate ? 'end' : false,
        animationDuration,
        fit: true,
        padding: 30,
        // Physics settings for good clustering
        idealEdgeLength: nodeCount > 100 ? 50 : 80,
        nodeRepulsion: nodeCount > 100 ? 4500 : 8500,
        nestingFactor: 0.1,
        gravity: 0.25,
        numIter: nodeCount > 200 ? 1000 : 2500,
        tile: true,
        tilingPaddingVertical: 10,
        tilingPaddingHorizontal: 10,
        gravityRangeCompound: 1.5,
        gravityCompound: 1.0,
        gravityRange: 3.8,
      } as cytoscape.LayoutOptions;

    case 'grid':
      return {
        name: 'grid',
        fit: true,
        padding: 30,
        avoidOverlap: true,
        animate: false,
        condense: true,
        rows: undefined,
        cols: undefined,
      };

    default:
      // Default to cose-bilkent for unknown layouts - it's the most robust
      return getLayoutOptions('cose-bilkent', _graph, nodeCount);
  }
}

export default GraphCanvas;
