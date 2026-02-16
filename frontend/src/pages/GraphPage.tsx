import { useState, useCallback } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { GraphCanvas } from '../components/GraphCanvas';
import type { LayoutType } from '../components/GraphCanvas';
import { Controls } from '../components/Controls';
import type { DirectionType } from '../components/Controls';
import { NodeDetails } from '../components/NodeDetails';
import { Legend } from '../components/Legend';
import { useRepos, useGraph } from '../hooks/useCodeIntel';
import type { ViewType, GraphNode } from '../types/graph';

export function GraphPage() {
  const { repo: routeRepo, view: routeView } = useParams<{ repo: string; view: string }>();
  const navigate = useNavigate();
  const { data: repos } = useRepos();
  const [searchParams, setSearchParams] = useSearchParams();

  // Derive state from URL params with fallbacks
  const selectedRepo = routeRepo ?? '';
  const view = (routeView as ViewType) ?? 'call';

  // Read graph controls from URL search params
  const depth = parseInt(searchParams.get('depth') ?? '2', 10);
  const root = searchParams.get('root') ?? undefined;
  const direction = (searchParams.get('direction') ?? 'both') as DirectionType;
  const maxNodes = parseInt(searchParams.get('maxNodes') ?? '100', 10);
  const showMetrics = searchParams.get('metrics') === 'true';
  const showSecurity = searchParams.get('security') === 'true';
  const clustered = searchParams.get('clustered') === 'true';
  const layout = (searchParams.get('layout') ?? 'dagre') as LayoutType;

  // Local UI state (not worth persisting in URL)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Helper to update a single search param without losing others
  const setParam = useCallback((key: string, value: string | undefined) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      if (value === undefined || value === '') {
        next.delete(key);
      } else {
        next.set(key, value);
      }
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  // Graph query
  const {
    data: graphResponse,
    isLoading: graphLoading,
    error: graphError,
    refetch,
  } = useGraph(
    {
      repo: selectedRepo,
      view,
      depth,
      root,
      direction: view === 'call' ? direction : undefined,
      include_metrics: showMetrics,
      include_security: showSecurity,
      cluster_by: clustered ? 'file' : 'none',
      max_nodes: maxNodes,
    },
    !!selectedRepo
  );

  // Backend now limits to maxNodes — just extract the graph
  const graph = graphResponse?.graph ?? null;

  const handleNodeSelect = useCallback((node: GraphNode | null) => setSelectedNode(node), []);
  const handleNodeDoubleClick = useCallback((node: GraphNode) => setParam('root', node.id), [setParam]);
  const handleNavigate = useCallback((filePath: string, line: number) => {
    if (selectedRepo && filePath) {
      navigate(`/${selectedRepo}/file/${filePath}?line=${line}`);
    }
  }, [selectedRepo, navigate]);

  return (
    <>
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Graph controls */}
        <Controls
          repos={repos ?? []}
          selectedRepo={selectedRepo}
          onRepoChange={() => {}} // Repo change handled by header selector
          view={view}
          onViewChange={(v) => {
            navigate(`/${selectedRepo}/graph/${v}?${searchParams.toString()}`, { replace: true });
          }}
          depth={depth}
          onDepthChange={(d) => setParam('depth', String(d))}
          root={root}
          onRootChange={(r) => setParam('root', r)}
          direction={direction}
          onDirectionChange={(d) => setParam('direction', d)}
          maxNodes={maxNodes}
          onMaxNodesChange={(n) => setParam('maxNodes', String(n))}
          showMetrics={showMetrics}
          onShowMetricsChange={(v) => setParam('metrics', v ? 'true' : undefined)}
          showSecurity={showSecurity}
          onShowSecurityChange={(v) => setParam('security', v ? 'true' : undefined)}
          clustered={clustered}
          onClusteredChange={(v) => setParam('clustered', v ? 'true' : undefined)}
          layout={layout}
          onLayoutChange={(l) => setParam('layout', l)}
          loading={graphLoading}
          onRefresh={() => refetch()}
        />

        <div className="flex-1 flex overflow-hidden">
          {/* Graph canvas */}
          <div className="flex-1 relative">
            {graphLoading ? (
              <div className="h-full flex items-center justify-center">
                <div className="relative w-8 h-8">
                  <div className="absolute inset-0 rounded-full border-2 border-slate-200 dark:border-slate-800" />
                  <div className="absolute inset-0 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
                </div>
              </div>
            ) : graphError || graphResponse?.error ? (
              <div className="h-full flex items-center justify-center">
                <div className="text-center px-6">
                  <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-red-50 dark:bg-red-950 flex items-center justify-center">
                    <svg className="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  </div>
                  <p className="text-slate-900 dark:text-white font-medium text-sm mb-1">Error loading graph</p>
                  <p className="text-slate-500 dark:text-slate-400 text-xs max-w-xs">
                    {graphResponse?.error ?? String(graphError)}
                  </p>
                </div>
              </div>
            ) : (
              <GraphCanvas
                graph={graph}
                onNodeSelect={handleNodeSelect}
                onNodeDoubleClick={handleNodeDoubleClick}
                layout={layout}
              />
            )}

            {/* Graph stats overlay */}
            {graph && (
              <div className="absolute bottom-4 left-4 bg-white/90 dark:bg-slate-900/90 backdrop-blur-sm rounded-lg shadow-sm border border-slate-200 dark:border-slate-800 px-3 py-2 text-xs text-slate-600 dark:text-slate-400">
                <span className="font-semibold text-slate-900 dark:text-white">{graph.metadata.node_count}</span> nodes
                <span className="mx-1.5 text-slate-300 dark:text-slate-700">&middot;</span>
                <span className="font-semibold text-slate-900 dark:text-white">{graph.metadata.edge_count}</span> edges
              </div>
            )}
          </div>

          {/* Side panel */}
          <div className="w-80 bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 flex flex-col flex-shrink-0">
            <div className="border-b border-slate-200 dark:border-slate-800 px-4 py-3">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Details</h2>
            </div>
            <div className="flex-1 overflow-auto">
              <NodeDetails
                node={selectedNode}
                onClose={() => setSelectedNode(null)}
                onNavigate={handleNavigate}
              />
            </div>
          </div>
        </div>

        {/* Legend */}
        <Legend />
      </div>
    </>
  );
}
