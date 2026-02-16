import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { codeIntelClient, CodeIntelClient } from '../api/client';
import type { GraphRequest, ViewType } from '../types/graph';

// Query keys
export const queryKeys = {
  health: ['health'] as const,
  tools: ['tools'] as const,
  repos: ['repos'] as const,
  graph: (request: GraphRequest) => ['graph', request] as const,
};

/**
 * Hook for checking server health
 */
export function useHealth(client: CodeIntelClient = codeIntelClient) {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: () => client.health(),
    retry: 3,
    retryDelay: 1000,
    staleTime: 30000, // 30 seconds
  });
}

/**
 * Hook for listing available tools
 */
export function useTools(client: CodeIntelClient = codeIntelClient) {
  return useQuery({
    queryKey: queryKeys.tools,
    queryFn: () => client.listTools(),
    staleTime: Infinity, // Tools don't change during session
  });
}

/**
 * Hook for listing available repositories
 */
export function useRepos(client: CodeIntelClient = codeIntelClient) {
  return useQuery({
    queryKey: queryKeys.repos,
    queryFn: () => client.listRepos(),
    staleTime: 60000, // 1 minute
  });
}

/**
 * Hook for fetching graph data
 */
export function useGraph(
  request: GraphRequest,
  enabled: boolean = true,
  client: CodeIntelClient = codeIntelClient
) {
  return useQuery({
    queryKey: queryKeys.graph(request),
    queryFn: () => client.getGraph(request),
    enabled,
    staleTime: 60000, // 1 minute
    retry: 1,
  });
}

/**
 * Hook for fetching graph data with tool call (more control)
 */
export function useCodeGraph(
  request: GraphRequest,
  enabled: boolean = true,
  client: CodeIntelClient = codeIntelClient
) {
  return useQuery({
    queryKey: ['codeGraph', request] as const,
    queryFn: () => client.getCodeGraph(request),
    enabled,
    staleTime: 60000,
    retry: 1,
  });
}

/**
 * Hook for calling arbitrary tools
 */
export function useToolCall(client: CodeIntelClient = codeIntelClient) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ tool, args }: { tool: string; args: Record<string, unknown> }) =>
      client.callTool({ tool, args }),
    onSuccess: (_data, variables) => {
      // Invalidate related queries if needed
      if (variables.tool === 'reindex') {
        queryClient.invalidateQueries({ queryKey: queryKeys.repos });
      }
    },
  });
}

/**
 * Custom hook combining graph state management
 */
export function useGraphVisualization(initialRepo: string = '') {
  const [repo, setRepo] = useState(initialRepo);
  const [view, setView] = useState<ViewType>('call');
  const [depth, setDepth] = useState(3);
  const [root, setRoot] = useState<string | undefined>();
  const [showMetrics, setShowMetrics] = useState(true);
  const [showSecurity, setShowSecurity] = useState(false);
  const [clustered, setClustered] = useState(false);

  const request: GraphRequest = {
    repo,
    view,
    depth,
    root,
    include_metrics: showMetrics,
    include_security: showSecurity,
    cluster_by: clustered ? 'file' : 'none',
  };

  const { data, isLoading, error, refetch } = useGraph(request, !!repo);

  return {
    // State
    repo,
    view,
    depth,
    root,
    showMetrics,
    showSecurity,
    clustered,

    // Setters
    setRepo,
    setView,
    setDepth,
    setRoot,
    setShowMetrics,
    setShowSecurity,
    setClustered,

    // Query results
    graph: data?.graph ?? null,
    isLoading,
    error: error ? String(error) : data?.error ?? null,
    refetch,
  };
}
