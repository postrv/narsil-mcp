import type { GraphRequest, GraphResponse, ToolCallRequest, ToolCallResponse } from '../types/graph';

/**
 * Determine the API base URL:
 * - In development (Vite dev server): use localhost:3000 where narsil-mcp runs
 * - In production (embedded): use same origin (empty string for relative URLs)
 */
function getDefaultBaseUrl(): string {
  // Check if we're in development mode (Vite sets this)
  if (import.meta.env.DEV) {
    return 'http://localhost:3000';
  }
  // In production/embedded mode, use same origin
  return '';
}

export class CodeIntelClient {
  private baseUrl: string;

  constructor(baseUrl: string = getDefaultBaseUrl()) {
    this.baseUrl = baseUrl;
  }

  /**
   * Health check endpoint
   */
  async health(): Promise<{ status: string; version: string }> {
    const response = await fetch(`${this.baseUrl}/health`);
    if (!response.ok) {
      throw new Error(`Health check failed: ${response.statusText}`);
    }
    return response.json();
  }

  /**
   * List available tools
   */
  async listTools(): Promise<string[]> {
    const response = await fetch(`${this.baseUrl}/tools`);
    if (!response.ok) {
      throw new Error(`Failed to list tools: ${response.statusText}`);
    }
    const data = await response.json();
    return data.tools.map((t: { name: string }) => t.name);
  }

  /**
   * Call a tool directly
   */
  async callTool(request: ToolCallRequest): Promise<ToolCallResponse> {
    const response = await fetch(`${this.baseUrl}/tools/call`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok && response.status !== 500) {
      throw new Error(`Tool call failed: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get graph data using the convenience endpoint
   */
  async getGraph(request: GraphRequest): Promise<GraphResponse> {
    const params = new URLSearchParams();

    params.set('repo', request.repo);
    params.set('view', request.view);
    if (request.root) params.set('root', request.root);
    if (request.depth !== undefined) params.set('depth', request.depth.toString());
    if (request.direction) params.set('direction', request.direction);
    if (request.include_metrics !== undefined)
      params.set('include_metrics', request.include_metrics.toString());
    if (request.include_security !== undefined)
      params.set('include_security', request.include_security.toString());
    if (request.include_excerpts !== undefined)
      params.set('include_excerpts', request.include_excerpts.toString());
    if (request.cluster_by) params.set('cluster_by', request.cluster_by);
    if (request.max_nodes !== undefined)
      params.set('max_nodes', request.max_nodes.toString());

    const response = await fetch(`${this.baseUrl}/graph?${params.toString()}`);

    if (!response.ok && response.status !== 500) {
      throw new Error(`Graph fetch failed: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get code graph using the tool call endpoint
   * This gives more control over the request parameters
   */
  async getCodeGraph(request: GraphRequest): Promise<GraphResponse> {
    const toolResponse = await this.callTool({
      tool: 'get_code_graph',
      args: {
        repo: request.repo,
        view: request.view,
        root: request.root,
        depth: request.depth ?? 3,
        direction: request.direction ?? 'both',
        include_metrics: request.include_metrics ?? true,
        include_security: request.include_security ?? false,
        include_excerpts: request.include_excerpts ?? false,
        cluster_by: request.cluster_by ?? 'none',
        max_nodes: request.max_nodes,
        filter: request.filter,
      },
    });

    if (!toolResponse.success) {
      return {
        success: false,
        error: toolResponse.error ?? 'Unknown error',
      };
    }

    return {
      success: true,
      graph: toolResponse.result as GraphResponse['graph'],
    };
  }

  /**
   * List available repositories
   */
  async listRepos(): Promise<string[]> {
    const response = await this.callTool({
      tool: 'list_repos',
      args: {},
    });

    if (!response.success) {
      throw new Error(response.error ?? 'Failed to list repos');
    }

    // Parse the markdown output to extract repo names
    // Format: "## repo-name" headers followed by metadata like "- **Path**: ..."
    const output = response.result as string;
    const repos: string[] = [];
    const lines = output.split('\n');
    for (const line of lines) {
      // Only extract from "## repo-name" headers (not bold text like **Path**)
      const match = line.match(/^##\s+(.+)$/);
      if (match) {
        repos.push(match[1].trim());
      }
    }
    return repos;
  }
}

// Default singleton instance
export const codeIntelClient = new CodeIntelClient();
