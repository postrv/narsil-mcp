import { codeIntelClient } from './client';

// -------------------------------------------------------------------
// Typed wrappers around callTool for common narsil-mcp tools.
// These parse the markdown/JSON responses into structured data.
// -------------------------------------------------------------------

export interface ProjectStructureNode {
  name: string;
  path: string;
  isDir: boolean;
  children?: ProjectStructureNode[];
}

export interface FileContent {
  path: string;
  content: string;
  language: string;
  lines: number;
}

export interface SymbolInfo {
  name: string;
  kind: string;
  line: number;
  file: string;
}

export interface IndexStatus {
  repos: number;
  files: number;
  symbols: number;
  languages: string[];
  features: string[];
}

/**
 * Get project structure as a parsed tree.
 * Calls `get_project_structure` and parses the indented text output.
 */
export async function getProjectStructure(repo: string): Promise<ProjectStructureNode[]> {
  const resp = await codeIntelClient.callTool({
    tool: 'get_project_structure',
    args: { repo },
  });
  if (!resp.success) throw new Error(resp.error ?? 'Failed to get project structure');
  const tree = parseProjectStructure(resp.result as string);

  // The backend wraps everything under the repo root directory (e.g. "narsil-mcp/").
  // Unwrap it so paths are relative to the repo root, as get_file expects.
  if (tree.length === 1 && tree[0].isDir) {
    const root = tree[0];
    const prefix = root.path + '/';
    function stripPrefix(nodes: ProjectStructureNode[]) {
      for (const node of nodes) {
        if (node.path.startsWith(prefix)) {
          node.path = node.path.substring(prefix.length);
        }
        if (node.children) stripPrefix(node.children);
      }
    }
    if (root.children) {
      stripPrefix(root.children);
      return root.children;
    }
  }

  return tree;
}

/**
 * Get file contents.
 * Calls `get_file` and returns structured data.
 */
export async function getFile(repo: string, path: string): Promise<FileContent> {
  const resp = await codeIntelClient.callTool({
    tool: 'get_file',
    args: { repo, path },
  });
  if (!resp.success) throw new Error(resp.error ?? 'Failed to get file');
  const rawContent = resp.result as string;
  const code = stripMarkdownWrapper(rawContent);
  const ext = path.split('.').pop() ?? '';
  return {
    path,
    content: code,
    language: extensionToLanguage(ext),
    lines: code.split('\n').length,
  };
}

/**
 * Find symbols in a repo, optionally filtered by file.
 */
export async function findSymbols(
  repo: string,
  opts?: { path?: string; kind?: string }
): Promise<SymbolInfo[]> {
  const args: Record<string, unknown> = { repo };
  if (opts?.path) args.path = opts.path;
  if (opts?.kind) args.kind = opts.kind;

  const resp = await codeIntelClient.callTool({
    tool: 'find_symbols',
    args,
  });
  if (!resp.success) throw new Error(resp.error ?? 'Failed to find symbols');
  return parseSymbolOutput(resp.result as string);
}

/**
 * Get index status.
 */
export async function getIndexStatus(): Promise<IndexStatus> {
  const resp = await codeIntelClient.callTool({
    tool: 'get_index_status',
    args: {},
  });
  if (!resp.success) throw new Error(resp.error ?? 'Failed to get index status');
  return parseIndexStatus(resp.result as string);
}

// -------------------------------------------------------------------
// Parsers for markdown tool output
// -------------------------------------------------------------------

function parseProjectStructure(output: string): ProjectStructureNode[] {
  const lines = output.split('\n').filter(l => l.trim());
  const root: ProjectStructureNode[] = [];
  const stack: { node: ProjectStructureNode; depth: number }[] = [];

  for (const line of lines) {
    // Skip header lines like "## Project Structure" or "```"
    if (line.startsWith('#') || line.startsWith('```')) continue;

    // Parse indented tree lines like "  src/" or "    main.rs"
    const match = line.match(/^(\s*)(.*)/);
    if (!match) continue;

    const indent = match[1].length;
    let name = match[2].trim();

    // Remove tree drawing characters
    name = name.replace(/^[│├└─\s]+/, '').trim();
    if (!name) continue;

    // Strip emoji prefix (📁, 🦀, 📝, etc.): skip to the first filename character
    const nameStart = name.search(/[\w./-]/);
    if (nameStart > 0) {
      name = name.substring(nameStart);
    }

    const isDir = name.endsWith('/');
    if (isDir) name = name.slice(0, -1);

    // Strip file size suffix like "(1.2KB)" from file names
    if (!isDir) {
      name = name.replace(/\s+\([^)]+\)\s*$/, '');
    }

    // Pop stack FIRST to find the correct parent at this depth
    while (stack.length > 0 && stack[stack.length - 1].depth >= indent) {
      stack.pop();
    }

    // Build path from the correct parent
    const parentPath = stack.length > 0 ? stack[stack.length - 1].node.path : '';
    const path = parentPath ? `${parentPath}/${name}` : name;

    const node: ProjectStructureNode = { name, path, isDir };
    if (isDir) node.children = [];

    if (stack.length > 0) {
      const parent = stack[stack.length - 1].node;
      if (parent.children) parent.children.push(node);
    } else {
      root.push(node);
    }

    if (isDir) {
      stack.push({ node, depth: indent });
    }
  }

  return root;
}

function parseSymbolOutput(output: string): SymbolInfo[] {
  const symbols: SymbolInfo[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    // Match lines like "- **function_name** (function) - src/main.rs:42"
    const match = line.match(/\*\*(\w+)\*\*\s*\((\w+)\)\s*-\s*(.+):(\d+)/);
    if (match) {
      symbols.push({
        name: match[1],
        kind: match[2],
        file: match[3],
        line: parseInt(match[4], 10),
      });
    }
  }

  return symbols;
}

function parseIndexStatus(output: string): IndexStatus {
  const status: IndexStatus = {
    repos: 0,
    files: 0,
    symbols: 0,
    languages: [],
    features: [],
  };

  const lines = output.split('\n');
  for (const line of lines) {
    const reposMatch = line.match(/Repositories:\s*(\d+)/i);
    if (reposMatch) status.repos = parseInt(reposMatch[1], 10);

    const filesMatch = line.match(/Files:\s*(\d+)/i);
    if (filesMatch) status.files = parseInt(filesMatch[1], 10);

    const symbolsMatch = line.match(/Symbols:\s*(\d+)/i);
    if (symbolsMatch) status.symbols = parseInt(symbolsMatch[1], 10);
  }

  return status;
}

/**
 * Strip the markdown wrapper that `get_file` adds around code.
 *
 * The tool returns output like:
 * ```
 * # path/to/file.rs
 *
 * Lines 1-100 of 100
 *
 * ```rust
 *    1 │ fn main() {
 *    2 │     println!("hello");
 * ```
 * ```
 *
 * This function extracts just the raw code lines without the header,
 * line-count metadata, fenced code markers, or line-number prefixes.
 */
export function stripMarkdownWrapper(raw: string): string {
  const lines = raw.split('\n');
  const codeLines: string[] = [];
  let insideCodeBlock = false;

  for (const line of lines) {
    // Detect fenced code block start/end
    if (line.startsWith('```')) {
      if (insideCodeBlock) {
        // End of code block — stop
        break;
      }
      insideCodeBlock = true;
      continue;
    }

    if (!insideCodeBlock) {
      // Skip header lines (# title, Lines X-Y, blank lines)
      continue;
    }

    // Strip line-number prefix: "   1 │ code" → "code"
    // The separator may arrive as U+2502, ASCII pipe, or as a multi-byte
    // mojibake sequence (â"‚) depending on encoding. Match the general
    // pattern instead: digits, whitespace, non-whitespace separator(s), space.
    const stripped = line.replace(/^\s*\d+\s+\S+\s?/, '');
    codeLines.push(stripped);
  }

  // If no code block found, return the raw content (already plain text)
  if (codeLines.length === 0) {
    return raw;
  }

  // Remove trailing empty line that comes from the final newline before ```
  while (codeLines.length > 0 && codeLines[codeLines.length - 1] === '') {
    codeLines.pop();
  }

  return codeLines.join('\n');
}

function extensionToLanguage(ext: string): string {
  const map: Record<string, string> = {
    rs: 'rust',
    py: 'python',
    js: 'javascript',
    jsx: 'jsx',
    ts: 'typescript',
    tsx: 'tsx',
    go: 'go',
    c: 'c',
    h: 'c',
    cpp: 'cpp',
    cc: 'cpp',
    hpp: 'cpp',
    java: 'java',
    cs: 'csharp',
    rb: 'ruby',
    sh: 'bash',
    bash: 'bash',
    zsh: 'bash',
    kt: 'kotlin',
    swift: 'swift',
    php: 'php',
    scala: 'scala',
    lua: 'lua',
    hs: 'haskell',
    ex: 'elixir',
    dart: 'dart',
    jl: 'julia',
    r: 'r',
    pl: 'perl',
    zig: 'zig',
    erl: 'erlang',
    elm: 'elm',
    nix: 'nix',
    toml: 'toml',
    yaml: 'yaml',
    yml: 'yaml',
    json: 'json',
    md: 'markdown',
    html: 'html',
    css: 'css',
    sql: 'sql',
    xml: 'xml',
    groovy: 'groovy',
    gradle: 'groovy',
  };
  return map[ext] ?? 'text';
}
