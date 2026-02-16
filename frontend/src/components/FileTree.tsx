import { useState, useCallback } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getProjectStructure, type ProjectStructureNode } from '../api/toolClient';

export function FileTree() {
  const { repo } = useParams<{ repo: string }>();

  const { data: tree, isLoading, error } = useQuery({
    queryKey: ['projectStructure', repo],
    queryFn: () => getProjectStructure(repo!),
    enabled: !!repo,
    staleTime: 120000,
  });

  if (!repo) {
    return (
      <div className="p-4 text-xs text-slate-400 dark:text-slate-500">
        Select a repository
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="p-4 space-y-2">
        {[1, 2, 3, 4, 5].map(i => (
          <div key={i} className="h-4 rounded bg-slate-100 dark:bg-slate-800 animate-pulse" style={{ width: `${50 + i * 10}%` }} />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 text-xs text-red-500">
        Failed to load file tree
      </div>
    );
  }

  return (
    <div className="overflow-auto text-xs">
      {tree?.map(node => (
        <TreeNode key={node.path} node={node} repo={repo} depth={0} />
      ))}
    </div>
  );
}

interface TreeNodeProps {
  node: ProjectStructureNode;
  repo: string;
  depth: number;
}

function TreeNode({ node, repo, depth }: TreeNodeProps) {
  const [expanded, setExpanded] = useState(depth < 1);

  const toggle = useCallback(() => {
    if (node.isDir) setExpanded(prev => !prev);
  }, [node.isDir]);

  const paddingLeft = 12 + depth * 16;

  if (node.isDir) {
    return (
      <>
        <button
          onClick={toggle}
          className="w-full flex items-center gap-1.5 py-1 px-2 hover:bg-slate-100 dark:hover:bg-slate-800 text-left"
          style={{ paddingLeft }}
        >
          <svg
            className={`w-3 h-3 text-slate-400 flex-shrink-0 transition-transform ${expanded ? 'rotate-90' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <svg className="w-3.5 h-3.5 text-amber-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
          </svg>
          <span className="truncate text-slate-700 dark:text-slate-300 font-medium">{node.name}</span>
        </button>
        {expanded && node.children?.map(child => (
          <TreeNode key={child.path} node={child} repo={repo} depth={depth + 1} />
        ))}
      </>
    );
  }

  return (
    <Link
      to={`/${repo}/file/${node.path}`}
      className="w-full flex items-center gap-1.5 py-1 px-2 hover:bg-slate-100 dark:hover:bg-slate-800"
      style={{ paddingLeft: paddingLeft + 16 }}
    >
      <FileIcon name={node.name} />
      <span className="truncate text-slate-600 dark:text-slate-400">{node.name}</span>
    </Link>
  );
}

function FileIcon({ name }: { name: string }) {
  const ext = name.split('.').pop()?.toLowerCase() ?? '';
  let color = 'text-slate-400';

  if (['rs'].includes(ext)) color = 'text-orange-400';
  else if (['ts', 'tsx'].includes(ext)) color = 'text-blue-400';
  else if (['js', 'jsx', 'mjs'].includes(ext)) color = 'text-yellow-400';
  else if (['py'].includes(ext)) color = 'text-green-400';
  else if (['go'].includes(ext)) color = 'text-cyan-400';
  else if (['toml', 'yaml', 'yml', 'json'].includes(ext)) color = 'text-purple-400';
  else if (['md', 'txt'].includes(ext)) color = 'text-slate-300';

  return (
    <svg className={`w-3.5 h-3.5 ${color} flex-shrink-0`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  );
}
