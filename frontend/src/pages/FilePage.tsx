import { useParams, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getFile } from '../api/toolClient';
import { CodeViewer } from '../components/CodeViewer';

export function FilePage() {
  const { repo, '*': filePath } = useParams<{ repo: string; '*': string }>();
  const [searchParams] = useSearchParams();
  const highlightLine = searchParams.get('line') ? parseInt(searchParams.get('line')!, 10) : undefined;

  const { data: file, isLoading, error } = useQuery({
    queryKey: ['file', repo, filePath],
    queryFn: () => getFile(repo!, filePath!),
    enabled: !!repo && !!filePath,
    staleTime: 60000,
  });

  if (!repo || !filePath) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <p className="text-sm text-slate-400">Select a file to view</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="relative w-8 h-8">
          <div className="absolute inset-0 rounded-full border-2 border-slate-200 dark:border-slate-800" />
          <div className="absolute inset-0 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center px-6">
          <p className="text-sm text-red-500 mb-1">Failed to load file</p>
          <p className="text-xs text-slate-400">{String(error)}</p>
        </div>
      </div>
    );
  }

  if (!file) return null;

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* File header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex-shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <svg className="w-4 h-4 text-slate-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <span className="text-sm font-mono text-slate-700 dark:text-slate-300 truncate">{file.path}</span>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-400 flex-shrink-0">
          <span>{file.lines} lines</span>
          <span className="px-1.5 py-0.5 bg-slate-100 dark:bg-slate-800 rounded text-[10px] font-medium uppercase">
            {file.language}
          </span>
        </div>
      </div>

      {/* Code content */}
      <div className="flex-1 overflow-auto">
        <CodeViewer code={file.content} language={file.language} highlightLine={highlightLine} />
      </div>
    </div>
  );
}
