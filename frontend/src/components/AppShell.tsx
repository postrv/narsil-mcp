import { Outlet, Link, useParams, useNavigate } from 'react-router-dom';
import { useExploration } from '../contexts/ExplorationContext';
import { Breadcrumbs } from './Breadcrumbs';
import { FileTree } from './FileTree';
import { useHealth, useRepos } from '../hooks/useCodeIntel';

export function AppShell() {
  const { repo } = useParams<{ repo: string }>();
  const navigate = useNavigate();
  const { data: health, isLoading: healthLoading, error: healthError } = useHealth();
  const { data: repos } = useRepos();
  const { sidebarOpen, toggleSidebar, darkMode, toggleDarkMode, presentationMode } = useExploration();

  if (healthLoading) {
    return (
      <div className="h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950">
        <div className="text-center">
          <div className="relative w-12 h-12 mx-auto mb-4">
            <div className="absolute inset-0 rounded-full border-2 border-slate-200 dark:border-slate-800" />
            <div className="absolute inset-0 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
          </div>
          <p className="text-slate-500 dark:text-slate-400 text-sm font-medium">Connecting to server...</p>
        </div>
      </div>
    );
  }

  if (healthError) {
    return (
      <div className="h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950">
        <div className="text-center max-w-md px-6">
          <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-red-50 dark:bg-red-950 flex items-center justify-center">
            <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">Connection Failed</h2>
          <p className="text-slate-500 dark:text-slate-400 text-sm mb-4">
            Could not connect to the narsil-mcp server. Make sure it's running with the{' '}
            <code className="px-1.5 py-0.5 bg-slate-100 dark:bg-slate-800 rounded text-xs font-mono">--http</code> flag.
          </p>
          <code className="block bg-slate-900 dark:bg-slate-800 text-slate-100 p-4 rounded-lg text-xs text-left font-mono">
            ./narsil-mcp --repos . --http --call-graph
          </code>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-slate-50 dark:bg-slate-950">
      {/* Header */}
      {!presentationMode && (
        <header className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-5 py-3 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            {/* Sidebar toggle */}
            <button
              onClick={toggleSidebar}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
              title={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
              aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>

            <Link to="/" className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-blue-500 flex items-center justify-center">
                <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <h1 className="text-base font-semibold text-slate-900 dark:text-white tracking-tight">narsil-mcp</h1>
            </Link>
            <span className="px-2 py-0.5 text-[10px] font-medium bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400 rounded-full uppercase tracking-wide">
              v{health?.version ?? '?'}
            </span>

            {/* Repo selector in header */}
            {repos && repos.length > 0 && (
              <>
                <div className="h-6 w-px bg-slate-200 dark:bg-slate-700" />
                <select
                  value={repo ?? ''}
                  onChange={(e) => {
                    const r = e.target.value;
                    if (r) navigate(`/${r}`);
                    else navigate('/');
                  }}
                  className="h-8 pl-3 pr-8 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                >
                  <option value="">Select repo...</option>
                  {repos.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </>
            )}
          </div>

          <div className="flex items-center gap-2">
            {/* Dark mode toggle */}
            <button
              onClick={toggleDarkMode}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
              title={darkMode ? 'Light mode' : 'Dark mode'}
              aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {darkMode ? (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
            </button>
            <span className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
              <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
              <span className="font-medium">Connected</span>
            </span>
          </div>
        </header>
      )}

      {/* Breadcrumbs */}
      {repo && !presentationMode && <Breadcrumbs />}

      {/* Main content area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        {repo && sidebarOpen && !presentationMode && (
          <aside className="w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col flex-shrink-0 overflow-hidden">
            <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800">
              <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                Files
              </span>
            </div>
            <div className="flex-1 overflow-auto">
              <FileTree />
            </div>
          </aside>
        )}

        {/* Content */}
        <div className="flex-1 flex overflow-hidden">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
