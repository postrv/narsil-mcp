import { Component, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ExplorationProvider } from './contexts/ExplorationContext';
import { AppShell } from './components/AppShell';
import { DashboardPage } from './pages/DashboardPage';
import { RepoOverviewPage } from './pages/RepoOverviewPage';
import { GraphPage } from './pages/GraphPage';
import { FilePage } from './pages/FilePage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60000,
      retry: 1,
    },
  },
});

interface ErrorBoundaryState {
  error: Error | null;
}

class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950">
          <div className="text-center max-w-md px-6">
            <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-red-50 dark:bg-red-950 flex items-center justify-center">
              <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">Something went wrong</h2>
            <p className="text-slate-500 dark:text-slate-400 text-sm mb-4">{this.state.error.message}</p>
            <button
              onClick={() => { this.setState({ error: null }); window.location.hash = '/'; }}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-500 hover:bg-blue-600 rounded-md transition-colors"
            >
              Return to dashboard
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <HashRouter>
          <ExplorationProvider>
            <Routes>
              <Route element={<AppShell />}>
                {/* Dashboard — repo picker */}
                <Route index element={<DashboardPage />} />

                {/* Repo overview */}
                <Route path=":repo" element={<RepoOverviewPage />} />

                {/* Graph views */}
                <Route path=":repo/graph/:view" element={<GraphPage />} />

                {/* Default graph redirect */}
                <Route path=":repo/graph" element={<Navigate to="call" replace />} />

                {/* File viewer */}
                <Route path=":repo/file/*" element={<FilePage />} />

                {/* Redirect legacy security path to graph view with security overlay */}
                <Route path=":repo/security" element={<Navigate to="../graph/call?security=true" replace />} />

                {/* Catch-all: redirect unmatched repo sub-paths to repo overview */}
                <Route path=":repo/*" element={<Navigate to=".." replace />} />
              </Route>
            </Routes>
          </ExplorationProvider>
        </HashRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
