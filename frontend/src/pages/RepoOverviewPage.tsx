import { Link, useParams } from 'react-router-dom';

export function RepoOverviewPage() {
  const { repo } = useParams<{ repo: string }>();

  if (!repo) return null;

  const quickLinks = [
    { label: 'Call Graph', path: `/${repo}/graph/call`, icon: 'M13 10V3L4 14h7v7l9-11h-7z', color: 'blue' },
    { label: 'Import Graph', path: `/${repo}/graph/import`, icon: 'M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14', color: 'emerald' },
    { label: 'Symbol Graph', path: `/${repo}/graph/symbol`, icon: 'M7 20l4-16m2 16l4-16M6 9h14M4 15h14', color: 'purple' },
    { label: 'Hybrid Graph', path: `/${repo}/graph/hybrid`, icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z', color: 'amber' },
    { label: 'Control Flow', path: `/${repo}/graph/flow`, icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2', color: 'orange' },
    { label: 'Security', path: `/${repo}/graph/call?security=true`, icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', color: 'red' },
  ];

  const colorMap: Record<string, string> = {
    blue: 'bg-blue-50 dark:bg-blue-950 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900',
    emerald: 'bg-emerald-50 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-100 dark:hover:bg-emerald-900',
    purple: 'bg-purple-50 dark:bg-purple-950 text-purple-600 dark:text-purple-400 hover:bg-purple-100 dark:hover:bg-purple-900',
    amber: 'bg-amber-50 dark:bg-amber-950 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900',
    orange: 'bg-orange-50 dark:bg-orange-950 text-orange-600 dark:text-orange-400 hover:bg-orange-100 dark:hover:bg-orange-900',
    red: 'bg-red-50 dark:bg-red-950 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900',
  };

  return (
    <div className="flex-1 p-8 overflow-auto">
      <div className="max-w-4xl mx-auto">
        <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">{repo}</h2>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-8">
          Choose a view to explore this repository.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {quickLinks.map(link => (
            <Link
              key={link.path}
              to={link.path}
              className={`group p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:border-slate-300 dark:hover:border-slate-700 hover:shadow-md transition-all`}
            >
              <div className={`w-10 h-10 rounded-lg ${colorMap[link.color]} flex items-center justify-center mb-3 transition-colors`}>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={link.icon} />
                </svg>
              </div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{link.label}</h3>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
