import { Link, useLocation, useParams } from 'react-router-dom';

export function Breadcrumbs() {
  const { repo } = useParams<{ repo: string }>();
  const location = useLocation();

  if (!repo) return null;

  const parts = location.pathname
    .replace(/^\//, '')
    .split('/')
    .filter(Boolean);

  // Build breadcrumb segments from the URL
  const crumbs: { label: string; path: string }[] = [
    { label: repo, path: `/${repo}` },
  ];

  // Determine what section we're in
  if (parts.length > 1) {
    const section = parts[1];
    if (section === 'graph' && parts[2]) {
      crumbs.push({ label: `${parts[2]} graph`, path: `/${repo}/graph/${parts[2]}` });
    } else if (section === 'file' && parts.length > 2) {
      const filePath = parts.slice(2).join('/');
      // Add path segments as breadcrumbs
      const pathSegments = filePath.split('/');
      let accumulated = '';
      for (const segment of pathSegments) {
        accumulated = accumulated ? `${accumulated}/${segment}` : segment;
        crumbs.push({
          label: segment,
          path: `/${repo}/file/${accumulated}`,
        });
      }
    } else if (section === 'symbol' && parts[2]) {
      crumbs.push({ label: parts[2], path: `/${repo}/symbol/${parts[2]}` });
    } else if (section === 'function' && parts[2]) {
      crumbs.push({ label: `${parts[2]}()`, path: `/${repo}/function/${parts[2]}` });
    } else if (section === 'security') {
      crumbs.push({ label: 'Security', path: `/${repo}/security` });
    } else if (section === 'search') {
      crumbs.push({ label: 'Search', path: `/${repo}/search${location.search}` });
    }
  }

  return (
    <nav className="flex items-center gap-1 px-5 py-2 text-xs border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-x-auto">
      <Link
        to="/"
        className="text-slate-400 dark:text-slate-500 hover:text-blue-600 dark:hover:text-blue-400 flex-shrink-0"
      >
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
        </svg>
      </Link>
      {crumbs.map((crumb, i) => (
        <span key={crumb.path} className="flex items-center gap-1 flex-shrink-0">
          <svg className="w-3 h-3 text-slate-300 dark:text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          {i === crumbs.length - 1 ? (
            <span className="font-medium text-slate-700 dark:text-slate-300">{crumb.label}</span>
          ) : (
            <Link
              to={crumb.path}
              className="text-slate-500 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400"
            >
              {crumb.label}
            </Link>
          )}
        </span>
      ))}
    </nav>
  );
}
