/** Top command bar */
import { useLocation } from 'react-router-dom';
import { useUIStore } from '@/store/uiState';

const TITLES: Record<string, { title: string; sub: string }> = {
  '/scan': { title: 'Recon + Vuln Flow', sub: 'Single URL → live monitor' },
  '/live': { title: 'Live Fuzz Monitor', sub: 'Real-time execution feed' },
  '/targets': { title: 'Targets & Scope', sub: 'Authorized attack surface' },
  '/experiments': { title: 'Fuzz Campaigns', sub: 'Batch experiment control' },
  '/findings': { title: 'Findings Database', sub: 'Confirmed vulnerabilities' },
  '/checklist': { title: 'Hunting Checklist', sub: 'Manual review playbook' },
};

const Topbar = () => {
  const { toggleSidebar, theme, toggleTheme } = useUIStore();
  const { pathname } = useLocation();

  const key = Object.keys(TITLES).find((k) => pathname.startsWith(k)) || '/scan';
  const { title, sub } = TITLES[key];

  return (
    <header className="sticky top-0 z-30 border-b border-carbon-700/50 bg-carbon-900/70 backdrop-blur-xl">
      <div className="flex items-center justify-between px-4 py-3 sm:px-6">
        <div className="flex items-center gap-3">
          <button
            onClick={toggleSidebar}
            className="rounded-lg p-2 text-carbon-300 hover:bg-carbon-800 hover:text-carbon-100 lg:hidden"
            aria-label="Toggle command rail"
          >
            <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <div className="leading-tight">
            <div className="flex items-center gap-2">
              <span className="hidden font-mono text-[11px] text-carbon-500 sm:inline">~/xss-boss</span>
              <span className="hidden text-carbon-600 sm:inline">/</span>
              <h2 className="font-display text-base font-bold tracking-tight text-carbon-100">{title}</h2>
            </div>
            <p className="text-[11px] text-carbon-400">{sub}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="hidden items-center gap-2 rounded-lg border border-carbon-700/70 bg-carbon-800/50 px-2.5 py-1.5 font-mono text-[11px] text-carbon-400 md:inline-flex">
            <kbd className="rounded bg-carbon-700/70 px-1.5 py-0.5 text-carbon-200">⌘</kbd>
            <kbd className="rounded bg-carbon-700/70 px-1.5 py-0.5 text-carbon-200">K</kbd>
            <span>command</span>
          </span>
          <button
            onClick={toggleTheme}
            className="rounded-lg border border-carbon-700/70 bg-carbon-800/50 p-2 text-carbon-300 transition hover:border-carbon-500 hover:text-carbon-100"
            aria-label="Toggle ambient brightness"
          >
            {theme === 'light' ? (
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
              </svg>
            ) : (
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};

export default Topbar;
