/**
 * Command rail — built on the 21st.dev "Sidebar" component (uniquesonu/sidebar),
 * adapted to XSS Boss routes, react-router navigation, and the console palette.
 */
import { Link, useLocation } from 'react-router-dom';
import {
  Radar,
  Activity,
  Crosshair,
  FlaskConical,
  Bug,
  ListChecks,
  ChevronLeft,
  Zap,
} from 'lucide-react';
import { useUIStore } from '@/store/uiState';

const menuItems = [
  { name: 'Recon & Vuln Scan', hint: 'URL → monitor', path: '/scan', icon: Radar },
  { name: 'Live Fuzz Monitor', hint: 'Real-time', path: '/live', icon: Activity },
  { name: 'Targets & Scope', hint: 'Authorization', path: '/targets', icon: Crosshair },
  { name: 'Fuzz Campaigns', hint: 'Batch runs', path: '/experiments', icon: FlaskConical },
  { name: 'Findings Database', hint: 'Confirmed', path: '/findings', icon: Bug },
  { name: 'Hunting Checklist', hint: 'Playbook', path: '/checklist', icon: ListChecks },
];

const Sidebar = () => {
  const location = useLocation();
  const { sidebarOpen, setSidebarOpen, sidebarCollapsed, toggleSidebarCollapsed } = useUIStore();

  const isActive = (path: string) => {
    if (path === '/scan') return location.pathname === '/' || location.pathname.startsWith('/scan');
    return location.pathname.startsWith(path);
  };

  return (
    <>
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-carbon-950/70 backdrop-blur-sm transition-opacity duration-300 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed left-0 top-0 z-40 flex h-full w-64 flex-col border-r border-carbon-700/60 bg-carbon-950/95 shadow-2xl backdrop-blur-xl transition-all duration-300 ease-in-out ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        } lg:translate-x-0 ${sidebarCollapsed ? 'lg:w-20' : 'lg:w-64'}`}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-carbon-700/60 px-5 py-5">
          <div className="flex items-center gap-3 overflow-hidden">
            <span className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 to-fuchsia-500 shadow-glow-brand">
              <Zap className="h-5 w-5 text-white" fill="currentColor" strokeWidth={0} />
            </span>
            {!sidebarCollapsed && (
              <div className="leading-tight">
                <h1 className="font-display text-lg font-bold tracking-tight text-carbon-100">XSS Boss</h1>
                <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-brand-300">Attack Console</p>
              </div>
            )}
          </div>
          {/* Desktop collapse toggle */}
          <button
            onClick={toggleSidebarCollapsed}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="hidden rounded-lg p-1.5 text-carbon-400 transition-colors hover:bg-carbon-800 hover:text-carbon-100 lg:block"
          >
            <ChevronLeft className={`h-5 w-5 transition-transform duration-300 ${sidebarCollapsed ? 'rotate-180' : ''}`} />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 overflow-y-auto p-3">
          {!sidebarCollapsed && <p className="px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-[0.24em] text-carbon-500">Operations</p>}
          {menuItems.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);
            return (
              <Link
                key={item.path}
                to={item.path}
                title={sidebarCollapsed ? item.name : undefined}
                onClick={() => { if (window.innerWidth < 1024) setSidebarOpen(false); }}
                className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 transition-all duration-200 ${
                  active
                    ? 'bg-gradient-to-r from-brand-600 to-fuchsia-600 text-white shadow-glow-brand'
                    : 'text-carbon-300 hover:bg-carbon-800/70 hover:text-carbon-100'
                } ${sidebarCollapsed ? 'justify-center' : ''}`}
              >
                <Icon
                  className={`h-5 w-5 flex-shrink-0 transition-colors ${active ? 'text-white' : 'text-carbon-400 group-hover:text-brand-300'}`}
                  strokeWidth={2}
                />
                {!sidebarCollapsed && (
                  <span className="flex-1 leading-tight">
                    <span className="block text-sm font-semibold tracking-tight">{item.name}</span>
                    <span className={`block text-[11px] ${active ? 'text-white/70' : 'text-carbon-500'}`}>{item.hint}</span>
                  </span>
                )}
                {active && !sidebarCollapsed && <span className="ml-auto h-2 w-2 rounded-full bg-white/80" />}
              </Link>
            );
          })}
        </nav>

        {/* Footer — engine status */}
        <div className="border-t border-carbon-700/60 p-3">
          {sidebarCollapsed ? (
            <div className="flex justify-center py-1" title="Engine online">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/70" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
              </span>
            </div>
          ) : (
            <div className="flex items-center justify-between rounded-xl border border-carbon-700/70 bg-carbon-800/50 px-3.5 py-3">
              <div className="flex items-center gap-2.5">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/70" />
                  <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
                </span>
                <div className="leading-tight">
                  <div className="text-xs font-semibold text-carbon-100">Engine online</div>
                  <div className="font-mono text-[10px] text-carbon-500">v1.2 · ready</div>
                </div>
              </div>
              <span className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase text-emerald-300">
                live
              </span>
            </div>
          )}
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
