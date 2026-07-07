/** Navigation sidebar component */
import { Link, useLocation } from 'react-router-dom';
import { useUIStore } from '@/store/uiState';

const Sidebar = () => {
  const location = useLocation();
  const { sidebarOpen, setSidebarOpen } = useUIStore();

  const navItems = [
    {
      path: '/scan',
      label: 'Recon & Vuln Scan',
      icon: (
        <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          <circle cx="10" cy="10" r="3" stroke="currentColor" strokeWidth="2" />
        </svg>
      ),
    },
    {
      path: '/live',
      label: 'Live Fuzz Monitor',
      icon: (
        <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      ),
    },
    {
      path: '/targets',
      label: 'Targets & Scope',
      icon: (
        <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
        </svg>
      ),
    },
    {
      path: '/experiments',
      label: 'Fuzz Campaigns',
      icon: (
        <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
        </svg>
      ),
    },
    {
      path: '/findings',
      label: 'Findings Database',
      icon: (
        <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
    },
    {
      path: '/checklist',
      label: 'Hunting Checklist',
      icon: (
        <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
        </svg>
      ),
    },
  ];

  const isActive = (path: string) => {
    if (path === '/scan') {
      return location.pathname === '/' || location.pathname.startsWith('/scan');
    }
    return location.pathname.startsWith(path);
  };

  return (
    <>
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className="fixed top-0 left-0 z-50 h-screen bg-gray-900 text-white transition-transform duration-300 lg:translate-x-0 w-64"
        style={{ transform: sidebarOpen ? 'translateX(0)' : undefined }}
      >
        <div className="flex flex-col h-full">
          <div className="p-6 border-b border-gray-800">
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <span className="text-red-500">⚡</span> XSS Boss
            </h1>
            <p className="text-sm text-gray-400 mt-1">Hackathon Edition</p>
          </div>

          <nav className="flex-1 p-4 space-y-2">
            {navItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center px-4 py-3 rounded-lg transition-colors ${
                  isActive(item.path)
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`}
                onClick={() => {
                  if (window.innerWidth < 1024) {
                    setSidebarOpen(false);
                  }
                }}
              >
                {item.icon}
                <span className="font-medium text-sm">{item.label}</span>
              </Link>
            ))}
          </nav>

          <div className="p-4 border-t border-gray-800 flex justify-between items-center text-xs text-gray-400">
            <span>Hackathon V1.2</span>
            <span className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse" title="System Ready"></span>
          </div>
        </div>
      </aside>
    </>
  );
};
export default Sidebar;
