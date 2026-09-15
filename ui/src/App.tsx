/** Main application component */
import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Sidebar from '@/components/layout/Sidebar';
import Topbar from '@/components/layout/Topbar';
import { useUIStore } from '@/store/uiState';
import './index.css';

const ScanPage = lazy(() => import('@/pages/ScanPage'));
const TargetsPage = lazy(() => import('@/pages/TargetsPage'));
const TargetDetailPage = lazy(() => import('@/pages/TargetDetailPage'));
const EndpointDetailPage = lazy(() => import('@/pages/EndpointDetailPage'));
const ParamDetailPage = lazy(() => import('@/pages/ParamDetailPage'));
const FindingPage = lazy(() => import('@/pages/FindingPage'));
const LiveFuzzPage = lazy(() => import('@/pages/LiveFuzzPage'));
const XssChecklistPage = lazy(() => import('@/pages/XssChecklistPage'));
const ExperimentPage = lazy(() => import('@/pages/ExperimentPage'));
const ProgramsPage = lazy(() => import('@/pages/ProgramsPage'));
const ProgramDetailPage = lazy(() => import('@/pages/ProgramDetailPage'));
const LogsPage = lazy(() => import('@/pages/LogsPage'));

const RouteFallback = () => (
  <div className="flex min-h-[50vh] items-center justify-center" role="status" aria-live="polite">
    <div className="rounded-xl border border-carbon-700 bg-carbon-850/80 px-5 py-3 font-mono text-sm text-carbon-300">
      Loading research console…
    </div>
  </div>
);

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function App() {
  const { sidebarCollapsed } = useUIStore();

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {/* Ambient console backdrop */}
        <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 bg-carbon-900">
          <div
            className="absolute inset-0"
            style={{
              backgroundImage:
                'radial-gradient(60% 45% at 12% 0%, rgba(123,104,255,0.16), transparent 60%),' +
                'radial-gradient(50% 40% at 92% 8%, rgba(240,73,158,0.10), transparent 60%),' +
                'radial-gradient(70% 60% at 50% 120%, rgba(16,185,129,0.06), transparent 60%)',
            }}
          />
          <div className="absolute inset-0 grid-overlay" />
        </div>

        <div className="min-h-screen">
          <Sidebar />
          <div className={`flex min-h-screen flex-col transition-all duration-300 ${sidebarCollapsed ? 'lg:ml-20' : 'lg:ml-64'}`}>
            <Topbar />
            <main className="flex-1 overflow-y-auto">
              <Suspense fallback={<RouteFallback />}>
                <Routes>
                  <Route path="/" element={<Navigate to="/scan" replace />} />
                  <Route path="/scan" element={<ScanPage />} />
                  <Route path="/programs" element={<ProgramsPage />} />
                  <Route path="/programs/:id" element={<ProgramDetailPage />} />
                  <Route path="/targets" element={<TargetsPage />} />
                  <Route path="/targets/:id" element={<TargetDetailPage />} />
                  <Route path="/endpoints/:id" element={<EndpointDetailPage />} />
                  <Route path="/params/:id" element={<ParamDetailPage />} />
                  <Route path="/findings" element={<FindingPage />} />
                  <Route path="/live" element={<LiveFuzzPage />} />
                  <Route path="/checklist" element={<XssChecklistPage />} />
                  <Route path="/experiments" element={<ExperimentPage />} />
                  <Route path="/logs" element={<LogsPage />} />
                  <Route path="*" element={<Navigate to="/scan" replace />} />
                </Routes>
              </Suspense>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
