/** Main application component */
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Sidebar from '@/components/layout/Sidebar';
import Topbar from '@/components/layout/Topbar';
import ScanPage from '@/pages/ScanPage';
import TargetsPage from '@/pages/TargetsPage';
import TargetDetailPage from '@/pages/TargetDetailPage';
import EndpointDetailPage from '@/pages/EndpointDetailPage';
import ParamDetailPage from '@/pages/ParamDetailPage';
import FindingPage from '@/pages/FindingPage';
import LiveFuzzPage from '@/pages/LiveFuzzPage';
import XssChecklistPage from '@/pages/XssChecklistPage';
import ExperimentPage from '@/pages/ExperimentPage';
import { useUIStore } from '@/store/uiState';
import './index.css';

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
  const { sidebarOpen } = useUIStore();

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="flex h-screen bg-gray-100">
          <Sidebar />
          <div className={`flex-1 flex flex-col transition-all duration-300 ${sidebarOpen ? 'lg:ml-64' : ''}`}>
            <Topbar />
            <main className="flex-1 overflow-y-auto">
              <Routes>
                <Route path="/" element={<Navigate to="/scan" replace />} />
                <Route path="/scan" element={<ScanPage />} />
                <Route path="/targets" element={<TargetsPage />} />
                <Route path="/targets/:id" element={<TargetDetailPage />} />
                <Route path="/endpoints/:id" element={<EndpointDetailPage />} />
                <Route path="/params/:id" element={<ParamDetailPage />} />
                <Route path="/findings" element={<FindingPage />} />
                <Route path="/live" element={<LiveFuzzPage />} />
                <Route path="/checklist" element={<XssChecklistPage />} />
                <Route path="/experiments" element={<ExperimentPage />} />
                <Route path="*" element={<Navigate to="/scan" replace />} />
              </Routes>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
