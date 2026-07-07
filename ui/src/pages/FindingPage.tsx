/** Findings page */
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useUIStore } from '@/store/uiState';
import { resultsApi } from '@/api/results';
import FindingTable from '@/components/tables/FindingTable';
import PoCViewerModal from '@/components/modals/PoCViewerModal';
import StatCard from '@/components/cards/StatCard';

const FindingPage = () => {
  const { openModal } = useUIStore();
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ['findings', severityFilter, statusFilter],
    queryFn: () => resultsApi.listFindings(undefined, undefined, statusFilter || undefined, severityFilter || undefined),
  });

  const handleViewPoC = (findingId: number) => {
    setSelectedFindingId(findingId);
    openModal('poc-viewer');
  };

  // Pass PoC handler to table
  const FindingTableWithPoC = () => (
    <FindingTable 
      findings={findings} 
      isLoading={isLoading}
      onViewPoC={handleViewPoC}
    />
  );

  const stats = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Findings</h1>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
        <StatCard label="Total" value={stats.total} icon="🔍" color="blue" />
        <StatCard label="Critical" value={stats.critical} icon="⚠️" color="red" />
        <StatCard label="High" value={stats.high} icon="🔴" color="red" />
        <StatCard label="Medium" value={stats.medium} icon="🟡" color="yellow" />
        <StatCard label="Low" value={stats.low} icon="🔵" color="blue" />
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4 mb-6">
        <div className="flex items-center space-x-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            >
              <option value="">All</option>
              <option value="draft">Draft</option>
              <option value="confirmed">Confirmed</option>
              <option value="reported">Reported</option>
              <option value="duplicate">Duplicate</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings table */}
      <div>
        <FindingTableWithPoC />
      </div>

      {selectedFindingId && <PoCViewerModal findingId={selectedFindingId} />}
    </div>
  );
};

export default FindingPage;

