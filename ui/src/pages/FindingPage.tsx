/** Findings page with interactive self-testing workbench and search */
import { useState, useMemo } from 'react';
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
  const [vulnTypeFilter, setVulnTypeFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ['findings', severityFilter, statusFilter],
    queryFn: () => resultsApi.listFindings(undefined, undefined, statusFilter || undefined, severityFilter || undefined),
  });

  const handleViewPoC = (findingId: number) => {
    setSelectedFindingId(findingId);
    openModal('poc-viewer');
  };

  // Filter findings client-side by search query and vuln type
  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      if (vulnTypeFilter && finding.vuln_type !== vulnTypeFilter) {
        return false;
      }
      if (!searchQuery.trim()) {
        return true;
      }
      const q = searchQuery.toLowerCase();
      const targetMatch = (finding.target_name || '').toLowerCase().includes(q) || (finding.target_domain || '').toLowerCase().includes(q);
      const endpointMatch = (finding.endpoint_url || '').toLowerCase().includes(q);
      const paramMatch = (finding.param_name || '').toLowerCase().includes(q);
      const payloadMatch = (finding.best_payload || '').toLowerCase().includes(q);
      const vulnTypeMatch = (finding.vuln_type || '').toLowerCase().includes(q);
      const statusMatch = `${finding.status || ''} ${finding.verification_state || ''}`.toLowerCase().includes(q);
      return targetMatch || endpointMatch || paramMatch || payloadMatch || vulnTypeMatch || statusMatch;
    });
  }, [findings, searchQuery, vulnTypeFilter]);

  const uniqueVulnTypes = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => {
      if (f.vuln_type) set.add(f.vuln_type);
    });
    return Array.from(set);
  }, [findings]);

  const stats = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    confirmed: findings.filter((f) => f.status === 'confirmed' && f.is_verified).length,
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-carbon-100 flex items-center space-x-3">
            <span>⚡ Findings & PoC Exploit Database</span>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-brand-500/20 text-brand-300 border border-brand-500/40 font-mono">
              {filteredFindings.length} / {findings.length}
            </span>
          </h1>
          <p className="text-sm text-carbon-400 mt-1">
            Manual testing suite: 1-click browser test triggers, ready-to-use cURL commands, Burp Repeater raw requests, and sandboxed live execution.
          </p>
        </div>
      </div>

      {/* Statistics Cards with Quick Filter Click */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div onClick={() => setSeverityFilter('')} className="cursor-pointer transition hover:scale-[1.02]">
          <StatCard label="Total" value={stats.total} icon="🔍" color="blue" />
        </div>
        <div onClick={() => setSeverityFilter(severityFilter === 'critical' ? '' : 'critical')} className="cursor-pointer transition hover:scale-[1.02]">
          <StatCard label="Critical" value={stats.critical} icon="⚠️" color="red" />
        </div>
        <div onClick={() => setSeverityFilter(severityFilter === 'high' ? '' : 'high')} className="cursor-pointer transition hover:scale-[1.02]">
          <StatCard label="High" value={stats.high} icon="🔴" color="red" />
        </div>
        <div onClick={() => setSeverityFilter(severityFilter === 'medium' ? '' : 'medium')} className="cursor-pointer transition hover:scale-[1.02]">
          <StatCard label="Medium" value={stats.medium} icon="🟡" color="yellow" />
        </div>
        <div onClick={() => setStatusFilter(statusFilter === 'confirmed' ? '' : 'confirmed')} className="cursor-pointer transition hover:scale-[1.02]">
          <StatCard label="Confirmed" value={stats.confirmed} icon="✅" color="green" />
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-carbon-800/80 border border-carbon-700/60 rounded-xl shadow p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Search Input */}
          <div className="lg:col-span-2">
            <label className="block text-xs font-semibold text-carbon-300 uppercase tracking-wider mb-1.5">
              Search Targets, Endpoints, Parameters, Payloads
            </label>
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="e.g. hunttest, httpbin.org, /search, Origin, <script>..."
                className="w-full bg-carbon-900 border border-carbon-600 rounded-lg px-3.5 py-2 text-sm text-carbon-100 placeholder-carbon-500 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  className="absolute right-3 top-2.5 text-xs text-carbon-400 hover:text-carbon-200"
                >
                  ✕
                </button>
              )}
            </div>
          </div>

          {/* Severity Dropdown */}
          <div>
            <label className="block text-xs font-semibold text-carbon-300 uppercase tracking-wider mb-1.5">
              Severity
            </label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full bg-carbon-900 border border-carbon-600 rounded-lg px-3 py-2 text-sm text-carbon-100 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Vuln Type / Status Dropdowns */}
          <div>
            <label className="block text-xs font-semibold text-carbon-300 uppercase tracking-wider mb-1.5">
              Vulnerability Type
            </label>
            <select
              value={vulnTypeFilter}
              onChange={(e) => setVulnTypeFilter(e.target.value)}
              className="w-full bg-carbon-900 border border-carbon-600 rounded-lg px-3 py-2 text-sm text-carbon-100 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
            >
              <option value="">All Types</option>
              {uniqueVulnTypes.map((type) => (
                <option key={type} value={type}>
                  {type.replace(/_/g, ' ').toUpperCase()}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Findings table */}
      <div>
        <FindingTable 
          findings={filteredFindings} 
          isLoading={isLoading}
          onViewPoC={handleViewPoC}
        />
      </div>

      {selectedFindingId && <PoCViewerModal findingId={selectedFindingId} />}
    </div>
  );
};

export default FindingPage;
