/** Target detail page */
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { targetsApi } from '@/api/targets';
import { endpointsApi } from '@/api/endpoints';
import { experimentsApi } from '@/api/experiments';
import { resultsApi } from '@/api/results';
import EndpointTable from '@/components/tables/EndpointTable';
import ExperimentTable from '@/components/tables/ExperimentTable';
import FindingTable from '@/components/tables/FindingTable';
import StatCard from '@/components/cards/StatCard';
import BurpIntegration from '@/components/burp/BurpIntegration';
import { getStatusColor, formatDate } from '@/utils/formatters';

const TargetDetailPage = () => {
  const { id } = useParams<{ id: string }>();
  const targetId = parseInt(id || '0');

  const { data: target, isLoading: targetLoading } = useQuery({
    queryKey: ['targets', targetId],
    queryFn: () => targetsApi.get(targetId),
    enabled: !!targetId,
  });

  const { data: endpoints = [], isLoading: endpointsLoading, refetch: refetchEndpoints } = useQuery({
    queryKey: ['endpoints', targetId],
    queryFn: () => endpointsApi.list(targetId),
    enabled: !!targetId,
  });

  const { data: experiments = [] } = useQuery({
    queryKey: ['experiments', targetId],
    queryFn: () => experimentsApi.list(targetId),
    enabled: !!targetId,
  });

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', targetId],
    queryFn: () => resultsApi.listFindings(targetId),
    enabled: !!targetId,
  });

  if (targetLoading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">Loading target...</div>
      </div>
    );
  }

  if (!target) {
    return (
      <div className="p-6">
        <p className="text-red-600">Target not found</p>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <Link to="/targets" className="text-blue-600 hover:text-blue-800 text-sm mb-2 inline-block">
          ← Back to Targets
        </Link>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{target.name}</h1>
            <p className="text-gray-600 mt-1">{target.base_url}</p>
          </div>
          <span className={`px-3 py-1 text-sm font-semibold rounded-full ${getStatusColor(target.status)}`}>
            {target.status}
          </span>
        </div>
        {target.notes && (
          <p className="text-gray-600 mt-2">{target.notes}</p>
        )}
        <div className="mt-4 text-sm text-gray-500">
          <p>Platform: {target.bounty_platform || 'N/A'}</p>
          <p>Created: {formatDate(target.created_at)}</p>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <StatCard label="Endpoints" value={endpoints.length} icon="🔗" color="blue" />
        <StatCard label="Experiments" value={experiments.length} icon="🧪" color="purple" />
        <StatCard label="Findings" value={findings.length} icon="🔍" color="red" />
        <StatCard
                label="Critical Findings"
                value={findings.filter((f: any) => f.severity === 'critical').length}
          icon="⚠️"
          color="red"
        />
      </div>
      
      {/* Burp Suite Integration */}
      <BurpIntegration
        targetId={targetId}
        targetUrl={target.base_url}
        onImportComplete={refetchEndpoints}
      />

      {/* Endpoints */}
      <div className="mb-8">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Endpoints</h2>
        <EndpointTable endpoints={endpoints} isLoading={endpointsLoading} />
      </div>

      {/* Experiments */}
      <div className="mb-8">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Experiments</h2>
        <ExperimentTable targetId={targetId} />
      </div>

      {/* Findings */}
      <div>
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Findings</h2>
        <FindingTable findings={findings} />
      </div>
    </div>
  );
};

export default TargetDetailPage;

