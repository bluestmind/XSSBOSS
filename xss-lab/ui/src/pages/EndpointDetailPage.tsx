/** Endpoint detail page */
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { endpointsApi } from '@/api/endpoints';
import { paramsApi } from '@/api/params';
import { contextsApi } from '@/api/contexts';
import { filtersApi } from '@/api/filters';
import ParamTable from '@/components/tables/ParamTable';
import ContextCard from '@/components/cards/ContextCard';
import FilterProfileCard from '@/components/cards/FilterProfileCard';
import { getMethodColor, formatDate } from '@/utils/formatters';

const EndpointDetailPage = () => {
  const { id } = useParams<{ id: string }>();
  const endpointId = parseInt(id || '0');

  const { data: endpoint, isLoading } = useQuery({
    queryKey: ['endpoints', endpointId],
    queryFn: () => endpointsApi.get(endpointId),
    enabled: !!endpointId,
  });

  const { data: params = [] } = useQuery({
    queryKey: ['params', endpointId],
    queryFn: () => paramsApi.getByEndpoint(endpointId),
    enabled: !!endpointId,
  });

  const { data: contexts = [] } = useQuery({
    queryKey: ['contexts', 'endpoint', endpointId],
    queryFn: () => contextsApi.getByEndpoint(endpointId),
    enabled: !!endpointId,
  });

  const { data: filterProfile } = useQuery({
    queryKey: ['filters', endpointId],
    queryFn: () => filtersApi.getByEndpoint(endpointId),
    enabled: !!endpointId,
  });

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">Loading endpoint...</div>
      </div>
    );
  }

  if (!endpoint) {
    return (
      <div className="p-6">
        <p className="text-red-600">Endpoint not found</p>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <Link to={`/targets/${endpoint.target_id}`} className="text-blue-600 hover:text-blue-800 text-sm mb-2 inline-block">
          ← Back to Target
        </Link>
        <div className="flex items-center space-x-3">
          <span className={`px-3 py-1 text-sm font-semibold rounded ${getMethodColor(endpoint.method)}`}>
            {endpoint.method}
          </span>
          <code className="text-lg font-mono text-gray-900">{endpoint.url_pattern}</code>
        </div>
        <p className="text-sm text-gray-500 mt-2">
          Discovered: {formatDate(endpoint.discovered_at)}
        </p>
      </div>

      {/* Parameters */}
      <div className="mb-8">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Parameters</h2>
        <ParamTable params={params} />
      </div>

      {/* Contexts */}
      {contexts.length > 0 && (
        <div className="mb-8">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Reflection Contexts</h2>
          <div className="grid grid-cols-1 gap-4">
            {contexts.map((context: any) => (
              <ContextCard key={context.id} context={context} />
            ))}
          </div>
        </div>
      )}

      {/* Sinks - shown per context in ContextCard */}

      {/* Filter Profile */}
      {filterProfile && (
        <div className="mb-8">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Filter Profile</h2>
          <FilterProfileCard profile={filterProfile} />
        </div>
      )}
    </div>
  );
};

export default EndpointDetailPage;

