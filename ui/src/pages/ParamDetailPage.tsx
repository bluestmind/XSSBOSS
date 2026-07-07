/** Parameter detail page */
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { paramsApi } from '@/api/params';
import { contextsApi } from '@/api/contexts';
import ContextCard from '@/components/cards/ContextCard';
import { getLocationColor } from '@/utils/formatters';

const ParamDetailPage = () => {
  const { id } = useParams<{ id: string }>();
  const paramId = parseInt(id || '0');

  // Fetch param details
  const { data: param, isLoading: paramLoading } = useQuery({
    queryKey: ['params', paramId],
    queryFn: () => paramsApi.get(paramId),
    enabled: !!paramId,
  });

  // Fetch contexts for this param
  const { data: paramContexts = [] } = useQuery({
    queryKey: ['contexts', 'param', paramId],
    queryFn: () => contextsApi.getByParam(paramId),
    enabled: !!paramId,
  });



  if (paramLoading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">Loading parameter...</div>
      </div>
    );
  }

  if (!param) {
    return (
      <div className="p-6">
        <p className="text-red-600">Parameter not found</p>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <Link to={`/endpoints/${param.endpoint_id}`} className="text-blue-600 hover:text-blue-800 text-sm mb-2 inline-block">
          ← Back to Endpoint
        </Link>
        <div className="flex items-center space-x-3">
          <code className="text-lg font-mono text-gray-900">{param.name}</code>
          <span className={`px-3 py-1 text-sm font-semibold rounded ${getLocationColor(param.location)}`}>
            {param.location}
          </span>
        </div>
        {param.sample_value && (
          <p className="text-sm text-gray-600 mt-2">
            Sample: <code className="font-mono">{param.sample_value}</code>
          </p>
        )}
      </div>

      {/* Contexts */}
      <div className="mb-8">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Reflection Contexts</h2>
        {paramContexts.length > 0 ? (
          <div className="grid grid-cols-1 gap-4">
            {paramContexts.map((context: any) => (
              <ContextCard key={context.id} context={context} />
            ))}
          </div>
        ) : (
          <p className="text-gray-500">No contexts detected yet. Run context detection to find reflections.</p>
        )}
      </div>

      {/* Sinks are shown within context cards */}
    </div>
  );
};

export default ParamDetailPage;

