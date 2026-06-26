/** Context visualization card */
import { useQuery } from '@tanstack/react-query';
import { sinksApi } from '@/api/sinks';
import { getContextTypeLabel } from '@/utils/formatters';
import SinkCard from './SinkCard';
import type { Context } from '@/types/api';

interface ContextCardProps {
  context: Context;
}

const ContextCard = ({ context }: ContextCardProps) => {
  // Fetch sinks for this context
  const { data: sinks = [] } = useQuery({
    queryKey: ['sinks', context.id],
    queryFn: () => sinksApi.getByContext(context.id),
    enabled: !!context.id,
  });

  return (
    <div className="bg-white rounded-lg shadow p-6 border-l-4 border-blue-500">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">
            {getContextTypeLabel(context.context_type)}
          </h3>
          <p className="text-sm text-gray-500 mt-1">Context ID: {context.id}</p>
        </div>
        <span className="px-3 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">
          {context.context_type}
        </span>
      </div>

      <div className="space-y-3">
        {context.tag && (
          <div>
            <span className="text-sm font-medium text-gray-700">Tag:</span>
            <code className="ml-2 text-sm text-gray-900 font-mono">{context.tag}</code>
          </div>
        )}

        {context.attribute && (
          <div>
            <span className="text-sm font-medium text-gray-700">Attribute:</span>
            <code className="ml-2 text-sm text-gray-900 font-mono">{context.attribute}</code>
          </div>
        )}

        {context.script_path && (
          <div>
            <span className="text-sm font-medium text-gray-700">Script Path:</span>
            <code className="ml-2 text-sm text-gray-600 font-mono break-all">{context.script_path}</code>
          </div>
        )}

        {context.snippet && (
          <div>
            <span className="text-sm font-medium text-gray-700 mb-2 block">Snippet:</span>
            <pre className="bg-gray-50 rounded p-3 text-xs overflow-x-auto border">
              <code>{context.snippet}</code>
            </pre>
          </div>
        )}
      </div>

      {/* Sinks for this context */}
      {sinks.length > 0 && (
        <div className="mt-4 pt-4 border-t border-gray-200">
          <h4 className="text-sm font-semibold text-gray-700 mb-2">Dangerous Sinks:</h4>
          <div className="space-y-2">
            {sinks.map((sink: any) => (
              <SinkCard key={sink.id} sink={sink} />
            ))}
          </div>
        </div>
      )}

      <div className="mt-4 pt-4 border-t border-gray-200">
        <p className="text-xs text-gray-500">
          Detected: {new Date(context.detected_at).toLocaleString()}
        </p>
      </div>
    </div>
  );
};

export default ContextCard;

