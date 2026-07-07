/** Sink information card */
import { getSinkTypeLabel } from '@/utils/formatters';
import type { Sink } from '@/types/api';

interface SinkCardProps {
  sink: Sink;
}

const SinkCard = ({ sink }: SinkCardProps) => {
  const isDangerous = ['innerHTML', 'eval', 'Function', 'document.write'].includes(sink.sink_type);

  return (
    <div className={`bg-white rounded-lg shadow p-6 border-l-4 ${isDangerous ? 'border-red-500' : 'border-orange-500'}`}>
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">
            {getSinkTypeLabel(sink.sink_type)}
          </h3>
          <p className="text-sm text-gray-500 mt-1">Sink ID: {sink.id}</p>
        </div>
        <div className="flex flex-col items-end space-y-1">
          <span className={`px-3 py-1 text-xs font-semibold rounded-full ${
            sink.detected_via === 'static' ? 'bg-blue-100 text-blue-800' : 'bg-purple-100 text-purple-800'
          }`}>
            {sink.detected_via}
          </span>
          {isDangerous && (
            <span className="px-2 py-1 text-xs font-semibold rounded bg-red-100 text-red-800">
              High Risk
            </span>
          )}
        </div>
      </div>

      <div className="space-y-3">
        {sink.js_location && (
          <div>
            <span className="text-sm font-medium text-gray-700">Location:</span>
            <code className="ml-2 text-sm text-gray-900 font-mono break-all">{sink.js_location}</code>
          </div>
        )}

        {sink.taint_path && Object.keys(sink.taint_path).length > 0 && (
          <div>
            <span className="text-sm font-medium text-gray-700 mb-2 block">Taint Path:</span>
            <pre className="bg-gray-50 rounded p-3 text-xs overflow-x-auto border">
              <code>{JSON.stringify(sink.taint_path, null, 2)}</code>
            </pre>
          </div>
        )}

        {sink.notes && (
          <div>
            <span className="text-sm font-medium text-gray-700">Notes:</span>
            <p className="mt-1 text-sm text-gray-600">{sink.notes}</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default SinkCard;

