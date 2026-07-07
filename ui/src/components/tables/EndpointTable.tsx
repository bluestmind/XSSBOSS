/** Endpoint table component */
import { Link } from 'react-router-dom';
import { getMethodColor, formatDate } from '@/utils/formatters';
import type { Endpoint } from '@/types/api';

interface EndpointTableProps {
  endpoints: Endpoint[];
  isLoading?: boolean;
}

const EndpointTable = ({ endpoints, isLoading }: EndpointTableProps) => {
  if (isLoading) {
    return (
      <div className="bg-carbon-800/70 rounded-lg shadow p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-carbon-700 rounded w-3/4"></div>
          <div className="h-4 bg-carbon-700 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-carbon-800/70 rounded-lg shadow overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-carbon-700/50">
          <thead className="bg-carbon-850/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Method
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                URL Pattern
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Discovered
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-carbon-800/70 divide-y divide-carbon-700/50">
            {endpoints.map((endpoint) => (
              <tr key={endpoint.id} className="hover:bg-carbon-850/50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded ${getMethodColor(endpoint.method)}`}>
                    {endpoint.method}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <code className="text-sm text-carbon-100 font-mono break-all">{endpoint.url_pattern}</code>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-carbon-400">
                  {formatDate(endpoint.discovered_at)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <Link
                    to={`/endpoints/${endpoint.id}`}
                    className="text-brand-300 hover:text-brand-100"
                  >
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {endpoints.length === 0 && (
        <div className="text-center py-12 text-carbon-400">
          No endpoints found.
        </div>
      )}
    </div>
  );
};

export default EndpointTable;

