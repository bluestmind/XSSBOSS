/** Parameter table component */
import { Link } from 'react-router-dom';
import { getLocationColor } from '@/utils/formatters';
import type { Param } from '@/types/api';

interface ParamTableProps {
  params: Param[];
  isLoading?: boolean;
}

const ParamTable = ({ params, isLoading }: ParamTableProps) => {
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
                Name
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Location
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Sample Value
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Controllable
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-carbon-800/70 divide-y divide-carbon-700/50">
            {params.map((param) => (
              <tr key={param.id} className="hover:bg-carbon-850/50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <code className="text-sm font-medium text-carbon-100">{param.name}</code>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded ${getLocationColor(param.location)}`}>
                    {param.location}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <code className="text-sm text-carbon-300 font-mono truncate max-w-xs">
                    {param.sample_value || '-'}
                  </code>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {param.is_controllable ? (
                    <span className="text-green-300 text-sm">✓ Yes</span>
                  ) : (
                    <span className="text-carbon-500 text-sm">✗ No</span>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <Link
                    to={`/params/${param.id}`}
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
      {params.length === 0 && (
        <div className="text-center py-12 text-carbon-400">
          No parameters found.
        </div>
      )}
    </div>
  );
};

export default ParamTable;

