/** Finding table component */
import { getStatusColor, formatPayload, formatDate } from '@/utils/formatters';
import type { Finding } from '@/types/api';

interface FindingTableProps {
  findings: Finding[];
  isLoading?: boolean;
  onViewPoC?: (id: number) => void;
}

const FindingTable = ({ findings, isLoading, onViewPoC }: FindingTableProps) => {
  if (isLoading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-3/4"></div>
          <div className="h-4 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Severity
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Payload
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Created
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {findings.map((finding) => (
              <tr key={finding.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <code className="text-sm text-gray-900 font-mono break-all">
                    {formatPayload(finding.best_payload, 80)}
                  </code>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(finding.status)}`}>
                    {finding.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {formatDate(finding.created_at)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  {onViewPoC && (
                    <>
                      <button
                        onClick={() => onViewPoC(finding.id)}
                        className="text-blue-600 hover:text-blue-900 mr-4 font-semibold"
                      >
                        View Details
                      </button>
                      <button
                        onClick={() => onViewPoC(finding.id)}
                        className="text-green-600 hover:text-green-900 font-semibold"
                      >
                        PoC
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {findings.length === 0 && (
        <div className="text-center py-12 text-gray-500">
          No findings yet. Run experiments to discover XSS vulnerabilities.
        </div>
      )}
    </div>
  );
};

export default FindingTable;

