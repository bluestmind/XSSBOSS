/** Target table component */
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { targetsApi } from '@/api/targets';
import { getStatusColor, formatDate } from '@/utils/formatters';
import type { Target } from '@/types/api';

const TargetTable = () => {
  const [sortField, setSortField] = useState<keyof Target>('created_at');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');

  const { data: targets = [], isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: targetsApi.list,
  });

  const handleSort = (field: keyof Target) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const sortedTargets = [...targets].sort((a, b) => {
    const aVal = a[sortField];
    const bVal = b[sortField];
    if (aVal === undefined && bVal === undefined) return 0;
    if (aVal === undefined) return sortDirection === 'asc' ? 1 : -1;
    if (bVal === undefined) return sortDirection === 'asc' ? -1 : 1;
    if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
    if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });

  if (isLoading) {
    return (
      <div className="bg-carbon-800/70 rounded-lg shadow p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-carbon-700 rounded w-3/4"></div>
          <div className="h-4 bg-carbon-700 rounded"></div>
          <div className="h-4 bg-carbon-700 rounded w-5/6"></div>
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
              <th
                className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider cursor-pointer hover:bg-carbon-800/60"
                onClick={() => handleSort('name')}
              >
                Name {sortField === 'name' && (sortDirection === 'asc' ? '↑' : '↓')}
              </th>
              <th
                className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider cursor-pointer hover:bg-carbon-800/60"
                onClick={() => handleSort('base_url')}
              >
                Base URL {sortField === 'base_url' && (sortDirection === 'asc' ? '↑' : '↓')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Platform
              </th>
              <th
                className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider cursor-pointer hover:bg-carbon-800/60"
                onClick={() => handleSort('status')}
              >
                Status {sortField === 'status' && (sortDirection === 'asc' ? '↑' : '↓')}
              </th>
              <th
                className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider cursor-pointer hover:bg-carbon-800/60"
                onClick={() => handleSort('created_at')}
              >
                Created {sortField === 'created_at' && (sortDirection === 'asc' ? '↑' : '↓')}
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-carbon-800/70 divide-y divide-carbon-700/50">
            {sortedTargets.map((target) => (
              <tr key={target.id} className="hover:bg-carbon-850/50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <Link
                    to={`/targets/${target.id}`}
                    className="text-sm font-medium text-brand-300 hover:text-brand-200"
                  >
                    {target.name}
                  </Link>
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm text-carbon-100 truncate max-w-xs">{target.base_url}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm text-carbon-400">{target.bounty_platform || '-'}</span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(target.status)}`}>
                    {target.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-carbon-400">
                  {formatDate(target.created_at)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <Link
                    to={`/targets/${target.id}`}
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
      {sortedTargets.length === 0 && (
        <div className="text-center py-12 text-carbon-400">
          No targets found. Create your first target to get started.
        </div>
      )}
    </div>
  );
};

export default TargetTable;

