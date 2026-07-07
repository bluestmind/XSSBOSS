/** Experiment table component */
import { useQuery } from '@tanstack/react-query';
import { experimentsApi } from '@/api/experiments';
import { getStatusColor, getStrategyLabel, formatDate } from '@/utils/formatters';

interface ExperimentTableProps {
  targetId?: number;
  onSelect?: (id: number) => void;
}

const ExperimentTable = ({ targetId, onSelect }: ExperimentTableProps) => {
  const { data: experiments = [], isLoading } = useQuery({
    queryKey: ['experiments', targetId],
    queryFn: () => experimentsApi.list(targetId),
  });

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
                Strategy
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Started
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-carbon-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-carbon-800/70 divide-y divide-carbon-700/50">
            {experiments.map((experiment) => (
              <tr key={experiment.id} className="hover:bg-carbon-850/50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <button
                    onClick={() => onSelect?.(experiment.id)}
                    className="text-sm font-medium text-brand-300 hover:text-brand-200 text-left"
                  >
                    {experiment.name}
                  </button>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm text-carbon-300">
                    {getStrategyLabel(experiment.strategy)}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(experiment.status)}`}>
                    {experiment.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-carbon-400">
                  {experiment.started_at ? formatDate(experiment.started_at) : '-'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <button
                    onClick={() => onSelect?.(experiment.id)}
                    className="text-brand-300 hover:text-brand-100"
                  >
                    View / Select
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {experiments.length === 0 && (
        <div className="text-center py-12 text-carbon-400">
          No experiments found. Create an experiment to start fuzzing.
        </div>
      )}
    </div>
  );
};

export default ExperimentTable;

