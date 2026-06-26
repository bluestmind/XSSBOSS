/** Experiment management page */
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useUIStore } from '@/store/uiState';
import { experimentsApi } from '@/api/experiments';
import ExperimentTable from '@/components/tables/ExperimentTable';
import CreateExperimentModal from '@/components/modals/CreateExperimentModal';
import StatCard from '@/components/cards/StatCard';
import { getStatusColor, getStrategyLabel } from '@/utils/formatters';

const ExperimentPage = () => {
  const { openModal } = useUIStore();
  const queryClient = useQueryClient();
  const [selectedExperimentId, setSelectedExperimentId] = useState<number | null>(null);

  // Handle experiment selection from table
  const handleExperimentSelect = (id: number) => {
    setSelectedExperimentId(id);
  };

  const { data: experiments = [] } = useQuery({
    queryKey: ['experiments'],
    queryFn: () => experimentsApi.list(),
  });

  const { data: selectedExperiment } = useQuery({
    queryKey: ['experiments', selectedExperimentId],
    queryFn: () => experimentsApi.get(selectedExperimentId!),
    enabled: !!selectedExperimentId,
  });

  const { data: stats } = useQuery({
    queryKey: ['experiments', selectedExperimentId, 'stats'],
    queryFn: () => experimentsApi.getStats(selectedExperimentId!),
    enabled: !!selectedExperimentId,
    refetchInterval: 5000, // Poll every 5 seconds
  });

  const startMutation = useMutation({
    mutationFn: experimentsApi.start,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      if (selectedExperimentId) {
        queryClient.invalidateQueries({ queryKey: ['experiments', selectedExperimentId] });
      }
    },
  });

  const stopMutation = useMutation({
    mutationFn: experimentsApi.stop,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      if (selectedExperimentId) {
        queryClient.invalidateQueries({ queryKey: ['experiments', selectedExperimentId] });
      }
    },
  });

  const resumeMutation = useMutation({
    mutationFn: experimentsApi.resume,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      if (selectedExperimentId) {
        queryClient.invalidateQueries({ queryKey: ['experiments', selectedExperimentId] });
      }
    },
  });

  const handleStart = (id: number) => {
    startMutation.mutate(id);
  };

  const handleStop = (id: number) => {
    stopMutation.mutate(id);
  };

  const handleResume = (id: number) => {
    resumeMutation.mutate(id);
  };

  const statsData = {
    total: experiments.length,
    running: experiments.filter((e) => e.status === 'running').length,
    completed: experiments.filter((e) => e.status === 'completed').length,
    pending: experiments.filter((e) => e.status === 'pending').length,
  };
  const selectedProgressPercent = stats?.total_test_cases
    ? (stats.completed / stats.total_test_cases) * 100
    : 0;

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Experiments</h1>
        <button
          onClick={() => openModal('create-experiment')}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
        >
          + Create Experiment
        </button>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Experiments" value={statsData.total} icon="🧪" color="blue" />
        <StatCard label="Running" value={statsData.running} icon="⚡" color="blue" />
        <StatCard label="Completed" value={statsData.completed} icon="✅" color="green" />
        <StatCard label="Pending" value={statsData.pending} icon="⏳" color="yellow" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Experiments table */}
        <div className="lg:col-span-2">
          <ExperimentTable onSelect={handleExperimentSelect} />
        </div>

        {/* Selected experiment details */}
        {selectedExperiment && (
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Experiment Details</h2>
              
              <div className="space-y-4">
                <div>
                  <p className="text-sm font-medium text-gray-700">Name</p>
                  <p className="text-sm text-gray-900">{selectedExperiment.name}</p>
                </div>
                
                <div>
                  <p className="text-sm font-medium text-gray-700">Strategy</p>
                  <p className="text-sm text-gray-900">{getStrategyLabel(selectedExperiment.strategy)}</p>
                </div>
                
                <div>
                  <p className="text-sm font-medium text-gray-700">Status</p>
                  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(selectedExperiment.status)}`}>
                    {selectedExperiment.status}
                  </span>
                </div>

                {stats && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-2">Progress</p>
                    <div className="space-y-2">
                      <div>
                        <div className="flex justify-between text-xs mb-1">
                          <span>Total: {stats.total_test_cases}</span>
                          <span>Completed: {stats.completed}</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div
                            className="bg-blue-600 h-2 rounded-full"
                            style={{ width: `${selectedProgressPercent}%` }}
                          />
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div>Pending: {stats.pending}</div>
                        <div>Queued: {stats.queued}</div>
                        <div>Running: {stats.running}</div>
                        <div>Failed: {stats.failed}</div>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex space-x-2 pt-4 border-t">
                  {selectedExperiment.status === 'pending' && (
                    <button
                      onClick={() => handleStart(selectedExperiment.id)}
                      className="flex-1 px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 text-sm"
                    >
                      Start
                    </button>
                  )}
                  {selectedExperiment.status === 'running' && (
                    <button
                      onClick={() => handleStop(selectedExperiment.id)}
                      className="flex-1 px-3 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 text-sm"
                    >
                      Stop
                    </button>
                  )}
                  {selectedExperiment.status === 'paused' && (
                    <button
                      onClick={() => handleResume(selectedExperiment.id)}
                      className="flex-1 px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 text-sm"
                    >
                      Continue
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <CreateExperimentModal />
    </div>
  );
};

export default ExperimentPage;

