/** Create experiment modal with multi-step wizard */
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { experimentsApi } from '@/api/experiments';
import { targetsApi } from '@/api/targets';
import { endpointsApi } from '@/api/endpoints';
import { paramsApi } from '@/api/params';
import { useUIStore } from '@/store/uiState';
import { getStrategyLabel } from '@/utils/formatters';
import type { ExperimentCreate } from '@/types/api';

const CreateExperimentModal = () => {
  const { activeModal, closeModal } = useUIStore();
  const queryClient = useQueryClient();
  const isOpen = activeModal === 'create-experiment';

  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState<Partial<ExperimentCreate>>({
    target_id: undefined,
    name: '',
    strategy: 'quick_light',
    limits: {
      max_test_cases: 100,
      concurrency: 4,
      timeout: 30,
    },
  });

  const [selectedEndpointId, setSelectedEndpointId] = useState<number | null>(null);
  const [selectedParamId, setSelectedParamId] = useState<number | null>(null);

  const { data: targets = [] } = useQuery({
    queryKey: ['targets'],
    queryFn: targetsApi.list,
    enabled: isOpen,
  });

  const { data: endpoints = [] } = useQuery({
    queryKey: ['endpoints', formData.target_id],
    queryFn: () => endpointsApi.list(formData.target_id),
    enabled: isOpen && !!formData.target_id && step >= 2,
  });

  const { data: params = [] } = useQuery({
    queryKey: ['params', selectedEndpointId],
    queryFn: () => paramsApi.getByEndpoint(selectedEndpointId!),
    enabled: isOpen && !!selectedEndpointId && step >= 3,
  });

  const mutation = useMutation({
    mutationFn: experimentsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      closeModal();
      setStep(1);
      setFormData({
        target_id: undefined,
        name: '',
        strategy: 'quick_light',
        limits: { max_test_cases: 100, concurrency: 4, timeout: 30 },
      });
      setSelectedEndpointId(null);
      setSelectedParamId(null);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (step < 5) {
      setStep(step + 1);
    } else {
      mutation.mutate(formData as ExperimentCreate);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        <div className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75" onClick={closeModal} />

        <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-2xl sm:w-full">
          <form onSubmit={handleSubmit}>
            <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Create Experiment</h3>

              {/* Progress steps */}
              <div className="mb-6">
                <div className="flex items-center">
                  {[1, 2, 3, 4, 5].map((s) => (
                    <div key={s} className="flex items-center">
                      <div
                        className={`w-8 h-8 rounded-full flex items-center justify-center ${
                          step >= s ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600'
                        }`}
                      >
                        {s}
                      </div>
                      {s < 5 && (
                        <div
                          className={`w-12 h-1 ${step > s ? 'bg-blue-600' : 'bg-gray-200'}`}
                        />
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Step 1: Select Target */}
              {step === 1 && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Select Target *</label>
                  <select
                    required
                    value={formData.target_id || ''}
                    onChange={(e) => setFormData({ ...formData, target_id: parseInt(e.target.value) })}
                    className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  >
                    <option value="">Choose a target...</option>
                    {targets.map((target) => (
                      <option key={target.id} value={target.id}>
                        {target.name} - {target.base_url}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Step 2: Select Endpoint */}
              {step === 2 && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Select Endpoint *</label>
                  <select
                    required
                    value={selectedEndpointId || ''}
                    onChange={(e) => setSelectedEndpointId(parseInt(e.target.value))}
                    className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  >
                    <option value="">Choose an endpoint...</option>
                    {endpoints.map((endpoint) => (
                      <option key={endpoint.id} value={endpoint.id}>
                        {endpoint.method} {endpoint.url_pattern}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Step 3: Select Parameter */}
              {step === 3 && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Select Parameter *</label>
                  <select
                    required
                    value={selectedParamId || ''}
                    onChange={(e) => setSelectedParamId(parseInt(e.target.value))}
                    className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  >
                    <option value="">Choose a parameter...</option>
                    {params.map((param) => (
                      <option key={param.id} value={param.id}>
                        {param.name} ({param.location})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Step 4: Choose Strategy */}
              {step === 4 && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Fuzzing Strategy *</label>
                  <div className="space-y-2">
                    {(['max_coverage', 'quick_light', 'unicode_hunt', 'js_string_specialist', 'csp_aware'] as const).map((strategy) => (
                      <label key={strategy} className="flex items-center p-3 border rounded-lg cursor-pointer hover:bg-gray-50">
                        <input
                          type="radio"
                          name="strategy"
                          value={strategy}
                          checked={formData.strategy === strategy}
                          onChange={(e) => setFormData({ ...formData, strategy: e.target.value as any })}
                          className="mr-3"
                        />
                        <div>
                          <div className="font-medium">{getStrategyLabel(strategy)}</div>
                          <div className="text-sm text-gray-500">
                            {strategy === 'max_coverage' && '🔥 COMBINE ALL Unicode, WAF, Hex, and CSP bypass methods'}
                            {strategy === 'quick_light' && 'Fast fuzzing with minimal mutations'}
                            {strategy === 'unicode_hunt' && 'Aggressive Unicode-based bypass attempts'}
                            {strategy === 'js_string_specialist' && 'Focus on JavaScript string context bypasses'}
                            {strategy === 'csp_aware' && 'Avoid script tags, use inline handlers'}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              )}

              {/* Step 5: Set Limits */}
              {step === 5 && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Experiment Name *</label>
                    <input
                      type="text"
                      required
                      value={formData.name || ''}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                      placeholder="My XSS Hunt"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Max Test Cases</label>
                    <input
                      type="number"
                      min="1"
                      value={formData.limits?.max_test_cases || 100}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          limits: { ...formData.limits, max_test_cases: parseInt(e.target.value) },
                        })
                      }
                      className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Concurrency</label>
                    <input
                      type="number"
                      min="1"
                      max="10"
                      value={formData.limits?.concurrency || 4}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          limits: { ...formData.limits, concurrency: parseInt(e.target.value) },
                        })
                      }
                      className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Timeout (seconds)</label>
                    <input
                      type="number"
                      min="5"
                      max="120"
                      value={formData.limits?.timeout || 30}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          limits: { ...formData.limits, timeout: parseInt(e.target.value) },
                        })
                      }
                      className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
              <button
                type="submit"
                disabled={mutation.isPending}
                className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
              >
                {step < 5 ? 'Next' : mutation.isPending ? 'Creating...' : 'Create Experiment'}
              </button>
              {step > 1 && (
                <button
                  type="button"
                  onClick={() => setStep(step - 1)}
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                >
                  Back
                </button>
              )}
              <button
                type="button"
                onClick={closeModal}
                className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default CreateExperimentModal;

