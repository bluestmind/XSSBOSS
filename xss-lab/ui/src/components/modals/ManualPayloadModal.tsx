/** Manual payload console modal */
import { useState } from 'react';
import { useUIStore } from '@/store/uiState';
import api from '@/utils/request';

interface ManualPayloadModalProps {
  endpointId?: number;
  paramId?: number;
  contextId?: number;
}

const ManualPayloadModal = ({ endpointId, paramId, contextId }: ManualPayloadModalProps) => {
  const { activeModal, closeModal } = useUIStore();
  const isOpen = activeModal === 'manual-payload';

  const [payload, setPayload] = useState('');
  const [token, setToken] = useState('');
  const [executionResult, setExecutionResult] = useState<any>(null);
  const [isExecuting, setIsExecuting] = useState(false);

  const generateToken = () => {
    const newToken = `XSSFUZZ_${Math.random().toString(36).substring(2, 15)}`;
    setToken(newToken);
    return newToken;
  };

  const insertToken = () => {
    const currentToken = token || generateToken();
    const placeholder = '{{TOKEN}}';
    if (payload.includes(placeholder)) {
      setPayload(payload.replace(placeholder, currentToken));
    } else {
      setPayload(payload + placeholder);
    }
  };

  const executePayload = async () => {
    if (!payload || !endpointId || !paramId) {
      alert('Missing required information');
      return;
    }

    setIsExecuting(true);
    try {
      // Replace {{TOKEN}} with actual token
      const currentToken = token || generateToken();
      const finalPayload = payload.replace(/\{\{TOKEN\}\}/g, currentToken);

      // Call backend to execute (this would trigger browser worker)
      const response = await api.post('/test-cases/execute', {
        endpoint_id: endpointId,
        param_id: paramId,
        context_id: contextId,
        payload: finalPayload,
        token: currentToken,
      });

      setExecutionResult(response.data);
    } catch (error: any) {
      setExecutionResult({ error: error.message });
    } finally {
      setIsExecuting(false);
    }
  };

  const previewPayload = payload.replace(/\{\{TOKEN\}\}/g, token || '{{TOKEN}}');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        <div className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75" onClick={closeModal} />

        <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
          <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Manual Payload Console</h3>

            <div className="space-y-4">
              {/* Token section */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Oracle Token</label>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="Auto-generated if empty"
                    className="flex-1 rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                  <button
                    type="button"
                    onClick={generateToken}
                    className="px-4 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 text-sm"
                  >
                    Generate
                  </button>
                </div>
              </div>

              {/* Payload editor */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm font-medium text-gray-700">Payload</label>
                  <button
                    type="button"
                    onClick={insertToken}
                    className="text-sm text-blue-600 hover:text-blue-800"
                  >
                    Insert {'{{TOKEN}}'}
                  </button>
                </div>
                <textarea
                  value={payload}
                  onChange={(e) => setPayload(e.target.value)}
                  rows={8}
                  className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm font-mono"
                  placeholder="Enter your payload here... Use {{TOKEN}} as placeholder"
                />
              </div>

              {/* Live preview */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Live Preview</label>
                <div className="bg-gray-50 rounded-md p-3 border border-gray-200">
                  <code className="text-sm font-mono break-all">{previewPayload || '(empty)'}</code>
                </div>
              </div>

              {/* Execution result */}
              {executionResult && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Execution Result</label>
                  {executionResult.error ? (
                    <div className="bg-red-50 border border-red-200 rounded-md p-3">
                      <p className="text-sm text-red-800">{executionResult.error}</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="bg-green-50 border border-green-200 rounded-md p-3">
                        <p className="text-sm text-green-800">
                          Oracle Status: {executionResult.oracle_hit ? 'HIT ✓' : 'MISSED ✗'}
                        </p>
                        {executionResult.duration_ms && (
                          <p className="text-xs text-green-600 mt-1">
                            Duration: {executionResult.duration_ms}ms
                          </p>
                        )}
                      </div>
                      {executionResult.screenshot_path && (
                        <div>
                          <p className="text-sm font-medium text-gray-700 mb-1">Screenshot:</p>
                          <img
                            src={executionResult.screenshot_path}
                            alt="Execution screenshot"
                            className="max-w-full rounded border"
                          />
                        </div>
                      )}
                      {executionResult.dom_snapshot && (
                        <div>
                          <p className="text-sm font-medium text-gray-700 mb-1">DOM Snapshot:</p>
                          <pre className="bg-gray-50 rounded p-3 text-xs overflow-auto max-h-64 border">
                            {executionResult.dom_snapshot.substring(0, 2000)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
            <button
              type="button"
              onClick={executePayload}
              disabled={isExecuting || !payload}
              className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
            >
              {isExecuting ? 'Executing...' : 'Execute Payload'}
            </button>
            <button
              type="button"
              onClick={closeModal}
              className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ManualPayloadModal;

