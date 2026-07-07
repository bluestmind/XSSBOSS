/** PoC viewer modal */
import { useQuery, useMutation } from '@tanstack/react-query';
import { resultsApi } from '@/api/results';
import { useUIStore } from '@/store/uiState';
import { formatDate, getStatusColor } from '@/utils/formatters';
import DecisionTree from '@/components/findings/DecisionTree';
import { burpApi } from '@/api/burp';

interface PoCViewerModalProps {
  findingId: number;
}

const renderTaintFlowVisual = (sinkType: string) => {
  if (!sinkType) return null;
  const match = sinkType.match(/^(.*?)\s*\(Source:\s*(.*?)\)$/);
  if (!match) {
    return (
      <div className="flex items-center space-x-2 bg-carbon-850/50 border rounded p-2 text-xs">
        <span className="font-semibold text-carbon-200 font-mono">{sinkType}</span>
      </div>
    );
  }
  const [, actualSink, sourceName] = match;
  return (
    <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-3 bg-gradient-to-r from-orange-50/50 to-red-50/30 border border-orange-100 rounded-lg p-3 shadow-xs">
      <div className="flex items-center space-x-2">
        <span className="text-xs px-2 py-0.5 bg-orange-500/15 text-orange-200 rounded font-semibold tracking-wider uppercase">Source</span>
        <span className="font-mono text-carbon-100 font-bold bg-carbon-850 border border-carbon-700/40 px-2 py-0.5 rounded text-xs">{sourceName}</span>
      </div>
      <div className="hidden sm:flex items-center text-orange-400 font-bold">➔</div>
      <div className="flex items-center space-x-2">
        <span className="text-xs px-2 py-0.5 bg-yellow-500/15 text-yellow-200 rounded font-semibold tracking-wider uppercase">Taint</span>
        <span className="font-mono text-carbon-400 text-xs italic">Data Propagated</span>
      </div>
      <div className="hidden sm:flex items-center text-red-400 font-bold">➔</div>
      <div className="flex items-center space-x-2">
        <span className="text-xs px-2 py-0.5 bg-red-500/15 text-red-200 rounded font-semibold tracking-wider uppercase">Sink</span>
        <span className="font-mono text-red-300 bg-carbon-850 border border-red-100 px-2 py-0.5 rounded text-xs">{actualSink}</span>
      </div>
    </div>
  );
};

const PoCViewerModal = ({ findingId }: PoCViewerModalProps) => {
  const { activeModal, closeModal } = useUIStore();
  const isOpen = activeModal === 'poc-viewer';

  const { data: finding, isLoading } = useQuery({
    queryKey: ['findings', findingId],
    queryFn: () => resultsApi.getFinding(findingId),
    enabled: isOpen && !!findingId,
  });

  const replayMutation = useMutation({
    mutationFn: () => resultsApi.replayFinding(findingId),
    onSuccess: (data) => {
      alert(data.message || 'PoC replay triggered successfully!');
    },
    onError: (err: any) => {
      alert(`Error replaying PoC: ${err?.message || err}`);
    }
  });

  const handleReplay = () => {
    replayMutation.mutate();
  };

  const repeaterMutation = useMutation({
    mutationFn: (tool: string) => burpApi.sendToRepeater(findingId, tool),
    onSuccess: (_, tool) => {
      alert(`Request sent to Burp Suite ${tool === 'intruder' ? 'Intruder' : 'Repeater'} queue successfully!`);
    },
    onError: (err: any) => {
      alert(`Error sending to Burp: ${err?.message || err}`);
    }
  });

  const handleSendToBurp = (tool: string) => {
    repeaterMutation.mutate(tool);
  };

  if (!isOpen) return null;

  if (isLoading) {
    return (
      <div className="fixed inset-0 z-50 overflow-y-auto">
        <div className="flex items-center justify-center min-h-screen px-4">
          <div className="bg-carbon-850 rounded-lg shadow-xl p-6">
            <p>Loading PoC...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        <div className="fixed inset-0 transition-opacity bg-carbon-950/80 backdrop-blur-sm" onClick={closeModal} />

        <div className="inline-block align-bottom bg-carbon-850 rounded-xl border border-carbon-700 text-left overflow-hidden shadow-2xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
          <div className="bg-carbon-850 px-4 pt-5 pb-4 sm:p-6 sm:pb-4 max-h-[80vh] overflow-y-auto">
            <h3 className="text-lg font-medium text-carbon-100 mb-4">Proof of Concept</h3>

            <div className="space-y-6">
              {/* Severity and Status */}
              <div className="flex items-center space-x-4">
                <span className={`px-3 py-1 text-sm font-semibold rounded-full ${getStatusColor(finding.severity)}`}>
                  {finding.severity}
                </span>
                <span className={`px-3 py-1 text-sm font-semibold rounded-full ${getStatusColor(finding.status)}`}>
                  {finding.status}
                </span>
              </div>

              {/* Decision Tree Checklist Mapping */}
              <DecisionTree finding={finding} />

              {/* Best Payload */}
              <div>
                <h4 className="text-sm font-semibold text-carbon-200 mb-2">Best Payload</h4>
                <pre className="bg-carbon-850/50 rounded p-3 text-sm overflow-x-auto border">
                  <code>{finding.best_payload}</code>
                </pre>
              </div>

              {/* HTTP Request */}
              {finding.poc_request && (
                <div>
                  <h4 className="text-sm font-semibold text-carbon-200 mb-2">HTTP Request</h4>
                  <div className="bg-carbon-850/50 rounded p-3 border">
                    {finding.poc_request.command ? (
                      <pre className="text-sm overflow-x-auto">
                        <code>{finding.poc_request.command}</code>
                      </pre>
                    ) : (
                      <pre className="text-sm overflow-x-auto">
                        <code>{JSON.stringify(finding.poc_request, null, 2)}</code>
                      </pre>
                    )}
                  </div>
                </div>
              )}

              {/* Report Text */}
              {finding.report_text && (
                <div>
                  <h4 className="text-sm font-semibold text-carbon-200 mb-2">Report</h4>
                  <div className="bg-carbon-850/50 rounded p-3 border whitespace-pre-wrap text-sm">
                    {finding.report_text}
                  </div>
                </div>
              )}

              {/* Screenshot */}
              {finding.screenshot_path && (
                <div>
                  <h4 className="text-sm font-semibold text-carbon-200 mb-2">Screenshot Evidence</h4>
                  <img
                    src={`/api/v1/results/findings/${finding.id}/screenshot`}
                    alt="XSS execution screenshot"
                    className="max-w-full rounded border"
                  />
                </div>
              )}

              {/* PoC HTML */}
              {finding.poc_html && (
                <div>
                  <h4 className="text-sm font-semibold text-carbon-200 mb-2">PoC HTML</h4>
                  <div className="bg-carbon-850/50 rounded p-3 border max-h-64 overflow-auto">
                    <pre className="text-xs">
                      <code>{finding.poc_html}</code>
                    </pre>
                  </div>
                </div>
              )}

              {/* Evidence References */}
              {finding.evidence_refs && (
                <div className="space-y-4">
                  <div>
                    <h4 className="text-sm font-semibold text-carbon-200 mb-2">Evidence</h4>
                    <div className="bg-carbon-850/50 rounded p-3 border text-sm space-y-2">
                      <p><span className="font-semibold text-carbon-300">Execution IDs:</span> {finding.evidence_refs.execution_ids?.join(', ') || 'N/A'}</p>
                      <p><span className="font-semibold text-carbon-300">Test Case ID:</span> {finding.evidence_refs.test_case_id || 'N/A'}</p>
                    </div>
                  </div>

                  {/* Profiler Tech Stack */}
                  {finding.evidence_refs.tech_stack && Object.keys(finding.evidence_refs.tech_stack).length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-carbon-200 mb-2">Target Client Technology Stack</h4>
                      <div className="bg-brand-500/10/50 border border-blue-100 rounded p-3 text-sm">
                        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                          {Object.entries(finding.evidence_refs.tech_stack).map(([lib, ver]) => (
                            <div key={lib} className="flex items-center space-x-2">
                              <span className="inline-block w-2.5 h-2.5 rounded-full bg-brand-500"></span>
                              <span className="font-medium text-carbon-200">{lib}:</span>
                              <span className="text-carbon-400 font-mono text-xs">{ver as string}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Taint Flow Trace & Dynamic Sink */}
                  {finding.evidence_refs.sink_details && finding.evidence_refs.sink_details.sink_type && (
                    <div>
                      <h4 className="text-sm font-semibold text-carbon-200 mb-2">Taint Flow & Execution Sink Trace</h4>
                      <div className="bg-red-500/1030 border border-red-100 rounded p-3 text-sm space-y-3">
                        {renderTaintFlowVisual(finding.evidence_refs.sink_details.sink_type)}
                        <div className="flex flex-col sm:flex-row sm:space-x-6 space-y-2 sm:space-y-0 pt-1">
                          <div>
                            <span className="font-semibold text-carbon-300">JS Code Source:</span>
                            <span className="ml-2 font-mono text-carbon-200 text-xs">
                              {finding.evidence_refs.sink_details.js_location || 'unknown'}
                            </span>
                          </div>
                        </div>
                        {finding.evidence_refs.sink_details.notes && (
                          <div>
                            <span className="font-semibold text-carbon-300 block mb-1">Execution Callstack Trace:</span>
                            <pre className="bg-carbon-850/50 border rounded p-2 text-xs overflow-x-auto font-mono text-carbon-200 max-h-48">
                              <code>{finding.evidence_refs.sink_details.notes}</code>
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Metadata */}
              <div className="pt-4 border-t border-carbon-700/60">
                <p className="text-xs text-carbon-400">
                  Created: {formatDate(finding.created_at)}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-carbon-850/50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
            <button
              type="button"
              onClick={handleReplay}
              className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-green-600 text-base font-medium text-white hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 sm:ml-3 sm:w-auto sm:text-sm"
            >
              Replay PoC
            </button>
            <button
              type="button"
              onClick={() => handleSendToBurp('repeater')}
              className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-orange-600 text-base font-medium text-white hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500 sm:ml-3 sm:w-auto sm:text-sm"
            >
              Send to Repeater (Auto-Sent)
            </button>
            <button
              type="button"
              onClick={() => handleSendToBurp('intruder')}
              className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-purple-600 text-base font-medium text-white hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 sm:ml-3 sm:w-auto sm:text-sm"
            >
              Send to Intruder (Auto-Sent)
            </button>
            <button
              type="button"
              onClick={closeModal}
              className="mt-3 w-full inline-flex justify-center rounded-md border border-carbon-600 shadow-sm px-4 py-2 bg-carbon-850 text-base font-medium text-carbon-200 hover:bg-carbon-850/50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-brand-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PoCViewerModal;

