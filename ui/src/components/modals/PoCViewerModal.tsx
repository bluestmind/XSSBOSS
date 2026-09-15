/** PoC viewer and interactive self-testing workbench modal */
import { useState } from 'react';
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
    <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-3 bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/30 rounded-lg p-3 shadow-xs">
      <div className="flex items-center space-x-2">
        <span className="text-xs px-2 py-0.5 bg-orange-500/20 text-orange-200 rounded font-semibold tracking-wider uppercase">Source</span>
        <span className="font-mono text-carbon-100 font-bold bg-carbon-850 border border-carbon-700/60 px-2 py-0.5 rounded text-xs">{sourceName}</span>
      </div>
      <div className="hidden sm:flex items-center text-orange-400 font-bold">➔</div>
      <div className="flex items-center space-x-2">
        <span className="text-xs px-2 py-0.5 bg-yellow-500/20 text-yellow-200 rounded font-semibold tracking-wider uppercase">Taint</span>
        <span className="font-mono text-carbon-400 text-xs italic">Data Propagated</span>
      </div>
      <div className="hidden sm:flex items-center text-red-400 font-bold">➔</div>
      <div className="flex items-center space-x-2">
        <span className="text-xs px-2 py-0.5 bg-red-500/20 text-red-200 rounded font-semibold tracking-wider uppercase">Sink</span>
        <span className="font-mono text-red-300 bg-carbon-850 border border-red-500/40 px-2 py-0.5 rounded text-xs">{actualSink}</span>
      </div>
    </div>
  );
};

const PoCViewerModal = ({ findingId }: PoCViewerModalProps) => {
  const { activeModal, closeModal } = useUIStore();
  const isOpen = activeModal === 'poc-viewer';
  const [activeTab, setActiveTab] = useState<'testing' | 'trace' | 'evidence' | 'report'>('testing');
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [sandboxExecuted, setSandboxExecuted] = useState<boolean>(false);

  const { data: finding, isLoading } = useQuery({
    queryKey: ['findings', findingId],
    queryFn: () => resultsApi.getFinding(findingId),
    enabled: isOpen && !!findingId,
  });

  const replayMutation = useMutation({
    mutationFn: () => resultsApi.replayFinding(findingId),
    onSuccess: (data) => {
      alert(data.message || 'PoC replay queued in browser worker successfully!');
    },
    onError: (err: any) => {
      alert(`Error replaying PoC: ${err?.message || err}`);
    }
  });

  const repeaterMutation = useMutation({
    mutationFn: (tool: string) => burpApi.sendToRepeater(findingId, tool),
    onSuccess: (_, tool) => {
      alert(`Request sent to Burp Suite ${tool === 'intruder' ? 'Intruder' : 'Repeater'} queue successfully!`);
    },
    onError: (err: any) => {
      alert(`Error sending to Burp: ${err?.message || err}`);
    }
  });

  const handleReplay = () => {
    replayMutation.mutate();
  };

  const handleSendToBurp = (tool: string) => {
    repeaterMutation.mutate(tool);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleDownloadPoC = () => {
    if (!finding) return;
    const htmlContent = finding.poc_html || `<!DOCTYPE html><html><body><h1>PoC for ${finding.endpoint_url || 'XSS'}</h1><script>${finding.best_payload}</script></body></html>`;
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `poc-finding-${finding.id}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!isOpen) return null;

  if (isLoading) {
    return (
      <div className="fixed inset-0 z-50 overflow-y-auto">
        <div className="flex items-center justify-center min-h-screen px-4">
          <div className="bg-carbon-850 rounded-xl shadow-2xl p-6 border border-carbon-700">
            <p className="text-carbon-200 font-mono">Loading Finding & PoC Details...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!finding) return null;

  const pocUrl = finding.poc_url || finding.endpoint_url || '';
  const displayStatus = finding.is_verified
    ? finding.verification_state.replace(/_/g, ' ')
    : 'unverified';
  const targetName = finding.target_name || finding.target_domain || 'Target';
  const method = finding.endpoint_method || 'GET';
  const paramName = finding.param_name || 'param';
  const paramLocation = finding.param_location || 'query';

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        <div className="fixed inset-0 transition-opacity bg-carbon-950/80 backdrop-blur-sm" onClick={closeModal} />

        <div className="inline-block align-bottom bg-carbon-850 rounded-2xl border border-carbon-700 text-left overflow-hidden shadow-2xl transform transition-all sm:my-8 sm:align-middle sm:max-w-5xl sm:w-full">
          {/* Modal Header */}
          <div className="bg-carbon-900 border-b border-carbon-700/80 px-6 py-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <div className="flex items-center space-x-3">
                  <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full uppercase ${getStatusColor(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full uppercase ${finding.is_verified ? getStatusColor(finding.status) : 'bg-yellow-500/20 text-yellow-200'}`}>
                    {displayStatus}
                  </span>
                  <h3 className="text-lg font-bold text-carbon-100 font-mono">
                    Finding #{finding.id}: {finding.vuln_type?.replace(/_/g, ' ').toUpperCase() || 'XSS VULNERABILITY'}
                  </h3>
                </div>
                <div className="flex items-center space-x-2 mt-1 text-xs text-carbon-400 font-mono">
                  <span className="font-bold text-carbon-200">{targetName}</span>
                  <span>•</span>
                  <span className="px-1.5 py-0.5 rounded bg-brand-500/20 text-brand-300 font-bold">{method}</span>
                  <span className="truncate max-w-md">{finding.endpoint_url || pocUrl}</span>
                  <span>•</span>
                  <span className="text-purple-300 font-bold">{paramName} ({paramLocation})</span>
                </div>
              </div>

              {/* Header Quick Actions */}
              <div className="flex items-center space-x-2">
                {pocUrl && (
                  <a
                    href={pocUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center px-3 py-1.5 text-xs font-bold rounded-lg bg-green-600 hover:bg-green-500 text-white transition shadow"
                  >
                    🚀 Open Manual Test
                  </a>
                )}
                <button
                  type="button"
                  onClick={handleDownloadPoC}
                  className="inline-flex items-center px-3 py-1.5 text-xs font-semibold rounded-lg bg-carbon-700 hover:bg-carbon-600 text-carbon-200 border border-carbon-600 transition"
                  title="Download standalone HTML PoC file"
                >
                  📥 Download PoC
                </button>
                <button
                  type="button"
                  onClick={closeModal}
                  className="text-carbon-400 hover:text-carbon-100 p-1.5 rounded-lg hover:bg-carbon-800 transition text-sm font-bold"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Tab Navigation */}
            <div className="flex items-center space-x-2 mt-4 pt-3 border-t border-carbon-700/60 text-xs font-semibold">
              <button
                onClick={() => setActiveTab('testing')}
                className={`px-3 py-1.5 rounded-lg transition ${activeTab === 'testing' ? 'bg-brand-500 text-white font-bold' : 'text-carbon-400 hover:text-carbon-200 hover:bg-carbon-800'}`}
              >
                🎯 Manual Testing & Payloads
              </button>
              <button
                onClick={() => setActiveTab('trace')}
                className={`px-3 py-1.5 rounded-lg transition ${activeTab === 'trace' ? 'bg-brand-500 text-white font-bold' : 'text-carbon-400 hover:text-carbon-200 hover:bg-carbon-800'}`}
              >
                🔬 Taint Trace & Sinks
              </button>
              <button
                onClick={() => setActiveTab('evidence')}
                className={`px-3 py-1.5 rounded-lg transition ${activeTab === 'evidence' ? 'bg-brand-500 text-white font-bold' : 'text-carbon-400 hover:text-carbon-200 hover:bg-carbon-800'}`}
              >
                📸 Screenshots & Evidence
              </button>
              <button
                onClick={() => setActiveTab('report')}
                className={`px-3 py-1.5 rounded-lg transition ${activeTab === 'report' ? 'bg-brand-500 text-white font-bold' : 'text-carbon-400 hover:text-carbon-200 hover:bg-carbon-800'}`}
              >
                📝 Bounty Report
              </button>
            </div>
          </div>

          {/* Modal Body */}
          <div className="bg-carbon-850 px-6 py-5 max-h-[70vh] overflow-y-auto space-y-6">
            {/* TAB 1: MANUAL TESTING & PAYLOADS */}
            {activeTab === 'testing' && (
              <div className="space-y-5">
                {/* 1. Exploit URL */}
                <div className="bg-carbon-900 border border-carbon-700/80 rounded-xl p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-green-300 uppercase tracking-wider flex items-center space-x-1.5">
                      <span>🌐 Direct Exploitation URL</span>
                    </span>
                    <div className="flex items-center space-x-2">
                      <a
                        href={pocUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs px-2.5 py-1 bg-green-600 hover:bg-green-500 text-white font-semibold rounded transition shadow"
                      >
                        🚀 Launch in Browser Tab
                      </a>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(pocUrl, 'modal-poc')}
                        className="text-xs px-2.5 py-1 bg-carbon-800 hover:bg-carbon-700 text-carbon-100 font-semibold rounded border border-carbon-700 transition"
                      >
                        {copiedField === 'modal-poc' ? '✓ Copied URL' : '📋 Copy URL'}
                      </button>
                    </div>
                  </div>
                  <div className="bg-carbon-950 p-2.5 rounded-lg text-xs font-mono text-carbon-200 break-all select-all border border-carbon-800">
                    {pocUrl}
                  </div>
                </div>

                {/* 2. Injected Payload */}
                <div className="bg-carbon-900 border border-carbon-700/80 rounded-xl p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-brand-300 uppercase tracking-wider">🎯 Verified Payload</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(finding.best_payload, 'modal-payload')}
                      className="text-xs px-2.5 py-1 bg-carbon-800 hover:bg-carbon-700 text-brand-300 font-semibold rounded border border-carbon-700 transition"
                    >
                      {copiedField === 'modal-payload' ? '✓ Copied Payload' : '📋 Copy Payload'}
                    </button>
                  </div>
                  <pre className="bg-carbon-950 p-3 rounded-lg text-xs font-mono text-green-300 overflow-x-auto border border-carbon-800">
                    <code>{finding.best_payload}</code>
                  </pre>
                </div>

                {/* 3. cURL Command */}
                {finding.curl_command && (
                  <div className="bg-carbon-900 border border-carbon-700/80 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-yellow-300 uppercase tracking-wider">⚡ Terminal cURL Command</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(finding.curl_command!, 'modal-curl')}
                        className="text-xs px-2.5 py-1 bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-200 border border-yellow-500/30 rounded font-semibold transition"
                      >
                        {copiedField === 'modal-curl' ? '✓ Copied cURL' : '📋 Copy cURL'}
                      </button>
                    </div>
                    <pre className="bg-carbon-950 p-3 rounded-lg text-xs font-mono text-yellow-100/90 overflow-x-auto border border-carbon-800 whitespace-pre-wrap break-all">
                      <code>{finding.curl_command}</code>
                    </pre>
                  </div>
                )}

                {/* 4. Raw HTTP Request for Burp Suite Repeater */}
                {finding.raw_http_request && (
                  <div className="bg-carbon-900 border border-carbon-700/80 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-orange-300 uppercase tracking-wider">🦊 Raw HTTP Request (Paste into Burp Repeater)</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(finding.raw_http_request!, 'modal-raw')}
                        className="text-xs px-2.5 py-1 bg-orange-500/20 hover:bg-orange-500/30 text-orange-200 border border-orange-500/30 rounded font-semibold transition"
                      >
                        {copiedField === 'modal-raw' ? '✓ Copied Burp Request' : '📋 Copy Raw HTTP Request'}
                      </button>
                    </div>
                    <pre className="bg-carbon-950 p-3 rounded-lg text-xs font-mono text-carbon-200 overflow-x-auto border border-carbon-800 whitespace-pre">
                      <code>{finding.raw_http_request}</code>
                    </pre>
                  </div>
                )}

                {/* 5. Live Sandboxed Execution Runner */}
                <div className="bg-carbon-900 border border-carbon-700/80 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-xs font-bold text-blue-300 uppercase tracking-wider block">🧪 Live Sandboxed PoC Runner</span>
                      <span className="text-[11px] text-carbon-400">Run the payload in a sandboxed execution frame to test behavior safely.</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => setSandboxExecuted(true)}
                      className="text-xs px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg transition shadow"
                    >
                      ▶ Run Payload in Sandbox
                    </button>
                  </div>
                  {sandboxExecuted && (
                    <div className="border border-carbon-700 rounded-lg overflow-hidden bg-white">
                      <iframe
                        srcDoc={finding.poc_html || `<!DOCTYPE html><html><head><title>XSS Sandbox</title></head><body style="font-family:sans-serif;padding:20px;"><h3>Sandboxed PoC Execution</h3><p>Injected Payload:</p><pre>${finding.best_payload}</pre>${finding.best_payload}</body></html>`}
                        sandbox="allow-scripts"
                        className="w-full h-48 border-0"
                        title="PoC Sandbox"
                      />
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 2: TAINT TRACE & SINKS */}
            {activeTab === 'trace' && (
              <div className="space-y-6">
                {/* Decision Tree Checklist Mapping */}
                <DecisionTree finding={finding} />

                {/* Taint Flow Visual & Dynamic Sink */}
                {finding.evidence_refs?.sink_details?.sink_type && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-carbon-300">Taint Flow & Execution Sink Trace</h4>
                    <div className="bg-carbon-900 border border-red-500/30 rounded-xl p-4 text-sm space-y-3">
                      {renderTaintFlowVisual(finding.evidence_refs.sink_details.sink_type)}
                      <div className="flex flex-col sm:flex-row sm:space-x-6 space-y-2 sm:space-y-0 pt-1 text-xs">
                        <div>
                          <span className="font-semibold text-carbon-400">JS Code Source:</span>
                          <span className="ml-2 font-mono text-carbon-200">
                            {finding.evidence_refs.sink_details.js_location || 'unknown'}
                          </span>
                        </div>
                      </div>
                      {finding.evidence_refs.sink_details.notes && (
                        <div>
                          <span className="font-semibold text-carbon-400 block mb-1 text-xs">Execution Callstack Trace:</span>
                          <pre className="bg-carbon-950 border border-carbon-800 rounded-lg p-3 text-xs overflow-x-auto font-mono text-carbon-200 max-h-48">
                            <code>{finding.evidence_refs.sink_details.notes}</code>
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Profiler Tech Stack */}
                {finding.evidence_refs?.tech_stack && Object.keys(finding.evidence_refs.tech_stack).length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-carbon-300">Target Client Technology Stack</h4>
                    <div className="bg-carbon-900 border border-brand-500/30 rounded-xl p-4 text-sm">
                      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                        {Object.entries(finding.evidence_refs.tech_stack).map(([lib, ver]) => (
                          <div key={lib} className="flex items-center space-x-2">
                            <span className="inline-block w-2.5 h-2.5 rounded-full bg-brand-500"></span>
                            <span className="font-medium text-carbon-200 text-xs">{lib}:</span>
                            <span className="text-carbon-400 font-mono text-xs">{ver as string}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: EVIDENCE & SCREENSHOTS */}
            {activeTab === 'evidence' && (
              <div className="space-y-5">
                {/* Screenshot */}
                {finding.screenshot_path ? (
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-carbon-300">DOM Execution Screenshot Evidence</h4>
                    <div className="border border-carbon-700 rounded-xl overflow-hidden bg-carbon-900 p-2">
                      <img
                        src={`/api/v1/results/findings/${finding.id}/screenshot`}
                        alt="XSS execution screenshot"
                        className="max-w-full rounded-lg border border-carbon-800"
                      />
                    </div>
                  </div>
                ) : (
                  <div className="bg-carbon-900 border border-carbon-700/60 rounded-xl p-6 text-center text-xs text-carbon-400">
                    No screenshot artifact stored for this finding.
                  </div>
                )}

                {/* Evidence References */}
                {finding.evidence_refs && (
                  <div className="bg-carbon-900 border border-carbon-700/80 rounded-xl p-4 space-y-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-carbon-300">Evidence Identifiers</h4>
                    <div className="text-xs space-y-1 font-mono text-carbon-300">
                      <p><span className="text-carbon-400">Execution IDs:</span> {finding.evidence_refs.execution_ids?.join(', ') || 'N/A'}</p>
                      <p><span className="text-carbon-400">Test Case ID:</span> {finding.evidence_refs.test_case_id || 'N/A'}</p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 4: BOUNTY REPORT */}
            {activeTab === 'report' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-carbon-300">Platform-Ready Markdown Report</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(finding.report_text || '', 'modal-report')}
                    className="text-xs px-2.5 py-1 bg-brand-500/20 hover:bg-brand-500/30 text-brand-300 border border-brand-500/40 rounded-lg font-semibold transition"
                  >
                    {copiedField === 'modal-report' ? '✓ Copied Markdown' : '📋 Copy Markdown Report'}
                  </button>
                </div>
                <div className="bg-carbon-900 border border-carbon-700/80 rounded-xl p-4 text-xs font-mono text-carbon-200 whitespace-pre-wrap max-h-96 overflow-y-auto">
                  {finding.report_text || 'No report generated yet.'}
                </div>
              </div>
            )}
          </div>

          {/* Modal Footer */}
          <div className="bg-carbon-900 border-t border-carbon-700/80 px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center space-x-2 text-xs text-carbon-400">
              <span>Created: {formatDate(finding.created_at)}</span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => handleSendToBurp('repeater')}
                className="px-3 py-1.5 rounded-lg bg-orange-600 hover:bg-orange-500 text-white font-bold text-xs shadow transition"
              >
                🦊 Send to Burp Repeater
              </button>
              <button
                type="button"
                onClick={() => handleSendToBurp('intruder')}
                className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs shadow transition"
              >
                🎯 Send to Burp Intruder
              </button>
              <button
                type="button"
                onClick={handleReplay}
                disabled={!finding.browser_replay_available || replayMutation.isPending}
                title={finding.browser_replay_available ? 'Queue the linked test case in the browser worker' : 'No linked test case is available for replay'}
                className="px-3 py-1.5 rounded-lg bg-green-600 hover:bg-green-500 disabled:bg-carbon-700 disabled:text-carbon-500 disabled:cursor-not-allowed text-white font-bold text-xs shadow transition"
              >
                🔄 {replayMutation.isPending ? 'Queueing…' : 'Replay Verified Test Case'}
              </button>
              <button
                type="button"
                onClick={closeModal}
                className="px-3 py-1.5 rounded-lg bg-carbon-800 hover:bg-carbon-700 text-carbon-200 border border-carbon-700 font-semibold text-xs transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PoCViewerModal;
