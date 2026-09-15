/** Finding table component with interactive self-testing workbench */
import { useState } from 'react';
import { getStatusColor, formatPayload, formatDate } from '@/utils/formatters';
import type { Finding } from '@/types/api';

interface FindingTableProps {
  findings: Finding[];
  isLoading?: boolean;
  onViewPoC?: (id: number) => void;
}

const FindingTable = ({ findings, isLoading, onViewPoC }: FindingTableProps) => {
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [expandedFindingId, setExpandedFindingId] = useState<number | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const toggleExpand = (id: number) => {
    setExpandedFindingId((prev) => (prev === id ? null : id));
  };

  if (isLoading) {
    return (
      <div className="bg-carbon-800/70 rounded-xl shadow p-6 border border-carbon-700/50">
        <div className="animate-pulse space-y-4">
          <div className="h-5 bg-carbon-700 rounded w-3/4"></div>
          <div className="h-4 bg-carbon-700 rounded"></div>
          <div className="h-4 bg-carbon-700 rounded w-5/6"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-carbon-800/70 rounded-xl shadow border border-carbon-700/50 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-carbon-700/50">
          <thead className="bg-carbon-850/80">
            <tr>
              <th className="px-4 py-3.5 text-left text-xs font-semibold text-carbon-400 uppercase tracking-wider">
                Severity & Type
              </th>
              <th className="px-4 py-3.5 text-left text-xs font-semibold text-carbon-400 uppercase tracking-wider">
                Target & Endpoint
              </th>
              <th className="px-4 py-3.5 text-left text-xs font-semibold text-carbon-400 uppercase tracking-wider">
                Parameter & Context
              </th>
              <th className="px-4 py-3.5 text-left text-xs font-semibold text-carbon-400 uppercase tracking-wider">
                Best Payload
              </th>
              <th className="px-4 py-3.5 text-left text-xs font-semibold text-carbon-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3.5 text-right text-xs font-semibold text-carbon-400 uppercase tracking-wider">
                Self-Test Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-carbon-800/70 divide-y divide-carbon-700/50">
            {findings.map((finding) => {
              const isExpanded = expandedFindingId === finding.id;
              const pocUrl = finding.poc_url || finding.endpoint_url || '';
              const targetDisplay = finding.target_name || finding.target_domain || 'Target';
              const method = finding.endpoint_method || 'GET';
              const paramLocation = finding.param_location || 'query';
              const paramName = finding.param_name || 'param';
              const vulnTypeFormatted = (finding.vuln_type || 'xss').replace(/_/g, ' ').toUpperCase();
              const displayStatus = finding.is_verified
                ? finding.verification_state.replace(/_/g, ' ')
                : 'unverified';

              return (
                <tr key={finding.id} className={`transition-colors ${isExpanded ? 'bg-carbon-750/70' : 'hover:bg-carbon-850/50'}`}>
                  {/* Severity & Vuln Type */}
                  <td className="px-4 py-4 whitespace-nowrap align-top">
                    <div className="flex flex-col space-y-1.5">
                      <span className={`inline-block px-2.5 py-0.5 text-xs font-bold rounded-full w-max ${getStatusColor(finding.severity)}`}>
                        {finding.severity.toUpperCase()}
                      </span>
                      <span className="text-xs font-medium text-brand-300 font-mono tracking-tight">
                        {vulnTypeFormatted}
                      </span>
                    </div>
                  </td>

                  {/* Target & Endpoint */}
                  <td className="px-4 py-4 align-top max-w-xs">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-xs font-bold text-carbon-100 bg-carbon-700/50 px-2 py-0.5 rounded border border-carbon-600/50 truncate max-w-[200px]" title={targetDisplay}>
                          {targetDisplay}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-brand-500/20 text-brand-300 border border-brand-500/30 uppercase">
                          {method}
                        </span>
                      </div>
                      <div className="text-xs text-carbon-300 font-mono truncate max-w-xs" title={finding.endpoint_url || pocUrl}>
                        {finding.endpoint_url || pocUrl}
                      </div>
                    </div>
                  </td>

                  {/* Parameter & Context */}
                  <td className="px-4 py-4 align-top whitespace-nowrap">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-1">
                        <span className="text-xs font-bold font-mono text-purple-300 bg-purple-950/40 border border-purple-800/50 px-2 py-0.5 rounded">
                          {paramName}
                        </span>
                        <span className="text-[10px] text-carbon-400 uppercase font-mono">
                          ({paramLocation})
                        </span>
                      </div>
                      {finding.context_type && (
                        <div className="text-[11px] text-carbon-400 font-mono">
                          ctx: <span className="text-carbon-200">{finding.context_type}</span>
                        </div>
                      )}
                    </div>
                  </td>

                  {/* Payload */}
                  <td className="px-4 py-4 align-top max-w-sm">
                    <div className="relative group">
                      <code className="text-xs text-green-300 bg-carbon-900/80 px-2 py-1 rounded border border-carbon-700 font-mono break-all line-clamp-2 block" title={finding.best_payload}>
                        {formatPayload(finding.best_payload, 100)}
                      </code>
                    </div>
                  </td>

                  {/* Status & Date */}
                  <td className="px-4 py-4 whitespace-nowrap align-top">
                    <div className="space-y-1">
                      <span
                        className={`inline-block px-2 py-0.5 text-xs font-semibold rounded-full ${finding.is_verified ? getStatusColor(finding.status) : 'bg-yellow-500/20 text-yellow-200'}`}
                        title={finding.verification_reason}
                      >
                        {displayStatus}
                      </span>
                      <div className="text-[11px] text-carbon-400">
                        {formatDate(finding.created_at)}
                      </div>
                    </div>
                  </td>

                  {/* Self-Test Actions */}
                  <td className="px-4 py-4 whitespace-nowrap text-right align-top font-medium">
                    <div className="flex flex-col items-end space-y-2">
                      <div className="flex items-center space-x-1.5">
                        {/* 1. Open in Browser Button */}
                        {pocUrl && (
                          <a
                            href={pocUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center px-2.5 py-1 text-xs font-semibold rounded bg-green-500/20 text-green-300 border border-green-500/40 hover:bg-green-500/30 transition shadow-sm"
                            title="Open the exact saved request URL for manual browser testing"
                          >
                            🚀 Open Manual Test
                          </a>
                        )}

                        {/* 2. Copy PoC Link */}
                        {pocUrl && (
                          <button
                            type="button"
                            onClick={() => copyToClipboard(pocUrl, `poc-${finding.id}`)}
                            className="inline-flex items-center px-2.5 py-1 text-xs font-semibold rounded bg-carbon-700 text-carbon-200 border border-carbon-600 hover:bg-carbon-600 transition"
                            title="Copy full exploit URL to clipboard"
                          >
                            {copiedField === `poc-${finding.id}` ? '✓ Copied URL' : '📋 Copy URL'}
                          </button>
                        )}
                      </div>

                      <div className="flex items-center space-x-1.5">
                        {/* 3. Copy cURL Command */}
                        {finding.curl_command && (
                          <button
                            type="button"
                            onClick={() => copyToClipboard(finding.curl_command!, `curl-${finding.id}`)}
                            className="inline-flex items-center px-2 py-0.5 text-[11px] font-semibold rounded bg-yellow-500/15 text-yellow-200 border border-yellow-500/30 hover:bg-yellow-500/25 transition"
                            title="Copy copy-pasteable cURL command"
                          >
                            {copiedField === `curl-${finding.id}` ? '✓ cURL Copied' : '⚡ cURL'}
                          </button>
                        )}

                        {/* 4. Toggle In-Line Drawer */}
                        <button
                          type="button"
                          onClick={() => toggleExpand(finding.id)}
                          className="inline-flex items-center px-2 py-0.5 text-[11px] font-semibold rounded bg-carbon-700/60 text-brand-300 hover:text-brand-100 hover:bg-carbon-700 transition"
                          title="Expand in-row inspection drawer"
                        >
                          {isExpanded ? '▲ Hide Quick PoC' : '▼ Quick Workbench'}
                        </button>

                        {/* 5. PoC Modal Details */}
                        {onViewPoC && (
                          <button
                            type="button"
                            onClick={() => onViewPoC(finding.id)}
                            className="inline-flex items-center px-2.5 py-0.5 text-[11px] font-bold rounded bg-brand-500/20 text-brand-300 border border-brand-500/40 hover:bg-brand-500/30 transition"
                            title="Open full Interactive PoC & Burp Suite Dispatcher"
                          >
                            🔍 Full PoC Modal
                          </button>
                        )}
                      </div>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Expanded Row In-Line Workbench Drawer */}
      {expandedFindingId && (() => {
        const expandedFinding = findings.find((f) => f.id === expandedFindingId);
        if (!expandedFinding) return null;
        const pocUrl = expandedFinding.poc_url || expandedFinding.endpoint_url || '';
        return (
          <div className="border-t-2 border-brand-500/60 bg-carbon-900/90 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="px-2.5 py-0.5 rounded bg-brand-500/20 text-brand-300 font-bold text-xs border border-brand-500/40">
                  FINDING #{expandedFinding.id} WORKBENCH
                </span>
                <span className="text-sm font-semibold text-carbon-100">
                  {expandedFinding.target_name || expandedFinding.target_domain} — {expandedFinding.endpoint_method} {expandedFinding.endpoint_url}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setExpandedFindingId(null)}
                className="text-xs text-carbon-400 hover:text-carbon-200 font-bold px-2 py-1 rounded bg-carbon-800 border border-carbon-700"
              >
                ✕ Close Workbench
              </button>
            </div>

            {!expandedFinding.is_verified && (
              <div className="rounded-lg border border-yellow-500/40 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-100">
                <strong>Unverified:</strong> {expandedFinding.verification_reason || 'No browser execution evidence is attached.'}
              </div>
            )}

            {/* Quick Testing Bar */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* PoC URL */}
              <div className="bg-carbon-850 p-3 rounded-lg border border-carbon-700/60 space-y-1.5 md:col-span-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-green-300 flex items-center space-x-1">
                    <span>
                      🌐 {expandedFinding.poc_source === 'stored_request' ? 'Exact Saved PoC URL' : 'Generated Manual-Test URL'}
                    </span>
                  </span>
                  <div className="flex items-center space-x-2">
                    <a
                      href={pocUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs px-2.5 py-1 bg-green-600 hover:bg-green-500 text-white font-semibold rounded transition shadow"
                    >
                      🚀 Open Manual Test
                    </a>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(pocUrl, 'drawer-poc')}
                      className="text-xs px-2.5 py-1 bg-carbon-700 hover:bg-carbon-600 text-carbon-100 font-semibold rounded border border-carbon-600 transition"
                    >
                      {copiedField === 'drawer-poc' ? '✓ Copied' : '📋 Copy URL'}
                    </button>
                  </div>
                </div>
                <div className="bg-carbon-950 p-2 rounded text-xs font-mono text-carbon-200 break-all select-all border border-carbon-800">
                  {pocUrl}
                </div>
              </div>

              {/* cURL Command */}
              {expandedFinding.curl_command && (
                <div className="bg-carbon-850 p-3 rounded-lg border border-carbon-700/60 space-y-1.5 md:col-span-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-yellow-300">⚡ cURL Terminal Command</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(expandedFinding.curl_command!, 'drawer-curl')}
                      className="text-xs px-2 py-0.5 bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-200 border border-yellow-500/30 rounded font-semibold transition"
                    >
                      {copiedField === 'drawer-curl' ? '✓ Copied cURL' : '📋 Copy cURL'}
                    </button>
                  </div>
                  <pre className="bg-carbon-950 p-2 rounded text-xs font-mono text-yellow-100/90 overflow-x-auto border border-carbon-800 max-h-24">
                    <code>{expandedFinding.curl_command}</code>
                  </pre>
                </div>
              )}

              {/* Payload Raw */}
              <div className="bg-carbon-850 p-3 rounded-lg border border-carbon-700/60 space-y-1.5 md:col-span-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-brand-300">🎯 Injected Payload</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(expandedFinding.best_payload, 'drawer-payload')}
                    className="text-xs px-2 py-0.5 bg-brand-500/20 hover:bg-brand-500/30 text-brand-200 border border-brand-500/30 rounded font-semibold transition"
                  >
                    {copiedField === 'drawer-payload' ? '✓ Copied' : '📋 Copy'}
                  </button>
                </div>
                <pre className="bg-carbon-950 p-2 rounded text-xs font-mono text-green-300 overflow-x-auto border border-carbon-800 max-h-24">
                  <code>{expandedFinding.best_payload}</code>
                </pre>
              </div>

              {/* Raw HTTP Request for Burp Repeater */}
              {expandedFinding.raw_http_request && (
                <div className="bg-carbon-850 p-3 rounded-lg border border-carbon-700/60 space-y-1.5 md:col-span-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-orange-300">🦊 Raw HTTP Request (Paste into Burp Suite Repeater)</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(expandedFinding.raw_http_request!, 'drawer-raw')}
                      className="text-xs px-2.5 py-1 bg-orange-500/20 hover:bg-orange-500/30 text-orange-200 border border-orange-500/30 rounded font-semibold transition"
                    >
                      {copiedField === 'drawer-raw' ? '✓ Copied Burp Request' : '📋 Copy Raw HTTP Request'}
                    </button>
                  </div>
                  <pre className="bg-carbon-950 p-2.5 rounded text-xs font-mono text-carbon-200 overflow-x-auto border border-carbon-800 max-h-36 whitespace-pre">
                    <code>{expandedFinding.raw_http_request}</code>
                  </pre>
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {findings.length === 0 && (
        <div className="text-center py-12 text-carbon-400">
          No findings yet. Run experiments to discover XSS vulnerabilities.
        </div>
      )}
    </div>
  );
};

export default FindingTable;
