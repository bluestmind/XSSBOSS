/** Live scan monitor */
import { useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useExperimentStore } from '@/store/experimentState';
import { experimentsApi } from '@/api/experiments';

const statusClass: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700',
  queued: 'bg-blue-100 text-blue-800',
  running: 'bg-yellow-100 text-yellow-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  hit: 'bg-green-100 text-green-800',
  missed: 'bg-gray-100 text-gray-700',
  error: 'bg-red-100 text-red-800',
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
};

const Badge = ({ value }: { value: string }) => (
  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${statusClass[value] || 'bg-gray-100 text-gray-700'}`}>
    {value}
  </span>
);

const formatTime = (value: string) => new Date(value).toLocaleTimeString();

const getExploitUrlFromExecution = (execution: any) => {
  if (!execution.endpoint_url || !execution.payload) return '';
  const testablePayload = execution.payload
    .replace(/__XSS__\(['"`][a-zA-Z0-9_-]+['"`]\)/gi, "alert(document.domain)")
    .replace(/__XSS__%28%27[a-zA-Z0-9_-]+%27%29/gi, "alert%28document.domain%29")
    .replace(/__XSS__%28%22[a-zA-Z0-9_-]+%22%29/gi, "alert%28document.domain%29")
    .replace(/__XSS__%28%60[a-zA-Z0-9_-]+%60%29/gi, "alert%28document.domain%29")
    .replace(/__XSS__%60[a-zA-Z0-9_-]+%60/gi, "alert%60document.domain%60");

  let base = execution.endpoint_url;
  
  if (execution.param_name === 'location.hash' || execution.payload.startsWith('#') || base.includes('#')) {
    const baseUrl = base.split('#')[0];
    return `${baseUrl}#${testablePayload}`;
  }

  if (execution.param_name === 'comment-text' || execution.param_name === 'comment') {
    const baseUrl = base.split('?')[0];
    return `${baseUrl}?inject_comment=${encodeURIComponent(testablePayload)}`;
  }

  try {
    const urlObj = new URL(base);
    if (execution.param_name) {
      urlObj.searchParams.set(execution.param_name, testablePayload);
    }
    return urlObj.toString();
  } catch (e) {
    const separator = base.includes('?') ? '&' : '?';
    return `${base}${separator}${execution.param_name}=${encodeURIComponent(testablePayload)}`;
  }
};

const LiveFuzzPage = () => {
  const { activeExperimentId, pollingInterval, setActiveExperiment, clearActiveExperiment } = useExperimentStore();

  const { data: experiments = [], isFetched: experimentsFetched } = useQuery({
    queryKey: ['experiments'],
    queryFn: () => experimentsApi.list(),
    refetchInterval: pollingInterval,
  });

  const { data: monitor, isError: monitorError } = useQuery({
    queryKey: ['experiments', activeExperimentId, 'monitor'],
    queryFn: () => experimentsApi.getMonitor(activeExperimentId!),
    enabled: !!activeExperimentId,
    refetchInterval: pollingInterval,
    retry: false,
  });

  const selectableExperiments = experiments.filter((exp) =>
    ['running', 'paused', 'pending', 'completed'].includes(exp.status)
  );

  const hitCount = useMemo(
    () => monitor?.recent_executions.filter((execution) => execution.oracle_status === 'hit').length || 0,
    [monitor]
  );

  useEffect(() => {
    if (!activeExperimentId || !experimentsFetched) return;
    const stillExists = experiments.some((experiment) => experiment.id === activeExperimentId);
    if (!stillExists) {
      clearActiveExperiment();
    }
  }, [activeExperimentId, clearActiveExperiment, experiments, experimentsFetched]);

  useEffect(() => {
    if (monitorError) {
      clearActiveExperiment();
    }
  }, [clearActiveExperiment, monitorError]);

  if (!activeExperimentId || monitorError || !monitor) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold text-gray-900">Live Monitor</h1>
          <Link to="/scan" className="px-4 py-2 rounded-md bg-blue-600 text-white text-sm font-medium hover:bg-blue-700">
            Start scan
          </Link>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Choose a scan to watch</h2>
          {selectableExperiments.length > 0 ? (
            <div className="divide-y divide-gray-100">
              {selectableExperiments.map((exp) => (
                <button
                  key={exp.id}
                  onClick={() => setActiveExperiment(exp.id)}
                  className="w-full text-left py-3 flex items-center justify-between hover:bg-gray-50 px-3 rounded-md"
                >
                  <div>
                    <div className="font-medium text-gray-900">{exp.name}</div>
                    <div className="text-xs text-gray-500">{exp.strategy}</div>
                  </div>
                  <Badge value={exp.status} />
                </button>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-600">No scans are available yet. Start one from the Scan page.</p>
          )}
        </div>
      </div>
    );
  }

  const stats = monitor.stats;
  const activeCount = stats.running + stats.queued + stats.pending;

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Live Monitor</h1>
          <p className="text-sm text-gray-600 mt-1">
            {monitor.target.name} · {monitor.target.base_url}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={activeExperimentId}
            onChange={(event) => setActiveExperiment(Number(event.target.value))}
            className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          >
            {selectableExperiments.map((exp) => (
              <option key={exp.id} value={exp.id}>
                #{exp.id} {exp.name}
              </option>
            ))}
          </select>
          <Link to="/scan" className="px-4 py-2 rounded-md bg-blue-600 text-white text-sm font-medium hover:bg-blue-700">
            New scan
          </Link>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-semibold text-gray-900 capitalize">{monitor.stage}</h2>
              <Badge value={monitor.experiment.status} />
            </div>
            <p className="text-sm text-gray-600 mt-1">{monitor.stage_detail}</p>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold text-gray-900">{monitor.progress_percent}%</div>
            <div className="text-xs text-gray-500">complete</div>
          </div>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3">
          <div className="bg-blue-600 h-3 rounded-full transition-all" style={{ width: `${monitor.progress_percent}%` }} />
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-xs text-gray-500">Active</div>
          <div className="text-2xl font-bold">{activeCount}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-xs text-gray-500">Running</div>
          <div className="text-2xl font-bold text-yellow-700">{stats.running}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-xs text-gray-500">Queued</div>
          <div className="text-2xl font-bold text-blue-700">{stats.queued}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-xs text-gray-500">Completed</div>
          <div className="text-2xl font-bold text-green-700">{stats.completed}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-xs text-gray-500">Hits</div>
          <div className="text-2xl font-bold text-green-700">{hitCount}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-xs text-gray-500">Findings</div>
          <div className="text-2xl font-bold text-red-700">{monitor.recent_findings.length}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-100">
            <h2 className="text-lg font-semibold text-gray-900">What is happening now</h2>
            <p className="text-sm text-gray-500">Latest generated payload checks and browser work.</p>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Targeted input</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Payload</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Updated</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-100">
                {monitor.recent_checks.map((check) => (
                  <tr key={check.id}>
                    <td className="px-4 py-3 whitespace-nowrap"><Badge value={check.status} /></td>
                    <td className="px-4 py-3 text-sm">
                      <div className="font-medium text-gray-900">{check.param_name} <span className="text-gray-500">({check.param_location})</span></div>
                      <div className="text-xs text-gray-500 truncate max-w-xs">{check.endpoint_method} {check.endpoint_url}</div>
                      {check.context_type && <div className="text-xs text-blue-700 mt-1">{check.context_type}</div>}
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-gray-700 max-w-sm truncate">{check.payload_preview}</td>
                    <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">{formatTime(check.updated_at)}</td>
                  </tr>
                ))}
                {monitor.recent_checks.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-10 text-center text-sm text-gray-500">
                      Waiting for discovered parameters and generated payload checks.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-100">
            <h2 className="text-lg font-semibold text-gray-900">Findings</h2>
            <p className="text-sm text-gray-500">Confirmed oracle hits become reportable here.</p>
          </div>
          <div className="divide-y divide-gray-100 max-h-[520px] overflow-y-auto">
            {monitor.recent_findings.map((finding) => (
              <Link key={finding.id} to="/findings" className="block p-4 hover:bg-gray-50">
                <div className="flex items-center justify-between mb-2">
                  <Badge value={finding.severity} />
                  <span className="text-xs text-gray-500">{formatTime(finding.created_at)}</span>
                </div>
                <div className="text-sm font-medium text-gray-900">{finding.param_name}</div>
                <div className="text-xs text-gray-500 truncate">{finding.endpoint_url}</div>
                <div className="text-xs font-mono text-gray-700 mt-2 truncate">{finding.payload_preview}</div>
              </Link>
            ))}
            {monitor.recent_findings.length === 0 && (
              <div className="p-8 text-center text-sm text-gray-500">No findings yet.</div>
            )}
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900">Browser executions</h2>
          <p className="text-sm text-gray-500">Recent real-browser runs and oracle results.</p>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Oracle</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Input</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Duration</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-100">
              {monitor.recent_executions.map((execution) => (
                <tr key={execution.id}>
                  <td className="px-4 py-3 whitespace-nowrap"><Badge value={execution.oracle_status} /></td>
                  <td className="px-4 py-3 text-sm">
                    <div className="font-medium text-gray-900">{execution.param_name || '-'}</div>
                    <div className="text-xs text-gray-500 truncate max-w-xl">{execution.endpoint_url || '-'}</div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">{execution.duration_ms ? `${execution.duration_ms}ms` : '-'}</td>
                  <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">{formatTime(execution.executed_at)}</td>
                  <td className="px-4 py-3 text-sm whitespace-nowrap">
                    {execution.oracle_status === 'hit' && execution.payload ? (
                      <div className="flex gap-2">
                        <a
                          href={getExploitUrlFromExecution(execution)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="bg-red-600 hover:bg-red-700 text-white font-semibold text-xs px-2.5 py-1 rounded transition shadow-sm"
                        >
                          💥 Exploit
                        </a>
                        <button
                          type="button"
                          onClick={() => {
                            const link = getExploitUrlFromExecution(execution);
                            navigator.clipboard.writeText(link);
                            alert('Exploit URL copied!');
                          }}
                          className="bg-gray-100 hover:bg-gray-200 text-gray-700 font-medium text-xs px-2.5 py-1 rounded transition"
                        >
                          📋 Copy
                        </button>
                      </div>
                    ) : (
                      <span className="text-gray-400 text-xs font-medium">-</span>
                    )}
                  </td>
                </tr>
              ))}
              {monitor.recent_executions.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-10 text-center text-sm text-gray-500">
                    Browser executions will appear after payload checks are queued.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default LiveFuzzPage;
