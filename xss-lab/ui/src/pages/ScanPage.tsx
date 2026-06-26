/** Single URL-to-monitor XSS flow */
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { experimentsApi } from '@/api/experiments';
import { scansApi } from '@/api/scans';
import { useExperimentStore } from '@/store/experimentState';
import type { ExperimentMonitor, MonitorEvent, ScanCreate } from '@/types/api';
// @ts-ignore
import EndpointsMap from '@/components/EndpointsMap';

type StepState = 'pending' | 'active' | 'done' | 'warning';

interface RunbookStep {
  id: string;
  phase: string;
  title: string;
  detail: string;
  state: StepState;
  count?: number;
}

const statusClass: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700',
  active: 'bg-blue-100 text-blue-800',
  done: 'bg-green-100 text-green-800',
  warning: 'bg-yellow-100 text-yellow-800',
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
  debug: 'bg-gray-100 text-gray-700',
  info: 'bg-blue-100 text-blue-800',
  success: 'bg-green-100 text-green-800',
};

const initialFormData: ScanCreate = {
  url: '',
  authorized: false,
  crawl: true,
  max_depth: 1,
  max_pages: 15,
  strategy: 'max_coverage',
  mode: 'full',
};

const Badge = ({ value }: { value: string }) => (
  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${statusClass[value] || 'bg-gray-100 text-gray-700'}`}>
    {value}
  </span>
);

const formatTime = (value: string) => new Date(value).toLocaleTimeString();

const getTestableUrl = (url?: string) => {
  if (!url) return '';
  let res = url;
  res = res.replace(/__XSS__\(['"`][a-zA-Z0-9_-]+['"`]\)/gi, "alert(document.domain)");
  res = res.replace(/__XSS__%28%27[a-zA-Z0-9_-]+%27%29/gi, "alert%28document.domain%29");
  res = res.replace(/__XSS__%28%22[a-zA-Z0-9_-]+%22%29/gi, "alert%28document.domain%29");
  res = res.replace(/__XSS__%28%60[a-zA-Z0-9_-]+%60%29/gi, "alert%28document.domain%29");
  res = res.replace(/__XSS__%60[a-zA-Z0-9_-]+%60/gi, "alert%60document.domain%60");
  return res;
};

const getTestableCommand = (command?: string) => {
  if (!command) return '';
  let res = command;
  res = res.replace(/__XSS__\(['"`][a-zA-Z0-9_-]+['"`]\)/gi, "alert(document.domain)");
  res = res.replace(/__XSS__%28%27[a-zA-Z0-9_-]+%27%29/gi, "alert%28document.domain%29");
  res = res.replace(/__XSS__%28%22[a-zA-Z0-9_-]+%22%29/gi, "alert%28document.domain%29");
  res = res.replace(/__XSS__%28%60[a-zA-Z0-9_-]+%60%29/gi, "alert%28document.domain%29");
  res = res.replace(/__XSS__%60[a-zA-Z0-9_-]+%60/gi, "alert%60document.domain%60");
  return res;
};

const formatVulnType = (value?: string) => {
  const labels: Record<string, string> = {
    xss: 'XSS',
    blind_xss: 'Blind XSS',
    ssrf_oob: 'SSRF',
    open_redirect: 'Open Redirect',
    cors_misconfiguration: 'CORS Misconfiguration',
    sqli: 'SQL Injection',
    sqli_error_based: 'SQL Injection',
    lfi: 'Path Traversal / LFI',
    path_traversal_lfi: 'Path Traversal / LFI',
  };
  return labels[value || ''] || (value || 'Vulnerability').replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
};

const formatStage = (value?: string) => {
  const labels: Record<string, string> = {
    recon: 'Recon',
    recon_complete: 'Recon complete',
    profiling: 'Profiling',
    queued: 'Queued',
    executing: 'Executing',
    completed: 'Completed',
    no_checks: 'No checks',
    burp_blocked: 'Burp blocked',
    target_unreachable: 'Target unreachable',
  };
  return labels[value || ''] || (value || 'Waiting').replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
};

const getErrorDetail = (error: unknown) => {
  if (!error) return '';
  const axiosError = error as any;
  const detail = axiosError.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || item.message || JSON.stringify(item)).join(' ');
  }
  if (axiosError.response?.status === 504 || axiosError.response?.status === 502) {
    return 'Backend API is not reachable on port 8000. Start XSS Boss API, then try again.';
  }
  if (axiosError.request && !axiosError.response) {
    return 'Backend API is offline or the Vite proxy cannot reach it. Start the API server on 127.0.0.1:8000.';
  }
  if (typeof axiosError.message === 'string') return axiosError.message;
  return 'Could not start scan.';
};

const summarizeExecutionLog = (value?: string) => {
  if (!value) return '';
  try {
    const parsed = JSON.parse(value);
    const errors = parsed.errors || parsed.page_errors || [];
    const consoleMessages = parsed.console || parsed.console_messages || [];
    const callbacks = parsed.callbacks || parsed.oracle_callbacks || [];
    if (errors.length) return `Error: ${String(errors[0])}`;
    if (callbacks.length) return `Oracle callback observed: ${String(callbacks[0])}`;
    if (consoleMessages.length) return `Console: ${String(consoleMessages[0])}`;
    return 'Browser completed without console errors or oracle callback.';
  } catch {
    return value;
  }
};

const buildRunbook = (monitor?: ExperimentMonitor, hasStarted = false): RunbookStep[] => {
  const stats = monitor?.stats;
  const total = stats?.total_test_cases || 0;
  const executed = monitor?.recent_executions.length || 0;
  const contexts = new Set(monitor?.recent_checks.map((check) => check.context_type).filter(Boolean));
  const findings = monitor?.recent_findings.length || 0;
  const active = (stats?.queued || 0) + (stats?.running || 0);
  const finished = (stats?.completed || 0) + (stats?.failed || 0);
  const isComplete = monitor?.experiment.status === 'completed';
  const isReconOnly = monitor?.experiment.limits?.scan_mode === 'recon' || monitor?.experiment.limits?.vuln_checks_enabled === false;
  const reconEndpointCount = Number(monitor?.experiment.limits?.recon_endpoint_count || 0);
  const reconParamCount = Number(monitor?.experiment.limits?.recon_param_count || 0);
  const noChecks = isComplete && total === 0 && !isReconOnly;
  const reconComplete = isComplete && isReconOnly;

  return [
    {
      id: 'scope',
      phase: 'Phase 1',
      title: 'Scope and authorization',
      detail: 'Create a target from the submitted URL and keep testing constrained to that host.',
      state: hasStarted ? 'done' : 'pending',
      count: hasStarted ? 1 : 0,
    },
    {
      id: 'recon',
      phase: 'Phase 1',
      title: 'Crawler and parameter inventory',
      detail: 'Crawl same-host links/forms, import the submitted URL, and map controllable inputs.',
      state: !hasStarted ? 'pending' : noChecks ? 'warning' : reconComplete || total > 0 || monitor?.stage !== 'recon' ? 'done' : 'active',
      count: reconEndpointCount || total,
    },
    {
      id: 'contexts',
      phase: 'Phase 2',
      title: isReconOnly ? 'Parameter enrichment' : 'Context-aware reflection mapping',
      detail: isReconOnly
        ? 'Mine scripts, forms, archive URLs, and imported traffic for controllable parameter names.'
        : 'Classify where each value lands: HTML text, attributes, JavaScript, URL, or JSON.',
      state: isReconOnly ? (reconComplete ? 'done' : hasStarted ? 'active' : 'pending') : contexts.size > 0 ? 'done' : total > 0 ? 'active' : 'pending',
      count: isReconOnly ? reconParamCount : contexts.size,
    },
    {
      id: 'filters',
      phase: 'Phase 3',
      title: 'Filter and WAF behavior profiling',
      detail: 'Probe escaping, stripped keywords, blocked tags, and normalization behavior.',
      state: isReconOnly ? (reconComplete ? 'done' : 'pending') : noChecks ? 'warning' : total > 0 ? 'done' : hasStarted ? 'active' : 'pending',
      count: total,
    },
    {
      id: 'payloads',
      phase: 'Phase 5',
      title: 'Payload generation and mutation',
      detail: 'Generate max-coverage payloads using context, filter profile, priority, and mutation strategy.',
      state: isReconOnly ? 'pending' : noChecks ? 'warning' : total > 0 ? 'done' : hasStarted ? 'active' : 'pending',
      count: total,
    },
    {
      id: 'queue',
      phase: 'Phase 7',
      title: 'Queue and protocol execution',
      detail: 'Queue checks by priority and preserve method, endpoint, parameter, and payload evidence.',
      state: active > 0 ? 'active' : finished > 0 ? 'done' : total > 0 ? 'warning' : 'pending',
      count: active,
    },
    {
      id: 'oracle',
      phase: 'Phase 8',
      title: 'Browser oracle telemetry',
      detail: 'Run payloads in the browser and record oracle status, console errors, screenshots, and DOM evidence.',
      state: executed > 0 ? (active > 0 ? 'active' : 'done') : total > 0 ? 'active' : 'pending',
      count: executed,
    },
    {
      id: 'findings',
      phase: 'Phase 8',
      title: 'Finding correlation',
      detail: 'Correlate oracle hits back to endpoint, parameter, payload, and proof artifacts.',
      state: isReconOnly ? 'pending' : findings > 0 ? 'done' : isComplete && !noChecks ? 'warning' : executed > 0 ? 'active' : 'pending',
      count: findings,
    },
    {
      id: 'complete',
      phase: 'Phase 10',
      title: isReconOnly ? 'Recon handoff' : 'False-negative review and completion',
      detail: isReconOnly
        ? 'Freeze the discovered attack surface so a full vuln scan can use it without repeating basic setup.'
        : 'Finish the run, review missed/error cases, and keep weak spots visible in the log stream.',
      state: noChecks ? 'warning' : isComplete ? 'done' : hasStarted ? 'active' : 'pending',
      count: finished,
    },
  ];
};

const getEngineDecision = (monitor?: ExperimentMonitor) => {
  if (!monitor) return 'Waiting for a run. Submit a URL or select a previous run.';
  const stats = monitor.stats;
  const isReconOnly = monitor.experiment.limits?.scan_mode === 'recon' || monitor.experiment.limits?.vuln_checks_enabled === false;
  if (monitor.stage === 'recon_complete') return monitor.stage_detail;
  if (monitor.stage === 'burp_blocked') {
    return 'Burp started but paused before crawling a seed URL. Fix the Burp task/connectivity issue, then remove this run and start again.';
  }
  if (monitor.stage === 'target_unreachable') {
    return 'Burp/proxy could not get usable responses from the target, so no reflection contexts or payload checks were generated.';
  }
  if (monitor.stage === 'no_checks' || (monitor.experiment.status === 'completed' && stats.total_test_cases === 0 && !isReconOnly)) {
    return 'Run ended fast because no controllable/reflected parameters became payload checks. Use a parameterized URL, crawlable form, or Burp-imported traffic.';
  }
  if (monitor.experiment.status === 'paused') return 'Paused by operator. Engine will not queue new payloads until resumed.';
  if (stats.running > 0) return `Testing ${stats.running} payload(s) now because they were highest priority for their context and parameter.`;
  if (stats.queued > 0) return `Waiting for browser workers. ${stats.queued} payload(s) are queued by priority.`;
  if (stats.pending > 0) return `Preparing next payload batch from ${stats.pending} pending checks.`;
  if (monitor.recent_findings.length > 0) return 'Oracle hit found. Engine correlated execution evidence into findings.';
  if (monitor.experiment.status === 'completed') return 'Run completed. No more payloads are pending or queued.';
  if (stats.total_test_cases === 0) return 'Recon and profiling are running before payload generation starts.';
  return monitor.stage_detail;
};

const LogRow = ({ event }: { event: MonitorEvent }) => (
  <div className="grid grid-cols-1 gap-2 border-b border-gray-100 px-4 py-3 last:border-b-0 lg:grid-cols-[90px_90px_1fr]">
    <div className="text-xs text-gray-500">{formatTime(event.timestamp)}</div>
    <div><Badge value={event.level} /></div>
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold uppercase text-blue-700">{event.phase}</span>
        <span className="text-sm font-medium text-gray-900">{event.message}</span>
      </div>
      {event.detail && (
        <p className="mt-1 text-sm leading-5 text-gray-600">{event.detail}</p>
      )}
    </div>
  </div>
);

const ScanPage = () => {
  const queryClient = useQueryClient();
  const { setActiveExperiment } = useExperimentStore();
  const [formData, setFormData] = useState<ScanCreate>(initialFormData);
  const [startedExperimentId, setStartedExperimentId] = useState<number | null>(null);
  const [logFilter, setLogFilter] = useState<'all' | 'errors' | 'hits'>('all');
  const [activeTabs, setActiveTabs] = useState<Record<number, 'verify' | 'evidence'>>({});
  const [pendingMode, setPendingMode] = useState<'recon' | 'full' | null>(null);

  const { data: health, isError: healthError } = useQuery({
    queryKey: ['scan-health'],
    queryFn: scansApi.health,
    retry: false,
    refetchInterval: 10000,
  });

  const { data: previousRuns = [] } = useQuery({
    queryKey: ['experiments'],
    queryFn: () => experimentsApi.list(),
    refetchInterval: 5000,
  });

  const { data: monitor, isError: monitorError } = useQuery({
    queryKey: ['experiments', startedExperimentId, 'monitor'],
    queryFn: () => experimentsApi.getMonitor(startedExperimentId!),
    enabled: !!startedExperimentId,
    refetchInterval: startedExperimentId ? 2000 : false,
    retry: false,
  });

  const mutation = useMutation({
    mutationFn: scansApi.create,
    onSuccess: (scan) => {
      setStartedExperimentId(scan.experiment_id);
      setActiveExperiment(scan.experiment_id);
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
    },
    onSettled: () => {
      setPendingMode(null);
    },
  });

  const pauseMutation = useMutation({
    mutationFn: (experimentId: number) => experimentsApi.stop(experimentId),
    onSuccess: (experiment) => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      queryClient.invalidateQueries({ queryKey: ['experiments', experiment.id, 'monitor'] });
    },
  });

  const resumeMutation = useMutation({
    mutationFn: (experimentId: number) => experimentsApi.resume(experimentId),
    onSuccess: (experiment) => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      queryClient.invalidateQueries({ queryKey: ['experiments', experiment.id, 'monitor'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (experimentId: number) => experimentsApi.delete(experimentId).then(() => experimentId),
    onSuccess: (experimentId) => {
      if (startedExperimentId === experimentId) {
        setStartedExperimentId(null);
        mutation.reset();
      }
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      queryClient.removeQueries({ queryKey: ['experiments', experimentId, 'monitor'] });
    },
  });

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    const mode = submitter?.value === 'recon' ? 'recon' : 'full';
    setPendingMode(mode);
    mutation.mutate({
      ...formData,
      mode,
      crawl: true,
      max_depth: 1,
      max_pages: 15,
      strategy: 'max_coverage',
    });
  };

  const stats = monitor?.stats;
  const activeCount = stats ? stats.running + stats.queued + stats.pending : 0;
  const hitCount = useMemo(
    () => monitor?.recent_executions.filter((execution) => execution.oracle_status === 'hit').length || 0,
    [monitor]
  );
  const sortedPreviousRuns = useMemo(
    () => [...previousRuns].sort((a, b) => b.id - a.id),
    [previousRuns]
  );
  const runbook = useMemo(() => buildRunbook(monitor, !!startedExperimentId), [monitor, startedExperimentId]);
  const visibleLogs = useMemo(() => {
    const events = monitor?.activity_log || [];
    if (logFilter === 'errors') return events.filter((event) => event.level === 'error' || event.message.toLowerCase().includes('failed'));
    if (logFilter === 'hits') return events.filter((event) => event.level === 'success' || event.message.toLowerCase().includes('hit'));
    return events;
  }, [logFilter, monitor]);
  const activePayloads = useMemo(
    () => (monitor?.recent_checks || []).filter((check) => ['running', 'queued'].includes(check.status)).slice(0, 8),
    [monitor]
  );
  const latestResults = useMemo(
    () => (monitor?.recent_executions || []).slice(0, 12),
    [monitor]
  );

  const errorDetail = getErrorDetail(mutation.error);

  return (
    <div className="p-6 max-w-7xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Recon + Vuln Flow</h1>
        <p className="mt-2 text-sm text-gray-600">
          Put in one authorized URL. Run recon first to map the surface, or run the full flow to move straight into typed vulnerability checks.
        </p>
        <div className={`mt-3 inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${
          healthError ? 'bg-red-100 text-red-800' : health ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-700'
        }`}>
          {healthError ? 'Backend offline' : health ? 'Backend online' : 'Checking backend...'}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow p-6 space-y-5">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Target URL</label>
          <input
            type="url"
            required
            value={formData.url}
            onChange={(event) => setFormData({ ...formData, url: event.target.value })}
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            placeholder="https://example.com/search?q=test"
          />
        </div>

        <label className="flex items-start gap-3 text-sm text-gray-700">
          <input
            type="checkbox"
            required
            checked={formData.authorized}
            onChange={(event) => setFormData({ ...formData, authorized: event.target.checked })}
            className="mt-1 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          />
          <span>I own this target or have explicit permission to test it.</span>
        </label>

        {errorDetail && (
          <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {errorDetail}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            name="mode"
            value="recon"
            disabled={mutation.isPending || healthError}
            className="inline-flex justify-center rounded-md border border-blue-200 px-4 py-2 bg-white text-sm font-medium text-blue-700 hover:bg-blue-50 disabled:opacity-50"
          >
            {mutation.isPending && pendingMode === 'recon' ? 'Starting recon...' : 'Run recon only'}
          </button>
          <button
            type="submit"
            name="mode"
            value="full"
            disabled={mutation.isPending || healthError}
            className="inline-flex justify-center rounded-md border border-transparent px-4 py-2 bg-blue-600 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {mutation.isPending && pendingMode === 'full' ? 'Starting full flow...' : 'Run recon + vuln scan'}
          </button>
          {startedExperimentId && (
            <button
              type="button"
              onClick={() => {
                setStartedExperimentId(null);
                setFormData(initialFormData);
                mutation.reset();
              }}
              className="inline-flex justify-center rounded-md border border-gray-300 px-4 py-2 bg-white text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              New URL
            </button>
          )}
        </div>
      </form>

      {mutation.data && !monitor && !monitorError && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-sm text-blue-900">{mutation.data.message}</p>
          <p className="mt-1 text-sm text-blue-800">Monitor is opening for experiment #{mutation.data.experiment_id}.</p>
        </div>
      )}

      {monitorError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700">
          The scan started, but the monitor is not reachable yet. The page will recover when the API responds.
        </div>
      )}

      <div className="bg-white rounded-lg shadow">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-100 px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Previous runs</h2>
            <p className="text-sm text-gray-500">Click any run to load its monitor on this same page.</p>
          </div>
          {startedExperimentId && (
            <div className="text-xs font-medium text-gray-500">Viewing experiment #{startedExperimentId}</div>
          )}
        </div>
        <div className="grid grid-cols-1 gap-3 p-4 md:grid-cols-2 xl:grid-cols-3">
          {sortedPreviousRuns.slice(0, 12).map((run) => (
            <button
              key={run.id}
              type="button"
              onClick={() => {
                setStartedExperimentId(run.id);
                setActiveExperiment(run.id);
                setLogFilter('all');
              }}
              className={`rounded-lg border p-4 text-left transition ${
                startedExperimentId === run.id ? 'border-blue-300 bg-blue-50' : 'border-gray-200 bg-white hover:border-blue-200 hover:bg-gray-50'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold text-gray-900">#{run.id} {run.name}</div>
                  <div className="mt-1 text-xs text-gray-500">{run.strategy}</div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge value={run.status} />
                  <span
                    role="button"
                    tabIndex={0}
                    onClick={(event) => {
                      event.stopPropagation();
                      if (window.confirm(`Remove experiment #${run.id}?`)) {
                        deleteMutation.mutate(run.id);
                      }
                    }}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        event.stopPropagation();
                        if (window.confirm(`Remove experiment #${run.id}?`)) {
                          deleteMutation.mutate(run.id);
                        }
                      }
                    }}
                    className="rounded-md border border-red-200 bg-white px-2 py-1 text-xs font-semibold text-red-700 hover:bg-red-50"
                  >
                    Remove
                  </span>
                </div>
              </div>
              <div className="mt-3 text-xs text-gray-500">
                Started {run.started_at ? new Date(run.started_at).toLocaleString() : 'not yet'}
              </div>
            </button>
          ))}
          {sortedPreviousRuns.length === 0 && (
            <div className="rounded-lg border border-dashed border-gray-200 p-6 text-sm text-gray-500">
              No previous runs yet.
            </div>
          )}
        </div>
      </div>

      <div className="bg-white rounded-lg shadow">
        <div className="border-b border-gray-100 px-6 py-4">
          <h2 className="text-lg font-semibold text-gray-900">Workflow runbook</h2>
          <p className="text-sm text-gray-500">Recon maps the attack surface first, then vuln engines test the discovered inputs.</p>
        </div>
        <div className="grid grid-cols-1 gap-3 p-4 md:grid-cols-2 xl:grid-cols-3">
          {runbook.map((step) => (
            <div key={step.id} className="rounded-lg border border-gray-200 p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-xs font-semibold uppercase text-blue-700">{step.phase}</div>
                  <div className="mt-1 text-sm font-semibold text-gray-900">{step.title}</div>
                </div>
                <Badge value={step.state} />
              </div>
              <p className="mt-2 text-xs leading-5 text-gray-600">{step.detail}</p>
              {typeof step.count === 'number' && (
                <div className="mt-3 text-xs font-medium text-gray-500">Observed: {step.count}</div>
              )}
            </div>
          ))}
        </div>
      </div>

      {monitor && stats && (
        <>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-lg font-semibold text-gray-900">{formatStage(monitor.stage)}</h2>
                  <Badge value={monitor.experiment.status} />
                </div>
                <p className="text-sm text-gray-600 mt-1">{monitor.stage_detail}</p>
                <p className="mt-2 rounded-md bg-blue-50 px-3 py-2 text-sm font-medium text-blue-900">
                  Engine decision: {getEngineDecision(monitor)}
                </p>
                <p className="text-xs text-gray-500 mt-1">{monitor.target.base_url}</p>
              </div>
              <div className="text-right">
                <div className="text-3xl font-bold text-gray-900">{monitor.progress_percent}%</div>
                <div className="text-xs text-gray-500">complete</div>
              </div>
            </div>
            <div className="mb-4 flex flex-wrap items-center gap-3">
              <button
                type="button"
                disabled={monitor.experiment.status !== 'running' || pauseMutation.isPending}
                onClick={() => pauseMutation.mutate(monitor.experiment.id)}
                className="inline-flex justify-center rounded-md border border-gray-300 px-3 py-1.5 bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              >
                {pauseMutation.isPending ? 'Pausing...' : 'Pause'}
              </button>
              <button
                type="button"
                disabled={monitor.experiment.status !== 'paused' || resumeMutation.isPending}
                onClick={() => resumeMutation.mutate(monitor.experiment.id)}
                className="inline-flex justify-center rounded-md border border-transparent px-3 py-1.5 bg-blue-600 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
              >
                {resumeMutation.isPending ? 'Resuming...' : 'Resume'}
              </button>
            </div>
            {monitor.throttle_status && (
              <div className="mb-4 rounded-lg border border-gray-200 bg-gray-50 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
                  <h3 className="text-sm font-semibold text-gray-700">⚡ Rate Limiter</h3>
                  <div className="flex items-center gap-2">
                    {monitor.throttle_status.current_delay_ms > monitor.throttle_status.base_delay_ms && (
                      <span className="inline-flex items-center rounded-full bg-yellow-100 px-2 py-0.5 text-xs font-semibold text-yellow-800">
                        Backing off
                      </span>
                    )}
                    {monitor.throttle_status.consecutive_errors > 0 && (
                      <span className="inline-flex items-center rounded-full bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-800">
                        {monitor.throttle_status.consecutive_errors} errors
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => {
                        fetch(`/api/v1/experiments/${monitor.experiment.id}/throttle/reset`, { method: 'POST' })
                          .then(() => queryClient.invalidateQueries({ queryKey: ['experiments', startedExperimentId, 'monitor'] }));
                      }}
                      className="rounded border border-gray-300 bg-white px-2 py-0.5 text-xs font-medium text-gray-600 hover:bg-gray-100"
                    >
                      Reset
                    </button>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div>
                    <div className="text-xs text-gray-500">Delay / request</div>
                    <div className={`text-sm font-bold ${monitor.throttle_status.current_delay_ms > monitor.throttle_status.base_delay_ms ? 'text-yellow-700' : 'text-gray-900'}`}>
                      {(monitor.throttle_status.current_delay_ms / 1000).toFixed(1)}s
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-500">Base delay</div>
                    <div className="text-sm font-bold text-gray-900">{(monitor.throttle_status.base_delay_ms / 1000).toFixed(1)}s</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-500">Req / minute</div>
                    <div className={`text-sm font-bold ${monitor.throttle_status.requests_last_minute >= monitor.throttle_status.max_requests_per_minute ? 'text-red-700' : 'text-gray-900'}`}>
                      {monitor.throttle_status.requests_last_minute} / {monitor.throttle_status.max_requests_per_minute}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-500">Adaptive</div>
                    <div className="text-sm font-bold text-gray-900">{monitor.throttle_status.adaptive_throttle ? 'On' : 'Off'}</div>
                  </div>
                </div>
              </div>
            )}
            <div className="w-full bg-gray-200 rounded-full h-3">
              <div className="bg-blue-600 h-3 rounded-full transition-all" style={{ width: `${monitor.progress_percent}%` }} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
            {[
              ['Active', activeCount, 'text-gray-900'],
              ['Running', stats.running, 'text-yellow-700'],
              ['Queued', stats.queued, 'text-blue-700'],
              ['Completed', stats.completed, 'text-green-700'],
              ['Hits', hitCount, 'text-green-700'],
              ['Findings', monitor.recent_findings.length, 'text-red-700'],
            ].map(([label, value, color]) => (
              <div key={label} className="bg-white rounded-lg shadow p-4">
                <div className="text-xs text-gray-500">{label}</div>
                <div className={`text-2xl font-bold ${color}`}>{value}</div>
              </div>
            ))}
          </div>

          <EndpointsMap targetId={monitor.target.id} monitor={monitor} />

          {/* Confirmed Findings Alerts */}
          {monitor.recent_findings.length > 0 && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-6 shadow-sm">
              <div className="flex items-center justify-between border-b border-red-200 pb-3 mb-4">
                <h2 className="text-lg font-bold text-red-950 flex items-center gap-2">
                  🚨 Confirmed Vulnerabilities ({monitor.recent_findings.length})
                </h2>
                <span className="text-xs bg-red-150 text-red-800 font-bold px-2.5 py-0.5 rounded-full uppercase animate-pulse">
                  Action Required
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {monitor.recent_findings.map((finding) => {
                  const vulnLabel = formatVulnType(finding.vuln_type);
                  const isRaw = !finding.payload_preview.includes('<') &&
                                !finding.payload_preview.includes('onload') &&
                                !finding.payload_preview.includes('onerror') &&
                                !finding.payload_preview.includes('onfocus') &&
                                !finding.payload_preview.includes('__XSS__') &&
                                !finding.payload_preview.includes('javascript:');
                  
                  const visualPayload = finding.payload_preview.replace(/__XSS__\(['"`][a-zA-Z0-9_-]+['"`]\)/gi, "alert(document.domain)");
                  const testUrl = getTestableUrl(finding.poc_request?.url);
                  const testCmd = getTestableCommand(finding.poc_request?.command);
                  const currentTab = activeTabs[finding.id] || 'verify';

                  return (
                    <div key={finding.id} className="bg-white border border-red-200 rounded-lg p-4 shadow-sm flex flex-col justify-between hover:border-red-350 transition duration-155">
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-red-100 text-red-800 uppercase">
                              {finding.severity}
                            </span>
                            <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-blue-100 text-blue-800">
                              {vulnLabel}
                            </span>
                            <span className="px-2 py-0.5 text-[10px] font-semibold rounded-full bg-gray-100 text-gray-700 uppercase">
                              {finding.confidence}
                            </span>
                          </div>
                          <span className="text-xs text-gray-500">{formatTime(finding.created_at)}</span>
                        </div>
                        <div className="text-sm font-semibold text-gray-950">
                          Parameter: <span className="font-mono text-red-700 bg-red-50 px-1 py-0.5 rounded">{finding.param_name}</span>
                        </div>
                        <div className="text-xs text-gray-650 mt-1 truncate font-mono">
                          {finding.endpoint_url}
                        </div>
                        {finding.evidence_summary && (
                          <div className="mt-2 rounded-md border border-blue-100 bg-blue-50 px-2.5 py-2 text-xs leading-5 text-blue-900">
                            {finding.evidence_summary}
                          </div>
                        )}
                        <div className="mt-3 text-xs font-bold text-gray-700">Exploit Proof of Concept (PoC):</div>
                        <div className="mt-1 font-mono text-[11px] bg-slate-900 text-green-400 p-2.5 rounded border border-slate-950 break-all select-all leading-relaxed max-h-24 overflow-y-auto">
                          {visualPayload}
                        </div>

                        {finding.payload_preview !== visualPayload && (
                          <div className="mt-1.5 text-[10px] text-gray-555 italic">
                            Fuzzer telemetry string: <code className="bg-gray-100 px-1 py-0.5 rounded break-all">{finding.payload_preview}</code>
                          </div>
                        )}

                        {finding.vuln_type === 'xss' && isRaw && (
                          <div className="mt-3 text-xs bg-amber-50 border border-amber-200 text-amber-900 rounded p-2.5 flex flex-col gap-1 leading-normal">
                            <div className="font-semibold flex items-center gap-1 text-amber-950">
                              ⚠️ Taint Flow / Reflection Detected
                            </div>
                            <div>
                              The parameter reflections flow directly into a dangerous DOM sink, but no active script execution has triggered automatically. Try manually injecting <code>{"<svg/onload=alert(1)>"}</code> or <code>{"javascript:alert(1)"}</code> to check for escape.
                            </div>
                          </div>
                        )}
                        
                        {/* Dynamic Tabs Selector */}
                        <div className="flex border-b border-gray-150 mt-4 mb-3">
                          <button
                            type="button"
                            onClick={() => setActiveTabs(prev => ({ ...prev, [finding.id]: 'verify' }))}
                            className={`flex-1 pb-2 text-xs font-semibold border-b-2 transition text-center ${
                              currentTab === 'verify'
                                ? 'border-red-500 text-red-700'
                                : 'border-transparent text-gray-500 hover:text-gray-700'
                            }`}
                          >
                            🚀 Verify Manual
                          </button>
                          <button
                            type="button"
                            onClick={() => setActiveTabs(prev => ({ ...prev, [finding.id]: 'evidence' }))}
                            className={`flex-1 pb-2 text-xs font-semibold border-b-2 transition text-center flex items-center justify-center gap-1.5 ${
                              currentTab === 'evidence'
                                ? 'border-red-500 text-red-700'
                                : 'border-transparent text-gray-500 hover:text-gray-700'
                            }`}
                          >
                            📸 Fuzzer Evidence
                            {(finding.screenshot_path || finding.execution_logs || finding.dom_snapshot) && (
                              <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block animate-ping"></span>
                            )}
                          </button>
                        </div>

                        {currentTab === 'verify' && (
                          <div className="pt-1 flex flex-wrap gap-2">
                            {finding.poc_request?.method === 'GET' && testUrl ? (
                              <>
                                <a
                                  href={testUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 bg-red-600 hover:bg-red-700 text-white font-medium text-xs px-3 py-1.5 rounded-md shadow transition"
                                >
                                  <span>🚀 Launch Exploit URL</span>
                                </a>
                                <button
                                  type="button"
                                  onClick={() => {
                                    navigator.clipboard.writeText(testUrl);
                                    alert('Exploit URL copied to clipboard!');
                                  }}
                                  className="bg-gray-100 hover:bg-gray-250 text-gray-750 font-medium text-xs px-3 py-1.5 rounded-md transition"
                                >
                                  📋 Copy URL
                                </button>
                              </>
                            ) : testCmd ? (
                              <button
                                type="button"
                                onClick={() => {
                                  navigator.clipboard.writeText(testCmd);
                                  alert('Replay curl command copied to clipboard!');
                                }}
                                className="inline-flex items-center gap-1 bg-slate-800 hover:bg-slate-755 text-white font-medium text-xs px-3 py-1.5 rounded-md transition"
                              >
                                <span>📋 Copy replay curl</span>
                              </button>
                            ) : (
                              <div className="text-xs text-gray-500 italic">No automated replay data. Copy payload above.</div>
                            )}
                          </div>
                        )}

                        {currentTab === 'evidence' && (
                          <div className="flex flex-col gap-3 pt-1">
                            {finding.screenshot_path ? (
                              <div>
                                <div className="text-[11px] font-bold text-gray-650 mb-1">Trigger Screenshot:</div>
                                <div className="relative border border-gray-250 rounded overflow-hidden bg-slate-100 group max-h-40">
                                  <img
                                    src={`http://${window.location.hostname}:8000/screenshots/${finding.screenshot_path}`}
                                    alt="Fuzzer execution screenshot"
                                    className="w-full h-auto object-cover max-h-40 cursor-zoom-in hover:scale-102 transition duration-200"
                                    onClick={() => window.open(`http://${window.location.hostname}:8000/screenshots/${finding.screenshot_path}`, '_blank')}
                                  />
                                  <div className="absolute bottom-1 right-1 bg-black/60 text-white text-[9px] px-1.5 py-0.5 rounded backdrop-blur-sm">
                                    Click to view full screenshot
                                  </div>
                                </div>
                              </div>
                            ) : (
                              <div className="text-[11px] text-gray-450 italic">No screenshot captured (headless fuzzer did not capture image).</div>
                            )}

                            {finding.execution_logs && (
                              <details className="mt-1 group">
                                <summary className="text-[11px] font-bold text-red-650 cursor-pointer select-none hover:text-red-800 transition">
                                  ▶ Browser Telemetry Logs
                                </summary>
                                <pre className="mt-1.5 font-mono text-[10px] bg-slate-950 text-slate-300 p-2 rounded max-h-36 overflow-y-auto leading-normal border border-slate-900 break-all whitespace-pre-wrap">
                                  {summarizeExecutionLog(finding.execution_logs)}
                                </pre>
                              </details>
                            )}

                            {finding.dom_snapshot && (
                              <details className="mt-1 group">
                                <summary className="text-[11px] font-bold text-red-650 cursor-pointer select-none hover:text-red-800 transition">
                                  ▶ DOM Injection Context
                                </summary>
                                <pre className="mt-1.5 font-mono text-[10px] bg-slate-950 text-green-400 p-2 rounded max-h-36 overflow-y-auto leading-normal border border-slate-900 break-all whitespace-pre-wrap font-bold">
                                  {finding.dom_snapshot}
                                </pre>
                              </details>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <div className="bg-white rounded-lg shadow">
              <div className="border-b border-gray-100 px-6 py-4">
                <h2 className="text-lg font-semibold text-gray-900">Testing now</h2>
                <p className="text-sm text-gray-500">Payloads currently queued or running in the browser.</p>
              </div>
              <div className="divide-y divide-gray-100">
                {activePayloads.map((check) => (
                  <div key={check.id} className="p-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge value={check.status} />
                        <span className="text-sm font-semibold text-gray-900">{check.param_name}</span>
                        {check.context_type && <span className="text-xs font-medium text-blue-700">{check.context_type}</span>}
                      </div>
                      <span className="text-xs text-gray-500">priority {check.priority}</span>
                    </div>
                    <div className="mt-2 text-xs text-gray-500">{check.endpoint_method} {check.endpoint_url}</div>
                    <div className="mt-2 rounded-md bg-gray-50 p-3 font-mono text-xs text-gray-800">{check.payload_preview}</div>
                  </div>
                ))}
                {activePayloads.length === 0 && (
                  <div className="px-6 py-10 text-center text-sm text-gray-500">
                    No payload is running right now. The engine may be profiling, paused, or finished.
                  </div>
                )}
              </div>
            </div>

            <div className="bg-white rounded-lg shadow">
              <div className="border-b border-gray-100 px-6 py-4">
                <h2 className="text-lg font-semibold text-gray-900">Latest results</h2>
                <p className="text-sm text-gray-500">Clean result view: hit, missed, or error with the reason.</p>
              </div>
              <div className="divide-y divide-gray-100">
                {latestResults.map((execution) => (
                  <div key={execution.id} className="p-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge value={execution.oracle_status} />
                        <span className="text-sm font-semibold text-gray-900">Payload #{execution.test_case_id}</span>
                        <span className="text-sm text-gray-700">{execution.param_name || '-'}</span>
                      </div>
                      <span className="text-xs text-gray-500">
                        {execution.duration_ms ? `${execution.duration_ms}ms` : '-'} · {formatTime(execution.executed_at)}
                      </span>
                    </div>
                    <div className="mt-2 text-xs text-gray-500">{execution.endpoint_url || '-'}</div>
                    <div className={`mt-2 rounded-md p-3 text-sm ${
                      execution.oracle_status === 'error' ? 'bg-red-50 text-red-800' : execution.oracle_status === 'hit' ? 'bg-green-50 text-green-800' : 'bg-gray-50 text-gray-700'
                    }`}>
                      {summarizeExecutionLog(execution.logs) || (execution.oracle_status === 'missed' ? 'No execution callback observed for this payload.' : 'No extra browser details.')}
                    </div>
                  </div>
                ))}
                {latestResults.length === 0 && (
                  <div className="px-6 py-10 text-center text-sm text-gray-500">
                    Results will appear after browser execution starts.
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-100 px-6 py-4">
              <div>
                <h2 className="text-lg font-semibold text-gray-900">Engine decisions</h2>
                <p className="text-sm text-gray-500">Why the engine queued, tested, skipped, or confirmed something. No raw browser noise here.</p>
              </div>
              <div className="flex rounded-md border border-gray-200 bg-gray-50 p-1">
                {(['all', 'errors', 'hits'] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setLogFilter(mode)}
                    className={`px-3 py-1 text-xs font-semibold capitalize rounded ${logFilter === mode ? 'bg-white text-blue-700 shadow-sm' : 'text-gray-600'}`}
                  >
                    {mode}
                  </button>
                ))}
              </div>
            </div>
            <div className="max-h-[560px] overflow-y-auto">
              {visibleLogs.map((event, index) => (
                <LogRow key={`${event.timestamp}-${index}`} event={event} />
              ))}
              {visibleLogs.length === 0 && (
                <div className="px-6 py-10 text-center text-sm text-gray-500">No logs for this filter yet.</div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
            <div className="xl:col-span-2 bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-100">
                <h2 className="text-lg font-semibold text-gray-900">Live checks</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Input</th>
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
              </div>
              <div className="divide-y divide-gray-100 max-h-[520px] overflow-y-auto">
                {monitor.recent_findings.map((finding) => (
                  <div key={finding.id} className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <Badge value={finding.severity} />
                      <span className="text-xs text-gray-500">{formatTime(finding.created_at)}</span>
                    </div>
                    <div className="text-sm font-medium text-gray-900">{finding.param_name}</div>
                    <div className="text-xs text-gray-500 truncate">{finding.endpoint_url}</div>
                    <div className="text-xs font-mono text-gray-700 mt-2 truncate">{finding.payload_preview}</div>
                  </div>
                ))}
                {monitor.recent_findings.length === 0 && (
                  <div className="p-8 text-center text-sm text-gray-500">No findings yet.</div>
                )}
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-100">
              <h2 className="text-lg font-semibold text-gray-900">All browser results</h2>
            </div>
            <div className="divide-y divide-gray-100">
              {monitor.recent_executions.map((execution) => (
                <div key={execution.id} className="p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-3">
                      <Badge value={execution.oracle_status} />
                      <span className="text-sm font-medium text-gray-900">{execution.param_name || '-'}</span>
                      <span className="text-xs text-gray-500">{execution.endpoint_url || '-'}</span>
                    </div>
                    <div className="text-xs text-gray-500">
                      {execution.duration_ms ? `${execution.duration_ms}ms` : '-'} · {formatTime(execution.executed_at)}
                    </div>
                  </div>
                  <div className={`mt-3 rounded-md p-3 text-sm ${
                    execution.oracle_status === 'error' ? 'bg-red-50 text-red-800' : execution.oracle_status === 'hit' ? 'bg-green-50 text-green-800' : 'bg-gray-50 text-gray-700'
                  }`}>
                    {summarizeExecutionLog(execution.logs) || (execution.oracle_status === 'missed' ? 'No execution callback observed for this payload.' : 'No extra browser details.')}
                  </div>
                </div>
              ))}
              {monitor.recent_executions.length === 0 && (
                <div className="px-6 py-10 text-center text-sm text-gray-500">
                  Browser executions will appear after payload checks are queued.
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default ScanPage;
