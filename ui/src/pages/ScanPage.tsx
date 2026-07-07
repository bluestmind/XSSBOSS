/** Single URL-to-monitor XSS flow */
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { experimentsApi } from '@/api/experiments';
import { scansApi } from '@/api/scans';
import { useExperimentStore } from '@/store/experimentState';
import type { ExperimentMonitor, ScanCreate } from '@/types/api';
import { KpiCard } from '@/components/ui/kpi-card';
import EngineLog from '@/components/ui/engine-log';
// @ts-expect-error -- legacy JSX component does not ship TypeScript declarations.
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
  pending: 'bg-carbon-700/50 text-carbon-300 border-carbon-600/60',
  active: 'bg-brand-500/15 text-brand-200 border-brand-500/30',
  done: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  warning: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  queued: 'bg-brand-500/15 text-brand-200 border-brand-500/30',
  running: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  completed: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  failed: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  paused: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  hit: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  missed: 'bg-carbon-700/50 text-carbon-300 border-carbon-600/60',
  error: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  critical: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  high: 'bg-orange-500/15 text-orange-200 border-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  low: 'bg-brand-500/15 text-brand-200 border-brand-500/30',
  debug: 'bg-carbon-700/50 text-carbon-300 border-carbon-600/60',
  info: 'bg-cyan-500/15 text-cyan-200 border-cyan-500/30',
  success: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
};

const initialFormData: ScanCreate = {
  url: '',
  authorized: false,
  crawl: true,
  max_depth: 1,
  max_pages: 15,
  strategy: 'smart_adaptive',
  autonomous_research: true,
  mode: 'full',
};

const Badge = ({ value }: { value: string }) => (
  <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${statusClass[value] || 'bg-carbon-700/50 text-carbon-300 border-carbon-600/60'}`}>
    {value}
  </span>
);

const formatTime = (value: string) => {
  if (!value) return '';
  try {
    const dateStr = value.endsWith('Z') || value.includes('+') ? value : value + 'Z';
    const d = new Date(dateStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
  } catch {
    return value;
  }
};

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

const getExploitUrlFromExecution = (execution: any) => {
  if (!execution.endpoint_url || !execution.payload) return '';
  const testablePayload = execution.payload
    .replace(/__XSS__\(['"`][a-zA-Z0-9_-]+['"`]\)/gi, "alert(document.domain)")
    .replace(/__XSS__%28%27[a-zA-Z0-9_-]+%27%29/gi, "alert%28document.domain%29")
    .replace(/__XSS__%28%22[a-zA-Z0-9_-]+%22%29/gi, "alert%28document.domain%29")
    .replace(/__XSS__%28%60[a-zA-Z0-9_-]+%60%29/gi, "alert%28document.domain%29")
    .replace(/__XSS__%60[a-zA-Z0-9_-]+%60/gi, "alert%60document.domain%60");

  const base = execution.endpoint_url;

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
  } catch {
    const separator = base.includes('?') ? '&' : '?';
    return `${base}${separator}${execution.param_name}=${encodeURIComponent(testablePayload)}`;
  }
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

const SectionHeader =({ title, hint, right }: { title: string; hint?: string; right?: React.ReactNode }) => (
  <div className="panel-header">
    <div>
      <h2 className="font-display text-base font-bold tracking-tight text-carbon-100">{title}</h2>
      {hint && <p className="mt-0.5 text-xs text-carbon-400">{hint}</p>}
    </div>
    {right}
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
      strategy: 'smart_adaptive',
      autonomous_research: true,
    });
  };

  const stats = monitor?.stats;
  const report = monitor?.experiment.limits?.report as
    | { html_url?: string; markdown_url?: string }
    | undefined;
  const research = monitor?.experiment.limits?.research as
    | {
        surface_nodes?: number;
        surface_edges?: number;
        hypotheses?: number;
        top_hypotheses?: Array<{
          id: number;
          type: string;
          title: string;
          priority: number;
          confidence: number;
        }>;
      }
    | undefined;
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

  const runbookAccent: Record<StepState, string> = {
    pending: 'border-carbon-700/70',
    active: 'border-brand-500/40 shadow-glow-brand',
    done: 'border-emerald-500/25',
    warning: 'border-amber-500/30',
  };
  const runbookDot: Record<StepState, string> = {
    pending: 'bg-carbon-500',
    active: 'bg-brand-400 animate-pulse-soft',
    done: 'bg-emerald-400',
    warning: 'bg-amber-400',
  };

  const ring = 2 * Math.PI * 26;
  const progressPct = monitor?.progress_percent ?? 0;

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-4 sm:p-6">
      {/* Hero */}
      <div className="animate-rise">
        <p className="eyebrow flex items-center gap-2">
          <span className="h-px w-6 bg-gradient-to-r from-brand-500 to-transparent" />
          Attack Console
        </p>
        <h1 className="mt-2 font-display text-3xl font-bold tracking-tight text-carbon-100 sm:text-4xl">
          Lock a target. <span className="bg-gradient-to-r from-brand-300 to-fuchsia-400 bg-clip-text text-transparent">Watch it break.</span>
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-carbon-300">
          Feed one authorized URL. Run recon to map the surface, or fire the full flow to move straight into
          typed vulnerability checks with live browser-oracle telemetry.
        </p>
      </div>

      {/* Target-lock command console */}
      <section className="panel scanline animate-rise overflow-hidden">
        <div className="flex items-center justify-between border-b border-carbon-700/60 bg-carbon-850/40 px-5 py-3">
          <div className="flex items-center gap-2.5 font-mono text-[11px] text-carbon-400">
            <span className="flex gap-1.5">
              <span className="h-3 w-3 rounded-full bg-rose-500/70" />
              <span className="h-3 w-3 rounded-full bg-amber-400/70" />
              <span className="h-3 w-3 rounded-full bg-emerald-400/70" />
            </span>
            <span className="ml-1 hidden sm:inline">target-lock — recon / vuln</span>
          </div>
          <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] font-semibold ${
            healthError ? 'border-rose-500/30 bg-rose-500/10 text-rose-200'
              : health ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
              : 'border-carbon-600 bg-carbon-800/50 text-carbon-300'
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${healthError ? 'bg-rose-400' : health ? 'bg-emerald-400 animate-pulse-soft' : 'bg-carbon-400'}`} />
            {healthError ? 'Backend offline' : health ? 'Backend online' : 'Checking backend…'}
          </span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5 p-5 sm:p-6">
          <div>
            <label className="eyebrow">Target URL</label>
            <div className="mt-2 flex items-center gap-2.5 rounded-xl border border-carbon-600 bg-carbon-950/70 px-3.5 transition focus-within:border-brand-500 focus-within:ring-2 focus-within:ring-brand-500/25">
              <span className="select-none font-mono text-lg text-brand-400">⌖</span>
              <input
                type="url"
                required
                value={formData.url}
                onChange={(event) => setFormData({ ...formData, url: event.target.value })}
                className="flex-1 bg-transparent py-3 font-mono text-sm text-carbon-100 placeholder-carbon-500 focus:outline-none"
                placeholder="https://example.com/search?q=test"
              />
              <span className="hidden select-none rounded border border-carbon-700 px-1.5 py-0.5 font-mono text-[10px] text-carbon-500 sm:block">GET</span>
            </div>
          </div>

          <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-carbon-700/70 bg-carbon-850/40 px-4 py-3 transition hover:border-carbon-600">
            <input
              type="checkbox"
              required
              checked={formData.authorized}
              onChange={(event) => setFormData({ ...formData, authorized: event.target.checked })}
              className="mt-0.5 h-4 w-4 rounded border-carbon-500 bg-carbon-900 text-brand-500 focus:ring-brand-500/40"
            />
            <span className="text-sm text-carbon-300">
              <span className="font-semibold text-carbon-100">Authorization confirmed.</span>{' '}
              I own this target or have explicit permission to test it.
            </span>
          </label>

          {errorDetail && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
              {errorDetail}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              name="mode"
              value="recon"
              disabled={mutation.isPending || healthError}
              className="btn btn-ghost"
            >
              {mutation.isPending && pendingMode === 'recon' ? 'Starting recon…' : 'Run recon only'}
            </button>
            <button
              type="submit"
              name="mode"
              value="full"
              disabled={mutation.isPending || healthError}
              className="btn btn-primary"
            >
              {mutation.isPending && pendingMode === 'full' ? 'Deploying…' : '⚡ Run recon + vuln scan'}
            </button>
            {startedExperimentId && (
              <button
                type="button"
                onClick={() => {
                  setStartedExperimentId(null);
                  setFormData(initialFormData);
                  mutation.reset();
                }}
                className="btn btn-ghost ml-auto"
              >
                New URL
              </button>
            )}
          </div>
        </form>
      </section>

      {mutation.data && !monitor && !monitorError && (
        <div className="rounded-2xl border border-brand-500/30 bg-brand-500/10 p-4">
          <p className="text-sm font-medium text-brand-100">{mutation.data.message}</p>
          <p className="mt-1 text-sm text-brand-200/80">Monitor is opening for experiment #{mutation.data.experiment_id}.</p>
        </div>
      )}

      {monitorError && (
        <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
          The scan started, but the monitor is not reachable yet. The page will recover when the API responds.
        </div>
      )}

      {/* Previous runs */}
      <section className="panel">
        <SectionHeader
          title="Previous runs"
          hint="Click any run to load its monitor on this same page."
          right={startedExperimentId ? (
            <div className="rounded-lg border border-carbon-700/70 bg-carbon-800/50 px-3 py-1.5 font-mono text-[11px] text-carbon-300">
              viewing #{startedExperimentId}
            </div>
          ) : undefined}
        />
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
              className={`rounded-xl border p-4 text-left transition ${
                startedExperimentId === run.id
                  ? 'border-brand-500/50 bg-brand-500/10 shadow-glow-brand'
                  : 'border-carbon-700/70 bg-carbon-850/40 hover:border-carbon-600 hover:bg-carbon-800/60'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-carbon-100">
                    <span className="font-mono text-brand-300">#{run.id}</span> {run.name}
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-carbon-400">{run.strategy}</div>
                </div>
                <div className="flex flex-shrink-0 items-center gap-2">
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
                    className="rounded-md border border-rose-500/30 bg-rose-500/5 px-2 py-1 text-[11px] font-semibold text-rose-300 hover:bg-rose-500/15"
                  >
                    Remove
                  </span>
                </div>
              </div>
              <div className="mt-3 font-mono text-[11px] text-carbon-500">
                started {run.started_at ? new Date(run.started_at).toLocaleString() : 'not yet'}
              </div>
            </button>
          ))}
          {sortedPreviousRuns.length === 0 && (
            <div className="rounded-xl border border-dashed border-carbon-700 p-6 text-sm text-carbon-400">
              No previous runs yet.
            </div>
          )}
        </div>
      </section>

      {/* Workflow runbook */}
      <section className="panel">
        <SectionHeader
          title="Workflow runbook"
          hint="Recon maps the attack surface first, then vuln engines test the discovered inputs."
        />
        <div className="grid grid-cols-1 gap-3 p-4 md:grid-cols-2 xl:grid-cols-3">
          {runbook.map((step) => (
            <div key={step.id} className={`rounded-xl border bg-carbon-850/40 p-4 transition ${runbookAccent[step.state]}`}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-mono text-[10px] font-semibold uppercase tracking-wide text-brand-300">{step.phase}</div>
                  <div className="mt-1 text-sm font-semibold text-carbon-100">{step.title}</div>
                </div>
                <span className={`mt-1 h-2.5 w-2.5 flex-shrink-0 rounded-full ${runbookDot[step.state]}`} />
              </div>
              <p className="mt-2 text-xs leading-5 text-carbon-400">{step.detail}</p>
              <div className="mt-3 flex items-center justify-between">
                <Badge value={step.state} />
                {typeof step.count === 'number' && (
                  <span className="font-mono text-[11px] text-carbon-500">obs: {step.count}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      {monitor && stats && (
        <>
          {/* Live engine HUD */}
          <section className="panel scanline p-6">
            <div className="mb-5 flex flex-wrap items-start justify-between gap-5">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-3">
                  <h2 className="font-display text-xl font-bold tracking-tight text-carbon-100">{formatStage(monitor.stage)}</h2>
                  <Badge value={monitor.experiment.status} />
                </div>
                <p className="mt-1.5 text-sm text-carbon-300">{monitor.stage_detail}</p>
                <div className="mt-3 flex items-start gap-2 rounded-xl border border-brand-500/25 bg-brand-500/10 px-3.5 py-2.5">
                  <span className="mt-0.5 font-mono text-xs font-bold uppercase tracking-wide text-brand-300">engine</span>
                  <p className="text-sm font-medium text-brand-100">{getEngineDecision(monitor)}</p>
                </div>
                <p className="mt-2 truncate font-mono text-[11px] text-carbon-500">{monitor.target.base_url}</p>
              </div>

              {/* Radial progress */}
              <div className="relative flex h-20 w-20 flex-shrink-0 items-center justify-center">
                <svg viewBox="0 0 64 64" className="h-20 w-20 -rotate-90">
                  <circle cx="32" cy="32" r="26" fill="none" stroke="rgba(42,56,84,0.7)" strokeWidth="6" />
                  <circle
                    cx="32" cy="32" r="26" fill="none" stroke="url(#ringGrad)" strokeWidth="6" strokeLinecap="round"
                    strokeDasharray={ring} strokeDashoffset={ring - (ring * progressPct) / 100}
                    className="transition-all duration-500"
                  />
                  <defs>
                    <linearGradient id="ringGrad" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0" stopColor="#7B68FF" />
                      <stop offset="1" stopColor="#F0499E" />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="font-display text-lg font-bold tabnum text-carbon-100">{progressPct}%</span>
                </div>
              </div>
            </div>

            <div className="mb-5 flex flex-wrap items-center gap-3">
              <button
                type="button"
                disabled={monitor.experiment.status !== 'running' || pauseMutation.isPending}
                onClick={() => pauseMutation.mutate(monitor.experiment.id)}
                className="btn btn-ghost px-3 py-2"
              >
                {pauseMutation.isPending ? 'Pausing…' : '❚❚ Pause'}
              </button>
              <button
                type="button"
                disabled={monitor.experiment.status !== 'paused' || resumeMutation.isPending}
                onClick={() => resumeMutation.mutate(monitor.experiment.id)}
                className="btn btn-primary px-3 py-2"
              >
                {resumeMutation.isPending ? 'Resuming…' : '▶ Resume'}
              </button>
              {report?.html_url && (
                <a href={report.html_url} target="_blank" rel="noopener noreferrer" className="btn btn-success px-3 py-2">
                  Open final report
                </a>
              )}
              {report?.markdown_url && (
                <a href={report.markdown_url} target="_blank" rel="noopener noreferrer" className="btn btn-ghost px-3 py-2">
                  Markdown result
                </a>
              )}
            </div>

            {monitor.pipeline_stages?.length > 0 && (
              <div className="mb-5 grid grid-cols-2 gap-2 md:grid-cols-5">
                {monitor.pipeline_stages.map((pipelineStage) => (
                  <div key={pipelineStage.name} className="rounded-xl border border-carbon-700/70 bg-carbon-850/40 p-3">
                    <div className="font-mono text-[10px] font-semibold uppercase tracking-wide text-carbon-400">
                      {pipelineStage.name.replace('_', ' ')}
                    </div>
                    <div className="mt-2"><Badge value={pipelineStage.status} /></div>
                    {pipelineStage.attempt_count > 1 && (
                      <div className="mt-1 font-mono text-[10px] text-amber-300">attempt {pipelineStage.attempt_count}</div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {research && Number(research.hypotheses || 0) > 0 && (
              <div className="mb-5 rounded-xl border border-fuchsia-500/25 bg-fuchsia-500/5 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="font-mono text-[10px] font-semibold uppercase tracking-widest text-fuchsia-300">
                      Autonomous research brain
                    </div>
                    <div className="mt-1 text-sm text-carbon-200">
                      {research.hypotheses} ranked hypotheses across {research.surface_nodes || 0} graph nodes and {research.surface_edges || 0} evidence edges
                    </div>
                  </div>
                  <a
                    href={`/api/v1/research/experiments/${monitor.experiment.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-ghost px-3 py-1.5 text-xs"
                  >
                    Open research state
                  </a>
                </div>
                <div className="mt-3 grid gap-2 md:grid-cols-2">
                  {(research.top_hypotheses || []).slice(0, 4).map((hypothesis) => (
                    <div key={hypothesis.id} className="rounded-lg border border-carbon-700/70 bg-carbon-900/60 px-3 py-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[10px] uppercase text-fuchsia-300">{hypothesis.type.replace(/_/g, ' ')}</span>
                        <span className="font-mono text-[10px] text-carbon-400">{Math.round(hypothesis.confidence * 100)}% confidence</span>
                      </div>
                      <div className="mt-1 text-xs font-medium text-carbon-200">{hypothesis.title}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {monitor.throttle_status && (
              <div className="mb-5 rounded-xl border border-carbon-700/70 bg-carbon-850/40 p-4">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                  <h3 className="flex items-center gap-1.5 text-sm font-semibold text-carbon-200">⚡ Rate limiter</h3>
                  <div className="flex items-center gap-2">
                    {monitor.throttle_status.current_delay_ms > monitor.throttle_status.base_delay_ms && (
                      <span className="inline-flex items-center rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-200">
                        Backing off
                      </span>
                    )}
                    {monitor.throttle_status.consecutive_errors > 0 && (
                      <span className="inline-flex items-center rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[11px] font-semibold text-rose-200">
                        {monitor.throttle_status.consecutive_errors} errors
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => {
                        fetch(`/api/v1/experiments/${monitor.experiment.id}/throttle/reset`, { method: 'POST' })
                          .then(() => queryClient.invalidateQueries({ queryKey: ['experiments', startedExperimentId, 'monitor'] }));
                      }}
                      className="rounded-md border border-carbon-600 bg-carbon-800/60 px-2 py-0.5 text-[11px] font-medium text-carbon-300 hover:bg-carbon-750"
                    >
                      Reset
                    </button>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div>
                    <div className="text-[11px] text-carbon-400">Delay / request</div>
                    <div className={`font-mono text-sm font-bold ${monitor.throttle_status.current_delay_ms > monitor.throttle_status.base_delay_ms ? 'text-amber-300' : 'text-carbon-100'}`}>
                      {(monitor.throttle_status.current_delay_ms / 1000).toFixed(1)}s
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-carbon-400">Base delay</div>
                    <div className="font-mono text-sm font-bold text-carbon-100">{(monitor.throttle_status.base_delay_ms / 1000).toFixed(1)}s</div>
                  </div>
                  <div>
                    <div className="text-[11px] text-carbon-400">Req / minute</div>
                    <div className={`font-mono text-sm font-bold ${monitor.throttle_status.requests_last_minute >= monitor.throttle_status.max_requests_per_minute ? 'text-rose-300' : 'text-carbon-100'}`}>
                      {monitor.throttle_status.requests_last_minute} / {monitor.throttle_status.max_requests_per_minute}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-carbon-400">Adaptive</div>
                    <div className="font-mono text-sm font-bold text-carbon-100">{monitor.throttle_status.adaptive_throttle ? 'On' : 'Off'}</div>
                  </div>
                </div>
              </div>
            )}

            <div className="h-2 w-full overflow-hidden rounded-full bg-carbon-800">
              <div
                className="h-2 rounded-full bg-gradient-to-r from-brand-500 to-fuchsia-500 transition-all duration-500"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </section>

          {/* Stat row — 21st.dev KPI cards */}
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
            <KpiCard size="sm" tone="primary" label="Active" value={activeCount} />
            <KpiCard size="sm" tone="warning" label="Running" value={stats.running} />
            <KpiCard size="sm" tone="default" label="Queued" value={stats.queued} />
            <KpiCard size="sm" tone="success" label="Completed" value={stats.completed} />
            <KpiCard size="sm" tone="success" label="Hits" value={hitCount} />
            <KpiCard size="sm" tone="danger" label="Findings" value={monitor.recent_findings.length} />
          </div>

          <EndpointsMap targetId={monitor.target.id} monitor={monitor} />

          {/* Confirmed Findings Alerts */}
          {monitor.recent_findings.length > 0 && (
            <div className="relative overflow-hidden rounded-2xl border border-rose-500/40 bg-rose-500/[0.06] p-6 shadow-glow-rose">
              <div className="mb-4 flex items-center justify-between border-b border-rose-500/30 pb-3">
                <h2 className="flex items-center gap-2 font-display text-lg font-bold text-rose-200 text-glow-rose">
                  🚨 Confirmed vulnerabilities ({monitor.recent_findings.length})
                </h2>
                <span className="animate-pulse-soft rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-wide text-rose-200">
                  Action required
                </span>
              </div>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
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
                    <div key={finding.id} className="flex flex-col justify-between rounded-xl border border-rose-500/25 bg-carbon-850/60 p-4 transition duration-150 hover:border-rose-500/50">
                      <div>
                        <div className="mb-2 flex items-center justify-between">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="rounded-full border border-rose-500/30 bg-rose-500/15 px-2 py-0.5 text-[11px] font-bold uppercase text-rose-200">
                              {finding.severity}
                            </span>
                            <span className="rounded-full border border-brand-500/30 bg-brand-500/15 px-2 py-0.5 text-[11px] font-bold text-brand-200">
                              {vulnLabel}
                            </span>
                            <span className="rounded-full border border-carbon-600 bg-carbon-800/60 px-2 py-0.5 text-[10px] font-semibold uppercase text-carbon-300">
                              {finding.confidence}
                            </span>
                          </div>
                          <span className="font-mono text-[11px] text-carbon-500">{formatTime(finding.created_at)}</span>
                        </div>
                        <div className="text-sm font-semibold text-carbon-100">
                          Parameter: <span className="rounded bg-rose-500/15 px-1 py-0.5 font-mono text-rose-200">{finding.param_name}</span>
                        </div>
                        <div className="mt-1 truncate font-mono text-[11px] text-carbon-400">
                          {finding.endpoint_url}
                        </div>
                        {finding.evidence_summary && (
                          <div className="mt-2 rounded-lg border border-brand-500/20 bg-brand-500/10 px-2.5 py-2 text-xs leading-5 text-brand-100">
                            {finding.evidence_summary}
                          </div>
                        )}
                        <div className="mt-3 text-[11px] font-bold uppercase tracking-wide text-carbon-400">Exploit proof of concept</div>
                        <div className="terminal mt-1 max-h-24 select-all overflow-y-auto break-all p-2.5 text-[11px] leading-relaxed text-emerald-300">
                          {visualPayload}
                        </div>

                        {finding.payload_preview !== visualPayload && (
                          <div className="mt-1.5 text-[10px] italic text-carbon-500">
                            Fuzzer telemetry string: <code className="break-all rounded bg-carbon-800 px-1 py-0.5 text-carbon-300">{finding.payload_preview}</code>
                          </div>
                        )}

                        {finding.vuln_type === 'xss' && isRaw && (
                          <div className="mt-3 flex flex-col gap-1 rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs leading-normal text-amber-100">
                            <div className="flex items-center gap-1 font-semibold text-amber-200">
                              ⚠️ Taint flow / reflection detected
                            </div>
                            <div>
                              The parameter reflections flow directly into a dangerous DOM sink, but no active script execution has triggered automatically. Try manually injecting <code className="rounded bg-carbon-800 px-1 text-amber-200">{"<svg/onload=alert(1)>"}</code> or <code className="rounded bg-carbon-800 px-1 text-amber-200">{"javascript:alert(1)"}</code> to check for escape.
                            </div>
                          </div>
                        )}

                        {/* Dynamic Tabs Selector */}
                        <div className="mb-3 mt-4 flex border-b border-carbon-700">
                          <button
                            type="button"
                            onClick={() => setActiveTabs(prev => ({ ...prev, [finding.id]: 'verify' }))}
                            className={`flex-1 border-b-2 pb-2 text-center text-xs font-semibold transition ${
                              currentTab === 'verify'
                                ? 'border-rose-500 text-rose-300'
                                : 'border-transparent text-carbon-400 hover:text-carbon-200'
                            }`}
                          >
                            🚀 Verify manual
                          </button>
                          <button
                            type="button"
                            onClick={() => setActiveTabs(prev => ({ ...prev, [finding.id]: 'evidence' }))}
                            className={`flex flex-1 items-center justify-center gap-1.5 border-b-2 pb-2 text-center text-xs font-semibold transition ${
                              currentTab === 'evidence'
                                ? 'border-rose-500 text-rose-300'
                                : 'border-transparent text-carbon-400 hover:text-carbon-200'
                            }`}
                          >
                            📸 Fuzzer evidence
                            {(finding.screenshot_path || finding.execution_logs || finding.dom_snapshot) && (
                              <span className="inline-block h-1.5 w-1.5 animate-ping rounded-full bg-rose-500"></span>
                            )}
                          </button>
                        </div>

                        {currentTab === 'verify' && (
                          <div className="flex flex-wrap gap-2 pt-1">
                            {finding.poc_request?.method === 'GET' && testUrl ? (
                              <>
                                <a
                                  href={testUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 rounded-md bg-gradient-to-r from-rose-600 to-rose-500 px-3 py-1.5 text-xs font-semibold text-white shadow-glow-rose transition hover:brightness-110"
                                >
                                  <span>🚀 Launch exploit URL</span>
                                </a>
                                <button
                                  type="button"
                                  onClick={() => {
                                    navigator.clipboard.writeText(testUrl);
                                    alert('Exploit URL copied to clipboard!');
                                  }}
                                  className="rounded-md border border-carbon-600 bg-carbon-800/60 px-3 py-1.5 text-xs font-medium text-carbon-200 transition hover:bg-carbon-750"
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
                                className="inline-flex items-center gap-1 rounded-md border border-carbon-600 bg-carbon-800/60 px-3 py-1.5 text-xs font-medium text-carbon-200 transition hover:bg-carbon-750"
                              >
                                <span>📋 Copy replay curl</span>
                              </button>
                            ) : (
                              <div className="text-xs italic text-carbon-400">No automated replay data. Copy payload above.</div>
                            )}
                          </div>
                        )}

                        {currentTab === 'evidence' && (
                          <div className="flex flex-col gap-3 pt-1">
                            {finding.screenshot_path ? (
                              <div>
                                <div className="mb-1 text-[11px] font-bold text-carbon-300">Trigger screenshot</div>
                                <div className="group relative max-h-40 overflow-hidden rounded-lg border border-carbon-700 bg-carbon-950">
                                  <img
                                    src={`/api/v1/results/findings/${finding.id}/screenshot`}
                                    alt="Fuzzer execution screenshot"
                                    className="h-auto max-h-40 w-full cursor-zoom-in object-cover transition duration-200 hover:scale-[1.02]"
                                    onClick={() => window.open(`/api/v1/results/findings/${finding.id}/screenshot`, '_blank', 'noopener,noreferrer')}
                                  />
                                  <div className="absolute bottom-1 right-1 rounded bg-black/60 px-1.5 py-0.5 text-[9px] text-white backdrop-blur-sm">
                                    Click to view full screenshot
                                  </div>
                                </div>
                              </div>
                            ) : (
                              <div className="text-[11px] italic text-carbon-500">No screenshot captured (headless fuzzer did not capture image).</div>
                            )}

                            {finding.execution_logs && (
                              <details className="group mt-1">
                                <summary className="cursor-pointer select-none text-[11px] font-bold text-rose-300 transition hover:text-rose-200">
                                  ▶ Browser telemetry logs
                                </summary>
                                <pre className="mt-1.5 max-h-36 overflow-y-auto whitespace-pre-wrap break-all rounded-lg border border-carbon-700 bg-carbon-950 p-2 font-mono text-[10px] leading-normal text-carbon-300">
                                  {summarizeExecutionLog(finding.execution_logs)}
                                </pre>
                              </details>
                            )}

                            {finding.dom_snapshot && (
                              <details className="group mt-1">
                                <summary className="cursor-pointer select-none text-[11px] font-bold text-rose-300 transition hover:text-rose-200">
                                  ▶ DOM injection context
                                </summary>
                                <pre className="mt-1.5 max-h-36 overflow-y-auto whitespace-pre-wrap break-all rounded-lg border border-carbon-700 bg-carbon-950 p-2 font-mono text-[10px] font-bold leading-normal text-emerald-300">
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
            <section className="panel">
              <SectionHeader title="Testing now" hint="Payloads currently queued or running in the browser." />
              <div className="divide-y divide-carbon-700/40">
                {activePayloads.map((check) => (
                  <div key={check.id} className="p-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge value={check.status} />
                        <span className="text-sm font-semibold text-carbon-100">{check.param_name}</span>
                        {check.context_type && <span className="font-mono text-[11px] font-medium text-brand-300">{check.context_type}</span>}
                      </div>
                      <span className="font-mono text-[11px] text-carbon-500">priority {check.priority}</span>
                    </div>
                    <div className="mt-2 truncate font-mono text-[11px] text-carbon-400">{check.endpoint_method} {check.endpoint_url}</div>
                    <div className="terminal mt-2 p-3 text-xs text-carbon-200">{check.payload_preview}</div>
                  </div>
                ))}
                {activePayloads.length === 0 && (
                  <div className="px-6 py-10 text-center text-sm text-carbon-400">
                    No payload is running right now. The engine may be profiling, paused, or finished.
                  </div>
                )}
              </div>
            </section>

            <section className="panel">
              <SectionHeader title="Latest results" hint="Clean result view: hit, missed, or error with the reason." />
              <div className="divide-y divide-carbon-700/40">
                {latestResults.map((execution) => (
                  <div key={execution.id} className="p-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge value={execution.oracle_status} />
                        <span className="text-sm font-semibold text-carbon-100">Payload #{execution.test_case_id}</span>
                        <span className="text-sm text-carbon-300">{execution.param_name || '-'}</span>
                      </div>
                      <span className="font-mono text-[11px] text-carbon-500">
                        {execution.duration_ms ? `${execution.duration_ms}ms` : '-'} · {formatTime(execution.executed_at)}
                      </span>
                    </div>
                    <div className="mt-2 truncate font-mono text-[11px] text-carbon-400">{execution.endpoint_url || '-'}</div>
                    <div className={`mt-2 rounded-lg border p-3 text-sm ${
                      execution.oracle_status === 'error' ? 'border-rose-500/25 bg-rose-500/10 text-rose-200' : execution.oracle_status === 'hit' ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200' : 'border-carbon-700/60 bg-carbon-850/50 text-carbon-300'
                    }`}>
                      {summarizeExecutionLog(execution.logs) || (execution.oracle_status === 'missed' ? 'No execution callback observed for this payload.' : 'No extra browser details.')}
                    </div>
                    {execution.oracle_status === 'hit' && execution.payload && (
                      <div className="mt-3 flex items-center gap-2">
                        <a
                          href={getExploitUrlFromExecution(execution)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 rounded-md bg-gradient-to-r from-rose-600 to-rose-500 px-3 py-1.5 text-xs font-semibold text-white shadow-glow-rose transition hover:brightness-110"
                        >
                          💥 Trigger XSS in target
                        </a>
                        <button
                          type="button"
                          onClick={() => {
                            const link = getExploitUrlFromExecution(execution);
                            navigator.clipboard.writeText(link);
                            alert('Exploit URL copied to clipboard!');
                          }}
                          className="rounded-md border border-carbon-600 bg-carbon-800/60 px-3 py-1.5 text-xs font-medium text-carbon-200 transition hover:bg-carbon-750"
                        >
                          📋 Copy link
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                {latestResults.length === 0 && (
                  <div className="px-6 py-10 text-center text-sm text-carbon-400">
                    Results will appear after browser execution starts.
                  </div>
                )}
              </div>
            </section>
          </div>

          <section className="panel">
            <SectionHeader
              title="Engine decisions"
              hint="Why the engine queued, tested, skipped, or confirmed something. No raw browser noise here."
              right={(
                <div className="flex rounded-lg border border-carbon-700/70 bg-carbon-850/60 p-1">
                  {(['all', 'errors', 'hits'] as const).map((mode) => (
                    <button
                      key={mode}
                      type="button"
                      onClick={() => setLogFilter(mode)}
                      className={`rounded px-3 py-1 text-xs font-semibold capitalize transition ${logFilter === mode ? 'bg-brand-500/20 text-brand-100' : 'text-carbon-400 hover:text-carbon-200'}`}
                    >
                      {mode}
                    </button>
                  ))}
                </div>
              )}
            />
            <div className="max-h-[560px] overflow-y-auto p-4">
              <EngineLog events={visibleLogs} />
            </div>
          </section>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
            <section className="panel xl:col-span-2">
              <SectionHeader title="Live checks" />
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-carbon-700/50">
                  <thead className="bg-carbon-850/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wide text-carbon-400">Status</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wide text-carbon-400">Input</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wide text-carbon-400">Payload</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wide text-carbon-400">Updated</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-carbon-700/40">
                    {monitor.recent_checks.map((check) => (
                      <tr key={check.id} className="transition hover:bg-carbon-800/40">
                        <td className="whitespace-nowrap px-4 py-3"><Badge value={check.status} /></td>
                        <td className="px-4 py-3 text-sm">
                          <div className="font-medium text-carbon-100">{check.param_name} <span className="text-carbon-400">({check.param_location})</span></div>
                          <div className="max-w-xs truncate font-mono text-[11px] text-carbon-400">{check.endpoint_method} {check.endpoint_url}</div>
                          {check.context_type && <div className="mt-1 font-mono text-[11px] text-brand-300">{check.context_type}</div>}
                        </td>
                        <td className="max-w-sm truncate px-4 py-3 font-mono text-[11px] text-carbon-300">{check.payload_preview}</td>
                        <td className="whitespace-nowrap px-4 py-3 font-mono text-[11px] text-carbon-500">{formatTime(check.updated_at)}</td>
                      </tr>
                    ))}
                    {monitor.recent_checks.length === 0 && (
                      <tr>
                        <td colSpan={4} className="px-4 py-10 text-center text-sm text-carbon-400">
                          Waiting for discovered parameters and generated payload checks.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="panel">
              <SectionHeader title="Findings" />
              <div className="max-h-[520px] divide-y divide-carbon-700/40 overflow-y-auto">
                {monitor.recent_findings.map((finding) => (
                  <div key={finding.id} className="p-4">
                    <div className="mb-2 flex items-center justify-between">
                      <Badge value={finding.severity} />
                      <span className="font-mono text-[11px] text-carbon-500">{formatTime(finding.created_at)}</span>
                    </div>
                    <div className="text-sm font-medium text-carbon-100">{finding.param_name}</div>
                    <div className="truncate font-mono text-[11px] text-carbon-400">{finding.endpoint_url}</div>
                    <div className="mt-2 truncate font-mono text-[11px] text-carbon-300">{finding.payload_preview}</div>
                  </div>
                ))}
                {monitor.recent_findings.length === 0 && (
                  <div className="p-8 text-center text-sm text-carbon-400">No findings yet.</div>
                )}
              </div>
            </section>
          </div>

          <section className="panel">
            <SectionHeader title="All browser results" />
            <div className="divide-y divide-carbon-700/40">
              {monitor.recent_executions.map((execution) => (
                <div key={execution.id} className="p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-3">
                      <Badge value={execution.oracle_status} />
                      <span className="text-sm font-medium text-carbon-100">{execution.param_name || '-'}</span>
                      <span className="truncate font-mono text-[11px] text-carbon-400">{execution.endpoint_url || '-'}</span>
                    </div>
                    <div className="font-mono text-[11px] text-carbon-500">
                      {execution.duration_ms ? `${execution.duration_ms}ms` : '-'} · {formatTime(execution.executed_at)}
                    </div>
                  </div>
                  <div className={`mt-3 rounded-lg border p-3 text-sm ${
                    execution.oracle_status === 'error' ? 'border-rose-500/25 bg-rose-500/10 text-rose-200' : execution.oracle_status === 'hit' ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200' : 'border-carbon-700/60 bg-carbon-850/50 text-carbon-300'
                  }`}>
                    {summarizeExecutionLog(execution.logs) || (execution.oracle_status === 'missed' ? 'No execution callback observed for this payload.' : 'No extra browser details.')}
                  </div>
                </div>
              ))}
              {monitor.recent_executions.length === 0 && (
                <div className="px-6 py-10 text-center text-sm text-carbon-400">
                  Browser executions will appear after payload checks are queued.
                </div>
              )}
            </div>
          </section>
        </>
      )}
    </div>
  );
};

export default ScanPage;
