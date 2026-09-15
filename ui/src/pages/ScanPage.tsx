/** Single URL-to-monitor XSS flow */
import { useCallback, useMemo, useState, useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Crosshair,
  ShieldCheck,
  Play,
  Pause,
  RotateCcw,
  Trash2,
  Search,
  ExternalLink,
  Bug,
  Layers,
  Zap,
  Plus,
  X,
  ChevronDown,
  ChevronRight,
  Trophy,
  CheckCircle2,
  Activity,
  AlertTriangle,
  Clock3,
  LoaderCircle,
  Wrench,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { experimentsApi } from '@/api/experiments';
import { programsApi } from '@/api/programs';
import { scansApi } from '@/api/scans';
import { useExperimentStore } from '@/store/experimentState';
import type { ExperimentMonitor, ScanCreate } from '@/types/api';
import { KpiCard } from '@/components/ui/kpi-card';
import EngineLog from '@/components/ui/engine-log';
// @ts-expect-error -- legacy JSX component does not ship TypeScript declarations.
import EndpointsMap from '@/components/EndpointsMap';
import { LiveBrowserPreview } from '@/components/LiveBrowserPreview';
import RiverFlowMonitor from '@/components/RiverFlowMonitor';

const statusClass: Record<string, string> = {
  pending: 'bg-carbon-700/50 text-carbon-300 border-carbon-600/60',
  active: 'bg-brand-500/15 text-brand-200 border-brand-500/30',
  done: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  warning: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  inconclusive: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
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
  max_depth: 2,
  max_pages: 100,
  strategy: 'smart_adaptive',
  autonomous_research: true,
  mode: 'full',
};

const initialAuthForm = {
  identity: 'user',
  cookie: '',
  authorization: '',
  healthCheckUrl: '/account',
  loginUrl: '',
  username: '',
  password: '',
  usernameSelector: '',
  passwordSelector: '',
  submitSelector: '',
  successSelector: '',
};

const parseCookieHeader = (value: string) => Object.fromEntries(
  value.split(';')
    .map((part) => part.trim())
    .filter((part) => part.includes('='))
    .map((part) => {
      const separator = part.indexOf('=');
      return [part.slice(0, separator).trim(), part.slice(separator + 1).trim()];
    })
);

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

const formatDuration = (value?: number) => {
  const seconds = Math.max(0, Math.floor(value || 0));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  if (hours) return `${hours}h ${minutes}m ${remainder}s`;
  if (minutes) return `${minutes}m ${remainder}s`;
  return `${remainder}s`;
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
    inconclusive: 'Inconclusive',
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
    if (callbacks.length) return `Oracle callback observed: ${String(callbacks[0])}`;
    if (errors.length) {
      const firstErr = String(errors[0]);
      if (firstErr.includes('Failed to load resource') || firstErr.includes('net::ERR_')) {
        return `Target page console: Subresource/tracker blocked or failed to load (${firstErr.split(' - ')[1] || firstErr})`;
      }
      return `Target page console: ${firstErr}`;
    }
    if (consoleMessages.length) return `Target page console: ${String(consoleMessages[0])}`;
    return 'Browser rendered successfully without oracle callback.';
  } catch {
    return value;
  }
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
  if (monitor.stage === 'inconclusive') return monitor.stage_detail;
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
  const [authOpen, setAuthOpen] = useState(false);
  const [authForm, setAuthForm] = useState(initialAuthForm);
  const [authError, setAuthError] = useState('');
  const [resolutionAuthJson, setResolutionAuthJson] = useState('');
  const [historyFilter, setHistoryFilter] = useState<'all' | 'running' | 'paused' | 'hits' | 'completed'>('all');
  const [historySearch, setHistorySearch] = useState('');
  const [showUrlLauncher, setShowUrlLauncher] = useState(false);
  const [expandedPrograms, setExpandedPrograms] = useState<Record<string, boolean>>({});
  const [expandedExecutions, setExpandedExecutions] = useState<Record<number, boolean>>({});
  const [clockNow, setClockNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setClockNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const toggleProgram = (key: string) => {
    setExpandedPrograms((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const toggleExecution = (id: number) => {
    setExpandedExecutions((prev) => ({ ...prev, [id]: !prev[id] }));
  };

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

  // Auto-select latest active/running run on initial load
  useEffect(() => {
    if (!startedExperimentId && previousRuns.length > 0) {
      const activeRun = previousRuns.find((r) => r.status === 'running' || r.status === 'paused');
      const targetRun = activeRun || previousRuns[0];
      if (targetRun) {
        setStartedExperimentId(targetRun.id);
        setActiveExperiment(targetRun.id);
      }
    }
  }, [previousRuns, startedExperimentId, setActiveExperiment]);

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

  const bulkDeleteCompletedMutation = useMutation({
    mutationFn: async () => {
      const toDelete = previousRuns.filter((r) => r.status === 'completed' || r.status === 'failed');
      for (const run of toDelete) {
        try {
          await experimentsApi.delete(run.id);
        } catch {
          // Continue deleting the remaining completed runs.
        }
      }
      return toDelete.map((r) => r.id);
    },
    onSuccess: (deletedIds) => {
      if (startedExperimentId && deletedIds.includes(startedExperimentId)) {
        setStartedExperimentId(null);
      }
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
    },
  });

  const huntProgramMutation = useMutation({
    mutationFn: (targetId: number) => programsApi.startHunt(targetId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      queryClient.invalidateQueries({ queryKey: ['programs'] });
    },
  });

  const resolveInterventionMutation = useMutation({
    mutationFn: ({ experimentId, interventionId }: { experimentId: number; interventionId: string }) => {
      let authInfo: Record<string, any> | undefined;
      if (resolutionAuthJson.trim()) authInfo = JSON.parse(resolutionAuthJson);
      return scansApi.resolveIntervention(experimentId, interventionId, {
        resolution: 'Updated authorized session supplied by operator',
        auth_info: authInfo,
      });
    },
    onSuccess: () => {
      setResolutionAuthJson('');
      setAuthError('');
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      queryClient.invalidateQueries({ queryKey: ['experiments', startedExperimentId, 'monitor'] });
    },
    onError: (error) => setAuthError(getErrorDetail(error)),
  });

  const buildAuthInfo = () => {
    if (!authOpen) return undefined;
    const identity = authForm.identity.trim() || 'user';
    const loginConfigured = Boolean(authForm.loginUrl.trim() || authForm.username || authForm.password);
    return {
      default_identity: identity,
      identities: {
        [identity]: {
          headers: authForm.authorization.trim() ? { Authorization: authForm.authorization.trim() } : {},
          cookies: parseCookieHeader(authForm.cookie),
          health_check_url: authForm.healthCheckUrl.trim() || undefined,
          login: loginConfigured ? {
            url: authForm.loginUrl.trim(),
            username: authForm.username,
            password: authForm.password,
            username_selector: authForm.usernameSelector.trim() || undefined,
            password_selector: authForm.passwordSelector.trim() || undefined,
            submit_selector: authForm.submitSelector.trim() || undefined,
            success_selector: authForm.successSelector.trim() || undefined,
          } : {},
        },
      },
    };
  };

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    let authInfo: Record<string, any> | undefined;
    try {
      authInfo = buildAuthInfo();
      setAuthError('');
    } catch {
      setAuthError('Advanced authentication JSON is invalid. Fix it before starting the campaign.');
      return;
    }
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    const mode = submitter?.value === 'recon' ? 'recon' : 'full';
    setPendingMode(mode);
    mutation.mutate({
      ...formData,
      mode,
      crawl: true,
      strategy: 'smart_adaptive',
      autonomous_research: true,
      auth_info: authInfo,
      auth_identity: authInfo
        ? String(authInfo.default_identity || authForm.identity.trim() || 'user')
        : undefined,
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

  interface ProgramHuntGroup {
    programKey: string;
    targetId?: number;
    programName: string;
    programHandle: string;
    runs: typeof previousRuns;
    activeCount: number;
    pausedCount: number;
    completedCount: number;
    failedCount: number;
    findingsCount: number;
    latestStartedAt?: string;
  }

  const getProgramInfo = useCallback((run: (typeof previousRuns)[0]) => {
    if (run.target_name) {
      return {
        name: run.target_name,
        handle: run.target_handle || run.target_name.toLowerCase().replace(/\s+/g, '_'),
      };
    }
    if (run.name && run.name.startsWith('Hunt: ')) {
      const parts = run.name.slice(6).split(' - ');
      const name = parts[0].trim();
      return {
        name,
        handle: name.toLowerCase().replace(/\s+/g, '_'),
      };
    }
    if (run.name && (run.name.includes('://') || run.name.startsWith('Scan: '))) {
      try {
        const urlStr = run.name.replace('Scan: ', '').trim();
        const host = new URL(urlStr).hostname;
        return { name: host, handle: host };
      } catch {
        // Fall through to the stable run-name fallback.
      }
    }
    return { name: run.name || `Target #${run.target_id}`, handle: `target_${run.target_id}` };
  }, []);

  const allProgramGroups = useMemo(() => {
    const map = new Map<string, ProgramHuntGroup>();

    for (const run of sortedPreviousRuns) {
      const { name, handle } = getProgramInfo(run);
      const key = `${run.target_id || ''}_${name}`;

      if (!map.has(key)) {
        map.set(key, {
          programKey: key,
          targetId: run.target_id,
          programName: name,
          programHandle: handle,
          runs: [],
          activeCount: 0,
          pausedCount: 0,
          completedCount: 0,
          failedCount: 0,
          findingsCount: 0,
          latestStartedAt: run.started_at,
        });
      }

      const grp = map.get(key)!;
      grp.runs.push(run);
      if (run.status === 'running' || run.status === 'pending') grp.activeCount += 1;
      else if (run.status === 'paused') grp.pausedCount += 1;
      else if (run.status === 'completed') grp.completedCount += 1;
      else if (run.status === 'failed') grp.failedCount += 1;

      const findings = Number((run.limits as Record<string, unknown> | undefined)?.findings_count || 0);
      grp.findingsCount += findings;
    }

    return Array.from(map.values());
  }, [sortedPreviousRuns, getProgramInfo]);

  const groupCounts = useMemo(() => ({
    all: allProgramGroups.length,
    running: allProgramGroups.filter((g) => g.activeCount > 0).length,
    paused: allProgramGroups.filter((g) => g.pausedCount > 0).length,
    hits: allProgramGroups.filter((g) => g.findingsCount > 0).length,
    completed: allProgramGroups.filter((g) => g.completedCount > 0 && g.activeCount === 0).length,
  }), [allProgramGroups]);

  const filteredProgramGroups = useMemo(() => {
    return allProgramGroups.filter((grp) => {
      if (historyFilter === 'running' && grp.activeCount === 0) return false;
      if (historyFilter === 'paused' && grp.pausedCount === 0) return false;
      if (historyFilter === 'hits' && grp.findingsCount === 0) return false;
      if (historyFilter === 'completed' && (grp.completedCount === 0 || grp.activeCount > 0)) return false;

      if (historySearch.trim()) {
        const q = historySearch.toLowerCase().trim();
        const pName = grp.programName.toLowerCase();
        const pHandle = grp.programHandle.toLowerCase();
        const hasMatchingRun = grp.runs.some((r) => (r.name || '').toLowerCase().includes(q) || String(r.id).includes(q));
        if (!pName.includes(q) && !pHandle.includes(q) && !hasMatchingRun) {
          return false;
        }
      }
      return true;
    });
  }, [allProgramGroups, historyFilter, historySearch]);

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
  const openInterventions = ((monitor?.experiment.limits?.human_interventions || []) as Array<{
    id: string;
    status: string;
    kind: string;
    reason: string;
    identity?: string;
    url?: string;
    workflow?: string;
  }>).filter((item) => item.status === 'open');

  const ring = 2 * Math.PI * 26;
  const progressPct = monitor?.progress_percent ?? 0;
  const liveProgress = monitor?.live_progress;
  const heartbeatAt = liveProgress?.updated_at ? Date.parse(liveProgress.updated_at) : Number.NaN;
  const heartbeatAge = Number.isFinite(heartbeatAt)
    ? Math.max(0, Math.floor((clockNow - heartbeatAt) / 1000))
    : Math.floor(monitor?.idle_seconds || 0);
  const heartbeatStale = Boolean(
    monitor?.experiment.status === 'running' && (monitor.progress_stale || heartbeatAge > 30)
  );
  const progressState = liveProgress?.state || monitor?.experiment.status || 'waiting';

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-4 sm:p-6">
      {/* Clean Modern Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-500/20 text-brand-300">
            <Crosshair className="h-5 w-5" />
          </span>
          <div>
            <h1 className="text-2xl font-bold font-display tracking-tight text-carbon-100">
              Recon & Vuln Scan Monitor
            </h1>
            <p className="text-xs text-carbon-400">
              Autonomous reflection mapping, live browser telemetry, and attack graph execution
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={() => setShowUrlLauncher((v) => !v)}
            className="btn btn-ghost px-3 py-1.5 text-xs text-brand-300 hover:bg-brand-500/10 border border-brand-500/30"
          >
            <Plus className="mr-1 h-3.5 w-3.5" />
            {showUrlLauncher ? 'Close URL Launcher' : 'Custom URL Scan'}
          </button>
          <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-semibold ${
            healthError ? 'border-rose-500/30 bg-rose-500/10 text-rose-200'
              : health ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
              : 'border-carbon-600 bg-carbon-800/50 text-carbon-300'
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${healthError ? 'bg-rose-400' : health ? 'bg-emerald-400 animate-pulse-soft' : 'bg-carbon-400'}`} />
            {healthError ? 'Backend offline' : health ? 'Engine Online' : 'Checking…'}
          </span>
        </div>
      </div>

      {/* Collapsible Custom URL Launcher */}
      {showUrlLauncher && (
        <section className="panel scanline animate-rise overflow-hidden">
          <div className="flex items-center justify-between border-b border-carbon-700/60 bg-carbon-850/40 px-5 py-3">
            <div className="flex items-center gap-2.5 font-mono text-[11px] text-carbon-400">
              <span className="flex gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-rose-500/70" />
                <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/70" />
              </span>
              <span className="ml-1">Target URL Direct Scan</span>
            </div>
            <button
              type="button"
              onClick={() => setShowUrlLauncher(false)}
              className="text-carbon-400 hover:text-carbon-200"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 p-5">
            <div>
              <label className="eyebrow">Target URL</label>
              <div className="mt-2 flex items-center gap-2.5 rounded-xl border border-carbon-600 bg-carbon-950/70 px-3.5 transition focus-within:border-brand-500 focus-within:ring-2 focus-within:ring-brand-500/25">
                <Crosshair className="h-5 w-5 shrink-0 text-brand-400" aria-hidden="true" />
                <input
                  type="url"
                  required
                  value={formData.url}
                  onChange={(event) => setFormData({ ...formData, url: event.target.value })}
                  className="flex-1 bg-transparent py-2.5 font-mono text-sm text-carbon-100 placeholder-carbon-500 focus:outline-none"
                  placeholder="https://example.com/search?q=test"
                />
                <span className="hidden select-none rounded border border-carbon-700 px-1.5 py-0.5 font-mono text-[10px] text-carbon-500 sm:block">GET</span>
              </div>
            </div>

            <div className="grid gap-3 rounded-xl border border-carbon-700/70 bg-carbon-850/30 p-4 sm:grid-cols-2">
              <div>
                <label htmlFor="scan-max-pages" className="mb-1 block text-xs font-semibold text-carbon-200">Representative page budget</label>
                <input
                  id="scan-max-pages"
                  type="number"
                  min={1}
                  max={500}
                  value={formData.max_pages ?? 100}
                  onChange={(event) => setFormData({ ...formData, max_pages: Math.max(1, Math.min(500, Number(event.target.value) || 1)) })}
                  className="field font-mono"
                />
                <p className="mt-1 text-[11px] leading-relaxed text-carbon-400">Template-equivalent blog, article, product, and ID routes are sampled instead of consuming one slot each.</p>
              </div>
              <div>
                <label htmlFor="scan-max-depth" className="mb-1 block text-xs font-semibold text-carbon-200">Maximum link depth</label>
                <input
                  id="scan-max-depth"
                  type="number"
                  min={0}
                  max={5}
                  value={formData.max_depth ?? 2}
                  onChange={(event) => setFormData({ ...formData, max_depth: Math.max(0, Math.min(5, Number(event.target.value) || 0)) })}
                  className="field font-mono"
                />
                <p className="mt-1 text-[11px] leading-relaxed text-carbon-400">Query-bearing and security-feature routes are prioritized before ordinary content pages.</p>
              </div>
            </div>

            <div className="rounded-xl border border-carbon-700/70 bg-carbon-850/30">
              <button
                type="button"
                aria-expanded={authOpen}
                aria-controls="authenticated-campaign-options"
                onClick={() => {
                  setAuthOpen((value) => !value);
                  setAuthError('');
                }}
                className="flex min-h-10 w-full items-center justify-between gap-4 px-4 py-2.5 text-left focus:outline-none"
              >
                <span>
                  <span className="block text-xs font-semibold text-carbon-100">Authenticated campaign</span>
                  <span className="block text-[11px] text-carbon-400">Optional cookies, bearer headers, login renewal, and multiple identities.</span>
                </span>
                <span className="font-mono text-xs text-brand-300">{authOpen ? 'Hide' : 'Configure'}</span>
              </button>

              {authOpen && (
                <div id="authenticated-campaign-options" className="space-y-4 border-t border-carbon-700/60 p-4">
                  <div className="grid gap-3 md:grid-cols-2">
                    <div>
                      <label htmlFor="auth-identity" className="mb-1 block text-xs font-semibold text-carbon-200">Identity label</label>
                      <input
                        id="auth-identity"
                        value={authForm.identity}
                        onChange={(event) => setAuthForm({ ...authForm, identity: event.target.value })}
                        className="field"
                        placeholder="author"
                      />
                    </div>
                    <div>
                      <label htmlFor="auth-health-url" className="mb-1 block text-xs font-semibold text-carbon-200">Session health URL</label>
                      <input
                        id="auth-health-url"
                        value={authForm.healthCheckUrl}
                        onChange={(event) => setAuthForm({ ...authForm, healthCheckUrl: event.target.value })}
                        className="field font-mono"
                        placeholder="/account"
                      />
                    </div>
                    <div>
                      <label htmlFor="auth-cookie" className="mb-1 block text-xs font-semibold text-carbon-200">Cookie header</label>
                      <input
                        id="auth-cookie"
                        value={authForm.cookie}
                        onChange={(event) => setAuthForm({ ...authForm, cookie: event.target.value })}
                        className="field font-mono"
                        placeholder="session=…; csrf=…"
                        autoComplete="off"
                      />
                    </div>
                    <div>
                      <label htmlFor="auth-header" className="mb-1 block text-xs font-semibold text-carbon-200">Authorization header</label>
                      <input
                        id="auth-header"
                        value={authForm.authorization}
                        onChange={(event) => setAuthForm({ ...authForm, authorization: event.target.value })}
                        className="field font-mono"
                        placeholder="Bearer …"
                        autoComplete="off"
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>

            <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-carbon-700/70 bg-carbon-850/40 px-4 py-2.5 transition hover:border-carbon-600">
              <input
                type="checkbox"
                required
                checked={formData.authorized}
                onChange={(event) => setFormData({ ...formData, authorized: event.target.checked })}
                className="mt-0.5 h-4 w-4 rounded border-carbon-500 bg-carbon-900 text-brand-500 focus:ring-brand-500/40"
              />
              <span className="text-xs text-carbon-300">
                <span className="font-semibold text-carbon-100">Authorization confirmed.</span>{' '}
                I own this target or have explicit permission to test it.
              </span>
            </label>

            {(errorDetail || authError) && (
              <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-xs text-rose-200">
                {authError || errorDetail}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="submit"
                name="mode"
                value="recon"
                disabled={mutation.isPending || healthError}
                className="btn btn-ghost px-3 py-1.5 text-xs"
              >
                {mutation.isPending && pendingMode === 'recon' ? 'Starting recon…' : 'Run recon only'}
              </button>
              <button
                type="submit"
                name="mode"
                value="full"
                disabled={mutation.isPending || healthError}
                className="btn btn-primary px-3.5 py-1.5 text-xs shadow-glow-brand"
              >
                {mutation.isPending && pendingMode === 'full' ? 'Deploying…' : <><ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />Run recon + vuln scan</>}
              </button>
            </div>
          </form>
        </section>
      )}

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

      {startedExperimentId && openInterventions.length > 0 && (
        <section className="panel border-amber-500/30" aria-live="polite">
          <SectionHeader
            title="Operator action required"
            hint="The campaign is paused safely. Supply a refreshed authorized session, then resume the same run."
            right={<Badge value="paused" />}
          />
          <div className="space-y-4 p-5">
            {openInterventions.map((item) => (
              <div key={item.id} className="rounded-xl border border-amber-500/25 bg-amber-500/10 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-semibold text-amber-100">{item.kind.replace(/_/g, ' ')}</p>
                  {item.identity && <span className="rounded-md border border-amber-500/30 px-2 py-1 font-mono text-[11px] text-amber-200">identity: {item.identity}</span>}
                </div>
                <p className="mt-2 text-sm leading-6 text-carbon-200">{item.reason}</p>
                {item.url && <p className="mt-2 break-all font-mono text-xs text-carbon-400">{item.url}</p>}
                <label htmlFor={`resolution-auth-${item.id}`} className="mt-4 block text-xs font-semibold text-carbon-200">Refreshed auth JSON (optional)</label>
                <textarea
                  id={`resolution-auth-${item.id}`}
                  value={resolutionAuthJson}
                  onChange={(event) => setResolutionAuthJson(event.target.value)}
                  className="mt-2 min-h-28 w-full rounded-lg border border-carbon-600 bg-carbon-950/70 p-3 font-mono text-sm leading-6 text-carbon-100 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/25"
                  placeholder="Paste updated cookies/storage or a full multi-identity configuration"
                  spellCheck={false}
                />
                <button
                  type="button"
                  disabled={resolveInterventionMutation.isPending}
                  onClick={() => resolveInterventionMutation.mutate({ experimentId: startedExperimentId, interventionId: item.id })}
                  className="btn btn-primary mt-3 min-h-11"
                >
                  {resolveInterventionMutation.isPending ? 'Validating session…' : 'Resolve and resume campaign'}
                </button>
              </div>
            ))}
            {resolveInterventionMutation.error && (
              <p className="text-sm text-rose-200">{getErrorDetail(resolveInterventionMutation.error)}</p>
            )}
          </div>
        </section>
      )}

      {/* Program Hunt Fleet & History Console */}
      <section className="panel">
        <div className="panel-header flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-carbon-700/60 p-4">
          <div>
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-brand-400" />
              <h2 className="font-display text-base font-bold tracking-tight text-carbon-100">
                Program Hunt Fleet & History
              </h2>
            </div>
            <p className="mt-0.5 text-xs text-carbon-400">
              Select any program to monitor live telemetry, resume fuzzing, or review confirmed vulnerabilities.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {previousRuns.filter((r) => r.status === 'completed' || r.status === 'failed').length > 0 && (
              <button
                type="button"
                disabled={bulkDeleteCompletedMutation.isPending}
                onClick={() => {
                  if (window.confirm('Clean up completed and failed runs from history?')) {
                    bulkDeleteCompletedMutation.mutate();
                  }
                }}
                className="btn btn-ghost px-2.5 py-1.5 text-xs text-carbon-400 hover:text-rose-300 hover:bg-rose-500/10"
              >
                <Trash2 className="mr-1 h-3.5 w-3.5" />
                {bulkDeleteCompletedMutation.isPending ? 'Cleaning…' : 'Clear Finished'}
              </button>
            )}
            {startedExperimentId && (
              <div className="rounded-lg border border-brand-500/40 bg-brand-500/10 px-3 py-1 font-mono text-[11px] font-semibold text-brand-200">
                Active: #{startedExperimentId}
              </div>
            )}
          </div>
        </div>

        {/* Filter Controls & Search */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-carbon-800 bg-carbon-900/40 p-3">
          {/* Tab Filter */}
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => setHistoryFilter('all')}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                historyFilter === 'all'
                  ? 'bg-brand-500 text-white shadow-glow-brand'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
              }`}
            >
              All Programs ({groupCounts.all})
            </button>
            <button
              type="button"
              onClick={() => setHistoryFilter('running')}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                historyFilter === 'running'
                  ? 'bg-amber-500 text-carbon-950 font-bold'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-amber-300'
              }`}
            >
              🔥 Hunting ({groupCounts.running})
            </button>
            <button
              type="button"
              onClick={() => setHistoryFilter('paused')}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                historyFilter === 'paused'
                  ? 'bg-amber-500/30 text-amber-200 border border-amber-500/50'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-amber-200'
              }`}
            >
              ⏸️ Paused ({groupCounts.paused})
            </button>
            <button
              type="button"
              onClick={() => setHistoryFilter('hits')}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                historyFilter === 'hits'
                  ? 'bg-emerald-500 text-carbon-950 font-bold shadow-glow-emerald'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-emerald-300'
              }`}
            >
              ⚡ With Hits ({groupCounts.hits})
            </button>
            <button
              type="button"
              onClick={() => setHistoryFilter('completed')}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                historyFilter === 'completed'
                  ? 'bg-carbon-700 text-carbon-100'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
              }`}
            >
              Completed ({groupCounts.completed})
            </button>
          </div>

          {/* Search bar */}
          <div className="relative min-w-[220px]">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-carbon-500" />
            <input
              type="text"
              value={historySearch}
              onChange={(e) => setHistorySearch(e.target.value)}
              placeholder="Search program or target…"
              className="w-full rounded-lg border border-carbon-700 bg-carbon-950/80 py-1.5 pl-8 pr-7 text-xs text-carbon-100 placeholder-carbon-500 focus:border-brand-500 focus:outline-none"
            />
            {historySearch && (
              <button
                type="button"
                onClick={() => setHistorySearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-carbon-400 hover:text-carbon-100"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
        </div>

        {/* Program-Grouped Fleet List */}
        <div className="divide-y divide-carbon-800/80">
          {filteredProgramGroups.map((group) => {
            const isGroupExpanded = expandedPrograms[group.programKey] ?? (group.activeCount > 0 || group.runs.some((r) => r.id === startedExperimentId));
            const hasActive = group.activeCount > 0;
            const hasSelected = group.runs.some((r) => r.id === startedExperimentId);

            return (
              <div key={group.programKey} className="transition">
                {/* Program Header Row */}
                <div
                  onClick={() => toggleProgram(group.programKey)}
                  className={`flex flex-col gap-3 p-4 transition cursor-pointer md:flex-row md:items-center justify-between ${
                    hasActive
                      ? 'bg-amber-500/[0.06] border-l-4 border-l-amber-400'
                      : hasSelected
                      ? 'bg-brand-500/[0.05] border-l-4 border-l-brand-500'
                      : 'hover:bg-carbon-850/60'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <button
                      type="button"
                      className="text-carbon-400 hover:text-carbon-100 flex-shrink-0"
                    >
                      {isGroupExpanded ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                    </button>

                    <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-carbon-800 border border-carbon-700/80 text-brand-400 flex-shrink-0">
                      <Trophy className="h-4 w-4" />
                    </span>

                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-bold text-sm text-carbon-100 group-hover:text-white truncate">
                          {group.programName}
                        </span>
                        <span className="font-mono text-xs text-carbon-400">
                          @{group.programHandle}
                        </span>
                      </div>

                      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                        {hasActive && (
                          <span className="flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-300 animate-pulse">
                            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                            {group.activeCount} Active
                          </span>
                        )}

                        {group.pausedCount > 0 && (
                          <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[11px] text-amber-200">
                            ⏸️ {group.pausedCount} Paused
                          </span>
                        )}

                        {group.findingsCount > 0 && (
                          <span className="flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-bold text-rose-300 shadow-glow-rose">
                            <Bug className="h-3 w-3 text-rose-400" />
                            {group.findingsCount} Findings
                          </span>
                        )}

                        {group.completedCount > 0 && (
                          <span className="flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-300">
                            <CheckCircle2 className="h-3 w-3" />
                            {group.completedCount} Completed
                          </span>
                        )}

                        <span className="rounded bg-carbon-800 border border-carbon-700/80 px-2 py-0.5 font-mono text-[10px] text-carbon-400">
                          {group.runs.length} Asset Hunts
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Program Group Actions */}
                  <div className="flex flex-wrap items-center gap-2 ml-7 md:ml-0" onClick={(e) => e.stopPropagation()}>
                    {group.targetId && (
                      <button
                        type="button"
                        disabled={huntProgramMutation.isPending}
                        onClick={() => huntProgramMutation.mutate(group.targetId!)}
                        className="rounded-lg border border-carbon-700 bg-carbon-800 px-3 py-1.5 text-xs font-semibold text-carbon-200 hover:bg-carbon-700 hover:text-white flex items-center gap-1 transition"
                      >
                        <RotateCcw className="h-3 w-3" />
                        Re-hunt Program
                      </button>
                    )}

                    {group.targetId && (
                      <Link
                        to={`/programs/${group.targetId}`}
                        className="rounded-lg border border-carbon-700 bg-carbon-800/80 px-2.5 py-1.5 text-xs text-brand-300 hover:bg-carbon-700 flex items-center gap-1"
                      >
                        <ExternalLink className="h-3 w-3" />
                        Program Scope
                      </Link>
                    )}
                  </div>
                </div>

                {/* Sub-runs list under expanded program */}
                {isGroupExpanded && (
                  <div className="bg-carbon-950/40 border-t border-carbon-800/60 pl-6 sm:pl-10 divide-y divide-carbon-800/40">
                    {group.runs.map((run) => {
                      const isSelected = startedExperimentId === run.id;
                      return (
                        <div
                          key={run.id}
                          onClick={() => {
                            setStartedExperimentId(run.id);
                            setActiveExperiment(run.id);
                            setLogFilter('all');
                          }}
                          className={`flex flex-col justify-between gap-2.5 p-3.5 transition cursor-pointer md:flex-row md:items-center ${
                            isSelected
                              ? 'bg-brand-500/10 border-l-2 border-l-brand-500'
                              : 'hover:bg-carbon-850/40'
                          }`}
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-mono text-xs font-bold text-brand-400">#{run.id}</span>
                              <span className="font-semibold text-xs text-carbon-200 group-hover:text-white truncate">
                                {run.name || `Target Hunt #${run.id}`}
                              </span>
                              <Badge value={run.status} />
                              <span className="rounded bg-carbon-800 px-1.5 py-0.5 font-mono text-[9px] text-carbon-400">
                                {run.strategy}
                              </span>
                            </div>

                            <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-carbon-400 font-mono">
                              <span>
                                {run.started_at ? new Date(run.started_at).toLocaleTimeString() : 'Not started'}
                              </span>
                              {run.completed_at && (
                                <span>
                                  · finished {new Date(run.completed_at).toLocaleTimeString()}
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="flex flex-wrap items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                            {run.status === 'running' ? (
                              <button
                                type="button"
                                disabled={pauseMutation.isPending}
                                onClick={() => pauseMutation.mutate(run.id)}
                                className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs font-semibold text-amber-300 hover:bg-amber-500/20"
                              >
                                <Pause className="mr-1 inline h-3 w-3" />
                                Pause
                              </button>
                            ) : run.status === 'paused' ? (
                              <button
                                type="button"
                                disabled={resumeMutation.isPending}
                                onClick={() => {
                                  setStartedExperimentId(run.id);
                                  setActiveExperiment(run.id);
                                  resumeMutation.mutate(run.id);
                                }}
                                className="rounded-md border border-brand-500/50 bg-brand-600 px-2.5 py-1 text-xs font-semibold text-white shadow-glow-brand hover:bg-brand-500"
                              >
                                <Play className="mr-1 inline h-3 w-3" />
                                Resume
                              </button>
                            ) : (
                              <button
                                type="button"
                                disabled={resumeMutation.isPending}
                                onClick={() => {
                                  setStartedExperimentId(run.id);
                                  setActiveExperiment(run.id);
                                  resumeMutation.mutate(run.id);
                                }}
                                className="rounded-md border border-carbon-700 bg-carbon-800 px-2.5 py-1 text-xs font-medium text-carbon-200 hover:bg-carbon-700 hover:text-white"
                              >
                                <RotateCcw className="mr-1 inline h-3 w-3" />
                                Re-run
                              </button>
                            )}

                            <button
                              type="button"
                              onClick={() => {
                                setStartedExperimentId(run.id);
                                setActiveExperiment(run.id);
                                setLogFilter('all');
                              }}
                              className={`rounded-md px-2.5 py-1 text-xs font-semibold transition ${
                                isSelected
                                  ? 'bg-brand-500/20 text-brand-300 border border-brand-500/40'
                                  : 'border border-carbon-700 bg-carbon-800/80 text-carbon-300 hover:bg-carbon-700 hover:text-carbon-100'
                              }`}
                            >
                              {isSelected ? 'Active' : 'Monitor'}
                            </button>

                            <button
                              type="button"
                              onClick={() => {
                                if (window.confirm(`Delete hunt #${run.id} (${run.name})?`)) {
                                  deleteMutation.mutate(run.id);
                                }
                              }}
                              className="rounded-md p-1 text-carbon-500 hover:bg-rose-500/15 hover:text-rose-300"
                              title="Remove run"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}

          {filteredProgramGroups.length === 0 && (
            <div className="p-8 text-center text-sm text-carbon-400">
              No program hunts match your filter or search.
            </div>
          )}
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
                <Badge value={monitor.stage === 'inconclusive' ? 'inconclusive' : monitor.experiment.status} />
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

            <div
              className={`mb-5 rounded-2xl border p-4 ${
                monitor.stage === 'inconclusive'
                  ? 'border-amber-500/35 bg-amber-500/[0.07]'
                  : progressState === 'error' || monitor.experiment.status === 'failed'
                  ? 'border-rose-500/35 bg-rose-500/[0.07]'
                  : heartbeatStale
                    ? 'border-amber-500/35 bg-amber-500/[0.07]'
                    : progressState === 'done' || monitor.experiment.status === 'completed'
                      ? 'border-emerald-500/30 bg-emerald-500/[0.06]'
                      : 'border-cyan-500/30 bg-cyan-500/[0.06]'
              }`}
              aria-live="polite"
              aria-atomic="true"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex min-w-0 items-start gap-3">
                  <span className="mt-0.5 flex h-9 w-9 flex-none items-center justify-center rounded-xl border border-current/15 bg-carbon-950/40">
                    {monitor.stage === 'inconclusive' ? (
                      <AlertTriangle className="h-4.5 w-4.5 text-amber-300" />
                    ) : progressState === 'error' || monitor.experiment.status === 'failed' ? (
                      <AlertTriangle className="h-4.5 w-4.5 text-rose-300" />
                    ) : monitor.experiment.status === 'running' ? (
                      <LoaderCircle className="h-4.5 w-4.5 animate-spin text-cyan-300 motion-reduce:animate-none" />
                    ) : (
                      <Activity className="h-4.5 w-4.5 text-emerald-300" />
                    )}
                  </span>
                  <div className="min-w-0">
                    <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-carbon-400">
                      What the scanner is doing now
                    </div>
                    <div className="mt-1 text-sm font-semibold text-carbon-100">
                      {liveProgress?.message || monitor.stage_detail}
                    </div>
                    {(liveProgress?.detail || heartbeatStale) && (
                      <div className={`mt-1.5 text-xs leading-relaxed ${heartbeatStale ? 'text-amber-200' : 'text-carbon-300'}`}>
                        {heartbeatStale
                          ? `No new heartbeat for ${formatDuration(heartbeatAge)}. The scan may be waiting on a page, proxy, or external tool; check Engine decisions below.`
                          : liveProgress?.detail}
                      </div>
                    )}
                  </div>
                </div>
                <Badge value={monitor.stage === 'inconclusive' ? 'inconclusive' : progressState} />
              </div>

              <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-xl border border-carbon-700/70 bg-carbon-950/35 px-3 py-2.5">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-carbon-500">
                    <Wrench className="h-3.5 w-3.5" /> Tool
                  </div>
                  <div className="mt-1 truncate text-xs font-semibold text-carbon-200">{liveProgress?.tool || 'scan orchestrator'}</div>
                </div>
                <div className="rounded-xl border border-carbon-700/70 bg-carbon-950/35 px-3 py-2.5">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-carbon-500">
                    <Clock3 className="h-3.5 w-3.5" /> Elapsed
                  </div>
                  <div className="mt-1 text-xs font-semibold tabnum text-carbon-200">{formatDuration(monitor.elapsed_seconds)}</div>
                </div>
                <div className="rounded-xl border border-carbon-700/70 bg-carbon-950/35 px-3 py-2.5">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-carbon-500">Current step</div>
                  <div className="mt-1 truncate text-xs font-semibold text-carbon-200">
                    {liveProgress?.completed != null && liveProgress?.total
                      ? `${liveProgress.completed} / ${liveProgress.total}`
                      : liveProgress?.phase?.replace(/_/g, ' ') || monitor.stage.replace(/_/g, ' ')}
                  </div>
                </div>
                <div className="rounded-xl border border-carbon-700/70 bg-carbon-950/35 px-3 py-2.5">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-carbon-500">Last heartbeat</div>
                  <div className={`mt-1 text-xs font-semibold tabnum ${heartbeatStale ? 'text-amber-200' : 'text-carbon-200'}`}>
                    {liveProgress?.updated_at ? `${formatDuration(heartbeatAge)} ago` : 'Waiting for first update'}
                  </div>
                </div>
              </div>
            </div>

            {/* River-to-Sea Fluid Telemetry & Micro-State Pipeline */}
            <RiverFlowMonitor monitor={monitor} className="mb-5" />

            <div className="mb-5 flex flex-wrap items-center gap-3">
              {monitor.experiment.status === 'running' ? (
                <button
                  type="button"
                  disabled={pauseMutation.isPending}
                  onClick={() => pauseMutation.mutate(monitor.experiment.id)}
                  className="btn btn-ghost px-3.5 py-2 text-amber-300 hover:bg-amber-500/15"
                >
                  <Pause className="mr-1.5 h-4 w-4" />
                  {pauseMutation.isPending ? 'Pausing…' : 'Pause Hunt'}
                </button>
              ) : (
                <button
                  type="button"
                  disabled={resumeMutation.isPending}
                  onClick={() => resumeMutation.mutate(monitor.experiment.id)}
                  className="btn btn-primary px-3.5 py-2 shadow-glow-brand"
                >
                  <Play className="mr-1.5 h-4 w-4" />
                  {resumeMutation.isPending ? 'Resuming…' : 'Resume Hunt'}
                </button>
              )}
              <Link
                to="/live"
                className="btn btn-ghost px-3.5 py-2 text-brand-300 hover:bg-brand-500/10"
              >
                <Zap className="mr-1.5 h-4 w-4" />
                Live Fuzz Canvas
              </Link>
              <Link
                to="/findings"
                className="btn btn-ghost px-3.5 py-2 text-emerald-300 hover:bg-emerald-500/10"
              >
                <Bug className="mr-1.5 h-4 w-4" />
                View Findings ({monitor.recent_findings?.length || 0})
              </Link>
              <a
                href={`/api/v1/experiments/${monitor.experiment.id}/audit`}
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-ghost px-3.5 py-2 text-cyan-300 hover:bg-cyan-500/10"
              >
                <Layers className="mr-1.5 h-4 w-4" />
                Full forensic audit
              </a>
              <a
                href={`/api/v1/logs/export?experiment_id=${monitor.experiment.id}`}
                className="btn btn-ghost px-3.5 py-2 text-violet-300 hover:bg-violet-500/10"
                download
              >
                <ExternalLink className="mr-1.5 h-4 w-4" />
                Download all events
              </a>
              {report?.html_url && (
                <a href={report.html_url} target="_blank" rel="noopener noreferrer" className="btn btn-success px-3 py-2 ml-auto">
                  <ExternalLink className="mr-1.5 h-4 w-4" />
                  Open final report
                </a>
              )}
            </div>

            <div className="mb-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-xl border border-carbon-700/70 bg-carbon-950/35 p-3">
                <div className="font-mono text-[10px] uppercase tracking-wider text-carbon-500">Burp REST</div>
                <div className={`mt-1 text-sm font-semibold ${monitor.experiment.limits?.burp_task_id ? 'text-emerald-300' : 'text-amber-300'}`}>
                  {monitor.experiment.limits?.burp_task_id ? 'Used by this run' : 'No attributed task'}
                </div>
                <div className="mt-1 line-clamp-2 text-[11px] text-carbon-400">
                  {monitor.experiment.limits?.burp_scan_message || monitor.experiment.limits?.burp_status || 'No Burp REST evidence recorded.'}
                </div>
              </div>
              <div className="rounded-xl border border-carbon-700/70 bg-carbon-950/35 p-3">
                <div className="font-mono text-[10px] uppercase tracking-wider text-carbon-500">Burp extension</div>
                <div className={`mt-1 text-sm font-semibold ${monitor.experiment.limits?.burp_extension_activity?.used ? 'text-emerald-300' : 'text-amber-300'}`}>
                  {monitor.experiment.limits?.burp_extension_activity?.used ? 'Traffic received' : 'No attributed traffic'}
                </div>
                <div className="mt-1 text-[11px] text-carbon-400">
                  {monitor.experiment.limits?.burp_extension_activity?.items || 0} imported item(s)
                </div>
              </div>
              <div className="rounded-xl border border-carbon-700/70 bg-carbon-950/35 p-3">
                <div className="font-mono text-[10px] uppercase tracking-wider text-carbon-500">Local LLM</div>
                <div className={`mt-1 text-sm font-semibold ${monitor.experiment.limits?.llm_mode === 'available' ? 'text-emerald-300' : 'text-amber-300'}`}>
                  {monitor.experiment.limits?.llm_mode === 'available'
                    ? 'Available to advisors'
                    : monitor.experiment.limits?.llm_mode === 'deterministic_only'
                      ? 'Unavailable · deterministic only'
                      : 'Participation not recorded'}
                </div>
                <div className="mt-1 line-clamp-2 text-[11px] text-carbon-400">
                  {monitor.experiment.limits?.llm_preflight?.model || 'No successful model preflight recorded.'}
                </div>
              </div>
              <div className="rounded-xl border border-carbon-700/70 bg-carbon-950/35 p-3">
                <div className="font-mono text-[10px] uppercase tracking-wider text-carbon-500">Browser oracle</div>
                <div className={`mt-1 text-sm font-semibold ${(monitor.performance_metrics?.total_executions || 0) > 0 ? 'text-emerald-300' : 'text-amber-300'}`}>
                  {monitor.performance_metrics?.total_executions || 0} real execution(s)
                </div>
                <div className="mt-1 text-[11px] text-carbon-400">
                  {monitor.performance_metrics?.oracle_hit_count || 0} hit · {monitor.performance_metrics?.oracle_miss_count || 0} miss · {monitor.performance_metrics?.oracle_error_count || 0} error
                </div>
              </div>
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

          {/* Live Browser Vision Preview */}
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <LiveBrowserPreview />
            <EndpointsMap targetId={monitor.target.id} monitor={monitor} />
          </div>

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
                        <span className="rounded bg-carbon-800 px-1.5 py-0.5 font-mono text-[10px] text-carbon-400">
                          ({check.param_location || 'query'})
                        </span>
                        {check.context_type && (
                          <span className="rounded border border-brand-500/30 bg-brand-500/10 px-1.5 py-0.5 font-mono text-[10px] font-medium text-brand-300">
                            Context: {check.context_type}
                          </span>
                        )}
                        {check.sinks && check.sinks.length > 0 && (
                          <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber-300">
                            Sink: {check.sinks.join(', ')}
                          </span>
                        )}
                      </div>
                      <span className="font-mono text-[11px] text-carbon-500">priority {check.priority}</span>
                    </div>
                    <div className="mt-2 truncate font-mono text-[11px] text-carbon-400">
                      <span className="font-bold text-carbon-300">{check.endpoint_method}</span> {check.endpoint_url}
                    </div>
                    <div className="terminal mt-2 p-3 text-xs text-carbon-200 select-all break-all">{check.payload_preview}</div>
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
                {latestResults.map((execution) => {
                  const isExpanded = !!expandedExecutions[execution.id];
                  return (
                    <div key={execution.id} className="p-4 transition hover:bg-carbon-850/30">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge value={execution.oracle_status} />
                          <span className="text-sm font-semibold text-carbon-100">Payload #{execution.test_case_id}</span>
                          <span className="text-sm font-medium text-carbon-300">{execution.param_name || '-'}</span>
                          {execution.param_location && (
                            <span className="rounded bg-carbon-800 px-1.5 py-0.5 font-mono text-[10px] text-carbon-400">
                              ({execution.param_location})
                            </span>
                          )}
                          {execution.context_type && (
                            <span className="rounded border border-brand-500/25 bg-brand-500/10 px-1.5 py-0.5 font-mono text-[10px] text-brand-300">
                              {execution.context_type}
                            </span>
                          )}
                          {execution.sinks && execution.sinks.length > 0 && (
                            <span className="rounded border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-amber-300">
                              Sink: {execution.sinks.join(', ')}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          {execution.status_code && (
                            <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${
                              execution.status_code < 400 ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300'
                            }`}>
                              HTTP {execution.status_code}
                            </span>
                          )}
                          <span className="font-mono text-[11px] text-carbon-500">
                            {execution.duration_ms ? `${execution.duration_ms}ms` : '-'} · {formatTime(execution.executed_at)}
                          </span>
                        </div>
                      </div>

                      <div className="mt-1.5 truncate font-mono text-[11px] text-carbon-400">
                        <span className="font-bold text-carbon-300">{execution.endpoint_method || 'GET'}</span> {execution.endpoint_url || '-'}
                      </div>

                      <div className={`mt-2 rounded-lg border p-3 text-xs leading-relaxed ${
                        execution.oracle_status === 'error'
                          ? 'border-rose-500/25 bg-rose-500/10 text-rose-200'
                          : execution.oracle_status === 'hit'
                          ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200'
                          : 'border-carbon-700/60 bg-carbon-850/50 text-carbon-300'
                      }`}>
                        {summarizeExecutionLog(execution.logs) || (execution.oracle_status === 'missed' ? 'No execution callback observed for this payload.' : 'No extra browser details.')}
                      </div>

                      {/* Action buttons & Drawer toggle */}
                      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                        <button
                          type="button"
                          onClick={() => toggleExecution(execution.id)}
                          className="flex items-center gap-1 text-xs font-semibold text-brand-300 transition hover:text-brand-200"
                        >
                          <span>{isExpanded ? '▲ Hide Response & Context' : '▼ Inspect Full Response, Sink & DOM'}</span>
                        </button>

                        {execution.oracle_status === 'hit' && execution.payload && (
                          <div className="flex items-center gap-2">
                            <a
                              href={getExploitUrlFromExecution(execution)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1.5 rounded-md bg-gradient-to-r from-rose-600 to-rose-500 px-3 py-1 text-xs font-semibold text-white shadow-glow-rose transition hover:brightness-110"
                            >
                              💥 Trigger XSS
                            </a>
                            <button
                              type="button"
                              onClick={() => {
                                const link = getExploitUrlFromExecution(execution);
                                navigator.clipboard.writeText(link);
                                alert('Exploit URL copied to clipboard!');
                              }}
                              className="rounded-md border border-carbon-600 bg-carbon-800/60 px-2.5 py-1 text-xs font-medium text-carbon-200 transition hover:bg-carbon-750"
                            >
                              📋 Copy URL
                            </button>
                          </div>
                        )}
                      </div>

                      {/* Expandable Deep Inspection Drawer */}
                      {isExpanded && (
                        <div className="mt-3 space-y-3 rounded-xl border border-carbon-700/80 bg-carbon-950/80 p-4 text-xs font-mono animate-rise">
                          {/* Attack & Context Header */}
                          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 border-b border-carbon-800 pb-3">
                            <div>
                              <span className="text-[10px] text-carbon-400 uppercase font-bold block">Reflected Context</span>
                              <span className="font-semibold text-brand-300">{execution.context_type || 'DOM / HTML'}</span>
                              {execution.context_tag && <span className="text-carbon-400 text-[10px] ml-1">&lt;{execution.context_tag}&gt;</span>}
                            </div>
                            <div>
                              <span className="text-[10px] text-carbon-400 uppercase font-bold block">Target Sink</span>
                              <span className="font-semibold text-amber-300">
                                {execution.sinks && execution.sinks.length > 0 ? execution.sinks.join(', ') : 'Direct DOM / Script'}
                              </span>
                            </div>
                            <div>
                              <span className="text-[10px] text-carbon-400 uppercase font-bold block">Injected Parameter</span>
                              <span className="font-semibold text-fuchsia-300">
                                {execution.param_name || '-'} ({execution.param_location || 'query'})
                              </span>
                            </div>
                            <div>
                              <span className="text-[10px] text-carbon-400 uppercase font-bold block">HTTP Status & Timing</span>
                              <span className={`font-semibold ${execution.status_code && execution.status_code < 400 ? 'text-emerald-400' : 'text-amber-400'}`}>
                                {execution.status_code ? `HTTP ${execution.status_code}` : 'Loaded in Chrome'} ({execution.duration_ms || '-'}ms)
                              </span>
                            </div>
                          </div>

                          {/* Full Injected Payload */}
                          <div>
                            <div className="flex items-center justify-between text-[10px] text-carbon-400 uppercase font-bold mb-1">
                              <span>Full Injected Payload</span>
                              <button
                                type="button"
                                onClick={() => {
                                  if (execution.payload) {
                                    navigator.clipboard.writeText(execution.payload);
                                    alert('Payload copied to clipboard!');
                                  }
                                }}
                                className="text-brand-300 hover:text-brand-200"
                              >
                                📋 Copy Payload
                              </button>
                            </div>
                            <div className="terminal p-2.5 text-xs text-brand-200 select-all break-all max-h-28 overflow-y-auto">
                              {execution.payload || 'No payload recorded'}
                            </div>
                          </div>

                          {/* Rendered DOM Response / Reflection */}
                          {execution.dom_snapshot ? (
                            <div>
                              <span className="text-[10px] text-carbon-400 uppercase font-bold block mb-1">Rendered DOM Response / Reflection</span>
                              <div className="terminal p-2.5 text-xs text-emerald-300 select-all max-h-36 overflow-y-auto whitespace-pre-wrap break-all">
                                {execution.dom_snapshot}
                              </div>
                            </div>
                          ) : (
                            <div className="text-[11px] text-carbon-500 italic">No rendered DOM snapshot stored for this execution.</div>
                          )}

                          {/* Response Headers */}
                          {execution.response_headers && Object.keys(execution.response_headers).length > 0 && (
                            <div>
                              <span className="text-[10px] text-carbon-400 uppercase font-bold block mb-1">Response Headers</span>
                              <div className="rounded-lg bg-carbon-900/90 p-2 text-[11px] text-carbon-300 max-h-28 overflow-y-auto space-y-0.5">
                                {Object.entries(execution.response_headers).map(([k, v]) => (
                                  <div key={k} className="flex gap-2">
                                    <span className="text-carbon-400 font-semibold">{k}:</span>
                                    <span className="truncate text-carbon-200">{String(v)}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Structured response security posture */}
                          {execution.response_posture && (
                            <div>
                              <div className="mb-1 flex items-center justify-between gap-2">
                                <span className="text-[10px] text-carbon-400 uppercase font-bold">Response Security Posture</span>
                                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                                  execution.response_posture.assessment?.metadata_observed
                                    ? 'bg-emerald-500/15 text-emerald-300'
                                    : 'bg-amber-500/15 text-amber-300'
                                }`}>
                                  {execution.response_posture.assessment?.metadata_observed ? 'Observed' : 'Metadata unavailable'}
                                </span>
                              </div>
                              <div className="grid grid-cols-2 gap-2 rounded-lg border border-carbon-700/70 bg-carbon-900/90 p-2 sm:grid-cols-4">
                                {[
                                  { label: 'CSP', state: execution.response_posture.observations?.csp?.state },
                                  { label: 'Trusted Types', state: execution.response_posture.observations?.trusted_types?.state },
                                  { label: 'CORS', state: execution.response_posture.observations?.cors?.state },
                                  { label: 'Cache', state: execution.response_posture.observations?.cache?.shared_cache_exposure || execution.response_posture.observations?.cache?.state },
                                ].map(({ label, state }) => (
                                  <div key={label} className="min-w-0">
                                    <span className="block text-[9px] font-bold uppercase text-carbon-500">{label}</span>
                                    <span className="block truncate text-[11px] text-carbon-200">{state || 'unknown'}</span>
                                  </div>
                                ))}
                              </div>
                              {execution.response_posture.evidence && execution.response_posture.evidence.length > 0 && (
                                <div className="mt-2 space-y-1">
                                  {execution.response_posture.evidence.slice(0, 4).map((item) => (
                                    <div key={item.code} className="rounded border border-carbon-700/60 bg-carbon-850/60 px-2 py-1 text-[10px] text-carbon-300">
                                      <span className="mr-1 font-bold text-brand-300">{item.code}</span>
                                      {item.summary}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}

                          {/* V8 source-region activation. This is reachability evidence, not data-flow proof. */}
                          {execution.runtime_code_coverage && (
                            <div>
                              <div className="mb-1 flex items-center justify-between gap-2">
                                <span className="text-[10px] text-carbon-400 uppercase font-bold">Runtime Code Activation</span>
                                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                                  execution.runtime_code_coverage.available
                                    ? 'bg-sky-500/15 text-sky-300'
                                    : 'bg-amber-500/15 text-amber-300'
                                }`}>
                                  {execution.runtime_code_coverage.available ? 'V8 observed' : 'Unavailable'}
                                </span>
                              </div>
                              <div className="grid grid-cols-3 gap-2 rounded-lg border border-carbon-700/70 bg-carbon-900/90 p-2">
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">Scripts</span>
                                  <span className="text-[11px] text-carbon-200">{execution.runtime_code_coverage.summary?.scripts_analyzed ?? 0}</span>
                                </div>
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">Reached sites</span>
                                  <span className="text-[11px] text-carbon-200">{execution.runtime_code_coverage.summary?.runtime_reached_sites ?? 0}</span>
                                </div>
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">Phases</span>
                                  <span className="text-[11px] text-carbon-200">{execution.runtime_code_coverage.phases?.join(', ') || 'none'}</span>
                                </div>
                              </div>
                              <p className="mt-1 text-[10px] text-carbon-500">
                                {execution.runtime_code_coverage.interpretation || 'Executed region observed; input influence still requires confirmation.'}
                              </p>
                            </div>
                          )}

                          {execution.runtime_lineage && (
                            <div>
                              <div className="mb-1 flex items-center justify-between gap-2">
                                <span className="text-[10px] text-carbon-400 uppercase font-bold">Runtime Causal Lineage</span>
                                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                                  (execution.runtime_lineage.summary?.value_influence ?? 0) > 0
                                    ? 'bg-fuchsia-500/15 text-fuchsia-300'
                                    : (execution.runtime_lineage.summary?.causal_only ?? 0) > 0
                                    ? 'bg-sky-500/15 text-sky-300'
                                    : 'bg-carbon-700/50 text-carbon-300'
                                }`}>
                                  {(execution.runtime_lineage.summary?.value_influence ?? 0) > 0
                                    ? 'A/A/B priority signal'
                                    : (execution.runtime_lineage.summary?.causal_only ?? 0) > 0
                                    ? 'Causal order only'
                                    : 'No lineage'}
                                </span>
                              </div>
                              <div className="grid grid-cols-3 gap-2 rounded-lg border border-carbon-700/70 bg-carbon-900/90 p-2">
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">Candidates</span>
                                  <span className="text-[11px] text-carbon-200">{execution.runtime_lineage.summary?.candidates ?? 0}</span>
                                </div>
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">Causal only</span>
                                  <span className="text-[11px] text-carbon-200">{execution.runtime_lineage.summary?.causal_only ?? 0}</span>
                                </div>
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">A/A/B signal</span>
                                  <span className="text-[11px] text-carbon-200">{execution.runtime_lineage.summary?.value_influence ?? 0}</span>
                                </div>
                              </div>
                              <p className="mt-1 text-[10px] text-carbon-500">
                                {(execution.runtime_lineage.summary?.value_influence ?? 0) > 0
                                  ? 'Fixed A/A/B order is sequence-confounded: time or server state can explain the B difference. This ranks follow-up work; only the execution oracle confirms XSS.'
                                  : execution.runtime_lineage.interpretation || 'Causal lineage ranks follow-up evidence; only the execution oracle confirms XSS.'}
                              </p>
                            </div>
                          )}

                          {execution.dom_marker_differential && (
                            <div>
                              <div className="mb-1 flex items-center justify-between gap-2">
                                <span className="text-[10px] text-carbon-400 uppercase font-bold">DOM Marker Differential</span>
                                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                                  execution.dom_marker_differential.differential_available
                                    ? 'bg-violet-500/15 text-violet-300'
                                    : 'bg-amber-500/15 text-amber-300'
                                }`}>
                                  {execution.dom_marker_differential.differential_available ? 'Before / after' : 'Single snapshot'}
                                </span>
                              </div>
                              <div className="grid grid-cols-3 gap-2 rounded-lg border border-carbon-700/70 bg-carbon-900/90 p-2">
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">Baseline</span>
                                  <span className="text-[11px] text-carbon-200">{execution.dom_marker_differential.summary?.baseline_marker_sites ?? 0}</span>
                                </div>
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">After</span>
                                  <span className="text-[11px] text-carbon-200">{execution.dom_marker_differential.summary?.after_marker_sites ?? 0}</span>
                                </div>
                                <div>
                                  <span className="block text-[9px] font-bold uppercase text-carbon-500">New sites</span>
                                  <span className="text-[11px] text-carbon-200">{execution.dom_marker_differential.summary?.new_marker_sites ?? 0}</span>
                                </div>
                              </div>
                              <p className="mt-1 text-[10px] text-carbon-500">
                                {execution.dom_marker_differential.interpretation || 'Marker placement observed; execution still requires separate evidence.'}
                              </p>
                            </div>
                          )}

                          {/* Taint flows */}
                          {execution.taint_flows && execution.taint_flows.length > 0 && (
                            <div>
                              <span className="text-[10px] text-carbon-400 uppercase font-bold block mb-1">DOM Taint Trace</span>
                              <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-2 text-[11px] text-amber-200 space-y-1">
                                {execution.taint_flows.map((t, idx) => (
                                  <div key={idx} className="flex items-start gap-1">
                                    <span className="text-amber-400 font-bold">⚡</span>
                                    <span>{t.text}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
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
