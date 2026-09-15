/**
 * Live Fuzz Monitor — Advanced Real-Time Execution Console
 * Deep-dive browser telemetry, interactive payload drawers, DOM snapshot inspection,
 * attack velocity metrics, WAF/defense profiling, audio hit chimes, and live controls.
 */
import { useEffect, useMemo, useState, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Zap,
  ShieldCheck,
  Play,
  Pause,
  RotateCcw,
  Volume2,
  VolumeX,
  Maximize2,
  Minimize2,
  Search,
  Copy,
  ExternalLink,
  Code,
  Plus,
  X,
  Download,
  Activity,
  Layers,
  Sparkles,
  Bug,
  Cpu,
  Radio,
} from 'lucide-react';
import { useExperimentStore } from '@/store/experimentState';
import { experimentsApi } from '@/api/experiments';
import type { MonitorCheck, MonitorExecution } from '@/types/api';
import { KpiCard } from '@/components/ui/kpi-card';
import EngineLog from '@/components/ui/engine-log';
import { LiveBrowserPreview } from '@/components/LiveBrowserPreview';
import RiverFlowMonitor from '@/components/RiverFlowMonitor';

const statusClass: Record<string, string> = {
  pending: 'bg-carbon-800/80 text-carbon-300 border-carbon-700',
  queued: 'bg-brand-500/15 text-brand-300 border-brand-500/30',
  running: 'bg-amber-500/15 text-amber-300 border-amber-500/30 animate-pulse-soft',
  completed: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  failed: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  hit: 'bg-emerald-500/20 text-emerald-200 border-emerald-500/50 shadow-glow-emerald font-bold',
  missed: 'bg-carbon-800/80 text-carbon-400 border-carbon-700/60',
  error: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  critical: 'bg-rose-500/25 text-rose-200 border-rose-500/50 font-bold',
  high: 'bg-orange-500/20 text-orange-200 border-orange-500/40 font-semibold',
  medium: 'bg-amber-500/20 text-amber-200 border-amber-500/40',
  low: 'bg-brand-500/15 text-brand-200 border-brand-500/30',
};

const Badge = ({ value, className = '' }: { value: string; className?: string }) => (
  <span
    className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
      statusClass[value] || 'bg-carbon-800/80 text-carbon-300 border-carbon-700'
    } ${className}`}
  >
    {value}
  </span>
);

const formatTime = (value?: string) => {
  if (!value) return '';
  try {
    const dateStr = value.endsWith('Z') || value.includes('+') ? value : value + 'Z';
    const d = new Date(dateStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
  } catch {
    return value;
  }
};

const formatFullDate = (value?: string) => {
  if (!value) return '';
  try {
    const dateStr = value.endsWith('Z') || value.includes('+') ? value : value + 'Z';
    return new Date(dateStr).toLocaleString();
  } catch {
    return value;
  }
};

const getExploitUrl = (endpointUrl?: string, paramName?: string, rawPayload?: string) => {
  if (!endpointUrl || !rawPayload) return '';
  const testablePayload = rawPayload
    .replace(/__XSS__\(['"`][a-zA-Z0-9_-]+['"`]\)/gi, 'alert(document.domain)')
    .replace(/__XSS__%28%27[a-zA-Z0-9_-]+%27%29/gi, 'alert%28document.domain%29')
    .replace(/__XSS__%28%22[a-zA-Z0-9_-]+%22%29/gi, 'alert%28document.domain%29')
    .replace(/__XSS__%28%60[a-zA-Z0-9_-]+%60%29/gi, 'alert%28document.domain%29')
    .replace(/__XSS__%60[a-zA-Z0-9_-]+%60/gi, 'alert%60document.domain%60');

  const base = endpointUrl;
  if (paramName === 'location.hash' || rawPayload.startsWith('#') || base.includes('#')) {
    const baseUrl = base.split('#')[0];
    return `${baseUrl}#${testablePayload}`;
  }

  if (paramName === 'comment-text' || paramName === 'comment') {
    const baseUrl = base.split('?')[0];
    return `${baseUrl}?inject_comment=${encodeURIComponent(testablePayload)}`;
  }

  try {
    const urlObj = new URL(base);
    if (paramName) {
      urlObj.searchParams.set(paramName, testablePayload);
    }
    return urlObj.toString();
  } catch {
    const separator = base.includes('?') ? '&' : '?';
    return `${base}${separator}${paramName || 'q'}=${encodeURIComponent(testablePayload)}`;
  }
};

const toHtmlEntity = (text: string) => {
  return text.replace(/[<>"'&]/g, (char) => {
    switch (char) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#39;';
      case '&': return '&amp;';
      default: return char;
    }
  });
};

const toHexEscape = (text: string) => {
  return text
    .split('')
    .map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
};

const toUnicodeEscape = (text: string) => {
  return text
    .split('')
    .map((c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
    .join('');
};

const playHitChime = () => {
  try {
    const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'triangle';
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(1760, ctx.currentTime + 0.15);
    gain.gain.setValueAtTime(0.3, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.35);
  } catch {
    // Audio is optional; browsers may deny AudioContext startup.
  }
};

const LiveFuzzPage = () => {
  const queryClient = useQueryClient();
  const { activeExperimentId, setActiveExperiment } = useExperimentStore();

  // Local Controls State
  const [pollingRate, setPollingRate] = useState<'1s' | '2s' | '5s' | 'paused'>('2s');
  const [audioEnabled, setAudioEnabled] = useState(true);
  const [zenMode, setZenMode] = useState(false);
  const [activeTab, setActiveTab] = useState<'checks' | 'browser' | 'surface' | 'findings' | 'brain'>('checks');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'hit' | 'running' | 'queued' | 'completed' | 'failed'>('all');
  const [contextFilter, setContextFilter] = useState<string>('all');
  const [selectedCheck, setSelectedCheck] = useState<MonitorCheck | null>(null);
  const [selectedExecution, setSelectedExecution] = useState<MonitorExecution | null>(null);
  const [showInjectModal, setShowInjectModal] = useState(false);
  const [showScreenshotModal, setShowScreenshotModal] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Manual Inject Form State
  const [injectEndpointId, setInjectEndpointId] = useState<number>(0);
  const [injectParamId, setInjectParamId] = useState<number>(0);
  const [injectPayloadText, setInjectPayloadText] = useState('');
  const [injectSuccessMsg, setInjectSuccessMsg] = useState('');

  const previousHitCountRef = useRef<number>(0);

  const activePollingMs = useMemo(() => {
    if (pollingRate === '1s') return 1000;
    if (pollingRate === '2s') return 2000;
    if (pollingRate === '5s') return 5000;
    return false;
  }, [pollingRate]);

  // Fetch all experiments
  const { data: experiments = [] } = useQuery({
    queryKey: ['experiments'],
    queryFn: () => experimentsApi.list(),
    refetchInterval: 5000,
  });

  // Auto-select running or latest experiment if none selected
  useEffect(() => {
    if (!activeExperimentId && experiments.length > 0) {
      const runningExp = experiments.find((exp) => exp.status === 'running' || exp.status === 'paused');
      const target = runningExp || experiments[0];
      if (target) {
        setActiveExperiment(target.id);
      }
    }
  }, [activeExperimentId, experiments, setActiveExperiment]);

  // Fetch active experiment live monitor snapshot
  const { data: monitor, isError: monitorError, isFetching: isRefreshing } = useQuery({
    queryKey: ['experiments', activeExperimentId, 'monitor'],
    queryFn: () => experimentsApi.getMonitor(activeExperimentId!),
    enabled: !!activeExperimentId,
    refetchInterval: activePollingMs,
    retry: false,
  });

  // Audio Hit notification trigger
  useEffect(() => {
    if (!monitor) return;
    const currentHits = monitor.stats ? (monitor.performance_metrics?.oracle_hit_count ?? monitor.recent_findings.length) : 0;
    if (previousHitCountRef.current > 0 && currentHits > previousHitCountRef.current && audioEnabled) {
      playHitChime();
    }
    previousHitCountRef.current = currentHits;
  }, [monitor, audioEnabled]);

  // Mutations for hunt control
  const pauseMutation = useMutation({
    mutationFn: (expId: number) => experimentsApi.stop(expId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      queryClient.invalidateQueries({ queryKey: ['experiments', activeExperimentId, 'monitor'] });
    },
  });

  const resumeMutation = useMutation({
    mutationFn: (expId: number) => experimentsApi.resume(expId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
      queryClient.invalidateQueries({ queryKey: ['experiments', activeExperimentId, 'monitor'] });
    },
  });

  const resetThrottleMutation = useMutation({
    mutationFn: (expId: number) => experimentsApi.resetThrottle(expId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments', activeExperimentId, 'monitor'] });
    },
  });

  const retryCheckMutation = useMutation({
    mutationFn: ({ expId, checkId }: { expId: number; checkId: number }) =>
      experimentsApi.retryTestCase(expId, checkId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments', activeExperimentId, 'monitor'] });
    },
  });

  const injectPayloadMutation = useMutation({
    mutationFn: (data: { endpoint_id: number; param_id: number; payload: string }) =>
      experimentsApi.injectPayload(activeExperimentId!, data),
    onSuccess: (res) => {
      setInjectSuccessMsg(`Dispatched test case #${res.test_case_id}!`);
      setTimeout(() => setInjectSuccessMsg(''), 3500);
      setInjectPayloadText('');
      setShowInjectModal(false);
      queryClient.invalidateQueries({ queryKey: ['experiments', activeExperimentId, 'monitor'] });
    },
  });

  const copyToClipboard = useCallback((text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  }, []);

  const exportTelemetryJson = () => {
    if (!monitor) return;
    const blob = new Blob([JSON.stringify(monitor, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xssboss-telemetry-exp-${monitor.experiment.id}-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const selectableExperiments = useMemo(
    () => experiments.filter((exp) => ['running', 'paused', 'pending', 'completed'].includes(exp.status)),
    [experiments]
  );

  // Filtered recent checks
  const filteredChecks = useMemo(() => {
    if (!monitor?.recent_checks) return [];
    return monitor.recent_checks.filter((check) => {
      if (statusFilter !== 'all' && check.status !== statusFilter) return false;
      if (contextFilter !== 'all' && check.context_type !== contextFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const payloadStr = (check.payload || check.payload_preview || '').toLowerCase();
        const paramStr = (check.param_name || '').toLowerCase();
        const urlStr = (check.endpoint_url || '').toLowerCase();
        const ctxStr = (check.context_type || '').toLowerCase();
        if (!payloadStr.includes(q) && !paramStr.includes(q) && !urlStr.includes(q) && !ctxStr.includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [monitor?.recent_checks, statusFilter, contextFilter, searchQuery]);

  // Filtered executions
  const filteredExecutions = useMemo(() => {
    if (!monitor?.recent_executions) return [];
    return monitor.recent_executions.filter((exec) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const logs = (exec.logs || exec.raw_logs || '').toLowerCase();
        const param = (exec.param_name || '').toLowerCase();
        const url = (exec.endpoint_url || '').toLowerCase();
        const payload = (exec.payload || '').toLowerCase();
        if (!logs.includes(q) && !param.includes(q) && !url.includes(q) && !payload.includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [monitor?.recent_executions, searchQuery]);

  // Context distribution stats
  const contextStats = useMemo(() => {
    if (monitor?.context_distribution && Object.keys(monitor.context_distribution).length > 0) {
      return monitor.context_distribution;
    }
    const dist: Record<string, number> = {};
    for (const check of monitor?.recent_checks || []) {
      if (check.context_type) {
        dist[check.context_type] = (dist[check.context_type] || 0) + 1;
      }
    }
    return dist;
  }, [monitor]);

  const totalContextReflections = useMemo(
    () => Object.values(contextStats).reduce((sum, count) => sum + count, 0),
    [contextStats]
  );

  if (!activeExperimentId || monitorError || !monitor) {
    return (
      <div className="mx-auto max-w-6xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold font-display tracking-tight text-carbon-100 flex items-center gap-2.5">
              <Zap className="h-6 w-6 text-brand-400" />
              Live Fuzz Monitor
            </h1>
            <p className="text-xs text-carbon-400 mt-1">
              Select an active or previous campaign to attach the live telemetry console.
            </p>
          </div>
          <Link
            to="/scan"
            className="btn btn-primary px-4 py-2 text-xs shadow-glow-brand"
          >
            <Plus className="h-4 w-4" />
            Start New Hunt
          </Link>
        </div>

        <div className="panel p-6">
          <h2 className="text-base font-semibold text-carbon-100 mb-4 flex items-center gap-2">
            <Radio className="h-4 w-4 text-brand-400 animate-pulse" />
            Available Scan Campaigns
          </h2>
          {selectableExperiments.length > 0 ? (
            <div className="divide-y divide-carbon-700/40">
              {selectableExperiments.map((exp) => (
                <button
                  key={exp.id}
                  onClick={() => setActiveExperiment(exp.id)}
                  className="w-full text-left py-3.5 flex items-center justify-between hover:bg-carbon-850/60 px-4 rounded-xl transition group"
                >
                  <div>
                    <div className="font-semibold text-carbon-100 group-hover:text-brand-200 transition">
                      #{exp.id} {exp.name || 'Unnamed Experiment'}
                    </div>
                    <div className="text-xs text-carbon-400 mt-0.5 flex items-center gap-2">
                      <span className="font-mono text-carbon-500">{exp.strategy}</span>
                      <span>·</span>
                      <span>{formatFullDate(exp.created_at)}</span>
                    </div>
                  </div>
                  <Badge value={exp.status} />
                </button>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-carbon-400 text-sm">
              <p>No scans are available to monitor yet.</p>
              <Link to="/scan" className="btn btn-ghost mt-4 inline-flex text-xs">
                Launch a scan first
              </Link>
            </div>
          )}
        </div>
      </div>
    );
  }

  const stats = monitor.stats;
  const activeCount = stats.running + stats.queued + stats.pending;
  const hitCount = monitor.performance_metrics?.oracle_hit_count ?? monitor.recent_findings.length;
  const metrics = monitor.performance_metrics;
  const waf = monitor.waf_status;
  const surface = monitor.attack_surface;
  const progressPct = monitor.progress_percent;
  const ring = 2 * Math.PI * 26;

  return (
    <div className={`space-y-6 transition-all ${zenMode ? 'fixed inset-0 z-50 overflow-y-auto bg-carbon-900 p-6' : 'mx-auto max-w-7xl p-4 sm:p-6'}`}>
      {/* Live Monitor Header & Command Bar */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-500/20 text-brand-300 border border-brand-500/30">
            <Zap className="h-5 w-5 animate-pulse" />
          </span>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-bold font-display tracking-tight text-carbon-100">
                Live Fuzz Monitor
              </h1>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-wider text-emerald-300">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Live Stream
              </span>
            </div>
            <p className="text-xs text-carbon-400 mt-0.5">
              {monitor.target.name} · <span className="font-mono text-carbon-300">{monitor.target.base_url}</span>
            </p>
          </div>
        </div>

        {/* Global Action Bar */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Experiment Switcher Dropdown */}
          <select
            value={activeExperimentId}
            onChange={(e) => setActiveExperiment(Number(e.target.value))}
            className="rounded-lg border border-carbon-700 bg-carbon-950/80 px-3 py-1.5 text-xs text-carbon-200 font-semibold focus:border-brand-500 focus:outline-none"
          >
            {selectableExperiments.map((exp) => (
              <option key={exp.id} value={exp.id}>
                #{exp.id} {exp.name || `Hunt #${exp.id}`} ({exp.status})
              </option>
            ))}
          </select>

          {/* Polling Speed Selector */}
          <div className="flex items-center rounded-lg border border-carbon-700/70 bg-carbon-950/70 p-0.5 text-xs font-mono">
            {(['1s', '2s', '5s', 'paused'] as const).map((rate) => (
              <button
                key={rate}
                onClick={() => setPollingRate(rate)}
                className={`rounded px-2 py-1 text-[10px] font-semibold transition ${
                  pollingRate === rate
                    ? 'bg-brand-600 text-white shadow-glow-brand'
                    : 'text-carbon-400 hover:text-carbon-200'
                }`}
                title={`Telemetry refresh rate: ${rate}`}
              >
                {rate === 'paused' ? '⏸' : rate}
              </button>
            ))}
          </div>

          {/* Audio Chime Toggle */}
          <button
            type="button"
            onClick={() => setAudioEnabled((v) => !v)}
            className={`btn btn-ghost px-2.5 py-1.5 text-xs ${audioEnabled ? 'text-brand-300 border-brand-500/40 bg-brand-500/10' : 'text-carbon-400'}`}
            title={audioEnabled ? 'Oracle Hit audio notification enabled' : 'Audio alerts muted'}
          >
            {audioEnabled ? <Volume2 className="h-3.5 w-3.5" /> : <VolumeX className="h-3.5 w-3.5" />}
          </button>

          {/* Pause / Resume Button */}
          {monitor.experiment.status === 'running' ? (
            <button
              type="button"
              disabled={pauseMutation.isPending}
              onClick={() => pauseMutation.mutate(monitor.experiment.id)}
              className="btn btn-ghost px-3 py-1.5 text-xs text-amber-300 border-amber-500/30 hover:bg-amber-500/15"
            >
              <Pause className="h-3.5 w-3.5 mr-1" />
              {pauseMutation.isPending ? 'Pausing…' : 'Pause'}
            </button>
          ) : (
            <button
              type="button"
              disabled={resumeMutation.isPending}
              onClick={() => resumeMutation.mutate(monitor.experiment.id)}
              className="btn btn-primary px-3 py-1.5 text-xs shadow-glow-brand"
            >
              <Play className="h-3.5 w-3.5 mr-1" />
              {resumeMutation.isPending ? 'Resuming…' : 'Resume'}
            </button>
          )}

          {/* Custom Payload Injector Trigger */}
          <button
            type="button"
            onClick={() => setShowInjectModal(true)}
            className="btn btn-ghost px-3 py-1.5 text-xs text-fuchsia-300 border-fuchsia-500/30 hover:bg-fuchsia-500/10"
          >
            <Plus className="h-3.5 w-3.5 mr-1" />
            Inject Payload
          </button>

          {/* Export Telemetry */}
          <button
            type="button"
            onClick={exportTelemetryJson}
            className="btn btn-ghost px-2.5 py-1.5 text-xs text-carbon-300 hover:text-white"
            title="Export raw telemetry snapshot (JSON)"
          >
            <Download className="h-3.5 w-3.5" />
          </button>

          {/* Zen Mode Toggle */}
          <button
            type="button"
            onClick={() => setZenMode((v) => !v)}
            className="btn btn-ghost px-2.5 py-1.5 text-xs text-carbon-300 hover:text-white"
            title={zenMode ? 'Exit Zen Mode' : 'Fullscreen / Zen Mode'}
          >
            {zenMode ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
          </button>

          <Link
            to="/scan"
            className="btn btn-ghost px-3 py-1.5 text-xs text-carbon-300 hover:text-white"
          >
            New Scan
          </Link>
        </div>
      </div>

      {/* River-to-Sea Fluid Telemetry & Micro-State Pipeline */}
      <RiverFlowMonitor monitor={monitor} />

      {/* Live Engine HUD & Velocity Banner */}
      <section className="panel scanline p-5">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-center">
          {/* Stage & AI Decision */}
          <div className="lg:col-span-8 space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="font-display text-lg font-bold tracking-tight text-carbon-100 capitalize">
                {monitor.stage.replace(/_/g, ' ')}
              </h2>
              <Badge value={monitor.experiment.status} />
              {isRefreshing && (
                <span className="font-mono text-[10px] text-brand-400 flex items-center gap-1">
                  <Activity className="h-3 w-3 animate-spin" /> syncing…
                </span>
              )}
            </div>
            <p className="text-xs text-carbon-300">{monitor.stage_detail}</p>

            {/* Engine Decision Pill */}
            <div className="flex items-start gap-2.5 rounded-xl border border-brand-500/25 bg-brand-500/10 px-3.5 py-2.5">
              <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-brand-300 mt-0.5">
                AI ENGINE
              </span>
              <p className="text-xs font-medium text-brand-100 leading-relaxed">
                {monitor.recent_findings.length > 0
                  ? `Vulnerabilities confirmed on target! Fuzzer is executing targeted evasion variations.`
                  : stats.running > 0
                  ? `Dispatching prioritized browser test cases against reflected DOM contexts.`
                  : stats.queued > 0
                  ? `Engine queued ${stats.queued} payloads based on reflection priority.`
                  : `Autonomous scan cycle active. Monitoring reflections, filters, and browser execution results.`}
              </p>
            </div>
          </div>

          {/* Radial Gauge & Rate Limiter Gauge */}
          <div className="lg:col-span-4 flex items-center justify-end gap-6 border-t lg:border-t-0 lg:border-l border-carbon-700/60 pt-4 lg:pt-0 lg:pl-6">
            {/* Rate Limiter Mini HUD */}
            {monitor.throttle_status && (
              <div className="text-right space-y-1">
                <div className="text-[10px] font-mono uppercase text-carbon-400">Rate Limiter</div>
                <div className="font-mono text-sm font-bold text-carbon-100">
                  {(monitor.throttle_status.current_delay_ms / 1000).toFixed(1)}s delay
                </div>
                <div className="text-[10px] font-mono text-carbon-400">
                  {monitor.throttle_status.requests_last_minute}/{monitor.throttle_status.max_requests_per_minute} req/m
                </div>
                <button
                  type="button"
                  onClick={() => resetThrottleMutation.mutate(monitor.experiment.id)}
                  className="text-[10px] font-mono text-brand-300 hover:underline"
                >
                  Reset Throttle
                </button>
              </div>
            )}

            {/* Radial Progress Ring */}
            <div className="relative flex h-20 w-20 flex-shrink-0 items-center justify-center">
              <svg viewBox="0 0 64 64" className="h-20 w-20 -rotate-90">
                <circle cx="32" cy="32" r="26" fill="none" stroke="rgba(42,56,84,0.7)" strokeWidth="6" />
                <circle
                  cx="32"
                  cy="32"
                  r="26"
                  fill="none"
                  stroke="url(#liveRingGrad)"
                  strokeWidth="6"
                  strokeLinecap="round"
                  strokeDasharray={ring}
                  strokeDashoffset={ring - (ring * progressPct) / 100}
                  className="transition-all duration-500"
                />
                <defs>
                  <linearGradient id="liveRingGrad" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#7B68FF" />
                    <stop offset="100%" stopColor="#10B981" />
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-display text-lg font-bold tabnum text-carbon-100">{progressPct}%</span>
                <span className="text-[9px] uppercase tracking-wider text-carbon-400">done</span>
              </div>
            </div>
          </div>
        </div>

        {/* Linear Progress bar */}
        <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-carbon-800">
          <div
            className="h-2 rounded-full bg-gradient-to-r from-brand-500 via-fuchsia-500 to-emerald-500 transition-all duration-500"
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </section>

      {/* 6 Cyber Telemetry KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard
          size="sm"
          tone="primary"
          label="Active Queue"
          value={activeCount}
          caption={`${stats.running} running · ${stats.queued} queued`}
        />
        <KpiCard
          size="sm"
          tone="success"
          label="Completed"
          value={stats.completed}
          caption={metrics?.throughput_per_min ? `${metrics.throughput_per_min} req/min` : 'Velocity'}
        />
        <KpiCard
          size="sm"
          tone={hitCount > 0 ? 'danger' : 'default'}
          label="Oracle Hits"
          value={hitCount}
          caption={metrics?.hit_rate_percent !== undefined ? `${metrics.hit_rate_percent}% Hit Rate` : 'Confirmed'}
        />
        <KpiCard
          size="sm"
          tone="warning"
          label="Avg Latency"
          value={metrics?.avg_duration_ms ? `${metrics.avg_duration_ms}ms` : '–'}
          caption={metrics?.min_duration_ms ? `${metrics.min_duration_ms}ms – ${metrics.max_duration_ms}ms` : 'Browser exec'}
        />
        <KpiCard
          size="sm"
          tone="default"
          label="Discovered Surface"
          value={surface?.param_count ?? totalContextReflections}
          caption={`${surface?.endpoint_count ?? '–'} endpoints · ${surface?.context_count ?? totalContextReflections} contexts`}
        />
        <KpiCard
          size="sm"
          tone={waf?.waf_detected ? 'warning' : 'success'}
          label="Defense State"
          value={waf?.waf_detected ? 'WAF Active' : 'Clean / No WAF'}
          caption={waf?.sanitizer_detected || (waf?.blocked_tokens_count ? `${waf.blocked_tokens_count} blocked rules` : 'Direct')}
        />
      </div>

      {/* Tab Navigation Workspace */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-carbon-700/60 pb-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setActiveTab('checks')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'checks'
                ? 'bg-brand-600 text-white shadow-glow-brand'
                : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
            }`}
          >
            <Zap className="h-3.5 w-3.5" />
            Live Checks & Stream
            <span className="rounded-full bg-black/30 px-1.5 py-0.2 font-mono text-[10px]">
              {filteredChecks.length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('browser')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'browser'
                ? 'bg-brand-600 text-white shadow-glow-brand'
                : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
            }`}
          >
            <Cpu className="h-3.5 w-3.5" />
            Browser Telemetry & DOM
            <span className="rounded-full bg-black/30 px-1.5 py-0.2 font-mono text-[10px]">
              {monitor.recent_executions.length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('surface')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'surface'
                ? 'bg-brand-600 text-white shadow-glow-brand'
                : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            Surface & Contexts
            <span className="rounded-full bg-black/30 px-1.5 py-0.2 font-mono text-[10px]">
              {Object.keys(contextStats).length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('findings')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'findings'
                ? 'bg-rose-600 text-white shadow-glow-rose'
                : 'text-carbon-400 hover:bg-carbon-800 hover:text-rose-300'
            }`}
          >
            <Bug className="h-3.5 w-3.5" />
            Confirmed Exploits
            <span className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] ${monitor.recent_findings.length > 0 ? 'bg-rose-500 text-white font-bold' : 'bg-black/30 text-carbon-400'}`}>
              {monitor.recent_findings.length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('brain')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition ${
              activeTab === 'brain'
                ? 'bg-brand-600 text-white shadow-glow-brand'
                : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
            }`}
          >
            <Sparkles className="h-3.5 w-3.5" />
            Autonomous Log
            <span className="rounded-full bg-black/30 px-1.5 py-0.2 font-mono text-[10px]">
              {monitor.activity_log.length}
            </span>
          </button>
        </div>

        {/* Global Live Search Bar */}
        <div className="relative min-w-[220px]">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-carbon-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search payload, param, logs…"
            className="w-full rounded-lg border border-carbon-700 bg-carbon-950/80 py-1.5 pl-8 pr-7 text-xs text-carbon-100 placeholder-carbon-500 focus:border-brand-500 focus:outline-none"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-carbon-400 hover:text-carbon-100"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>
      </div>

      {/* Live Browser Vision Stream */}
      <div className="mb-6">
        <LiveBrowserPreview />
      </div>

      {/* TAB 1: Live Checks & Stream */}
      {activeTab === 'checks' && (
        <div className="space-y-4">
          {/* Filter Pills Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-carbon-850/40 p-3 rounded-xl border border-carbon-700/60">
            <div className="flex flex-wrap items-center gap-1.5">
              {(['all', 'running', 'queued', 'completed', 'failed'] as const).map((status) => (
                <button
                  key={status}
                  onClick={() => setStatusFilter(status)}
                  className={`rounded-lg px-2.5 py-1 text-xs font-semibold uppercase tracking-wider transition ${
                    statusFilter === status
                      ? 'bg-brand-500 text-white shadow-glow-brand'
                      : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>

            {/* Context Filter Dropdown */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-carbon-400">Context:</span>
              <select
                value={contextFilter}
                onChange={(e) => setContextFilter(e.target.value)}
                className="rounded-lg border border-carbon-700 bg-carbon-950/80 px-2.5 py-1 text-xs text-carbon-200 focus:border-brand-500 focus:outline-none"
              >
                <option value="all">All Contexts ({totalContextReflections})</option>
                {Object.entries(contextStats).map(([ctx, count]) => (
                  <option key={ctx} value={ctx}>
                    {ctx} ({count})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Interactive Live Checks Table */}
          <div className="panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-carbon-700/50">
                <thead className="bg-carbon-850/60">
                  <tr>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-carbon-400">Status</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-carbon-400">Target Input & Context</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-carbon-400">Payload Preview</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-carbon-400">Priority</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-carbon-400">Updated</th>
                    <th className="px-4 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-carbon-400">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-carbon-700/40">
                  {filteredChecks.map((check) => {
                    const isSelected = selectedCheck?.id === check.id;
                    const exploitUrl = getExploitUrl(check.endpoint_url, check.param_name, check.payload || check.payload_preview);

                    return (
                      <tr
                        key={check.id}
                        onClick={() => setSelectedCheck(isSelected ? null : check)}
                        className={`transition cursor-pointer ${
                          isSelected ? 'bg-brand-500/10 border-l-4 border-l-brand-500' : 'hover:bg-carbon-800/40'
                        }`}
                      >
                        <td className="whitespace-nowrap px-4 py-3.5">
                          <Badge value={check.status} />
                        </td>
                        <td className="px-4 py-3.5 text-xs">
                          <div className="font-semibold text-carbon-100 flex items-center gap-1.5">
                            <span>{check.param_name}</span>
                            <span className="font-mono text-[10px] text-carbon-400">({check.param_location})</span>
                          </div>
                          <div className="max-w-xs truncate font-mono text-[10px] text-carbon-400 mt-0.5">
                            {check.endpoint_method} {check.endpoint_url}
                          </div>
                          {check.context_type && (
                            <div className="mt-1 font-mono text-[10px] text-brand-300 font-semibold flex items-center gap-1">
                              <Code className="h-3 w-3" />
                              {check.context_type}
                              {check.context_tag && <span className="text-carbon-400">&lt;{check.context_tag}&gt;</span>}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3.5 max-w-sm">
                          <div className="terminal p-2 text-xs text-carbon-200 font-mono break-all line-clamp-2">
                            {check.payload || check.payload_preview}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-4 py-3.5 font-mono text-xs text-carbon-300">
                          P-{check.priority}
                          {check.attempt_count ? <span className="text-carbon-500 text-[10px] block">try #{check.attempt_count}</span> : null}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3.5 font-mono text-[11px] text-carbon-400">
                          {formatTime(check.updated_at)}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3.5 text-right" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1.5">
                            {exploitUrl && (
                              <a
                                href={exploitUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="btn btn-ghost px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/10"
                                title="Launch testable payload in browser"
                              >
                                <ExternalLink className="h-3 w-3 mr-1" />
                                Launch
                              </a>
                            )}
                            <button
                              type="button"
                              onClick={() => copyToClipboard(check.payload || check.payload_preview, `check-${check.id}`)}
                              className="btn btn-ghost px-2 py-1 text-[11px] text-carbon-300 hover:text-white"
                              title="Copy raw payload"
                            >
                              <Copy className="h-3 w-3 mr-1" />
                              {copiedKey === `check-${check.id}` ? 'Copied!' : 'Copy'}
                            </button>
                            <button
                              type="button"
                              disabled={retryCheckMutation.isPending}
                              onClick={() => retryCheckMutation.mutate({ expId: activeExperimentId!, checkId: check.id })}
                              className="btn btn-ghost px-2 py-1 text-[11px] text-brand-300 hover:bg-brand-500/10"
                              title="Re-queue test case"
                            >
                              <RotateCcw className="h-3 w-3" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredChecks.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-12 text-center text-sm text-carbon-400">
                        No payload checks match the filter or search query.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Slide-out / Expandable Payload Inspector Drawer */}
          {selectedCheck && (
            <div className="panel p-6 border-brand-500/40 bg-carbon-850/80 animate-rise space-y-4">
              <div className="flex items-center justify-between border-b border-carbon-700/60 pb-3">
                <div className="flex items-center gap-2">
                  <Badge value={selectedCheck.status} />
                  <h3 className="font-display text-sm font-bold text-carbon-100">
                    Payload Inspector · Check #{selectedCheck.id}
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedCheck(null)}
                  className="text-carbon-400 hover:text-carbon-100"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">Full Raw Payload</label>
                  <div className="terminal mt-1.5 p-3 text-xs text-emerald-300 select-all font-mono break-all max-h-36 overflow-y-auto">
                    {selectedCheck.payload || selectedCheck.payload_preview}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => copyToClipboard(selectedCheck.payload || selectedCheck.payload_preview, 'drawer-raw')}
                      className="btn btn-ghost px-2.5 py-1 text-xs"
                    >
                      <Copy className="h-3 w-3 mr-1" />
                      {copiedKey === 'drawer-raw' ? 'Copied Raw!' : 'Copy Raw Payload'}
                    </button>
                    {getExploitUrl(selectedCheck.endpoint_url, selectedCheck.param_name, selectedCheck.payload || selectedCheck.payload_preview) && (
                      <a
                        href={getExploitUrl(selectedCheck.endpoint_url, selectedCheck.param_name, selectedCheck.payload || selectedCheck.payload_preview)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="btn btn-primary px-2.5 py-1 text-xs shadow-glow-brand"
                      >
                        <ExternalLink className="h-3 w-3 mr-1" />
                        Launch in Browser
                      </a>
                    )}
                  </div>
                </div>

                {/* Encoding Variations */}
                <div>
                  <label className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">Encoding Variations</label>
                  <div className="mt-1.5 space-y-2 text-xs">
                    <div className="rounded-lg border border-carbon-700 bg-carbon-950/70 p-2 font-mono">
                      <span className="text-carbon-400 text-[10px] block">URL Encoded:</span>
                      <code className="text-brand-300 break-all select-all text-[11px]">
                        {encodeURIComponent(selectedCheck.payload || selectedCheck.payload_preview)}
                      </code>
                    </div>
                    <div className="rounded-lg border border-carbon-700 bg-carbon-950/70 p-2 font-mono">
                      <span className="text-carbon-400 text-[10px] block">HTML Entities:</span>
                      <code className="text-amber-300 break-all select-all text-[11px]">
                        {toHtmlEntity(selectedCheck.payload || selectedCheck.payload_preview)}
                      </code>
                    </div>
                    <div className="rounded-lg border border-carbon-700 bg-carbon-950/70 p-2 font-mono">
                      <span className="text-carbon-400 text-[10px] block">Hex Escaped:</span>
                      <code className="text-fuchsia-300 break-all select-all text-[11px]">
                        {toHexEscape(selectedCheck.payload || selectedCheck.payload_preview)}
                      </code>
                    </div>
                    <div className="rounded-lg border border-carbon-700 bg-carbon-950/70 p-2 font-mono">
                      <span className="text-carbon-400 text-[10px] block">Unicode Escaped:</span>
                      <code className="text-emerald-300 break-all select-all text-[11px]">
                        {toUnicodeEscape(selectedCheck.payload || selectedCheck.payload_preview)}
                      </code>
                    </div>
                  </div>
                </div>
              </div>

              {/* Context Breakdown */}
              <div className="border-t border-carbon-700/60 pt-3 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div>
                  <span className="text-carbon-400 block text-[11px]">Reflection Context:</span>
                  <span className="font-mono font-bold text-brand-300">{selectedCheck.context_type || 'UNKNOWN'}</span>
                </div>
                <div>
                  <span className="text-carbon-400 block text-[11px]">Target Parameter:</span>
                  <span className="font-mono text-carbon-200">{selectedCheck.param_name} ({selectedCheck.param_location})</span>
                </div>
                <div>
                  <span className="text-carbon-400 block text-[11px]">Endpoint URL:</span>
                  <span className="font-mono text-carbon-300 truncate block">{selectedCheck.endpoint_url}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Browser Telemetry & DOM */}
      {activeTab === 'browser' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Execution Runs List */}
          <div className="lg:col-span-5 panel divide-y divide-carbon-700/40 max-h-[700px] overflow-y-auto">
            <div className="p-4 bg-carbon-850/60 sticky top-0 z-10 border-b border-carbon-700/60 flex items-center justify-between">
              <h3 className="font-display text-sm font-bold text-carbon-100">
                Recent Browser Executions ({filteredExecutions.length})
              </h3>
              <span className="text-[11px] font-mono text-carbon-400">Headless Playwright</span>
            </div>

            {filteredExecutions.map((exec) => {
              const isSelected = selectedExecution?.id === exec.id;
              return (
                <div
                  key={exec.id}
                  onClick={() => setSelectedExecution(exec)}
                  className={`p-4 cursor-pointer transition ${
                    isSelected ? 'bg-brand-500/15 border-l-4 border-l-brand-500' : 'hover:bg-carbon-850/60'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <Badge value={exec.oracle_status} />
                    <span className="font-mono text-[11px] text-carbon-400">
                      {exec.duration_ms ? `${exec.duration_ms}ms` : '–'} · {formatTime(exec.executed_at)}
                    </span>
                  </div>
                  <div className="mt-2 text-xs font-semibold text-carbon-100">
                    Param: <span className="font-mono text-brand-300">{exec.param_name || '–'}</span>
                  </div>
                  <div className="mt-0.5 truncate font-mono text-[10px] text-carbon-400">
                    {exec.endpoint_url}
                  </div>
                  {exec.logs && (
                    <div className="mt-2 text-[11px] text-carbon-300 line-clamp-1 italic">
                      {exec.logs}
                    </div>
                  )}
                </div>
              );
            })}

            {filteredExecutions.length === 0 && (
              <div className="p-8 text-center text-sm text-carbon-400">
                Browser executions will appear once payload checks run.
              </div>
            )}
          </div>

          {/* Right: Selected Execution Deep-Dive Inspector */}
          <div className="lg:col-span-7 panel p-6 space-y-5">
            {selectedExecution ? (
              <>
                <div className="flex items-center justify-between border-b border-carbon-700/60 pb-3">
                  <div>
                    <h3 className="font-display text-base font-bold text-carbon-100 flex items-center gap-2">
                      <Cpu className="h-4 w-4 text-brand-400" />
                      Execution Inspector · Run #{selectedExecution.id}
                    </h3>
                    <p className="text-xs text-carbon-400 mt-0.5 font-mono">
                      Test Case #{selectedExecution.test_case_id} · {formatFullDate(selectedExecution.executed_at)}
                    </p>
                  </div>
                  <Badge value={selectedExecution.oracle_status} />
                </div>

                {/* Duration & Worker Metadata */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-carbon-850/40 p-3 rounded-xl border border-carbon-700/60 text-xs">
                  <div>
                    <span className="text-carbon-400 block text-[10px]">Latency</span>
                    <span className="font-mono font-bold text-emerald-300">{selectedExecution.duration_ms ? `${selectedExecution.duration_ms}ms` : '–'}</span>
                  </div>
                  <div>
                    <span className="text-carbon-400 block text-[10px]">Worker ID</span>
                    <span className="font-mono text-carbon-200 truncate block">{selectedExecution.browser_worker_id || 'playwright-pool-1'}</span>
                  </div>
                  <div>
                    <span className="text-carbon-400 block text-[10px]">Attempt</span>
                    <span className="font-mono text-carbon-200">#{selectedExecution.attempt_no || 1}</span>
                  </div>
                  <div>
                    <span className="text-carbon-400 block text-[10px]">Oracle Result</span>
                    <span className="font-mono font-bold uppercase text-brand-300">{selectedExecution.oracle_status}</span>
                  </div>
                </div>

                {/* Tested Payload */}
                {selectedExecution.payload && (
                  <div>
                    <label className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">Tested Payload</label>
                    <div className="terminal mt-1.5 p-3 text-xs text-carbon-200 font-mono break-all">
                      {selectedExecution.payload}
                    </div>
                  </div>
                )}

                {/* Browser Console Logs */}
                <div>
                  <label className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">Browser Console Logs & Callbacks</label>
                  <pre className="terminal mt-1.5 p-3 text-xs font-mono text-carbon-300 whitespace-pre-wrap max-h-48 overflow-y-auto">
                    {selectedExecution.raw_logs || selectedExecution.logs || 'Browser executed cleanly without console messages.'}
                  </pre>
                </div>

                {/* DOM Snapshot Viewer */}
                {selectedExecution.dom_snapshot && (
                  <div>
                    <label className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">Live DOM Snapshot</label>
                    <pre className="terminal mt-1.5 p-3 text-xs font-mono text-emerald-300 whitespace-pre-wrap max-h-56 overflow-y-auto">
                      {selectedExecution.dom_snapshot}
                    </pre>
                  </div>
                )}

                {/* Screenshot Preview */}
                {selectedExecution.screenshot_path && (
                  <div>
                    <label className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">Trigger Screenshot</label>
                    <div
                      onClick={() => setShowScreenshotModal(selectedExecution.screenshot_path!)}
                      className="mt-1.5 cursor-zoom-in rounded-lg border border-carbon-700 overflow-hidden max-h-48 bg-black group relative"
                    >
                      <img
                        src={`/api/v1/results/findings/${selectedExecution.test_case_id}/screenshot`}
                        alt="Browser execution"
                        className="w-full h-auto object-cover group-hover:scale-[1.02] transition duration-200"
                      />
                      <span className="absolute bottom-2 right-2 rounded bg-black/70 px-2 py-0.5 text-[10px] text-white">
                        Click to Zoom
                      </span>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="py-24 text-center text-sm text-carbon-400">
                <Cpu className="h-10 w-10 mx-auto mb-2 opacity-30" />
                Select any browser execution run on the left to inspect its telemetry, DOM state, and console output.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: Surface & Contexts Matrix */}
      {activeTab === 'surface' && (
        <div className="space-y-6">
          {/* Contexts Distribution Grid */}
          <section className="panel p-6">
            <h3 className="font-display text-base font-bold text-carbon-100 mb-4 flex items-center gap-2">
              <Layers className="h-4 w-4 text-brand-400" />
              Discovered Injection Contexts ({totalContextReflections} total reflections)
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {Object.entries(contextStats).map(([ctx, count]) => {
                const pct = totalContextReflections ? Math.round((count / totalContextReflections) * 100) : 0;
                return (
                  <div key={ctx} className="rounded-xl border border-carbon-700/60 bg-carbon-850/40 p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-brand-300">{ctx}</span>
                      <span className="font-mono text-xs font-semibold text-carbon-100">{count} ({pct}%)</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-carbon-800 overflow-hidden">
                      <div className="h-1.5 rounded-full bg-brand-500" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
              {Object.keys(contextStats).length === 0 && (
                <div className="col-span-3 text-center py-8 text-sm text-carbon-400">
                  Reflection contexts are currently being profiled.
                </div>
              )}
            </div>
          </section>

          {/* Defense & WAF Profile Summary */}
          {waf && (
            <section className="panel p-6">
              <h3 className="font-display text-base font-bold text-carbon-100 mb-4 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                Target Filter & WAF Profiling
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="rounded-xl border border-carbon-700/60 bg-carbon-850/40 p-4">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">WAF Status</span>
                  <div className="mt-1 text-sm font-semibold text-carbon-100 flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${waf.waf_detected ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                    {waf.waf_detected ? 'WAF Protection Detected' : 'No WAF Detected (Direct Reachable)'}
                  </div>
                </div>
                <div className="rounded-xl border border-carbon-700/60 bg-carbon-850/40 p-4">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">Blocked Token Rules</span>
                  <div className="mt-1 text-sm font-semibold text-rose-300 font-mono">
                    {waf.blocked_tokens_count} tokens filtered
                  </div>
                  {waf.sample_blocked_tokens.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {waf.sample_blocked_tokens.map((token, i) => (
                        <span key={i} className="rounded bg-rose-500/15 text-rose-200 text-[10px] px-1.5 py-0.5 font-mono">
                          {token}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="rounded-xl border border-carbon-700/60 bg-carbon-850/40 p-4">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-carbon-400">Allowed Token Rules</span>
                  <div className="mt-1 text-sm font-semibold text-emerald-300 font-mono">
                    {waf.allowed_tokens_count} tokens bypass
                  </div>
                  {waf.sample_allowed_tokens.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {waf.sample_allowed_tokens.map((token, i) => (
                        <span key={i} className="rounded bg-emerald-500/15 text-emerald-200 text-[10px] px-1.5 py-0.5 font-mono">
                          {token}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </section>
          )}
        </div>
      )}

      {/* TAB 4: Confirmed Exploits Desk */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {monitor.recent_findings.map((finding) => {
              const testUrl = getExploitUrl(finding.endpoint_url, finding.param_name, finding.payload_preview);

              return (
                <div
                  key={finding.id}
                  className="panel p-5 border-rose-500/40 bg-carbon-850/70 shadow-glow-rose space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Badge value={finding.severity} />
                      <span className="font-bold text-xs uppercase text-brand-200 font-mono">
                        {finding.vuln_type}
                      </span>
                    </div>
                    <span className="font-mono text-[11px] text-carbon-400">{formatTime(finding.created_at)}</span>
                  </div>

                  <div>
                    <div className="text-sm font-semibold text-carbon-100">
                      Parameter: <span className="rounded bg-rose-500/15 px-1.5 py-0.5 font-mono text-rose-200">{finding.param_name}</span>
                    </div>
                    <div className="text-xs font-mono text-carbon-400 truncate mt-0.5">{finding.endpoint_url}</div>
                  </div>

                  {/* PoC Box */}
                  <div>
                    <label className="text-[10px] font-bold uppercase tracking-wider text-carbon-400">Exploit Proof of Concept</label>
                    <div className="terminal mt-1 p-2.5 text-xs text-emerald-300 font-mono select-all break-all max-h-24 overflow-y-auto">
                      {finding.payload_preview}
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-wrap gap-2 pt-2 border-t border-carbon-700/60">
                    {testUrl && (
                      <a
                        href={testUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="btn btn-primary px-3 py-1.5 text-xs shadow-glow-brand"
                      >
                        <ExternalLink className="h-3 w-3 mr-1" />
                        Launch in Target
                      </a>
                    )}
                    <button
                      type="button"
                      onClick={() => copyToClipboard(testUrl, `finding-url-${finding.id}`)}
                      className="btn btn-ghost px-2.5 py-1.5 text-xs text-carbon-200 hover:text-white"
                    >
                      <Copy className="h-3 w-3 mr-1" />
                      {copiedKey === `finding-url-${finding.id}` ? 'URL Copied!' : 'Copy URL'}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        const reportMd = `### Vulnerability Report: ${finding.vuln_type.toUpperCase()}\n- **Target**: ${finding.endpoint_url}\n- **Parameter**: ${finding.param_name}\n- **Severity**: ${finding.severity}\n- **PoC**: \`${finding.payload_preview}\`\n- **Exploit URL**: ${testUrl}`;
                        copyToClipboard(reportMd, `finding-md-${finding.id}`);
                      }}
                      className="btn btn-ghost px-2.5 py-1.5 text-xs text-brand-300 hover:bg-brand-500/10"
                    >
                      <Sparkles className="h-3 w-3 mr-1" />
                      {copiedKey === `finding-md-${finding.id}` ? 'Report Copied!' : 'Copy Report MD'}
                    </button>
                  </div>
                </div>
              );
            })}

            {monitor.recent_findings.length === 0 && (
              <div className="col-span-2 panel p-12 text-center text-sm text-carbon-400">
                <ShieldCheck className="h-10 w-10 mx-auto mb-2 opacity-30 text-emerald-400" />
                No confirmed findings yet. Confirmed oracle hits and browser callbacks will appear here with 1-click exploit triggers.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: Autonomous Brain Decisions */}
      {activeTab === 'brain' && (
        <section className="panel p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-carbon-700/60 pb-3">
            <div>
              <h3 className="font-display text-base font-bold text-carbon-100 flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-brand-400" />
                Autonomous Engine Decision Feed
              </h3>
              <p className="text-xs text-carbon-400 mt-0.5">
                Real-time reasoning logs explaining why payloads were selected, queued, or executed.
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                const logsText = monitor.activity_log.map((l) => `[${l.timestamp}] [${l.level.toUpperCase()}] [${l.phase}] ${l.message} ${l.detail || ''}`).join('\n');
                copyToClipboard(logsText, 'all-logs');
              }}
              className="btn btn-ghost px-2.5 py-1 text-xs"
            >
              <Copy className="h-3 w-3 mr-1" />
              {copiedKey === 'all-logs' ? 'Logs Copied!' : 'Copy All Logs'}
            </button>
          </div>
          <div className="max-h-[600px] overflow-y-auto">
            <EngineLog events={monitor.activity_log} />
          </div>
        </section>
      )}

      {/* MODAL: Custom Payload Injector */}
      {showInjectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
          <div className="panel w-full max-w-xl p-6 space-y-4 bg-carbon-900 border-brand-500/50 shadow-glow-brand">
            <div className="flex items-center justify-between border-b border-carbon-700/60 pb-3">
              <h3 className="font-display text-base font-bold text-carbon-100 flex items-center gap-2">
                <Zap className="h-5 w-5 text-brand-400" />
                On-the-Fly Payload Injector
              </h3>
              <button
                type="button"
                onClick={() => setShowInjectModal(false)}
                className="text-carbon-400 hover:text-carbon-100"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!injectPayloadText.trim()) return;
                const sampleCheck = monitor.recent_checks[0];
                injectPayloadMutation.mutate({
                  endpoint_id: injectEndpointId || sampleCheck?.endpoint_id || 1,
                  param_id: injectParamId || 1,
                  payload: injectPayloadText.trim(),
                });
              }}
              className="space-y-4"
            >
              <div>
                <label className="text-xs font-bold uppercase tracking-wider text-carbon-300 block mb-1">
                  Target Parameter & Endpoint
                </label>
                <select
                  value={`${injectEndpointId}-${injectParamId}`}
                  onChange={(e) => {
                    const [epId, pId] = e.target.value.split('-').map(Number);
                    setInjectEndpointId(epId);
                    setInjectParamId(pId);
                  }}
                  className="w-full rounded-lg border border-carbon-700 bg-carbon-950 px-3 py-2 text-xs font-mono text-carbon-100 focus:border-brand-500 focus:outline-none"
                >
                  {monitor.recent_checks.map((check) => (
                    <option key={check.id} value={`${check.endpoint_id}-${check.id}`}>
                      {check.param_name} ({check.context_type || 'default'}) — {check.endpoint_method} {check.endpoint_url}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs font-bold uppercase tracking-wider text-carbon-300 block mb-1">
                  Payload String
                </label>
                <textarea
                  required
                  rows={3}
                  value={injectPayloadText}
                  onChange={(e) => setInjectPayloadText(e.target.value)}
                  placeholder={'<script>alert(1)</script> or "><svg onload=alert(1)>'}
                  className="w-full rounded-lg border border-carbon-700 bg-carbon-950 p-3 text-xs font-mono text-carbon-100 placeholder-carbon-500 focus:border-brand-500 focus:outline-none"
                />
              </div>

              {/* Quick Presets */}
              <div className="space-y-1.5">
                <span className="text-[10px] uppercase font-bold text-carbon-400">Quick Presets:</span>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    '<script>alert(document.domain)</script>',
                    '"><svg onload=alert(1)>',
                    'javascript:alert(1)',
                    '" autofocus onfocus=alert(1) x="',
                    "'-alert(1)-'",
                    '{{7*7}}',
                    '${alert(1)}',
                  ].map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => setInjectPayloadText(preset)}
                      className="rounded bg-carbon-800 px-2 py-0.5 font-mono text-[10px] text-brand-300 hover:bg-carbon-700"
                    >
                      {preset}
                    </button>
                  ))}
                </div>
              </div>

              {injectSuccessMsg && (
                <div className="rounded-lg bg-emerald-500/20 border border-emerald-500/40 p-2.5 text-xs text-emerald-200 font-semibold">
                  {injectSuccessMsg}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2 border-t border-carbon-700/60">
                <button
                  type="button"
                  onClick={() => setShowInjectModal(false)}
                  className="btn btn-ghost px-3 py-1.5 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={injectPayloadMutation.isPending}
                  className="btn btn-primary px-4 py-1.5 text-xs shadow-glow-brand"
                >
                  {injectPayloadMutation.isPending ? 'Dispatching…' : 'Dispatch Payload'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Screenshot Lightbox */}
      {showScreenshotModal && (
        <div
          onClick={() => setShowScreenshotModal(null)}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-4 animate-fade-in cursor-zoom-out"
        >
          <div className="relative max-w-4xl w-full p-2 bg-carbon-900 border border-carbon-700 rounded-2xl overflow-hidden shadow-2xl">
            <button
              type="button"
              onClick={() => setShowScreenshotModal(null)}
              className="absolute top-4 right-4 z-10 rounded-full bg-black/60 p-2 text-white hover:bg-black/90"
            >
              <X className="h-5 w-5" />
            </button>
            <img
              src={`/api/v1/results/findings/${selectedExecution?.test_case_id || 1}/screenshot`}
              alt="High resolution trigger proof"
              className="w-full h-auto rounded-xl object-contain max-h-[80vh]"
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveFuzzPage;
