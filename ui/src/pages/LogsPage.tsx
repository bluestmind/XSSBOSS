import React, { useCallback, useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import {
  Terminal,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Info,
  Search,
  Trash2,
  Download,
  Copy,
  Check,
  Pause,
  Play,
  ArrowDown,
  RefreshCw,
  SlidersHorizontal,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Shield,
  Layers,
  Globe,
  Radio,
} from 'lucide-react';

interface LogItem {
  id: number;
  timestamp: string;
  level: string;
  module: string;
  experiment_id?: number | null;
  target_id?: number | null;
  message: string;
  detail?: string | null;
  data?: Record<string, any>;
}

interface LogStats {
  total: number;
  hits: number;
  errors: number;
  warnings: number;
  info: number;
  debug: number;
  modules: Record<string, number>;
}

const MODULE_OPTIONS = [
  { id: 'all', label: 'All Modules', icon: Layers },
  { id: 'orchestrator', label: 'Orchestrator', icon: Radio },
  { id: 'crawler', label: 'Crawler & Recon', icon: Globe },
  { id: 'profiler', label: 'Context & Filters', icon: SlidersHorizontal },
  { id: 'fuzzer', label: 'Fuzzing & Mutations', icon: Sparkles },
  { id: 'browser', label: 'Browser & CDP', icon: Terminal },
  { id: 'auditor', label: 'Security Auditors', icon: Shield },
  { id: 'burp', label: 'Burp Suite REST', icon: Activity },
  { id: 'rate_limiter', label: 'Rate Limits & Proxy', icon: RefreshCw },
];

const LEVEL_COLORS: Record<string, { badge: string; text: string; bg: string; icon: any }> = {
  HIT: {
    badge: 'border-emerald-500/50 bg-emerald-500/20 text-emerald-300 font-bold shadow-[0_0_12px_rgba(16,185,129,0.35)]',
    text: 'text-emerald-300',
    bg: 'bg-emerald-950/20 border-emerald-900/30',
    icon: CheckCircle2,
  },
  ERROR: {
    badge: 'border-rose-500/50 bg-rose-500/20 text-rose-300 font-semibold shadow-[0_0_12px_rgba(244,63,94,0.25)]',
    text: 'text-rose-300',
    bg: 'bg-rose-950/15 border-rose-900/30',
    icon: XCircle,
  },
  WARNING: {
    badge: 'border-amber-500/50 bg-amber-500/20 text-amber-300 font-semibold',
    text: 'text-amber-300',
    bg: 'bg-amber-950/10 border-amber-900/20',
    icon: AlertTriangle,
  },
  INFO: {
    badge: 'border-cyan-500/40 bg-cyan-500/15 text-cyan-300',
    text: 'text-cyan-300',
    bg: 'bg-carbon-900/40 border-carbon-800/40',
    icon: Info,
  },
  DEBUG: {
    badge: 'border-carbon-600 bg-carbon-800/70 text-carbon-400',
    text: 'text-carbon-400',
    bg: 'bg-carbon-950/30 border-carbon-850/40',
    icon: Terminal,
  },
};

const formatTimestamp = (ts: string) => {
  if (!ts) return '';
  try {
    const d = new Date(ts.endsWith('Z') || ts.includes('+') ? ts : ts + 'Z');
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
  } catch {
    return ts;
  }
};

const LogsPage: React.FC = () => {
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [stats, setStats] = useState<LogStats>({
    total: 0,
    hits: 0,
    errors: 0,
    warnings: 0,
    info: 0,
    debug: 0,
    modules: {},
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(true);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [selectedModule, setSelectedModule] = useState<string>('all');
  const [selectedLevel, setSelectedLevel] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedLogId, setExpandedLogId] = useState<number | null>(null);
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [copiedAll, setCopiedAll] = useState<boolean>(false);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Fetch initial batch of logs and statistics
  const fetchLogs = useCallback(async () => {
    try {
      const [logsRes, statsRes] = await Promise.all([
        axios.get('/api/v1/logs', {
          params: {
            limit: 300,
            level: selectedLevel !== 'ALL' ? selectedLevel : undefined,
            module: selectedModule !== 'all' ? selectedModule : undefined,
            search: searchQuery.trim() ? searchQuery.trim() : undefined,
          },
        }),
        axios.get('/api/v1/logs/stats'),
      ]);

      if (logsRes.data && Array.isArray(logsRes.data.logs)) {
        setLogs(logsRes.data.logs);
      }
      if (statsRes.data) {
        setStats(statsRes.data);
      }
    } catch (err) {
      console.error('Failed to fetch diagnostic logs:', err);
    } finally {
      setIsLoading(false);
    }
  }, [selectedLevel, selectedModule, searchQuery]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // Connect Server-Sent Events (SSE) stream for live diagnostic logs
  useEffect(() => {
    if (!isLiveStreaming) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      return;
    }

    const es = new EventSource('/api/v1/logs/stream');
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        if (parsed.type === 'connected') return;

        setLogs((prev) => {
          // Check for deduplication by ID
          if (prev.some((item) => item.id === parsed.id)) return prev;
          return [parsed, ...prev.slice(0, 499)];
        });

        setStats((prev) => {
          return {
            ...prev,
            total: prev.total + 1,
            hits: parsed.level === 'HIT' ? prev.hits + 1 : prev.hits,
            errors: parsed.level === 'ERROR' ? prev.errors + 1 : prev.errors,
            warnings: parsed.level === 'WARNING' ? prev.warnings + 1 : prev.warnings,
            info: parsed.level === 'INFO' ? prev.info + 1 : prev.info,
            debug: parsed.level === 'DEBUG' ? prev.debug + 1 : prev.debug,
            modules: {
              ...prev.modules,
              [parsed.module]: (prev.modules[parsed.module] || 0) + 1,
            },
          };
        });
      } catch {
        // Ignore unparseable frames
      }
    };

    es.onerror = () => {
      // Reconnection handled automatically by browser EventSource
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
    };
  }, [isLiveStreaming]);

  // Auto-scroll when new logs arrive if enabled
  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  // Filter logs for visible display
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (selectedLevel !== 'ALL' && log.level !== selectedLevel) return false;
      if (selectedModule !== 'all' && log.module.toLowerCase() !== selectedModule.toLowerCase()) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const msgMatch = log.message?.toLowerCase().includes(q);
        const detailMatch = log.detail?.toLowerCase().includes(q);
        const modMatch = log.module?.toLowerCase().includes(q);
        if (!msgMatch && !detailMatch && !modMatch) return false;
      }
      return true;
    });
  }, [logs, selectedLevel, selectedModule, searchQuery]);

  const handleClearLogs = async () => {
    if (!window.confirm('Clear all captured diagnostic log entries?')) return;
    try {
      await axios.delete('/api/v1/logs/clear');
      setLogs([]);
      setStats({ total: 0, hits: 0, errors: 0, warnings: 0, info: 0, debug: 0, modules: {} });
    } catch (err) {
      console.error('Failed to clear logs:', err);
    }
  };

  const handleCopyLog = (log: LogItem) => {
    const text = `[${log.timestamp}] [${log.level}] [${log.module.toUpperCase()}] ${log.message}${log.detail ? '\nDetail: ' + log.detail : ''}${log.data && Object.keys(log.data).length ? '\nData: ' + JSON.stringify(log.data, null, 2) : ''}`;
    navigator.clipboard.writeText(text);
    setCopiedId(log.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCopyAll = () => {
    const text = filteredLogs
      .map(
        (l) =>
          `[${l.timestamp}] [${l.level}] [${l.module.toUpperCase()}] ${l.message}${l.detail ? ' | ' + l.detail : ''}`
      )
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredLogs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xssboss-pipeline-logs-${new Date().toISOString().slice(0, 19)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-[1600px] space-y-5 p-4 sm:p-6 lg:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 to-cyan-500 shadow-glow-brand">
              <Terminal className="h-5 w-5 text-white" />
            </span>
            <div>
              <h1 className="font-display text-2xl font-bold tracking-tight text-carbon-100">
                Pipeline Diagnostic Logs
              </h1>
              <p className="text-xs text-carbon-400">
                Live stream of crawler events, CDP headless browser traces, fuzzer mutations, WAF rate limits & auditor findings
              </p>
            </div>
          </div>
        </div>

        {/* Live Stream & Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Live stream toggle */}
          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            className={`flex items-center gap-2 rounded-xl border px-3.5 py-2 text-xs font-semibold transition-all ${
              isLiveStreaming
                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.2)]'
                : 'border-carbon-700 bg-carbon-850 text-carbon-400 hover:text-carbon-200'
            }`}
          >
            {isLiveStreaming ? (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
                </span>
                <span>Live Feed Active</span>
                <Pause className="h-3.5 w-3.5 opacity-70" />
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5" />
                <span>Stream Paused</span>
              </>
            )}
          </button>

          {/* Auto scroll toggle */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`flex items-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-medium transition-all ${
              autoScroll
                ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                : 'border-carbon-700 bg-carbon-850 text-carbon-400 hover:text-carbon-200'
            }`}
            title="Auto-scroll to latest incoming events"
          >
            <ArrowDown className={`h-3.5 w-3.5 ${autoScroll ? 'animate-bounce' : ''}`} />
            <span>Auto-Scroll</span>
          </button>

          {/* Refresh */}
          <button
            onClick={fetchLogs}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-xl border border-carbon-700 bg-carbon-850 px-3 py-2 text-xs font-medium text-carbon-300 hover:bg-carbon-800 hover:text-carbon-100 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          {/* Export options */}
          <button
            onClick={handleExportJSON}
            className="flex items-center gap-1.5 rounded-xl border border-carbon-700 bg-carbon-850 px-3 py-2 text-xs font-medium text-carbon-300 hover:bg-carbon-800 hover:text-carbon-100 transition-colors"
            title="Download JSON log file"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export JSON</span>
          </button>

          {/* Copy visible logs */}
          <button
            onClick={handleCopyAll}
            className="flex items-center gap-1.5 rounded-xl border border-carbon-700 bg-carbon-850 px-3 py-2 text-xs font-medium text-carbon-300 hover:bg-carbon-800 hover:text-carbon-100 transition-colors"
            title="Copy visible text logs to clipboard"
          >
            {copiedAll ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copiedAll ? 'Copied!' : 'Copy View'}</span>
          </button>

          {/* Clear logs */}
          <button
            onClick={handleClearLogs}
            className="flex items-center gap-1.5 rounded-xl border border-rose-900/40 bg-rose-950/20 px-3 py-2 text-xs font-medium text-rose-400 hover:bg-rose-900/40 hover:text-rose-200 transition-colors"
            title="Clear all log entries"
          >
            <Trash2 className="h-3.5 w-3.5" />
            <span>Clear</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Summary Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <div className="rounded-xl border border-carbon-700/60 bg-carbon-900/60 p-3.5 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-carbon-400">Total Events</span>
            <Layers className="h-4 w-4 text-carbon-500" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-carbon-100">{stats.total}</div>
        </div>

        <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-3.5 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-emerald-400">🚨 Findings / Hits</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-emerald-300">{stats.hits}</div>
        </div>

        <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 p-3.5 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-rose-400">❌ Errors</span>
            <XCircle className="h-4 w-4 text-rose-400" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-rose-300">{stats.errors}</div>
        </div>

        <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-3.5 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-amber-400">⚠️ Warnings</span>
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-amber-300">{stats.warnings}</div>
        </div>

        <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-3.5 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-cyan-400">ℹ️ Info Traces</span>
            <Info className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-cyan-300">{stats.info}</div>
        </div>

        <div className="rounded-xl border border-carbon-700/60 bg-carbon-900/60 p-3.5 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-wider text-carbon-400">Active Modules</span>
            <Activity className="h-4 w-4 text-brand-400" />
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-brand-300">
            {Object.keys(stats.modules || {}).length}
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="space-y-3 rounded-2xl border border-carbon-700/70 bg-carbon-900/80 p-4 shadow-xl backdrop-blur-xl">
        {/* Subsystem tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
          {MODULE_OPTIONS.map((mod) => {
            const Icon = mod.icon;
            const isSelected = selectedModule === mod.id;
            const count = mod.id === 'all' ? stats.total : stats.modules?.[mod.id] || 0;
            return (
              <button
                key={mod.id}
                onClick={() => setSelectedModule(mod.id)}
                className={`flex items-center gap-2 whitespace-nowrap rounded-xl px-3 py-2 text-xs font-semibold transition-all ${
                  isSelected
                    ? 'bg-gradient-to-r from-brand-600 to-cyan-600 text-white shadow-glow-brand'
                    : 'border border-carbon-800 bg-carbon-950/60 text-carbon-400 hover:border-carbon-700 hover:text-carbon-200'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{mod.label}</span>
                {count > 0 && (
                  <span
                    className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] ${
                      isSelected ? 'bg-white/20 text-white' : 'bg-carbon-800 text-carbon-400'
                    }`}
                  >
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Level Filters & Search Row */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          {/* Level selector */}
          <div className="flex items-center gap-1 overflow-x-auto">
            {['ALL', 'HIT', 'ERROR', 'WARNING', 'INFO', 'DEBUG'].map((lvl) => {
              const active = selectedLevel === lvl;
              return (
                <button
                  key={lvl}
                  onClick={() => setSelectedLevel(lvl)}
                  className={`rounded-lg px-2.5 py-1 font-mono text-[11px] font-bold uppercase transition-all ${
                    active
                      ? lvl === 'HIT'
                        ? 'border border-emerald-500/60 bg-emerald-500/25 text-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.3)]'
                        : lvl === 'ERROR'
                        ? 'border border-rose-500/60 bg-rose-500/25 text-rose-300'
                        : lvl === 'WARNING'
                        ? 'border border-amber-500/60 bg-amber-500/25 text-amber-300'
                        : 'border border-brand-500/60 bg-brand-500/25 text-brand-300'
                      : 'border border-carbon-800 bg-carbon-950/40 text-carbon-400 hover:text-carbon-200'
                  }`}
                >
                  {lvl}
                </button>
              );
            })}
          </div>

          {/* Search bar */}
          <div className="relative flex-1 sm:max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-carbon-500" />
            <input
              type="text"
              placeholder="Search URLs, payloads, parameters, error messages..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-xl border border-carbon-700/80 bg-carbon-950/80 py-2 pl-9 pr-4 text-xs text-carbon-100 placeholder-carbon-500 transition-colors focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-carbon-500 hover:text-carbon-300"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Terminal Log Console */}
      <div className="overflow-hidden rounded-2xl border border-carbon-700/80 bg-carbon-950/90 shadow-2xl backdrop-blur-xl">
        {/* Terminal Titlebar */}
        <div className="flex items-center justify-between border-b border-carbon-800 bg-carbon-900/90 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <span className="h-3 w-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="h-3 w-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="h-3 w-3 rounded-full bg-emerald-500/80 inline-block" />
            <span className="ml-2 font-mono text-xs text-carbon-400">
              xssboss@pipeline-monitor:~/{selectedModule} ({filteredLogs.length} events)
            </span>
          </div>
          <div className="flex items-center gap-2 text-[11px] font-mono text-carbon-500">
            <span>Buffer: 500 max</span>
            <span>•</span>
            <span className={isLiveStreaming ? 'text-emerald-400' : 'text-amber-400'}>
              {isLiveStreaming ? '● STREAMING' : '❚❚ PAUSED'}
            </span>
          </div>
        </div>

        {/* Log Entries View */}
        <div className="max-h-[650px] min-h-[400px] overflow-y-auto font-mono text-xs">
          {isLoading && logs.length === 0 ? (
            <div className="flex min-h-[300px] items-center justify-center p-8 text-center text-carbon-400">
              <RefreshCw className="mr-2 h-5 w-5 animate-spin text-brand-400" />
              <span>Connecting to diagnostic telemetry stream...</span>
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="flex min-h-[300px] flex-col items-center justify-center p-8 text-center text-carbon-500">
              <Terminal className="mb-2 h-8 w-8 text-carbon-600" />
              <p className="text-sm font-medium text-carbon-400">No diagnostic events match current filter.</p>
              <p className="mt-1 text-xs text-carbon-500">
                Launch a scan or widen the module/level filter to view runtime engine events.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-carbon-850/60">
              {filteredLogs.map((log) => {
                const style = LEVEL_COLORS[log.level] || LEVEL_COLORS.INFO;
                const isExpanded = expandedLogId === log.id;
                const isCopied = copiedId === log.id;
                const hasDetails = Boolean(log.detail || (log.data && Object.keys(log.data).length > 0));

                return (
                  <div
                    key={log.id}
                    className={`group px-4 py-2.5 transition-colors hover:bg-carbon-900/60 ${style.bg}`}
                  >
                    <div className="flex items-start gap-3">
                      {/* Timestamp */}
                      <span className="shrink-0 pt-0.5 text-[11px] text-carbon-500">
                        {formatTimestamp(log.timestamp)}
                      </span>

                      {/* Level Badge */}
                      <span
                        className={`inline-flex shrink-0 items-center justify-center rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${style.badge}`}
                      >
                        {log.level}
                      </span>

                      {/* Module Badge */}
                      <span className="shrink-0 rounded bg-carbon-800/80 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-brand-300">
                        {log.module}
                      </span>

                      {/* Log Message */}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-baseline justify-between gap-2">
                          <span className={`break-words font-medium ${style.text}`}>{log.message}</span>
                          <div className="flex shrink-0 items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button
                              onClick={() => handleCopyLog(log)}
                              className="rounded p-1 text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200"
                              title="Copy log entry"
                            >
                              {isCopied ? (
                                <Check className="h-3.5 w-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="h-3.5 w-3.5" />
                              )}
                            </button>
                            {hasDetails && (
                              <button
                                onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                                className="rounded p-1 text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200"
                                title="Toggle details"
                              >
                                {isExpanded ? (
                                  <ChevronDown className="h-3.5 w-3.5" />
                                ) : (
                                  <ChevronRight className="h-3.5 w-3.5" />
                                )}
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Inline detail preview */}
                        {log.detail && !isExpanded && (
                          <p className="mt-0.5 line-clamp-1 text-[11px] text-carbon-400">{log.detail}</p>
                        )}

                        {/* Expanded Drawer / Detail View */}
                        {isExpanded && (
                          <div className="mt-3 space-y-2 rounded-xl border border-carbon-800 bg-carbon-950 p-3.5">
                            {log.detail && (
                              <div>
                                <div className="text-[10px] font-bold uppercase tracking-wider text-carbon-500">
                                  Extended Detail / Trace:
                                </div>
                                <pre className="mt-1 whitespace-pre-wrap rounded bg-carbon-900 p-2 text-[11px] text-carbon-300">
                                  {log.detail}
                                </pre>
                              </div>
                            )}

                            {log.data && Object.keys(log.data).length > 0 && (
                              <div>
                                <div className="text-[10px] font-bold uppercase tracking-wider text-carbon-500">
                                  Structured JSON Metadata:
                                </div>
                                <pre className="mt-1 overflow-x-auto rounded bg-carbon-900 p-2 text-[11px] text-cyan-300">
                                  {JSON.stringify(log.data, null, 2)}
                                </pre>
                              </div>
                            )}

                            {(log.experiment_id || log.target_id) && (
                              <div className="flex items-center gap-4 text-[11px] text-carbon-400">
                                {log.experiment_id && <span>Experiment ID: #{log.experiment_id}</span>}
                                {log.target_id && <span>Target ID: #{log.target_id}</span>}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
              <div ref={terminalEndRef} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LogsPage;
