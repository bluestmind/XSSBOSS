import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  Compass,
  Waves,
  GitFork,
  Eye,
  ShieldAlert,
  Crosshair,
  Zap,
  Anchor,
  Clock3,
  Search,
  ArrowDown,
  Pause,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Filter,
} from 'lucide-react';
import type { ExperimentMonitor, MicroEvent, RiverMilestone } from '@/types/api';

interface RiverFlowMonitorProps {
  monitor: ExperimentMonitor;
  onSelectStage?: (stageKey: string) => void;
  className?: string;
}

const STAGE_ICONS: Record<string, React.ElementType> = {
  springs: Compass,
  recon: Waves,
  params: GitFork,
  contexts: Eye,
  filters: ShieldAlert,
  auditors: Crosshair,
  browser: Zap,
  sea: Anchor,
};

const STAGE_COLORS: Record<string, { ring: string; text: string; bg: string; border: string; glow: string }> = {
  springs: { ring: 'ring-cyan-500/50', text: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/30', glow: 'shadow-[0_0_15px_rgba(6,182,212,0.3)]' },
  recon: { ring: 'ring-blue-500/50', text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30', glow: 'shadow-[0_0_15px_rgba(59,130,246,0.3)]' },
  params: { ring: 'ring-indigo-500/50', text: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'border-indigo-500/30', glow: 'shadow-[0_0_15px_rgba(99,102,241,0.3)]' },
  contexts: { ring: 'ring-amber-500/50', text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30', glow: 'shadow-[0_0_15px_rgba(245,158,11,0.3)]' },
  filters: { ring: 'ring-purple-500/50', text: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/30', glow: 'shadow-[0_0_15px_rgba(168,85,247,0.3)]' },
  auditors: { ring: 'ring-rose-500/50', text: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/30', glow: 'shadow-[0_0_15px_rgba(244,63,94,0.3)]' },
  browser: { ring: 'ring-sky-500/50', text: 'text-sky-300', bg: 'bg-sky-500/10', border: 'border-sky-500/30', glow: 'shadow-[0_0_15px_rgba(14,165,233,0.4)]' },
  sea: { ring: 'ring-emerald-500/50', text: 'text-emerald-300', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', glow: 'shadow-[0_0_18px_rgba(16,185,129,0.5)]' },
};

const DEFAULT_MILESTONES: RiverMilestone[] = [
  { key: 'springs', name: 'The Springs', subtitle: 'Target Source & Scope', icon: 'Compass', status: 'settled', count: 1, water_percent: 100, order: 1 },
  { key: 'recon', name: 'Recon Rapids', subtitle: 'Crawler & Route Spider', icon: 'Waves', status: 'pending', count: 0, water_percent: 0, order: 2 },
  { key: 'params', name: 'Param Tributaries', subtitle: 'Surface & Point Expansion', icon: 'GitFork', status: 'pending', count: 0, water_percent: 0, order: 3 },
  { key: 'contexts', name: 'Context Confluence', subtitle: 'Reflection & Sink Mapping', icon: 'Eye', status: 'pending', count: 0, water_percent: 0, order: 4 },
  { key: 'filters', name: 'Filter Channels', subtitle: 'WAF & Character Profiling', icon: 'ShieldAlert', status: 'pending', count: 0, water_percent: 0, order: 5 },
  { key: 'auditors', name: 'Auditor Cascades', subtitle: 'Focused Web Probes', icon: 'Crosshair', status: 'pending', count: 0, water_percent: 0, order: 6 },
  { key: 'browser', name: 'Browser Whirlpool', subtitle: 'Chromium Execution Oracle', icon: 'Zap', status: 'pending', count: 0, water_percent: 0, order: 7 },
  { key: 'sea', name: 'Sea of Findings', subtitle: 'Confirmed PoC Evidence', icon: 'Anchor', status: 'pending', count: 0, water_percent: 0, order: 8 },
];

export const RiverFlowMonitor: React.FC<RiverFlowMonitorProps> = ({
  monitor,
  onSelectStage,
  className = '',
}) => {
  const [selectedStageFilter, setSelectedStageFilter] = useState<string>('all');
  const [resultFilter, setResultFilter] = useState<'all' | 'hit' | 'reflected' | 'waf' | 'error'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const [copiedSeq, setCopiedSeq] = useState<number | null>(null);
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);
  const streamBottomRef = useRef<HTMLDivElement>(null);

  const riverFlow = monitor.river_flow;
  const liveProgress = monitor.live_progress;
  const doingStatus =
    riverFlow?.doing_status ||
    monitor.doing_status ||
    liveProgress?.doing_status ||
    liveProgress?.message ||
    monitor.stage_detail ||
    'Scanner is cruising smoothly along the pipeline';

  const currentMicro = riverFlow?.micro_state || monitor.micro_state || liveProgress?.micro_state;

  // Derive milestones with fallback
  const milestones: RiverMilestone[] = useMemo(() => {
    if (riverFlow?.milestones && riverFlow.milestones.length > 0) {
      return riverFlow.milestones;
    }
    return DEFAULT_MILESTONES;
  }, [riverFlow]);

  // Derive micro events stream
  const rawEvents: MicroEvent[] = useMemo(() => {
    if (monitor.micro_events && monitor.micro_events.length > 0) {
      return monitor.micro_events;
    }
    // Synthesize fallback events from progress history
    return (monitor.progress_history || []).map((h, i) => ({
      sequence: h.sequence || i + 1,
      timestamp: h.updated_at,
      river_stage: h.river_stage || 'recon',
      stage_label: h.river_stage?.toUpperCase() || 'RECON',
      title: h.message,
      detail: h.detail,
      status: h.state === 'error' ? ('error' as const) : ('info' as const),
      outcome: h.state === 'done' ? 'Completed' : undefined,
      tool: h.tool,
    }));
  }, [monitor.micro_events, monitor.progress_history]);

  // Filtered micro events
  const filteredEvents = useMemo(() => {
    return rawEvents.filter((ev) => {
      // Stage filter
      if (selectedStageFilter !== 'all' && ev.river_stage !== selectedStageFilter) {
        return false;
      }
      // Result filter
      if (resultFilter === 'hit' && ev.status !== 'hit' && !ev.title.toLowerCase().includes('hit')) {
        return false;
      }
      if (resultFilter === 'reflected' && !ev.title.toLowerCase().includes('reflect') && !ev.outcome?.toLowerCase().includes('context')) {
        return false;
      }
      if (resultFilter === 'waf' && !ev.title.toLowerCase().includes('waf') && !ev.title.toLowerCase().includes('filter')) {
        return false;
      }
      if (resultFilter === 'error' && ev.status !== 'error') {
        return false;
      }
      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const text = `${ev.title} ${ev.detail || ''} ${ev.endpoint || ''} ${ev.param || ''} ${ev.outcome || ''}`.toLowerCase();
        if (!text.includes(q)) return false;
      }
      return true;
    });
  }, [rawEvents, selectedStageFilter, resultFilter, searchQuery]);

  // Auto-scroll stream to bottom when new events arrive
  useEffect(() => {
    if (autoScroll && streamBottomRef.current) {
      streamBottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [filteredEvents.length, autoScroll]);

  const handleCopy = (text: string, seq: number) => {
    navigator.clipboard.writeText(text);
    setCopiedSeq(seq);
    setTimeout(() => setCopiedSeq(null), 2000);
  };

  const isRunning = monitor.experiment.status === 'running';

  return (
    <div className={`space-y-4 rounded-2xl border border-carbon-700/60 bg-carbon-900/90 p-4 sm:p-6 shadow-2xl backdrop-blur-md ${className}`}>
      {/* --- WATERWAY HEADER --- */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-carbon-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/20 via-blue-500/20 to-indigo-500/20 border border-cyan-500/40 text-cyan-300">
            <Waves className={`h-5 w-5 ${isRunning ? 'animate-pulse' : ''}`} />
            {isRunning && (
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500" />
              </span>
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold font-display tracking-tight text-carbon-100 flex items-center gap-2">
                River-to-Sea Audit Pipeline
              </h2>
              <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                isRunning
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 animate-pulse-soft'
                  : monitor.experiment.status === 'completed'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
                  : 'bg-carbon-800 text-carbon-400 border border-carbon-700'
              }`}>
                {riverFlow?.water_velocity || (isRunning ? 'Flowing to Sea' : 'Settled')}
              </span>
            </div>
            <p className="text-xs text-carbon-400">
              Live continuous micro-state telemetry from source origin to verified findings
            </p>
          </div>
        </div>

        {/* Global Liveness Heartbeat */}
        <div className="flex items-center gap-3 text-xs font-mono text-carbon-400">
          <div className="flex items-center gap-1.5 rounded-lg border border-carbon-800 bg-carbon-950/70 px-3 py-1.5">
            <Clock3 className="h-3.5 w-3.5 text-cyan-400" />
            <span>Last Heartbeat:</span>
            <span className={`font-bold ${monitor.progress_stale ? 'text-amber-400' : 'text-carbon-200'}`}>
              {monitor.idle_seconds != null ? `${Math.round(monitor.idle_seconds)}s ago` : 'just now'}
            </span>
          </div>
        </div>
      </div>

      {/* --- LIVE "DOING STATUS" WATERWAY HUD --- */}
      <div className={`relative overflow-hidden rounded-xl border p-4 transition-all duration-300 ${
        monitor.progress_stale
          ? 'border-amber-500/40 bg-gradient-to-r from-amber-500/10 via-carbon-900 to-amber-500/5'
          : isRunning
          ? 'border-cyan-500/30 bg-gradient-to-r from-cyan-950/40 via-carbon-900/90 to-blue-950/30'
          : 'border-carbon-700/50 bg-carbon-850/40'
      }`}>
        {/* Ambient river flow glow lines */}
        {isRunning && (
          <div className="pointer-events-none absolute inset-0 opacity-20 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-400 via-transparent to-transparent animate-pulse" />
        )}

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="min-w-0 flex-1 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
              <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-cyan-400">
                WHAT THE SCANNER IS DOING RIGHT NOW
              </span>
              {currentMicro?.action && (
                <span className="rounded bg-carbon-800 px-2 py-0.5 font-mono text-[10px] text-cyan-300 border border-cyan-500/30">
                  {currentMicro.action.replace(/_/g, ' ')}
                </span>
              )}
            </div>
            <p className="text-sm sm:text-base font-semibold tracking-tight text-carbon-100 line-clamp-2">
              {doingStatus}
            </p>
          </div>

          {/* Micro Action Pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {currentMicro?.endpoint && (
              <div className="flex items-center gap-1 rounded-lg border border-carbon-700 bg-carbon-950/80 px-2.5 py-1 text-carbon-300 max-w-[220px] truncate" title={currentMicro.endpoint}>
                <span className="text-carbon-500">URL:</span>
                <span className="truncate text-cyan-300">{currentMicro.endpoint}</span>
              </div>
            )}
            {currentMicro?.param && (
              <div className="flex items-center gap-1 rounded-lg border border-carbon-700 bg-carbon-950/80 px-2.5 py-1 text-carbon-300">
                <span className="text-carbon-500">Param:</span>
                <span className="font-bold text-amber-300">{currentMicro.param}</span>
              </div>
            )}
            {currentMicro?.result && (
              <div className={`flex items-center gap-1 rounded-lg border px-2.5 py-1 font-semibold ${
                currentMicro.result.toLowerCase().includes('hit') || currentMicro.result.toLowerCase().includes('fired')
                  ? 'border-emerald-500/50 bg-emerald-500/20 text-emerald-200'
                  : 'border-carbon-700 bg-carbon-950/80 text-carbon-200'
              }`}>
                <span>Result:</span>
                <span>{currentMicro.result}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* --- THE 8 RIVER MILESTONES (WATERWAY PIPELINE) --- */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs text-carbon-400">
          <span className="font-mono text-[11px] uppercase tracking-wider text-carbon-400">
            Waterway Journey (Click any stage to filter stream)
          </span>
          <span className="font-mono text-[11px] text-cyan-400">
            {monitor.progress_percent}% Overall Current
          </span>
        </div>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
          {milestones.map((milestone) => {
            const Icon = STAGE_ICONS[milestone.key] || Waves;
            const colors = STAGE_COLORS[milestone.key] || STAGE_COLORS.recon;
            const isSelected = selectedStageFilter === milestone.key;
            const isCurrent = riverFlow?.current_stage === milestone.key;

            return (
              <button
                key={milestone.key}
                type="button"
                onClick={() => {
                  const nextFilter = selectedStageFilter === milestone.key ? 'all' : milestone.key;
                  setSelectedStageFilter(nextFilter);
                  if (onSelectStage) onSelectStage(nextFilter);
                }}
                className={`group relative flex flex-col justify-between rounded-xl border p-2.5 text-left transition-all duration-200 ${
                  isSelected
                    ? `${colors.border} ${colors.bg} ${colors.glow} ring-2 ${colors.ring}`
                    : isCurrent
                    ? 'border-cyan-500/50 bg-carbon-850/80 ring-1 ring-cyan-500/30'
                    : milestone.status === 'settled'
                    ? 'border-carbon-700/60 bg-carbon-850/40 hover:border-carbon-600'
                    : 'border-carbon-800 bg-carbon-950/40 opacity-70 hover:opacity-100'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <div className={`flex h-7 w-7 items-center justify-center rounded-lg ${colors.bg} ${colors.text}`}>
                      <Icon className={`h-4 w-4 ${isCurrent && isRunning ? 'animate-pulse' : ''}`} />
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                      milestone.status === 'settled'
                        ? 'text-emerald-400 bg-emerald-500/10'
                        : milestone.status === 'flowing'
                        ? 'text-cyan-300 bg-cyan-500/15 animate-pulse'
                        : milestone.status === 'eddied'
                        ? 'text-amber-400 bg-amber-500/10'
                        : 'text-carbon-500 bg-carbon-900'
                    }`}>
                      {milestone.status === 'settled' ? '✓' : milestone.status === 'flowing' ? 'Active' : milestone.count}
                    </span>
                  </div>

                  <div className="mt-2 font-display text-xs font-bold tracking-tight text-carbon-100 truncate">
                    {milestone.name}
                  </div>
                  <div className="text-[10px] text-carbon-400 truncate">
                    {milestone.subtitle}
                  </div>
                </div>

                {/* Water Level Fill Gauge */}
                <div className="mt-2.5 space-y-1">
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-carbon-800">
                    <div
                      className={`h-full transition-all duration-500 rounded-full ${
                        milestone.status === 'settled'
                          ? 'bg-emerald-400'
                          : isCurrent
                          ? 'bg-gradient-to-r from-cyan-400 to-blue-500 animate-pulse'
                          : 'bg-carbon-600'
                      }`}
                      style={{ width: `${milestone.water_percent}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[9px] font-mono text-carbon-500">
                    <span>{milestone.count} items</span>
                    <span>{milestone.water_percent}%</span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* --- THE RIVER STREAM: LIVE TELEMETRY WATERFALL --- */}
      <div className="rounded-xl border border-carbon-800 bg-carbon-950/60 p-4 space-y-3">
        {/* Stream Filter Bar */}
        <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between border-b border-carbon-800/80 pb-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[10px] uppercase font-bold text-carbon-400 mr-1 flex items-center gap-1">
              <Filter className="h-3 w-3" /> Filter Stream:
            </span>
            {(
              [
                { key: 'all', label: 'All Results' },
                { key: 'hit', label: '🔥 Hits / PoCs' },
                { key: 'reflected', label: 'Reflections' },
                { key: 'waf', label: 'WAF & Filters' },
                { key: 'error', label: 'Errors' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.key}
                type="button"
                onClick={() => setResultFilter(tab.key)}
                className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                  resultFilter === tab.key
                    ? 'bg-cyan-500 text-carbon-950 font-bold shadow-[0_0_10px_rgba(6,182,212,0.4)]'
                    : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            {/* Search filter */}
            <div className="relative flex-1 sm:w-48">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-carbon-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter parameters, URLs…"
                className="w-full rounded-lg border border-carbon-800 bg-carbon-900 py-1 pl-8 pr-3 text-xs text-carbon-200 placeholder-carbon-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            {/* Auto-scroll toggle */}
            <button
              type="button"
              onClick={() => setAutoScroll((v) => !v)}
              className={`rounded-lg border px-2 py-1 text-xs font-mono flex items-center gap-1 transition ${
                autoScroll
                  ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                  : 'border-carbon-800 text-carbon-500 hover:text-carbon-300'
              }`}
              title={autoScroll ? 'Auto-scroll enabled' : 'Auto-scroll paused'}
            >
              {autoScroll ? <ArrowDown className="h-3 w-3 animate-bounce" /> : <Pause className="h-3 w-3" />}
              <span className="hidden sm:inline">{autoScroll ? 'Live Stream' : 'Paused'}</span>
            </button>
          </div>
        </div>

        {/* Selected River Stage Badge if active */}
        {selectedStageFilter !== 'all' && (
          <div className="flex items-center justify-between rounded-lg bg-carbon-900 px-3 py-1.5 text-xs text-carbon-300 border border-carbon-800">
            <span>
              Filtering stream to <strong className="text-cyan-300 uppercase">{selectedStageFilter}</strong> stage only
            </span>
            <button
              type="button"
              onClick={() => setSelectedStageFilter('all')}
              className="text-xs text-carbon-400 hover:text-white font-mono"
            >
              Clear Filter ✕
            </button>
          </div>
        )}

        {/* Stream Event List */}
        <div className="max-h-72 overflow-y-auto space-y-2 pr-1 custom-scrollbar">
          {filteredEvents.length > 0 ? (
            filteredEvents.map((event) => {
              const isHit = event.status === 'hit' || event.title.toLowerCase().includes('hit') || event.title.toLowerCase().includes('oracle hit');
              const isExpanded = expandedSeq === event.sequence;
              const stageColor = STAGE_COLORS[event.river_stage] || STAGE_COLORS.recon;

              return (
                <div
                  key={event.sequence}
                  className={`rounded-xl border p-3 transition text-xs font-mono ${
                    isHit
                      ? 'border-emerald-500/60 bg-emerald-500/10 shadow-[0_0_15px_rgba(16,185,129,0.2)]'
                      : event.status === 'error'
                      ? 'border-rose-500/40 bg-rose-500/5'
                      : 'border-carbon-800/80 bg-carbon-900/60 hover:bg-carbon-850/60'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2.5 min-w-0 flex-1">
                      {/* Stage Pill */}
                      <span className={`inline-flex shrink-0 items-center rounded-md px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${stageColor.border} ${stageColor.bg} ${stageColor.text}`}>
                        {event.river_stage}
                      </span>

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`font-semibold ${isHit ? 'text-emerald-300 text-sm font-bold' : 'text-carbon-100'}`}>
                            {event.title}
                          </span>
                          {event.outcome && (
                            <span className={`rounded px-1.5 py-0.2 font-mono text-[10px] font-bold ${
                              isHit
                                ? 'bg-emerald-500/30 text-emerald-200 border border-emerald-500/50'
                                : 'bg-carbon-800 text-carbon-300'
                            }`}>
                              {event.outcome}
                            </span>
                          )}
                        </div>

                        {/* Metadata row */}
                        <div className="mt-1 flex flex-wrap items-center gap-2.5 text-[11px] text-carbon-400 font-sans">
                          {event.endpoint && (
                            <span className="truncate max-w-sm font-mono text-carbon-300">
                              {event.endpoint}
                            </span>
                          )}
                          {event.param && (
                            <span className="rounded bg-carbon-800/80 px-1.5 py-0.5 font-mono text-[10px] text-amber-300">
                              param: {event.param}
                            </span>
                          )}
                          {event.detail && (
                            <span className="text-carbon-400 truncate max-w-md">
                              {event.detail}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-[10px] text-carbon-500">
                        {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : ''}
                      </span>

                      {/* Detail toggle / copy button */}
                      {event.detail && (
                        <button
                          type="button"
                          onClick={() => setExpandedSeq(isExpanded ? null : event.sequence)}
                          className="rounded p-1 text-carbon-500 hover:text-carbon-200"
                          title="Inspect detail"
                        >
                          {isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Expanded Detail Box */}
                  {isExpanded && event.detail && (
                    <div className="mt-2.5 rounded-lg border border-carbon-700 bg-carbon-950 p-2.5 text-[11px] text-carbon-300 font-mono overflow-x-auto">
                      <div className="flex items-center justify-between text-carbon-500 mb-1">
                        <span>Event Detail Payload:</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(event.detail!, event.sequence)}
                          className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                        >
                          {copiedSeq === event.sequence ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                          {copiedSeq === event.sequence ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                      <pre className="whitespace-pre-wrap break-all text-carbon-200">{event.detail}</pre>
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            <div className="py-8 text-center text-xs text-carbon-500 font-mono">
              No events match the current filter or search.
            </div>
          )}
          <div ref={streamBottomRef} />
        </div>
      </div>
    </div>
  );
};

export default RiverFlowMonitor;
