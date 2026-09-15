import { useState, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Trophy,
  Zap,
  Activity,
  Search,
  ArrowUpDown,
  Bug,
  Globe,
  RotateCcw,
  CheckCircle2,
  X,
  ChevronRight,
} from 'lucide-react';
import { programsApi, type ProgramRank, type HuntStatus, type ProgramsResponse } from '@/api/programs';
import StatCard from '@/components/cards/StatCard';

const sevColor: Record<string, string> = {
  critical: 'text-rose-400 font-semibold',
  high: 'text-orange-400 font-semibold',
  medium: 'text-amber-400',
  low: 'text-emerald-400',
  none: 'text-carbon-400',
  '': 'text-carbon-400',
};

const ProgramCard = ({ program }: { program: ProgramRank }) => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: status, refetch } = useQuery<HuntStatus>({
    queryKey: ['hunt-status', program.target_id],
    queryFn: () => programsApi.huntStatus(program.target_id),
    initialData: {
      status: program.run_status ?? 'idle',
      findings_count: program.findings_count,
      endpoints_count: program.endpoints_count,
    },
    refetchInterval: (q) =>
      ['queued', 'running'].includes((q.state.data as HuntStatus)?.status) ? 2000 : false,
  });

  const hunt = useMutation({
    mutationFn: () => programsApi.startHunt(program.target_id),
    onMutate: async () => {
      queryClient.setQueryData(['hunt-status', program.target_id], {
        status: 'queued',
        findings_count: program.findings_count,
        endpoints_count: program.endpoints_count,
      });
    },
    onSuccess: () => {
      queryClient.setQueryData(['hunt-status', program.target_id], {
        status: 'running',
        findings_count: program.findings_count,
        endpoints_count: program.endpoints_count,
      });
      queryClient.invalidateQueries({ queryKey: ['hunt-status', program.target_id] });
      queryClient.invalidateQueries({ queryKey: ['programs'] });
      refetch();
    },
    onError: (err: any) => {
      queryClient.setQueryData(['hunt-status', program.target_id], {
        status: 'failed',
        error: err?.response?.data?.detail || err?.message || 'Failed to start hunt',
      });
    },
  });

  const s = status?.status ?? program.run_status ?? 'idle';
  const isRunning = s === 'running' || s === 'queued' || hunt.isPending;
  const isWorked = s === 'completed' || (program.experiments_count && program.experiments_count > 0);
  const findingsCount = status?.findings_count ?? program.findings_count ?? 0;
  const endpointsCount = status?.endpoints_count ?? program.endpoints_count ?? 0;

  return (
    <div
      onClick={() => navigate(`/programs/${program.target_id}`)}
      className={`group rounded-xl border p-5 flex flex-col justify-between transition-all duration-200 cursor-pointer ${
        isRunning
          ? 'border-amber-500/50 bg-amber-500/[0.04] shadow-glow-brand'
          : findingsCount > 0
          ? 'border-rose-500/40 bg-carbon-850/70 hover:border-rose-500/70'
          : isWorked
          ? 'border-carbon-700/80 bg-carbon-850/50 hover:border-brand-500/40 hover:bg-carbon-800/60'
          : 'border-carbon-750 bg-carbon-900/40 hover:border-carbon-600 hover:bg-carbon-850/50'
      }`}
    >
      <div>
        {/* Header with name & priority */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 className="text-carbon-100 font-bold text-base leading-tight group-hover:text-white truncate">
              {program.name}
            </h3>
            <span className="font-mono text-xs text-carbon-400">@{program.handle}</span>
          </div>

          <div className="flex flex-col items-end flex-shrink-0">
            <span className="rounded-md bg-brand-500/15 border border-brand-500/30 px-2 py-0.5 font-mono text-xs font-bold text-brand-300">
              {program.priority_score}
            </span>
            <span className="text-[9px] uppercase font-mono tracking-widest text-carbon-500 mt-0.5">priority</span>
          </div>
        </div>

        {/* Scope tags */}
        <div className="flex flex-wrap items-center gap-1.5 mt-3 text-xs">
          <span
            className={`rounded px-2 py-0.5 text-[11px] font-semibold ${
              program.offers_bounties
                ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                : 'bg-carbon-800 text-carbon-400 border border-carbon-700'
            }`}
          >
            {program.offers_bounties ? '💰 Cash Bounty' : 'VDP'}
          </span>
          <span className="rounded bg-carbon-800/80 border border-carbon-700/60 px-2 py-0.5 font-mono text-[11px] text-carbon-300">
            {program.web_asset_count} assets
          </span>
          <span className="rounded bg-carbon-800/80 border border-carbon-700/60 px-2 py-0.5 font-mono text-[11px] text-carbon-300">
            {program.bounty_eligible_count} eligible
          </span>
          {program.wildcard_count > 0 && (
            <span className="rounded bg-carbon-800/80 border border-carbon-700/60 px-2 py-0.5 font-mono text-[11px] text-carbon-400">
              {program.wildcard_count} wildcard
            </span>
          )}
          <span className={`text-[11px] ml-auto font-mono ${sevColor[program.top_severity] ?? 'text-carbon-400'}`}>
            max: {program.top_severity}
          </span>
        </div>

        {/* Telemetry Chips for worked/running programs */}
        {(isWorked || isRunning || findingsCount > 0 || endpointsCount > 0) && (
          <div className="mt-3.5 flex flex-wrap items-center gap-2 border-t border-carbon-800/80 pt-3">
            {isRunning && (
              <span className="flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-0.5 text-xs font-semibold text-amber-300 animate-pulse">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                Live Hunting
              </span>
            )}

            {isWorked && !isRunning && (
              <span className="flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-semibold text-emerald-300">
                <CheckCircle2 className="h-3 w-3" />
                Hunted
              </span>
            )}

            {findingsCount > 0 && (
              <span className="flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 text-xs font-bold text-rose-300 shadow-glow-rose">
                <Bug className="h-3 w-3 text-rose-400" />
                {findingsCount} Findings
              </span>
            )}

            {endpointsCount > 0 && (
              <span className="flex items-center gap-1 rounded-full border border-carbon-700 bg-carbon-800 px-2 py-0.5 font-mono text-[11px] text-carbon-300">
                <Globe className="h-2.5 w-2.5 text-carbon-400" />
                {endpointsCount} Endpoints
              </span>
            )}

            {program.last_hunted_at && (
              <span className="font-mono text-[10px] text-carbon-500 ml-auto">
                {new Date(program.last_hunted_at).toLocaleDateString()}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Action Footer */}
      <div className="flex items-center justify-between gap-2 mt-4 pt-3 border-t border-carbon-800/80">
        <span className="text-xs text-brand-300/80 group-hover:text-brand-300 flex items-center gap-0.5">
          Program scope <ChevronRight className="h-3 w-3" />
        </span>

        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
          {isRunning ? (
            <Link
              to="/scan"
              className="px-3 py-1.5 rounded-lg text-xs font-bold bg-amber-500 text-carbon-950 hover:bg-amber-400 flex items-center gap-1 shadow-glow-brand"
            >
              <Activity className="h-3.5 w-3.5" />
              Live Monitor
            </Link>
          ) : isWorked ? (
            <button
              disabled={hunt.isPending}
              onClick={() => hunt.mutate()}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-carbon-800 border border-carbon-700 text-carbon-200 hover:bg-carbon-700 hover:text-white flex items-center gap-1 transition"
            >
              <RotateCcw className="h-3 w-3" />
              Re-hunt
            </button>
          ) : (
            <button
              disabled={hunt.isPending}
              onClick={() => hunt.mutate()}
              className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-brand-600 text-white hover:bg-brand-500 flex items-center gap-1 shadow-glow-brand transition disabled:opacity-50"
            >
              <Zap className="h-3 w-3" />
              Start hunt on program
            </button>
          )}
        </div>
      </div>

      {s === 'failed' && status?.error && (
        <p className="text-[11px] text-rose-400 mt-2 truncate" title={status.error}>
          {status.error}
        </p>
      )}
    </div>
  );
};

const ProgramsPage = () => {
  const [statusTab, setStatusTab] = useState<'all' | 'working' | 'hunted' | 'hits' | 'paused' | 'idle'>('all');
  const [bountyOnly, setBountyOnly] = useState(true);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'priority' | 'findings' | 'assets' | 'recent'>('priority');

  const { data: response, isLoading } = useQuery<ProgramsResponse>({
    queryKey: ['programs', bountyOnly, search],
    queryFn: () => programsApi.list(bountyOnly, 1000, search),
    refetchInterval: 5000,
  });

  const rawPrograms = useMemo(() => response?.programs || [], [response?.programs]);
  const stats = response?.stats || {
    total: rawPrograms.length,
    active: rawPrograms.filter((p) => p.run_status === 'running' || p.run_status === 'queued').length,
    hunted: rawPrograms.filter((p) => p.run_status === 'completed' || (p.experiments_count && p.experiments_count > 0)).length,
    with_findings: rawPrograms.filter((p) => (p.findings_count && p.findings_count > 0)).length,
    paused: rawPrograms.filter((p) => p.run_status === 'paused').length,
    idle: rawPrograms.filter((p) => p.run_status === 'idle' && (!p.experiments_count || p.experiments_count === 0)).length,
    total_findings: rawPrograms.reduce((acc, p) => acc + (p.findings_count || 0), 0),
  };

  // Filter and sort programs
  const filteredPrograms = useMemo(() => {
    return rawPrograms
      .filter((p) => {
        if (statusTab === 'working' && p.run_status !== 'running' && p.run_status !== 'queued') return false;
        if (statusTab === 'hunted' && p.run_status !== 'completed' && (!p.experiments_count || p.experiments_count === 0)) return false;
        if (statusTab === 'hits' && (!p.findings_count || p.findings_count === 0)) return false;
        if (statusTab === 'paused' && p.run_status !== 'paused') return false;
        if (statusTab === 'idle' && (p.run_status !== 'idle' || (p.experiments_count && p.experiments_count > 0))) return false;
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'findings') return (b.findings_count || 0) - (a.findings_count || 0);
        if (sortBy === 'assets') return b.web_asset_count - a.web_asset_count;
        if (sortBy === 'recent') {
          const dateA = a.last_hunted_at ? new Date(a.last_hunted_at).getTime() : 0;
          const dateB = b.last_hunted_at ? new Date(b.last_hunted_at).getTime() : 0;
          return dateB - dateA;
        }
        return b.priority_score - a.priority_score;
      });
  }, [rawPrograms, statusTab, sortBy]);

  const totalAssets = rawPrograms.reduce((n, p) => n + p.web_asset_count, 0);

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-4 sm:p-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-500/20 text-brand-300">
              <Trophy className="h-5 w-5" />
            </span>
            <div>
              <h1 className="text-2xl font-bold font-display tracking-tight text-carbon-100">
                Bug Bounty Programs
              </h1>
              <p className="text-xs text-carbon-400">
                Ranked targets by expected value · 1-click autonomous hunting · persistent progress
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[240px]">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-carbon-500" />
            <input
              type="text"
              placeholder="Search program or @handle…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-lg border border-carbon-700 bg-carbon-850/80 py-1.5 pl-9 pr-8 text-xs text-carbon-100 placeholder-carbon-500 focus:border-brand-500 focus:outline-none"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-carbon-400 hover:text-carbon-100"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>

          <label className="flex items-center gap-2 rounded-lg border border-carbon-700 bg-carbon-850/60 px-3 py-1.5 text-xs text-carbon-300 cursor-pointer whitespace-nowrap hover:border-carbon-600">
            <input
              type="checkbox"
              checked={bountyOnly}
              onChange={(e) => setBountyOnly(e.target.checked)}
              className="rounded border-carbon-700 text-brand-500 focus:ring-brand-500/25"
            />
            <span>💰 Cash Bounties Only</span>
          </label>
        </div>
      </div>

      {/* Top Global Metric Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
        <StatCard label="Programs" value={stats.total} icon="🎯" color="blue" />
        <StatCard label="Cash Bounties" value={rawPrograms.filter(p => p.offers_bounties).length} icon="💰" color="green" />
        <StatCard label="Working On" value={stats.active} icon="🔥" color="yellow" />
        <StatCard label="Hunted / Worked" value={stats.hunted} icon="✅" color="blue" />
        <StatCard label="Confirmed Hits" value={stats.total_findings} icon="🚨" color="red" />
        <StatCard label="In-Scope Assets" value={totalAssets} icon="🌐" color="blue" />
      </div>

      {/* Filter Tabs & Sorting */}
      <div className="panel">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-4 border-b border-carbon-700/60 bg-carbon-900/40">
          {/* Status Tabs */}
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => setStatusTab('all')}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                statusTab === 'all'
                  ? 'bg-brand-500 text-white shadow-glow-brand'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
              }`}
            >
              All Programs ({stats.total})
            </button>
            <button
              type="button"
              onClick={() => setStatusTab('working')}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                statusTab === 'working'
                  ? 'bg-amber-500 text-carbon-950 font-bold'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-amber-300'
              }`}
            >
              🔥 Working On ({stats.active})
            </button>
            <button
              type="button"
              onClick={() => setStatusTab('hunted')}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                statusTab === 'hunted'
                  ? 'bg-emerald-500 text-carbon-950 font-bold shadow-glow-emerald'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-emerald-300'
              }`}
            >
              ✅ Hunted / Worked ({stats.hunted})
            </button>
            <button
              type="button"
              onClick={() => setStatusTab('hits')}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                statusTab === 'hits'
                  ? 'bg-rose-500 text-white font-bold shadow-glow-rose'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-rose-300'
              }`}
            >
              ⚡ With Findings ({stats.with_findings})
            </button>
            <button
              type="button"
              onClick={() => setStatusTab('paused')}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                statusTab === 'paused'
                  ? 'bg-amber-500/30 text-amber-200 border border-amber-500/50'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-amber-200'
              }`}
            >
              ⏸️ Paused ({stats.paused})
            </button>
            <button
              type="button"
              onClick={() => setStatusTab('idle')}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                statusTab === 'idle'
                  ? 'bg-carbon-700 text-carbon-100'
                  : 'text-carbon-400 hover:bg-carbon-800 hover:text-carbon-200'
              }`}
            >
              Not Started ({stats.idle})
            </button>
          </div>

          {/* Sort Dropdown */}
          <div className="flex items-center gap-2 self-end lg:self-auto">
            <span className="text-xs text-carbon-400 flex items-center gap-1">
              <ArrowUpDown className="h-3 w-3" /> Sort:
            </span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="rounded-lg border border-carbon-700 bg-carbon-850 px-2.5 py-1 text-xs text-carbon-200 focus:border-brand-500 focus:outline-none"
            >
              <option value="priority">Priority Score (Highest first)</option>
              <option value="findings">Findings / Hits (Most first)</option>
              <option value="assets">Asset Surface (Largest first)</option>
              <option value="recent">Recently Hunted</option>
            </select>
          </div>
        </div>

        {/* Program Cards Grid */}
        <div className="p-4 sm:p-5">
          {isLoading ? (
            <div className="py-16 text-center text-sm text-carbon-400">
              Loading ranked program profiles…
            </div>
          ) : filteredPrograms.length === 0 ? (
            <div className="py-16 text-center text-sm text-carbon-400">
              No programs match the selected filter or search term.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
              {filteredPrograms.map((p: ProgramRank) => (
                <ProgramCard key={p.target_id} program={p} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ProgramsPage;
