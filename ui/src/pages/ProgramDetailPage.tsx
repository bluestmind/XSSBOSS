import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { programsApi, type ProgramProfile } from '@/api/programs';
import StatCard from '@/components/cards/StatCard';
import SecurityProfileTable from '@/components/tables/SecurityProfileTable';

const sevColor: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-emerald-400',
  none: 'text-carbon-400',
  '': 'text-carbon-400',
};

const statusStyle: Record<string, string> = {
  idle: 'bg-carbon-700/60 text-carbon-300',
  planned: 'bg-carbon-700/60 text-carbon-300',
  queued: 'bg-blue-500/20 text-blue-300 animate-pulse',
  running: 'bg-brand-500/20 text-brand-300 animate-pulse',
  completed: 'bg-emerald-500/20 text-emerald-300',
  failed: 'bg-red-500/20 text-red-300',
  budget_exhausted: 'bg-yellow-500/20 text-yellow-300',
};

const Badge = ({ text }: { text: string }) => (
  <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${statusStyle[text] ?? statusStyle.idle}`}>{text}</span>
);

const ProgramDetailPage = () => {
  const { id } = useParams();
  const targetId = Number(id);
  const queryClient = useQueryClient();

  const { data: profile, isLoading, refetch } = useQuery<ProgramProfile>({
    queryKey: ['program', targetId],
    queryFn: () => programsApi.profile(targetId),
    refetchInterval: (q) =>
      ['queued', 'running'].includes((q.state.data as ProgramProfile)?.run?.status) ? 2000 : false,
  });

  const hunt = useMutation({
    mutationFn: () => programsApi.startHunt(targetId),
    onMutate: () => {
      if (profile) {
        queryClient.setQueryData(['program', targetId], {
          ...profile,
          run: { ...profile.run, status: 'queued' },
        });
      }
    },
    onSuccess: () => {
      if (profile) {
        queryClient.setQueryData(['program', targetId], {
          ...profile,
          run: { ...profile.run, status: 'running' },
        });
      }
      queryClient.invalidateQueries({ queryKey: ['program', targetId] });
      refetch();
    },
    onError: (err: any) => {
      if (profile) {
        queryClient.setQueryData(['program', targetId], {
          ...profile,
          run: {
            ...profile.run,
            status: 'failed',
            error: err?.response?.data?.detail || err?.message || 'Failed to start hunt',
          },
        });
      }
    },
  });

  const exportBurp = async () => {
    const data = await programsApi.burpScope(targetId);
    const blob = new Blob([JSON.stringify(data.burp_scope, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `burp-scope-${targetId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading || !profile) {
    return <div className="p-6 text-carbon-400">Loading program…</div>;
  }

  const { rank, summary, worklist, run } = profile;
  const status = run?.status ?? 'idle';
  const busy = status === 'queued' || status === 'running' || hunt.isPending;
  const report = run?.report;

  return (
    <div className="p-6">
      <Link to="/programs" className="text-sm text-brand-300 hover:underline">← Programs</Link>

      <div className="flex items-start justify-between mt-2 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-carbon-100">{rank.name}</h1>
          <span className="text-sm text-carbon-400">
            @{rank.handle} · {rank.offers_bounties ? '💰 Bounty' : 'VDP'} · priority{' '}
            <span className="text-brand-300 font-semibold">{rank.priority_score}</span> · <Badge text={status} />
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={exportBurp}
            className="px-4 py-2 bg-carbon-800/70 text-brand-300 border border-brand-500/30 rounded-md hover:bg-brand-500/10"
          >
            Export Burp Scope
          </button>
          <button
            disabled={busy}
            onClick={() => hunt.mutate()}
            className="px-4 py-2 bg-brand-600 text-white rounded-md hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {busy ? 'Hunting…' : 'Start find on program'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <StatCard label="Web Assets" value={summary.web_assets} icon="🌐" color="blue" />
        <StatCard label="Bounty Eligible" value={summary.bounty_eligible_assets} icon="💰" color="green" />
        <StatCard label="Exclusions" value={summary.exclusions} icon="🚫" color="yellow" />
        <StatCard label="Findings" value={report?.total_findings ?? 0} icon="🐞" color="green" />
      </div>

      {rank.reasons?.length > 0 && (
        <p className="text-xs text-carbon-400 mb-6">Priority: {rank.reasons.join(' · ')}</p>
      )}

      {/* Error banner if hunt failed */}
      {status === 'failed' && run?.error && (
        <div className="mb-6 p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-sm flex items-start gap-3">
          <span className="text-lg">⚠️</span>
          <div>
            <h4 className="font-semibold text-red-200">Program Hunt Failed</h4>
            <p className="text-xs text-red-300/90 mt-1">{run.error}</p>
          </div>
        </div>
      )}

      {/* Per-asset run outcomes (when a hunt has produced results) */}
      {report && (
        <div className="mb-8">
          <h2 className="text-lg font-semibold text-carbon-100 mb-3">
            Run outcomes <span className="text-xs text-carbon-500">({report.stopped_reason})</span>
          </h2>
          <div className="overflow-x-auto rounded-lg border border-carbon-700/60">
            <table className="min-w-full text-sm">
              <thead className="bg-carbon-800/60 text-carbon-400 text-xs">
                <tr>
                  <th className="text-left px-3 py-2">Host</th>
                  <th className="text-left px-3 py-2">Status</th>
                  <th className="text-right px-3 py-2">Endpoints</th>
                  <th className="text-right px-3 py-2">Findings</th>
                  <th className="text-right px-3 py-2">Requests</th>
                </tr>
              </thead>
              <tbody>
                {report.outcomes.map((o) => (
                  <tr key={o.host} className="border-t border-carbon-800/60">
                    <td className="px-3 py-2 text-carbon-200">{o.host}</td>
                    <td className="px-3 py-2">
                      <Badge text={o.status} />
                      {o.error && (
                        <span className="block text-[11px] text-red-400 mt-0.5 max-w-xs truncate" title={o.error}>
                          {o.error}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-right text-carbon-300">{o.endpoints}</td>
                    <td className={`px-3 py-2 text-right ${o.findings > 0 ? 'text-emerald-300 font-semibold' : 'text-carbon-400'}`}>{o.findings}</td>
                    <td className="px-3 py-2 text-right text-carbon-400">{o.requests_used}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Defense & Security Telemetry Profile */}
      <div className="mb-8">
        <h2 className="text-lg font-semibold text-carbon-100 mb-3 flex items-center gap-2">
          <span>🛡️ Defense & Security Telemetry Profile</span>
          <span className="text-xs font-normal text-carbon-400">(WAF, CSP, DOM Sinks, Character Matrix, Tech Stack)</span>
        </h2>
        <SecurityProfileTable profile={profile.security_profile} />
      </div>

      {/* Prioritized asset worklist */}
      <h2 className="text-lg font-semibold text-carbon-100 mb-3">
        Prioritized worklist <span className="text-xs text-carbon-500">({worklist.length} assets)</span>
      </h2>
      <div className="overflow-x-auto rounded-lg border border-carbon-700/60">
        <table className="min-w-full text-sm">
          <thead className="bg-carbon-800/60 text-carbon-400 text-xs">
            <tr>
              <th className="text-left px-3 py-2 w-10">#</th>
              <th className="text-left px-3 py-2">Host</th>
              <th className="text-left px-3 py-2">Type</th>
              <th className="text-left px-3 py-2">Bounty</th>
              <th className="text-left px-3 py-2">Max Severity</th>
            </tr>
          </thead>
          <tbody>
            {worklist.map((a, i) => (
              <tr key={a.host + i} className="border-t border-carbon-800/60">
                <td className="px-3 py-2 text-carbon-500">{i + 1}</td>
                <td className="px-3 py-2 text-carbon-200">
                  {a.host}
                  {a.is_wildcard && <span className="ml-1 text-[10px] text-brand-400">(wildcard)</span>}
                </td>
                <td className="px-3 py-2 text-carbon-400">{a.asset_type || '-'}</td>
                <td className={`px-3 py-2 ${a.eligible_for_bounty ? 'text-emerald-300' : 'text-carbon-400'}`}>
                  {a.eligible_for_bounty ? 'yes' : 'no'}
                </td>
                <td className={`px-3 py-2 ${sevColor[a.max_severity] ?? 'text-carbon-400'}`}>{a.max_severity || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ProgramDetailPage;
