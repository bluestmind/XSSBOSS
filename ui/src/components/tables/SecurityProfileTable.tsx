import React, { useState } from 'react';
import type { SecurityProfile } from '@/api/programs';
import { paramsApi } from '@/api/params';

interface SecurityProfileTableProps {
  profile?: SecurityProfile;
}

const colorStyles: Record<string, { bg: string; text: string; border: string; badge: string }> = {
  emerald: {
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-300',
    border: 'border-emerald-500/30',
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  },
  amber: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-300',
    border: 'border-amber-500/30',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  },
  orange: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-300',
    border: 'border-orange-500/30',
    badge: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  },
  rose: {
    bg: 'bg-rose-500/10',
    text: 'text-rose-300',
    border: 'border-rose-500/30',
    badge: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
  },
};

export const SecurityProfileTable: React.FC<SecurityProfileTableProps> = ({ profile }) => {
  const [activeTab, setActiveTab] = useState<'matrix' | 'headers' | 'cookies' | 'sinks' | 'redirects' | 'data_loads' | 'functions' | 'endpoints'>('matrix');
  const [newParamName, setNewParamName] = useState('');
  const [newParamCategory, setNewParamCategory] = useState('redirect');
  const [addFeedback, setAddFeedback] = useState<string | null>(null);

  const handleAddParam = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newParamName.trim()) return;
    try {
      await paramsApi.addCustomParam(newParamName.trim(), newParamCategory, `Program: ${profile?.target_name || 'Manual'}`);
      setAddFeedback(`Learned '${newParamName.trim()}' (${newParamCategory})! Saved to persistent dictionary.`);
      setNewParamName('');
      setTimeout(() => setAddFeedback(null), 4000);
    } catch (err: any) {
      alert(`Error registering parameter: ${err?.message || err}`);
    }
  };

  if (!profile) {
    return (
      <div className="p-6 rounded-xl bg-carbon-900/50 border border-carbon-800 text-carbon-400 text-sm">
        No security telemetry or filter profile recorded yet. Launch an autonomous scan or recon to generate real-time profile data.
      </div>
    );
  }

  const {
    defense_score,
    waf,
    csp,
    security_headers,
    cors,
    cookies,
    character_matrix,
    sinks,
    dom_clobbering,
    subresource_integrity,
    redirects,
    initial_data_loads,
    javascript_functions,
    tech_stack,
    endpoints,
  } = profile;

  return (
    <div className="space-y-6">
      {/* Top Security Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Defense Grade & Hardening Score */}
        <div className="p-4 rounded-xl bg-carbon-900/70 border border-carbon-800/80 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-carbon-400">🏆 Defense Grade</span>
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-black border ${
              (defense_score?.overall_grade || 'B').startsWith('A')
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                : (defense_score?.overall_grade || 'B').startsWith('B')
                ? 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
            }`}>
              {defense_score?.overall_grade || 'B / MODERATE'}
            </span>
          </div>
          <div className="text-2xl font-black text-carbon-100">
            {defense_score?.overall_score ?? 65}<span className="text-xs text-carbon-400 font-normal"> / 100</span>
          </div>
          <div className="w-full bg-carbon-800 rounded-full h-1.5 mt-2 overflow-hidden">
            <div
              className="bg-brand-400 h-1.5 rounded-full"
              style={{ width: `${Math.min(100, Math.max(5, defense_score?.overall_score ?? 65))}%` }}
            />
          </div>
        </div>

        {/* WAF Shield Status */}
        <div className="p-4 rounded-xl bg-carbon-900/70 border border-carbon-800/80 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-carbon-400">🛡️ WAF Protection</span>
            <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${
              waf.waf_detected 
                ? 'bg-orange-500/20 text-orange-300 border-orange-500/30' 
                : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
            }`}>
              {waf.waf_detected ? 'ACTIVE SHIELD' : 'NO WAF'}
            </span>
          </div>
          <div className="text-base font-bold text-carbon-100 truncate" title={waf.waf_name}>{waf.waf_name}</div>
          <div className="text-xs text-carbon-400 mt-1 truncate">
            Mode: <span className="text-carbon-200 font-medium">{waf.blocking_mode}</span>
          </div>
        </div>

        {/* CSP Policy Status */}
        <div className="p-4 rounded-xl bg-carbon-900/70 border border-carbon-800/80 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-carbon-400">📜 Content Security Policy</span>
            <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${
              !csp.has_csp 
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' 
                : csp.unsafe_inline 
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                : 'bg-blue-500/20 text-blue-300 border-blue-500/30'
            }`}>
              {csp.has_csp ? 'ENFORCED' : 'MISSING (VULNERABLE)'}
            </span>
          </div>
          <div className="text-sm font-bold text-carbon-100 truncate" title={csp.risk_assessment}>
            {csp.risk_assessment}
          </div>
          <div className="text-xs text-carbon-400 mt-1 truncate">
            script-src: <span className="text-brand-300 font-mono">{csp.script_src}</span>
          </div>
        </div>

        {/* Security Headers & CORS */}
        <div className="p-4 rounded-xl bg-carbon-900/70 border border-carbon-800/80 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-carbon-400">🔐 Security Headers</span>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
              GRADE {security_headers?.grade || 'B'}
            </span>
          </div>
          <div className="text-sm font-bold text-carbon-100">
            {security_headers?.enforced_count ?? 4} / {security_headers?.total_count ?? 7} Enforced
          </div>
          <div className="text-xs text-carbon-400 mt-1 truncate">
            CORS: <span className="text-carbon-200 font-medium">{cors?.status || 'Restricted'}</span>
          </div>
        </div>
      </div>

      {/* Technology & Sanitizer Badges */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-carbon-900/50 border border-carbon-800">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-semibold uppercase tracking-wider text-carbon-400 mr-2">⚡ Tech Stack:</span>
          {tech_stack.frameworks.map((fw, idx) => (
            <span key={idx} className="px-2 py-0.5 rounded bg-carbon-800 text-carbon-200 border border-carbon-700 text-[11px] font-mono">
              {fw}
            </span>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-semibold uppercase tracking-wider text-carbon-400 mr-2">🧼 Sanitizers:</span>
          {tech_stack.sanitizers.map((s, idx) => (
            <span key={`san-${idx}`} className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 text-[11px] font-mono">
              {s}
            </span>
          ))}
        </div>
      </div>

      {/* Tabs for Detailed Telemetry */}
      <div className="border-b border-carbon-800 flex flex-wrap items-center gap-2 md:gap-4">
        <button
          onClick={() => setActiveTab('matrix')}
          className={`pb-2.5 text-xs md:text-sm font-semibold transition border-b-2 ${
            activeTab === 'matrix' ? 'border-brand-500 text-brand-300' : 'border-transparent text-carbon-400 hover:text-carbon-200'
          }`}
        >
          🔤 Character Filter ({character_matrix.length})
        </button>
        <button
          onClick={() => setActiveTab('headers')}
          className={`pb-2.5 text-xs md:text-sm font-semibold transition border-b-2 ${
            activeTab === 'headers' ? 'border-brand-500 text-brand-300' : 'border-transparent text-carbon-400 hover:text-carbon-200'
          }`}
        >
          🔐 Headers & CORS ({security_headers?.items?.length ?? 7})
        </button>
        <button
          onClick={() => setActiveTab('cookies')}
          className={`pb-2.5 text-xs md:text-sm font-semibold transition border-b-2 ${
            activeTab === 'cookies' ? 'border-brand-500 text-brand-300' : 'border-transparent text-carbon-400 hover:text-carbon-200'
          }`}
        >
          🍪 Cookies & Tokens ({cookies?.total ?? 0})
        </button>
        <button
          onClick={() => setActiveTab('sinks')}
          className={`pb-2.5 text-xs md:text-sm font-semibold transition border-b-2 ${
            activeTab === 'sinks' ? 'border-brand-500 text-brand-300' : 'border-transparent text-carbon-400 hover:text-carbon-200'
          }`}
        >
          🎯 Sinks & Clobbering ({sinks.total})
        </button>
        <button
          onClick={() => setActiveTab('redirects')}
          className={`pb-2.5 text-xs md:text-sm font-semibold transition border-b-2 ${
            activeTab === 'redirects' ? 'border-brand-500 text-brand-300' : 'border-transparent text-carbon-400 hover:text-carbon-200'
          }`}
        >
          🔀 Redirects & Navigation ({redirects?.total ?? 0})
        </button>
        <button
          onClick={() => setActiveTab('data_loads')}
          className={`pb-2.5 text-xs md:text-sm font-semibold transition border-b-2 ${
            activeTab === 'data_loads' ? 'border-brand-500 text-brand-300' : 'border-transparent text-carbon-400 hover:text-carbon-200'
          }`}
        >
          📦 Initial Page Data ({initial_data_loads?.total ?? 0})
        </button>
        <button
          onClick={() => setActiveTab('functions')}
          className={`pb-2.5 text-xs md:text-sm font-semibold transition border-b-2 ${
            activeTab === 'functions' ? 'border-brand-500 text-brand-300' : 'border-transparent text-carbon-400 hover:text-carbon-200'
          }`}
        >
          ⚡ JS Functions & SRI ({javascript_functions?.total ?? 0})
        </button>
        <button
          onClick={() => setActiveTab('endpoints')}
          className={`pb-2.5 text-xs md:text-sm font-semibold transition border-b-2 ${
            activeTab === 'endpoints' ? 'border-brand-500 text-brand-300' : 'border-transparent text-carbon-400 hover:text-carbon-200'
          }`}
        >
          🌐 Endpoints ({endpoints.length})
        </button>
      </div>

      {/* TAB 1: Character Filter Matrix */}
      {activeTab === 'matrix' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-carbon-200 uppercase tracking-wider">
              Input Filter Behavior (Tested Characters)
            </h3>
            <div className="flex flex-wrap items-center gap-3 text-xs text-carbon-400">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400"></span> Raw Reflection</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400"></span> HTML Encoded</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-orange-400"></span> Escaped (\)</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-rose-400"></span> Blocked / Stripped</span>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {character_matrix.map((item, i) => {
              const style = colorStyles[item.color] || colorStyles.emerald;
              return (
                <div
                  key={i}
                  className={`p-3 rounded-lg border ${style.bg} ${style.border} flex flex-col justify-between transition hover:scale-[1.02]`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-lg font-mono font-black text-carbon-100">{item.char}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${style.badge}`}>
                      {item.status.includes('ALLOWED') ? 'PASS' : item.status.includes('ENCODED') ? 'ENCODED' : item.status.includes('ESCAPED') ? 'ESCAPED' : 'BLOCK'}
                    </span>
                  </div>
                  <div className="mt-2 text-[11px] text-carbon-300 font-medium">{item.label}</div>
                  <div className={`mt-0.5 text-[10px] font-mono ${style.text}`}>{item.status}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 2: Security Headers & CORS */}
      {activeTab === 'headers' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-carbon-200 uppercase tracking-wider">HTTP Security Headers Matrix</h3>
              <p className="text-xs text-carbon-400 mt-0.5">Defense-in-depth header compliance and risk analysis</p>
            </div>
            <span className="px-3 py-1 rounded-full text-xs font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
              Score: {security_headers?.score_percent ?? 70}%
            </span>
          </div>

          <div className="overflow-x-auto rounded-xl border border-carbon-800 shadow-md">
            <table className="w-full text-left text-xs text-carbon-300">
              <thead className="bg-carbon-900/80 text-carbon-400 uppercase font-semibold text-[11px] border-b border-carbon-800">
                <tr>
                  <th className="p-3">Security Header</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Detected Value</th>
                  <th className="p-3">Risk Evaluation</th>
                  <th className="p-3">Recommendation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-carbon-800/60 font-mono">
                {(security_headers?.items || []).map((h, idx) => {
                  const isEnforced = h.status === 'Enforced';
                  return (
                    <tr key={idx} className="hover:bg-carbon-800/30 transition">
                      <td className="p-3 font-semibold text-carbon-100 font-sans">{h.header}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          isEnforced
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                            : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                        }`}>
                          {h.status}
                        </span>
                      </td>
                      <td className="p-3 text-carbon-300 truncate max-w-xs" title={h.value}>{h.value}</td>
                      <td className="p-3">
                        <span className={isEnforced ? 'text-emerald-400' : 'text-amber-400'}>{h.risk}</span>
                      </td>
                      <td className="p-3 text-carbon-400 font-sans">{h.recommendation}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* CORS Sub-Panel */}
          <div className="p-4 rounded-xl bg-carbon-900/60 border border-carbon-800">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs font-bold text-carbon-200 uppercase tracking-wider">🌐 Cross-Origin Resource Sharing (CORS) Policy</h4>
              <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold border ${
                cors?.status === 'Vulnerable'
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                  : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
              }`}>
                {cors?.status || 'Restricted'}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="p-2.5 rounded bg-carbon-800/50 border border-carbon-700/50">
                <span className="text-carbon-400 block text-[11px]">Access-Control-Allow-Origin:</span>
                <span className="text-carbon-200 font-mono font-bold">{cors?.allow_origin || 'Same-Origin'}</span>
              </div>
              <div className="p-2.5 rounded bg-carbon-800/50 border border-carbon-700/50">
                <span className="text-carbon-400 block text-[11px]">Allow-Credentials:</span>
                <span className={`font-mono font-bold ${cors?.allow_credentials ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {cors?.allow_credentials ? 'true (Credentials Allowed)' : 'false (Safe)'}
                </span>
              </div>
              <div className="p-2.5 rounded bg-carbon-800/50 border border-carbon-700/50">
                <span className="text-carbon-400 block text-[11px]">Risk Evaluation:</span>
                <span className="text-carbon-300 font-sans">{cors?.risk_assessment || 'Low Risk'}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Cookie Security */}
      {activeTab === 'cookies' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-carbon-200 uppercase tracking-wider">🍪 Cookie & Session Token Hardening</h3>
              <p className="text-xs text-carbon-400 mt-0.5">Flagging missing HttpOnly, Secure, and SameSite protection flags</p>
            </div>
            <span className="text-xs text-carbon-400">{cookies?.total ?? 0} Cookies Monitored</span>
          </div>

          <div className="overflow-x-auto rounded-xl border border-carbon-800 shadow-md">
            <table className="w-full text-left text-xs text-carbon-300">
              <thead className="bg-carbon-900/80 text-carbon-400 uppercase font-semibold text-[11px] border-b border-carbon-800">
                <tr>
                  <th className="p-3">Cookie Name</th>
                  <th className="p-3">Domain</th>
                  <th className="p-3">HttpOnly</th>
                  <th className="p-3">Secure (SSL)</th>
                  <th className="p-3">SameSite</th>
                  <th className="p-3">Risk / Token Exfiltration Rating</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-carbon-800/60 font-mono">
                {(cookies?.items || []).map((c, idx) => (
                  <tr key={idx} className="hover:bg-carbon-800/30 transition">
                    <td className="p-3 font-semibold text-carbon-100 font-sans">{c.name}</td>
                    <td className="p-3 text-carbon-400">{c.domain}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        c.httponly ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                      }`}>
                        {c.httponly ? 'TRUE (Safe)' : 'FALSE (XSS Vulnerable)'}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        c.secure ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                      }`}>
                        {c.secure ? 'HTTPS' : 'HTTP (Insecure)'}
                      </span>
                    </td>
                    <td className="p-3 text-carbon-200 font-bold">{c.samesite}</td>
                    <td className="p-3 font-sans">
                      <span className={c.httponly ? 'text-emerald-400' : 'text-rose-400 font-semibold'}>{c.risk_level}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: DOM Sinks & Taint Trace */}
      {activeTab === 'sinks' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-carbon-200 uppercase tracking-wider">🎯 Discovered DOM Sinks</h3>
              <p className="text-xs text-carbon-400 mt-0.5">Instrumented execution and taint injection points in client DOM</p>
            </div>
            <span className="text-xs text-carbon-400">{sinks.total} Hooked Sinks</span>
          </div>

          <div className="overflow-x-auto rounded-xl border border-carbon-800 shadow-md">
            <table className="w-full text-left text-xs text-carbon-300">
              <thead className="bg-carbon-900/80 text-carbon-400 uppercase font-semibold text-[11px] border-b border-carbon-800">
                <tr>
                  <th className="p-3">Sink Type</th>
                  <th className="p-3">Context Type</th>
                  <th className="p-3">Detection Engine</th>
                  <th className="p-3">JS Location</th>
                  <th className="p-3">Analysis Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-carbon-800/60 font-mono">
                {sinks.items.map((s, idx) => (
                  <tr key={idx} className="hover:bg-carbon-800/30 transition">
                    <td className="p-3 font-semibold text-carbon-100 font-sans">
                      <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 text-[11px]">
                        ⚡ {s.sink_type}
                      </span>
                    </td>
                    <td className="p-3 text-carbon-300">{s.context_type}</td>
                    <td className="p-3 text-carbon-400">{s.detected_via}</td>
                    <td className="p-3 text-carbon-300 truncate max-w-xs">{s.js_location}</td>
                    <td className="p-3 text-carbon-400 font-sans">{s.notes || 'Hooked via Browser Worker Runtime'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* DOM Clobbering Surface */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-carbon-200 uppercase tracking-wider">🪤 DOM Clobbering Global Namespace Surface</h4>
            <div className="overflow-x-auto rounded-xl border border-carbon-800 shadow-md">
              <table className="w-full text-left text-xs text-carbon-300">
                <thead className="bg-carbon-900/80 text-carbon-400 uppercase font-semibold text-[11px] border-b border-carbon-800">
                  <tr>
                    <th className="p-3">Target ID / Name</th>
                    <th className="p-3">Element Type</th>
                    <th className="p-3">Clobber Type</th>
                    <th className="p-3">Risk Analysis</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-carbon-800/60 font-mono">
                  {(dom_clobbering?.items || []).map((dc, idx) => (
                    <tr key={idx} className="hover:bg-carbon-800/30 transition">
                      <td className="p-3 font-semibold text-brand-300 font-bold">{dc.id_or_name}</td>
                      <td className="p-3 text-carbon-300 font-sans">{dc.element_type}</td>
                      <td className="p-3 text-carbon-400">{dc.clobber_type}</td>
                      <td className="p-3 text-carbon-300 font-sans">{dc.risk_analysis}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Redirects & Navigation Flows */}
      {activeTab === 'redirects' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-carbon-200 uppercase tracking-wider">
                Redirect Parameters & Navigation Flows ({redirects?.total ?? 0})
              </h3>
              <span className="text-xs text-carbon-400">
                Audited navigation parameters and open-redirect surfaces
              </span>
            </div>

            {/* Quick Train Parameter Dictionary Toolbar */}
            <form onSubmit={handleAddParam} className="flex items-center gap-2">
              <input
                type="text"
                value={newParamName}
                onChange={(e) => setNewParamName(e.target.value)}
                placeholder="Teach new redirect param (e.g. partner_url)..."
                className="px-2.5 py-1 text-xs rounded bg-carbon-800 border border-carbon-700 text-carbon-100 placeholder-carbon-500 focus:outline-none focus:border-brand-500 w-64 font-mono"
              />
              <select
                value={newParamCategory}
                onChange={(e) => setNewParamCategory(e.target.value)}
                className="px-2 py-1 text-xs rounded bg-carbon-800 border border-carbon-700 text-carbon-200 focus:outline-none"
              >
                <option value="redirect">Redirect Param</option>
                <option value="search_query">Search Query</option>
                <option value="jsonp_callback">JSONP Callback</option>
                <option value="debug_privileged">Debug Flag</option>
                <option value="dom_state">DOM State Blob</option>
              </select>
              <button
                type="submit"
                className="px-3 py-1 bg-brand-600 hover:bg-brand-500 text-white rounded text-xs font-semibold shadow transition whitespace-nowrap"
              >
                ➕ Learn Param
              </button>
            </form>
          </div>

          {addFeedback && (
            <div className="p-2 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs font-medium animate-fade-in">
              ✨ {addFeedback}
            </div>
          )}

          {!redirects || redirects.items.length === 0 ? (
            <div className="p-6 rounded-lg bg-carbon-900/40 border border-carbon-800 text-carbon-400 text-xs text-center">
              No navigation or redirect parameters detected yet.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-carbon-800">
              <table className="min-w-full text-xs">
                <thead className="bg-carbon-900 text-carbon-400">
                  <tr>
                    <th className="text-left px-3 py-2.5 font-semibold">Parameter</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Redirect Type</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Endpoint URL</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Risk Rating</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Sample Injection</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-carbon-800 bg-carbon-900/50">
                  {redirects.items.map((r, idx) => (
                    <tr key={idx} className="hover:bg-carbon-800/30">
                      <td className="px-3 py-2 font-mono font-bold text-amber-300">
                        {r.param_name} <span className="text-[10px] text-carbon-500 font-normal">({r.param_location})</span>
                      </td>
                      <td className="px-3 py-2 text-carbon-300 font-medium">{r.redirect_type}</td>
                      <td className="px-3 py-2 font-mono text-carbon-400 truncate max-w-xs" title={r.endpoint_url}>
                        {r.endpoint_url}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          r.risk_rating.includes('High') ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' : 'bg-carbon-800 text-carbon-400'
                        }`}>
                          {r.risk_rating}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-[11px] text-brand-300 truncate max-w-xs" title={r.sample_destination}>
                        {r.sample_destination}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: Initial Data Loads & Hydration Payloads */}
      {activeTab === 'data_loads' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-carbon-200 uppercase tracking-wider">
              Initial Page Data & SSR Hydration Payloads ({initial_data_loads?.total ?? 0})
            </h3>
            <span className="text-xs text-carbon-400">
              State blobs and JSON payloads loaded into page memory on initial request
            </span>
          </div>

          {!initial_data_loads || initial_data_loads.items.length === 0 ? (
            <div className="p-6 rounded-lg bg-carbon-900/40 border border-carbon-800 text-carbon-400 text-xs text-center">
              No hydration JSON state blobs identified.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {initial_data_loads.items.map((data, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-carbon-900/70 border border-carbon-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-carbon-100">📦 {data.data_type}</span>
                    <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 text-[10px] font-mono">
                      {data.size_bytes} bytes
                    </span>
                  </div>
                  <div className="text-xs text-carbon-400">
                    Source: <code className="text-brand-300 font-mono text-[11px]">{data.source}</code>
                  </div>
                  <div>
                    <div className="text-[11px] font-semibold text-carbon-300 mb-1">Extracted State Keys:</div>
                    <div className="flex flex-wrap gap-1">
                      {data.keys.map((k, ki) => (
                        <span key={ki} className="px-2 py-0.5 rounded bg-carbon-800 text-carbon-200 text-[10px] font-mono">
                          {k}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-black/50 border border-carbon-800 font-mono text-[11px] text-carbon-300 overflow-x-auto max-h-24">
                    {data.sample_snippet}
                  </div>
                  <div className="text-[11px] text-amber-300/90 font-medium">
                    ⚠️ {data.risk_analysis}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 5: JavaScript Functions & Handlers */}
      {activeTab === 'functions' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-carbon-200 uppercase tracking-wider">
              JavaScript Functions & Interactive Event Handlers ({javascript_functions?.total ?? 0})
            </h3>
            <span className="text-xs text-carbon-400">
              Active global functions, event listeners, and postMessage handlers
            </span>
          </div>

          {!javascript_functions || javascript_functions.items.length === 0 ? (
            <div className="p-6 rounded-lg bg-carbon-900/40 border border-carbon-800 text-carbon-400 text-xs text-center">
              No custom JavaScript functions recorded.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-carbon-800">
              <table className="min-w-full text-xs">
                <thead className="bg-carbon-900 text-carbon-400">
                  <tr>
                    <th className="text-left px-3 py-2.5 font-semibold">Function Name / Signature</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Category</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Source Location</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Security & Attack Surface Role</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-carbon-800 bg-carbon-900/50">
                  {javascript_functions.items.map((fn, idx) => (
                    <tr key={idx} className="hover:bg-carbon-800/30">
                      <td className="px-3 py-2 font-mono font-bold text-brand-300 truncate max-w-xs" title={fn.signature}>
                        ⚡ {fn.function_name}
                      </td>
                      <td className="px-3 py-2 text-carbon-200 font-medium">
                        <span className="px-2 py-0.5 rounded bg-carbon-800 text-carbon-300 text-[10px]">
                          {fn.category}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-carbon-400 text-[11px] truncate max-w-xs" title={fn.source}>
                        {fn.source}
                      </td>
                      <td className="px-3 py-2 text-carbon-300 text-[11px]">
                        {fn.security_role}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Subresource Integrity (SRI) Panel */}
          <div className="space-y-3 pt-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-carbon-200 uppercase tracking-wider">📦 Subresource Integrity (SRI) & CDN Dependencies</h4>
              <span className="text-xs text-carbon-400">
                {subresource_integrity?.scripts_with_sri ?? 0} / {subresource_integrity?.total_scripts ?? 0} SRI Hashes Enforced
              </span>
            </div>
            <div className="overflow-x-auto rounded-lg border border-carbon-800">
              <table className="min-w-full text-xs">
                <thead className="bg-carbon-900 text-carbon-400">
                  <tr>
                    <th className="text-left px-3 py-2.5 font-semibold">Script / Asset URL</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Origin Type</th>
                    <th className="text-left px-3 py-2.5 font-semibold">SRI Hash</th>
                    <th className="text-left px-3 py-2.5 font-semibold">Risk Evaluation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-carbon-800 bg-carbon-900/50 font-mono">
                  {(subresource_integrity?.items || []).map((sri, idx) => (
                    <tr key={idx} className="hover:bg-carbon-800/30">
                      <td className="px-3 py-2 text-carbon-100 truncate max-w-xs" title={sri.full_url}>{sri.url}</td>
                      <td className="px-3 py-2 text-carbon-400 font-sans">{sri.origin_type}</td>
                      <td className="px-3 py-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          sri.has_sri
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                            : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                        }`}>
                          {sri.has_sri ? 'SRI ENFORCED' : 'NO INTEGRITY HASH'}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-sans text-carbon-300">{sri.risk}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: Per-Endpoint Defense Matrix */}
      {activeTab === 'endpoints' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-carbon-200 uppercase tracking-wider">
              Endpoint Security & Protection Telemetry ({endpoints.length})
            </h3>
          </div>

          <div className="overflow-x-auto rounded-lg border border-carbon-800">
            <table className="min-w-full text-xs">
              <thead className="bg-carbon-900 text-carbon-400">
                <tr>
                  <th className="text-left px-3 py-2.5 font-semibold w-16">Method</th>
                  <th className="text-left px-3 py-2.5 font-semibold">Endpoint URL</th>
                  <th className="text-center px-3 py-2.5 font-semibold">WAF</th>
                  <th className="text-center px-3 py-2.5 font-semibold">CSP</th>
                  <th className="text-center px-3 py-2.5 font-semibold">Sinks</th>
                  <th className="text-left px-3 py-2.5 font-semibold">Contexts</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-carbon-800 bg-carbon-900/50">
                {endpoints.map((ep, idx) => (
                  <tr key={idx} className="hover:bg-carbon-800/30">
                    <td className="px-3 py-2 font-mono font-bold text-brand-300">{ep.method}</td>
                    <td className="px-3 py-2 text-carbon-200 font-mono truncate max-w-sm" title={ep.url}>
                      {ep.url}
                    </td>
                    <td className="px-3 py-2 text-center">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        ep.waf !== 'None' ? 'bg-orange-500/20 text-orange-300' : 'bg-carbon-800 text-carbon-400'
                      }`}>
                        {ep.waf}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-center">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        ep.csp === 'Enforced' ? 'bg-blue-500/20 text-blue-300' : 'bg-rose-500/20 text-rose-300'
                      }`}>
                        {ep.csp}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-center text-carbon-300 font-semibold">
                      {ep.sinks_count > 0 ? (
                        <span className="text-rose-400 font-bold">{ep.sinks_count}</span>
                      ) : (
                        <span className="text-carbon-500">0</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-carbon-400 font-mono text-[11px]">
                      {ep.contexts.length > 0 ? ep.contexts.join(', ') : 'Pending reflection probe'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityProfileTable;
