/** Program dashboard API — ranked programs + one-click hunt */
import api from '@/utils/request';

export interface ProgramStats {
  total: number;
  active: number;
  hunted: number;
  with_findings: number;
  paused: number;
  idle: number;
  total_findings: number;
}

export interface ProgramRank {
  target_id: number;
  handle: string;
  name: string;
  priority_score: number;
  offers_bounties: boolean;
  web_asset_count: number;
  bounty_eligible_count: number;
  wildcard_count: number;
  top_severity: string;
  reasons: string[];
  run_status?: 'idle' | 'queued' | 'running' | 'paused' | 'completed' | 'failed';
  findings_count?: number;
  endpoints_count?: number;
  experiments_count?: number;
  last_hunted_at?: string | null;
  active_experiment_id?: number | null;
}

export interface ProgramsResponse {
  count: number;
  stats: ProgramStats;
  programs: ProgramRank[];
}

export interface ProgramRunReport {
  total_findings: number;
  total_requests: number;
  assets_run: number;
  assets_skipped: number;
  stopped_reason: string;
  outcomes: Array<{
    host: string;
    status: string;
    endpoints: number;
    findings: number;
    requests_used: number;
    max_severity: string;
    error?: string;
  }>;
}

export interface HuntStatus {
  status: string; // idle | queued | running | completed | failed
  started_at?: string;
  finished_at?: string;
  report?: ProgramRunReport | null;
  error?: string | null;
  findings_count?: number;
  endpoints_count?: number;
  active_experiment_id?: number | null;
}

export const programsApi = {
  list: async (bountyOnly = false, limit = 500, query = ''): Promise<ProgramsResponse> => {
    const qParam = query ? `&query=${encodeURIComponent(query)}` : '';
    const res = await api.get<ProgramsResponse>(
      `/programs?bounty_only=${bountyOnly}&limit=${limit}${qParam}`,
    );
    return res.data;
  },

  profile: async (targetId: number) => {
    const res = await api.get(`/programs/${targetId}`);
    return res.data;
  },

  startHunt: async (targetId: number, opts?: { maxAssets?: number; budget?: number; strategy?: string }) => {
    const params = new URLSearchParams({
      max_assets: String(opts?.maxAssets ?? 10),
      budget: String(opts?.budget ?? 1500),
      strategy: opts?.strategy ?? 'max_coverage',
    });
    const res = await api.post(`/programs/${targetId}/hunt?${params.toString()}`);
    return res.data;
  },

  huntStatus: async (targetId: number): Promise<HuntStatus> => {
    const res = await api.get<HuntStatus>(`/programs/${targetId}/hunt/status`);
    return res.data;
  },

  burpScope: async (targetId: number) => {
    const res = await api.get(`/burp/program-scope/${targetId}`);
    return res.data as {
      burp_scope: unknown;
      include_prefixes: string[];
      summary: Record<string, unknown>;
      worklist: Array<Record<string, unknown>>;
    };
  },
};

export interface WorklistAsset {
  identifier: string;
  host: string;
  asset_type: string;
  eligible_for_bounty: boolean;
  max_severity: string;
  is_wildcard: boolean;
}

export interface WafProfile {
  waf_detected: boolean;
  waf_name: string;
  status: string;
  blocking_mode: string;
  detected_list: string[];
}

export interface CspProfile {
  has_csp: boolean;
  status: string;
  risk_assessment: string;
  raw_policy?: string | null;
  unsafe_inline: boolean;
  unsafe_eval: boolean;
  script_src: string;
  directives: Record<string, any>;
}

export interface CharacterFilterItem {
  char: string;
  label: string;
  status: string;
  color: 'emerald' | 'amber' | 'orange' | 'rose';
}

export interface SinkItem {
  id: number;
  sink_type: string;
  detected_via: string;
  js_location: string;
  notes?: string | null;
  context_type: string;
}

export interface EndpointSecuritySummary {
  id: number;
  method: string;
  url: string;
  sinks_count: number;
  sinks: string[];
  contexts: string[];
  waf: string;
  csp: string;
  status: string;
}

export interface RedirectItem {
  endpoint_url: string;
  method: string;
  param_name: string;
  param_location: string;
  redirect_type: string;
  sample_destination: string;
  risk_rating: string;
  validation: string;
}

export interface InitialDataLoadItem {
  data_type: string;
  source: string;
  keys: string[];
  sample_snippet: string;
  size_bytes: number;
  risk_analysis: string;
}

export interface JavaScriptFunctionItem {
  function_name: string;
  category: string;
  source: string;
  signature: string;
  security_role: string;
}

export interface DefenseScore {
  overall_score: number;
  overall_grade: string;
  breakdown: {
    waf_shield: number;
    csp_enforcement: number;
    security_headers: number;
    cookie_hardening: number;
    cors_isolation: number;
  };
}

export interface SecurityHeaderItem {
  header: string;
  status: string;
  value: string;
  risk: string;
  color: string;
  recommendation: string;
}

export interface SecurityHeadersProfile {
  grade: string;
  score_percent: number;
  enforced_count: number;
  total_count: number;
  items: SecurityHeaderItem[];
}

export interface CorsProfile {
  status: string;
  allow_origin: string;
  allow_credentials: boolean;
  risk_assessment: string;
  methods_allowed: string[];
  headers_allowed: string[];
}

export interface CookieSecurityItem {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string;
  risk_level: string;
  sample_value: string;
  domain: string;
}

export interface DomClobberingItem {
  id_or_name: string;
  element_type: string;
  source: string;
  clobber_type: string;
  risk_analysis: string;
}

export interface SriItem {
  url: string;
  full_url: string;
  origin_type: string;
  has_sri: boolean;
  risk: string;
  domain: string;
}

export interface SecurityProfile {
  target_id: number;
  target_name: string;
  base_url: string;
  defense_score?: DefenseScore;
  waf: WafProfile;
  csp: CspProfile;
  security_headers?: SecurityHeadersProfile;
  cors?: CorsProfile;
  cookies?: {
    total: number;
    items: CookieSecurityItem[];
  };
  character_matrix: CharacterFilterItem[];
  sinks: {
    total: number;
    breakdown: Record<string, number>;
    items: SinkItem[];
  };
  contexts: {
    total: number;
    breakdown: Record<string, number>;
  };
  dom_clobbering?: {
    total: number;
    items: DomClobberingItem[];
  };
  subresource_integrity?: {
    total_scripts: number;
    scripts_with_sri: number;
    third_party_domains: string[];
    items: SriItem[];
  };
  redirects: {
    total: number;
    items: RedirectItem[];
  };
  initial_data_loads: {
    total: number;
    items: InitialDataLoadItem[];
  };
  javascript_functions: {
    total: number;
    items: JavaScriptFunctionItem[];
  };
  tech_stack: {
    frameworks: string[];
    sanitizers: string[];
  };
  endpoints: EndpointSecuritySummary[];
}

export interface ProgramProfile {
  target_id: number;
  rank: ProgramRank;
  summary: {
    handle: string;
    offers_bounties: boolean;
    web_assets: number;
    bounty_eligible_assets: number;
    exclusions: number;
    top_priority: string[];
  };
  worklist: WorklistAsset[];
  security_profile?: SecurityProfile;
  run: HuntStatus;
}

