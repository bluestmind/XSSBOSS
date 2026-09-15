/** API response types */

export interface Target {
  id: number;
  name: string;
  base_url: string;
  notes?: string;
  bounty_platform?: string;
  scope_tags?: Record<string, any>;
  auth_info?: Record<string, any>;
  status: 'recon_only' | 'fuzzing' | 'triage' | 'done';
  created_at: string;
  updated_at: string;
}

export interface TargetCreate {
  name: string;
  base_url: string;
  notes?: string;
  bounty_platform?: string;
  scope_tags?: Record<string, any>;
  auth_info?: Record<string, any>;
  status?: 'recon_only' | 'fuzzing' | 'triage' | 'done';
}

export interface ScanCreate {
  url: string;
  authorized: boolean;
  name?: string;
  crawl?: boolean;
  passive_recon?: boolean;
  max_depth?: number;
  max_pages?: number;
  strategy?: 'quick_light' | 'smart_adaptive' | 'unicode_hunt' | 'js_string_specialist' | 'csp_aware' | 'max_coverage' | 'genetic_evolutionary';
  autonomous_research?: boolean;
  mode?: 'recon' | 'full';
  auth_info?: Record<string, any>;
  auth_identity?: string;
}

export interface ScanIntervention {
  id: string;
  status: 'open' | 'resolved';
  kind: string;
  reason: string;
  identity?: string;
  url?: string;
  workflow?: string;
  created_at: string;
}

export interface ScanResponse {
  target_id: number;
  experiment_id: number;
  endpoint_count: number;
  status: string;
  message: string;
}

export interface ProgramImportRequest {
  platforms: string[];
  handles?: string[];
  slugs?: string[];
  limit_per_platform?: number;
  max_scopes_per_program?: number;
  yeswehack_types?: string[];
  update_existing?: boolean;
  dry_run?: boolean;
  browser_profile_path?: string;
  browser_profile_name?: string;
}

export interface ProgramImportTarget {
  action: string;
  platform: string;
  program_key: string;
  name: string;
  base_url: string;
  target_id?: number;
  in_scope_count: number;
  out_of_scope_count: number;
  notes?: string;
  scope_tags?: Record<string, any>;
}

export interface ProgramImportError {
  platform: string;
  program_key?: string;
  message: string;
}

export interface ProgramImportResponse {
  requested_platforms: string[];
  dry_run: boolean;
  imported: number;
  updated: number;
  skipped: number;
  errors: ProgramImportError[];
  targets: ProgramImportTarget[];
}

export interface Endpoint {
  id: number;
  target_id: number;
  method: string;
  url_pattern: string;
  sample_request_body?: Record<string, any>;
  sample_response_body?: string;
  auth_context?: Record<string, any>;
  discovered_at: string;
  created_at: string;
  updated_at: string;
}

export interface Param {
  id: number;
  endpoint_id: number;
  name: string;
  location: 'query' | 'body' | 'json' | 'path' | 'header' | 'cookie';
  sample_value?: string;
  is_controllable: boolean;
  created_at: string;
  updated_at: string;
}

export interface Context {
  id: number;
  param_id: number;
  endpoint_id: number;
  context_type: 'HTML_TEXT' | 'ATTR_QUOTED' | 'ATTR_UNQUOTED' | 'EVENT_HANDLER_ATTR' | 'JS_STRING_LITERAL' | 'JS_IDENTIFIER' | 'URL_FRAGMENT' | 'URL_QUERY' | 'JSON_VALUE';
  tag?: string;
  attribute?: string;
  script_path?: string;
  snippet?: string;
  detected_at: string;
  created_at: string;
  updated_at: string;
}

export interface Sink {
  id: number;
  context_id: number;
  sink_type: string;
  js_location?: string;
  taint_path?: Record<string, any>;
  detected_via: 'static' | 'dynamic';
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface FilterProfile {
  id: number;
  endpoint_id: number;
  summary?: string;
  blocked_tokens?: string[];
  allowed_tokens?: string[];
  normalization_behavior?: string[];
  waf_detected: boolean;
  sanitizer_detected?: string;
  probe_results?: any[];
  profiled_at: string;
  created_at: string;
  updated_at: string;
}

export interface Experiment {
  id: number;
  target_id: number;
  name: string;
  strategy: 'quick_light' | 'smart_adaptive' | 'unicode_hunt' | 'js_string_specialist' | 'csp_aware' | 'max_coverage' | 'genetic_evolutionary';
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed';
  limits?: Record<string, any>;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
  target_name?: string;
  target_handle?: string;
}

export interface ExperimentCreate {
  target_id: number;
  name: string;
  strategy: 'quick_light' | 'smart_adaptive' | 'unicode_hunt' | 'js_string_specialist' | 'csp_aware' | 'max_coverage' | 'genetic_evolutionary';
  limits?: Record<string, any>;
}

export interface TestCase {
  id: number;
  experiment_id: number;
  endpoint_id: number;
  param_id: number;
  context_id?: number;
  payload: string;
  token: string;
  priority: number;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed';
  created_at: string;
  updated_at: string;
}

export interface Execution {
  id: number;
  test_case_id: number;
  browser_worker_id?: string;
  oracle_status: 'hit' | 'missed' | 'error';
  oracle_token?: string;
  logs?: string;
  screenshot_path?: string;
  dom_snapshot?: string;
  executed_at: string;
  duration_ms?: number;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: number;
  endpoint_id: number;
  param_id: number;
  context_id?: number;
  sink_id?: number;
  vuln_type: string;
  scanner_module: string;
  confidence: string;
  evidence_summary?: string;
  best_payload: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'draft' | 'confirmed' | 'reported' | 'duplicate';
  report_text?: string;
  evidence_refs?: Record<string, any>;
  poc_request?: Record<string, any>;
  poc_html?: string;
  screenshot_path?: string;
  target_name?: string;
  target_domain?: string;
  endpoint_url?: string;
  endpoint_method?: string;
  param_name?: string;
  param_location?: string;
  poc_url?: string;
  poc_source?: 'stored_request' | 'reconstructed';
  curl_command?: string;
  raw_http_request?: string;
  is_verified: boolean;
  verification_state: 'browser_confirmed' | 'confirmed' | 'unverified';
  verification_reason?: string;
  browser_replay_available: boolean;
  context_type?: string;
  sink_type?: string;
  created_at: string;
  updated_at: string;
}

export interface ExperimentStats {
  total_test_cases: number;
  pending: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
}

export interface MonitorCheck {
  id: number;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed';
  priority: number;
  payload_preview: string;
  payload?: string;
  token_preview: string;
  token?: string;
  technique?: string;
  attempt_count?: number;
  endpoint_id: number;
  endpoint_method: string;
  endpoint_url: string;
  param_name: string;
  param_location: string;
  context_type?: string;
  context_tag?: string;
  context_attribute?: string;
  context_snippet?: string;
  sinks?: string[];
  updated_at: string;
}

export interface RuntimeLineageFlow {
  candidate_id?: string;
  classification: 'causal_only' | 'value_influence';
  source_id?: string;
  source_category?: string;
  source_fingerprint?: string;
  sink_id?: string;
  sink_category?: string;
  sink_fingerprint?: string;
  relation: 'direct' | 'async';
  depth: number;
  latency_ms: number;
}

export interface RuntimeLineageEvidence {
  schema_version: string;
  interpretation?: string;
  limits?: {
    max_depth?: number;
    ttl_ms?: number;
    max_events?: number;
    max_candidates?: number;
    max_observations?: number;
    max_runs?: number;
    events_truncated?: boolean;
    candidates_truncated?: boolean;
    observations_truncated?: boolean;
    runs_truncated?: boolean;
  };
  budget_exhausted?: string[];
  summary?: {
    events_seen?: number;
    events_accepted?: number;
    events_rejected?: number;
    observations_seen?: number;
    observations_accepted?: number;
    observations_rejected?: number;
    candidates?: number;
    causal_only?: number;
    value_influence?: number;
  };
  causal_flows?: RuntimeLineageFlow[];
  value_influences?: RuntimeLineageFlow[];
}

export interface MonitorExecution {
  id: number;
  test_case_id: number;
  oracle_status: 'hit' | 'missed' | 'error';
  duration_ms?: number;
  logs?: string;
  raw_logs?: string;
  dom_snapshot?: string;
  browser_worker_id?: string;
  attempt_no?: number;
  screenshot_path?: string;
  executed_at: string;
  endpoint_url?: string;
  endpoint_method?: string;
  param_name?: string;
  param_location?: string;
  context_type?: string;
  context_tag?: string;
  context_attribute?: string;
  sinks?: string[];
  payload?: string;
  token?: string;
  status_code?: number | null;
  response_headers?: Record<string, string | string[]>;
  response_posture?: {
    schema_version: string;
    assessment?: {
      mode?: string;
      exploitability?: string;
      metadata_observed?: boolean;
    };
    observations?: {
      csp?: { state?: string };
      trusted_types?: { state?: string };
      cors?: { state?: string };
      cookies?: { state?: string; cookie_count?: number | null };
      cache?: { state?: string; shared_cache_exposure?: string };
    };
    evidence?: Array<{ code: string; level: string; summary: string }>;
    recommendations?: Array<{ code: string; priority: string; summary: string }>;
    limitations?: string[];
  };
  runtime_code_coverage?: {
    schema_version: string;
    available: boolean;
    interpretation?: string;
    phases?: string[];
    budget_exhausted?: string[];
    summary?: {
      scripts_analyzed?: number;
      runtime_reached_sites?: number;
      source_bytes_analyzed?: number;
      categories?: Record<string, number>;
    };
    findings?: Array<{
      category: string;
      site_kind: string;
      runtime_reached: boolean;
      phase: string;
    }>;
    errors?: string[];
  };
  runtime_lineage?: RuntimeLineageEvidence;
  dom_marker_differential?: {
    schema_version: string;
    available: boolean;
    differential_available?: boolean;
    interpretation?: string;
    phases?: string[];
    summary?: {
      baseline_marker_sites?: number;
      after_marker_sites?: number;
      new_marker_sites?: number;
      materialized_sites?: number;
      contexts?: Record<string, number>;
    };
    sites?: Array<{
      tag: string;
      context: string;
      attribute_name?: string | null;
      shadow_root_type?: string | null;
      phase: string;
    }>;
    budget_exhausted?: string[];
    errors?: string[];
  };
  final_url?: string;
  taint_flows?: Array<{ type?: string; text?: string }>;
}

export interface MonitorFinding {
  id: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'draft' | 'confirmed' | 'reported' | 'duplicate';
  vuln_type: string;
  scanner_module: string;
  confidence: string;
  evidence_summary?: string;
  endpoint_url: string;
  param_name: string;
  payload_preview: string;
  created_at: string;
  poc_request?: {
    command?: string;
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    payload?: string;
    param_location?: string;
  };
  screenshot_path?: string;
  execution_logs?: string;
  dom_snapshot?: string;
}

export interface MonitorEvent {
  timestamp: string;
  level: 'debug' | 'info' | 'success' | 'warning' | 'error' | string;
  phase: string;
  message: string;
  detail?: string;
}

export interface ThrottleStatus {
  host: string;
  current_delay_ms: number;
  base_delay_ms: number;
  requests_last_minute: number;
  max_requests_per_minute: number;
  consecutive_errors: number;
  adaptive_throttle: boolean;
}

export interface PerformanceMetrics {
  avg_duration_ms: number;
  min_duration_ms: number;
  max_duration_ms: number;
  total_executions: number;
  oracle_hit_count: number;
  oracle_miss_count: number;
  oracle_error_count: number;
  hit_rate_percent: number;
  throughput_per_min: number;
}

export interface WafStatus {
  waf_detected: boolean;
  sanitizer_detected?: string;
  blocked_tokens_count: number;
  allowed_tokens_count: number;
  sample_blocked_tokens: string[];
  sample_allowed_tokens: string[];
}

export interface AttackSurfaceSummary {
  endpoint_count: number;
  param_count: number;
  controllable_param_count: number;
  context_count: number;
}

export interface MicroState {
  action: string;
  substep?: string;
  endpoint?: string;
  param?: string;
  context?: string;
  technique?: string;
  result?: string;
  result_badge?: string;
  duration_ms?: number;
  status?: string;
  timestamp?: string;
}

export interface MicroEvent {
  sequence: number;
  timestamp: string;
  river_stage: string;
  stage_label: string;
  icon?: string;
  title: string;
  detail?: string;
  status: 'running' | 'success' | 'warning' | 'error' | 'hit' | 'info';
  outcome?: string;
  endpoint?: string;
  param?: string;
  context?: string;
  technique?: string;
  tool?: string;
}

export interface RiverMilestone {
  key: string;
  name: string;
  subtitle: string;
  icon: string;
  status: 'pending' | 'flowing' | 'settled' | 'eddied';
  count: number;
  water_percent: number;
  order: number;
}

export interface RiverFlow {
  current_stage: string;
  doing_status: string;
  milestones: RiverMilestone[];
  micro_state?: MicroState;
  water_velocity: string;
}

export interface ExperimentMonitor {
  experiment: Experiment;
  target: {
    id: number;
    name: string;
    base_url: string;
    status: string;
  };
  stats: ExperimentStats;
  stage: string;
  stage_detail: string;
  doing_status?: string;
  micro_state?: MicroState;
  micro_events?: MicroEvent[];
  river_flow?: RiverFlow;
  progress_percent: number;
  live_progress?: {
    sequence: number;
    phase: string;
    tool: string;
    message: string;
    detail?: string;
    state: 'working' | 'waiting' | 'error' | 'done' | string;
    completed?: number;
    total?: number;
    overall_percent?: number;
    doing_status?: string;
    river_stage?: string;
    micro_state?: MicroState;
    updated_at: string;
  };
  progress_history: Array<{
    sequence: number;
    phase: string;
    tool: string;
    message: string;
    detail?: string;
    state: string;
    completed?: number;
    total?: number;
    overall_percent?: number;
    doing_status?: string;
    river_stage?: string;
    updated_at: string;
  }>;
  elapsed_seconds: number;
  idle_seconds: number;
  progress_stale: boolean;
  pipeline_stages: Array<{
    name: string;
    status: string;
    attempt_count: number;
    started_at?: string;
    completed_at?: string;
    error?: string;
  }>;
  recent_checks: MonitorCheck[];
  recent_executions: MonitorExecution[];
  recent_findings: MonitorFinding[];
  activity_log: MonitorEvent[];
  throttle_status?: ThrottleStatus;
  context_distribution?: Record<string, number>;
  performance_metrics?: PerformanceMetrics;
  waf_status?: WafStatus;
  attack_surface?: AttackSurfaceSummary;
}
