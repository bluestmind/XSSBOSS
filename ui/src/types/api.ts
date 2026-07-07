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
  max_depth?: number;
  max_pages?: number;
  strategy?: 'quick_light' | 'unicode_hunt' | 'js_string_specialist' | 'csp_aware' | 'max_coverage';
  mode?: 'recon' | 'full';
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
  strategy: 'quick_light' | 'unicode_hunt' | 'js_string_specialist' | 'csp_aware' | 'max_coverage';
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed';
  limits?: Record<string, any>;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ExperimentCreate {
  target_id: number;
  name: string;
  strategy: 'quick_light' | 'unicode_hunt' | 'js_string_specialist' | 'csp_aware' | 'max_coverage';
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
  token_preview: string;
  endpoint_id: number;
  endpoint_method: string;
  endpoint_url: string;
  param_name: string;
  param_location: string;
  context_type?: string;
  updated_at: string;
}

export interface MonitorExecution {
  id: number;
  test_case_id: number;
  oracle_status: 'hit' | 'missed' | 'error';
  duration_ms?: number;
  logs?: string;
  screenshot_path?: string;
  executed_at: string;
  endpoint_url?: string;
  param_name?: string;
  payload?: string;
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
  progress_percent: number;
  recent_checks: MonitorCheck[];
  recent_executions: MonitorExecution[];
  recent_findings: MonitorFinding[];
  activity_log: MonitorEvent[];
  throttle_status?: ThrottleStatus;
}

