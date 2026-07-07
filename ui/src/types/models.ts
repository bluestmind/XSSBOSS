/** Domain model types */

export type TargetStatus = 'recon_only' | 'fuzzing' | 'triage' | 'done';
export type ParamLocation = 'query' | 'body' | 'json' | 'path' | 'header' | 'cookie';
export type ContextType = 'HTML_TEXT' | 'ATTR_QUOTED' | 'ATTR_UNQUOTED' | 'EVENT_HANDLER_ATTR' | 'JS_STRING_LITERAL' | 'JS_IDENTIFIER' | 'URL_FRAGMENT' | 'URL_QUERY' | 'JSON_VALUE';
export type SinkType = 'innerHTML' | 'outerHTML' | 'insertAdjacentHTML' | 'eval' | 'Function' | 'setTimeout' | 'setInterval' | 'document.write' | 'href' | 'src' | 'jQuery_html';
export type ExperimentStrategy = 'quick_light' | 'smart_adaptive' | 'unicode_hunt' | 'js_string_specialist' | 'csp_aware' | 'max_coverage' | 'genetic_evolutionary';
export type ExperimentStatus = 'pending' | 'running' | 'paused' | 'completed' | 'failed';
export type TestCaseStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed';
export type OracleStatus = 'hit' | 'missed' | 'error';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type FindingStatus = 'draft' | 'confirmed' | 'reported' | 'duplicate';

