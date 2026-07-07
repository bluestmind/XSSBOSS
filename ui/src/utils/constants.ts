/** Application constants */

export const API_BASE_URL = (import.meta as any).env.VITE_API_BASE_URL || '/api/v1';

export const API_ENDPOINTS = {
  targets: `${API_BASE_URL}/targets`,
  endpoints: `${API_BASE_URL}/endpoints`,
  experiments: `${API_BASE_URL}/experiments`,
  findings: `${API_BASE_URL}/results/findings`,
  executions: `${API_BASE_URL}/results/executions`,
  oracle: `${API_BASE_URL}/oracle`,
} as const;

export const CONTEXT_TYPE_LABELS: Record<string, string> = {
  HTML_TEXT: 'HTML Text',
  ATTR_QUOTED: 'Quoted Attribute',
  ATTR_UNQUOTED: 'Unquoted Attribute',
  EVENT_HANDLER_ATTR: 'Event Handler',
  JS_STRING_LITERAL: 'JS String',
  JS_IDENTIFIER: 'JS Identifier',
  URL_FRAGMENT: 'URL Fragment',
  URL_QUERY: 'URL Query',
  JSON_VALUE: 'JSON Value',
};

export const SINK_TYPE_LABELS: Record<string, string> = {
  innerHTML: 'innerHTML',
  outerHTML: 'outerHTML',
  insertAdjacentHTML: 'insertAdjacentHTML',
  eval: 'eval()',
  Function: 'Function()',
  setTimeout: 'setTimeout()',
  setInterval: 'setInterval()',
  'document.write': 'document.write()',
  href: 'href',
  src: 'src',
  jQuery_html: 'jQuery.html()',
};

export const STRATEGY_LABELS: Record<string, string> = {
  quick_light: 'Quick & Light',
  unicode_hunt: 'Unicode Hunt',
  js_string_specialist: 'JS String Specialist',
  csp_aware: 'CSP Aware',
  max_coverage: 'Max Coverage Special',
  genetic_evolutionary: 'Genetic Evolutionary',
};

export const STATUS_COLORS: Record<string, string> = {
  // Target status
  recon_only: 'bg-gray-100 text-gray-800',
  fuzzing: 'bg-blue-100 text-blue-800',
  triage: 'bg-yellow-100 text-yellow-800',
  done: 'bg-green-100 text-green-800',
  // Experiment status
  pending: 'bg-gray-100 text-gray-800',
  running: 'bg-blue-100 text-blue-800',
  paused: 'bg-yellow-100 text-yellow-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  // Test case status
  queued: 'bg-purple-100 text-purple-800',
  // Severity
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
  // Finding status
  draft: 'bg-gray-100 text-gray-800',
  confirmed: 'bg-green-100 text-green-800',
  reported: 'bg-blue-100 text-blue-800',
  duplicate: 'bg-gray-100 text-gray-800',
};

export const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-green-100 text-green-800',
  POST: 'bg-blue-100 text-blue-800',
  PUT: 'bg-yellow-100 text-yellow-800',
  DELETE: 'bg-red-100 text-red-800',
  PATCH: 'bg-purple-100 text-purple-800',
};

export const LOCATION_COLORS: Record<string, string> = {
  query: 'bg-blue-100 text-blue-800',
  body: 'bg-purple-100 text-purple-800',
  json: 'bg-indigo-100 text-indigo-800',
  path: 'bg-pink-100 text-pink-800',
  header: 'bg-orange-100 text-orange-800',
  cookie: 'bg-teal-100 text-teal-800',
};

