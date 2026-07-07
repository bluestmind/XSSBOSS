/** Decision Tree & XSS Checklist Mapping UI Component */
import React from 'react';

interface DecisionTreeProps {
  finding: any;
}

const DecisionTree: React.FC<DecisionTreeProps> = ({ finding }) => {
  if (!finding) return null;

  const endpoint = finding.endpoint || {};
  const param = finding.param || {};
  const context = finding.context || {};
  const evidence = finding.evidence_refs || {};

  // Resolve steps status
  const steps = [
    {
      id: 'step1',
      title: 'Phase 1: Setup & Target Scoping',
      status: 'completed',
      detail: `URL Submitted: ${endpoint.url_pattern || 'N/A'}`,
      description: 'Scope check verified. Added to active endpoint inventory.',
      decisions: [
        { key: 'Target Platform', value: finding.target?.bounty_platform || 'Generic Web' },
        { key: 'HTTP Method', value: endpoint.method || 'GET' },
        { key: 'Discovery Source', value: param.burp_flagged ? 'Burp Suite REST Sync' : 'XSS Boss Crawler' }
      ]
    },
    {
      id: 'step2',
      title: 'Phase 2: Parameter Extraction',
      status: 'completed',
      detail: `Parameter Flagged: "${param.name || 'N/A'}" (${param.location || 'N/A'})`,
      description: 'Analyzed for reflection context. Marked as controllable parameter.',
      decisions: [
        { key: 'Location', value: param.location || 'query' },
        { key: 'Sample Value', value: param.sample_value || 'N/A' },
        { key: 'Burp Suite Flagged', value: param.burp_flagged ? 'YES (High Priority)' : 'NO (Normal Priority)' }
      ]
    },
    {
      id: 'step3',
      title: 'Phase 3: Syntax Context Detection',
      status: 'completed',
      detail: `Reflection Context: ${context.context_type || 'HTML_TEXT'}`,
      description: 'Syntax analyzer parsed response structure to identify escape context.',
      decisions: [
        { key: 'HTML Tag Context', value: context.tag ? `<${context.tag}>` : 'None (Outside Tags)' },
        { key: 'Quote Breakout', value: context.context_type?.includes('QUOTED') ? 'Required' : 'Not Required' },
        { key: 'Pre-seeded Context', value: context.snippet?.includes('[Pre-seeded') ? 'YES (Burp)' : 'NO (Telemetry)' }
      ]
    },
    {
      id: 'step4',
      title: 'Phase 4: Filter & WAF Profiling',
      status: 'completed',
      detail: 'Filter Profiling Analysis Completed',
      description: 'Pre-tested escape tokens to check regex filters, sanitization rules, or active WAF blocking.',
      decisions: [
        { key: 'WAF Blocked Tokens', value: evidence.tech_stack?.waf ? 'Detected WAF Filter' : 'None Detected' },
        { key: 'Sanitization Rule', value: context.context_type === 'JSON_VALUE' ? 'JSON Escaped' : 'Reflected Raw' },
        { key: 'Payload Strategy', value: 'Dynamic Bypass Mutation' }
      ]
    },
    {
      id: 'step5',
      title: 'Phase 5: Fuzzer Execution & Telemetry',
      status: 'completed',
      detail: 'Selenium Sandbox Auditing Executed',
      description: 'Injected mutated payloads and executed them in a headless Chrome container instrumented with DOM hooks.',
      decisions: [
        { key: 'Active Payload', value: finding.best_payload },
        { key: 'Browser Workers', value: '1 Native Selenium Instance' },
        { key: 'Telemetry Hook', value: 'DOM Sink Interceptor / Synthetic Event Fuzzer' }
      ]
    },
    {
      id: 'step6',
      title: 'Phase 6: Oracle Telemetry Validation',
      status: 'completed',
      detail: `Dynamic Verification: XSS HIT Confirmed!`,
      description: 'Oracle backend server caught execution sink callbacks from the instrumented DOM hooks.',
      decisions: [
        { key: 'Sink Type Triggered', value: evidence.sink_details?.sink_type || 'Event / JS Evaluation' },
        { key: 'Screenshot Saved', value: finding.screenshot_path ? 'YES' : 'NO' },
        { key: 'PoC HTML Generated', value: finding.poc_html ? 'YES' : 'NO' }
      ]
    }
  ];

  return (
    <div className="bg-gray-50 rounded-lg border border-gray-200 p-6 my-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-md font-semibold text-gray-900">XSS Checklist Execution Tree</h4>
        <span className="px-2.5 py-0.5 text-xs font-semibold bg-green-100 text-green-800 rounded-full">
          Vulnerability Confirmed (PoC Ready)
        </span>
      </div>
      <p className="text-xs text-gray-500 mb-6">
        Below is the step-by-step decision checklist that led from submitting the URL target to generating this verified PoC.
      </p>

      {/* Decision Path Tree Layout */}
      <div className="relative border-l-2 border-blue-200 ml-4 space-y-8 pb-4">
        {steps.map((step, index) => (
          <div key={step.id} className="relative pl-8">
            {/* Tree Node Dot */}
            <span className="absolute -left-[9px] top-1 flex h-4 w-4 items-center justify-center rounded-full bg-blue-500 ring-4 ring-white">
              <span className="h-1.5 w-1.5 rounded-full bg-white" />
            </span>

            {/* Content Container */}
            <div className="bg-white rounded-lg border border-gray-200 p-4 shadow-sm hover:shadow-md transition-shadow">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-semibold text-blue-600 uppercase tracking-wider">{step.title}</span>
                <span className="px-2 py-0.5 text-[10px] font-medium bg-green-50 text-green-700 rounded border border-green-200">
                  PASSED
                </span>
              </div>
              <h5 className="text-sm font-semibold text-gray-900 mb-1">{step.detail}</h5>
              <p className="text-xs text-gray-500 leading-relaxed mb-3">{step.description}</p>

              {/* Decisions metadata sub-table */}
              <div className="bg-gray-50 rounded border border-gray-150 p-2.5">
                <span className="text-[10px] font-bold text-gray-400 uppercase block mb-1.5">Checks & Decisions Made</span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                  {step.decisions.map((dec, i) => (
                    <div key={i} className="flex flex-col">
                      <span className="text-[10px] text-gray-400 font-medium">{dec.key}</span>
                      <span className="font-mono text-gray-800 break-all truncate" title={dec.value}>
                        {dec.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Tree Line Connector arrow (except last step) */}
            {index < steps.length - 1 && (
              <div className="absolute left-[7px] bottom-[-24px] text-blue-300 font-bold text-lg select-none">
                ↓
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default DecisionTree;
