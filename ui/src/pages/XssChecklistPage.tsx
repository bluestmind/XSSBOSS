import { useState, useEffect } from 'react';

interface ChecklistItem {
  id: string;
  label?: string;
  description?: string;
  details?: string;
  technique?: string;
  scenario?: string;
}

interface ChecklistSection {
  id: string;
  title: string;
  type: 'list' | 'table';
  headers?: string[];
  items: ChecklistItem[];
}

const XssChecklistPage = () => {
  const [completedItems, setCompletedItems] = useState<string[]>([]);
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});
  const [filterMode, setFilterMode] = useState<'all' | 'pending' | 'completed'>('all');

  // Load completed items from local storage on mount
  useEffect(() => {
    const saved = localStorage.getItem('xssboss_checklist_completed');
    if (saved) {
      try {
        setCompletedItems(JSON.parse(saved));
      } catch (e) {
        console.error('Failed to load checklist state', e);
      }
    }
  }, []);

  const sections: ChecklistSection[] = [
    {
      id: 'phase1',
      title: 'Phase 1: Setup, Target Scope & Traffic Recon',
      type: 'list',
      items: [
        {
          id: 'p1_define_scope',
          label: 'Define Boundaries & Scope Rules',
          description: 'Set up target base URLs and configure include/exclude scope patterns (e.g., in_scope: ["*.target.com"], out_of_scope: ["legacy.target.com"]) to enforce scan compliance.'
        },
        {
          id: 'p1_import_traffic',
          label: 'Import Authorized Session Traffic',
          description: 'Load Burp Suite XML exports or HAR logs containing session state to pre-populate the endpoint map with real application routes.'
        },
        {
          id: 'p1_headless_crawl',
          label: 'Headless Crawler Discovery',
          description: 'Run the Playwright-based recursive crawler on authenticated routes to spider dynamic forms, buttons, and hidden inputs.'
        },
        {
          id: 'p1_param_inventory',
          label: 'Analyze Parameter Controllability',
          description: 'Build an inventory of parameters across queries, bodies, custom headers, cookies, and JSON keys, identifying if they are user-controllable.'
        }
      ]
    },
    {
      id: 'phase2',
      title: 'Phase 2: Context-Aware Reflection Mapping',
      type: 'table',
      headers: ['Context / Target', 'Reflected Scenario to Test', 'XSS Boss Automatic Coverage'],
      items: [
        {
          id: 'p2_html_text',
          technique: 'HTML Text Reflection',
          scenario: 'Input lands inside raw text nodes: <div>INPUT</div>',
          details: 'HTML_TEXT context: Tests tag escapes, tags injection (e.g., </div><svg/onload=__XSS__(\'{{TOKEN}}\')>).'
        },
        {
          id: 'p2_attr_quoted',
          technique: 'Quoted Attribute',
          scenario: 'Input lands inside quoted values: <input value="INPUT"> or <a href=\'INPUT\'>',
          details: 'ATTR_QUOTED context: Audits quotes types, tests quote breaks, adds event triggers (e.g., " autofocus onfocus=__XSS__(\'{{TOKEN}}\')).'
        },
        {
          id: 'p2_attr_unquoted',
          technique: 'Unquoted Attribute',
          scenario: 'Input lands inside unquoted attributes: <div class=INPUT>',
          details: 'ATTR_UNQUOTED context: Automatically leverages whitespace separators to inject standalone attributes (e.g., onerror=__XSS__(\'{{TOKEN}}\')).'
        },
        {
          id: 'p2_event_handler',
          technique: 'Event Handler Attr',
          scenario: 'Input lands inside event hooks: <button onclick="select(\'INPUT\')">',
          details: 'EVENT_HANDLER_ATTR context: Tests inline execution escaping without tag breakout (e.g., \');__XSS__(\'{{TOKEN}}\');//).'
        },
        {
          id: 'p2_js_string',
          technique: 'JS String Literal',
          scenario: 'Input lands inside script string constants: var msg = "INPUT";',
          details: 'JS_STRING_LITERAL context: Audits js string breakouts, constructs comment bypasses (e.g., \';__XSS__(\'{{TOKEN}}\');// or </script><script>).'
        },
        {
          id: 'p2_js_identifier',
          technique: 'JS Raw Identifier',
          scenario: 'Input lands as code block or variable name: funcName(INPUT);',
          details: 'JS_IDENTIFIER context: Inspects expression blocks to chain variables or invoke standalone scripts directly.'
        },
        {
          id: 'p2_url_fragment',
          technique: 'URL Fragment / Query',
          scenario: 'Input lands inside href/src attributes: <a href="INPUT"> or <iframe src="INPUT">',
          details: 'URL_FRAGMENT / URL_QUERY: Focuses on script uri schemas (e.g., javascript:__XSS__(\'{{TOKEN}}\') or data:text/html,...).'
        },
        {
          id: 'p2_json_value',
          technique: 'JSON Value Reflection',
          scenario: 'Input lands inside nested API JSON values: {"user":{"name":"INPUT"}}',
          details: 'JSON_VALUE context: Tests object escaping, backslash bypasses, and structural breakdown (e.g., ","x":"</script><script>...).'
        }
      ]
    },
    {
      id: 'phase3',
      title: 'Phase 3: Filter & WAF Behavior Profiling',
      type: 'table',
      headers: ['Filter Technique', 'How to Manually Validate', 'XSS Boss Behavior Profile Auditing'],
      items: [
        {
          id: 'p3_status_code',
          technique: 'Status-Code Auditing',
          scenario: 'Verify if common payloads trigger immediate backend blocks: 403 Forbidden, 400 Bad Request, or 406 Not Acceptable.',
          details: 'Sends sample battery of characters and tags, logging HTTP status codes to detect active Web Application Firewalls (WAF).'
        },
        {
          id: 'p3_tag_reflection',
          technique: 'Tag Reflection Verification',
          scenario: 'Test if brackets < and > are reflected raw, HTML entity-encoded, stripped entirely, or lead to error conditions.',
          details: 'Fuzzes structural inputs (<test>, </div><b>x</b>) to assess browser-side execution capability in HTML contexts.'
        },
        {
          id: 'p3_quote_escaping',
          technique: 'Quote & Char Escaping',
          scenario: 'Verify quote conversions: check if single/double quotes are escaped (\' -> \\\', " -> &quot;) or reflected.',
          details: 'Detects escaping constraints dynamically, preventing the generation of redundant breakout-dependent payloads.'
        },
        {
          id: 'p3_keyword_stripping',
          technique: 'Keyword Stripping',
          scenario: 'Submit strings like "script", "onerror", "onload", and "javascript" to verify if they are removed, blocked, or altered.',
          details: 'Flags missing keywords from responses and automatically shifts strategy to casing, splitting, or homoglyph mutations.'
        }
      ]
    },
    {
      id: 'phase4',
      title: 'Phase 4: Sink Mapping & Taint Tracing',
      type: 'table',
      headers: ['Sink Category', 'Vulnerable Sinks to Check', 'XSS Boss Mapping Coverage'],
      items: [
        {
          id: 'p4_static_audit',
          technique: 'Static JS Auditing',
          scenario: 'Scan imported and client-side JavaScript bundle files for references to unsafe sink invocations.',
          details: 'Downloads, parses, and searches local/imported script files for dangerous calls like innerHTML, eval, etc.'
        },
        {
          id: 'p4_classic_dom',
          technique: 'Classic DOM HTML Sinks',
          scenario: 'Inputs written directly to document markup structures: innerHTML, outerHTML, document.write(), document.writeln().',
          details: 'The browser worker hooks these setters via oracle_inject.js, logging execution if the unique token reaches the sink.'
        },
        {
          id: 'p4_dynamic_execution',
          technique: 'Dynamic Code Interpreter Sinks',
          scenario: 'Inputs evaluated dynamically as script code: eval(), Function(), setTimeout("INPUT"), setInterval("INPUT").',
          details: 'Wraps global timers and execution functions in the chromium environment to capture raw string evaluations.'
        },
        {
          id: 'p4_modern_sinks',
          technique: 'Modern HTML5/DOM Sinks',
          scenario: 'Modern APIs handling partial HTML fragments: Range.createContextualFragment(), DOMParser.parseFromString().',
          details: 'Hooks contextual fragment APIs and parsing methods to catch modern execution paths.'
        },
        {
          id: 'p4_sanitizer_sinks',
          technique: 'Sanitizer Sinks',
          scenario: 'Inputs bound via newer native sanitization APIs: setHTML(), setHTMLUnsafe().',
          details: 'Audits if sanitizers are used, logging input flows and identifying structural sanitization bypass vectors.'
        }
      ]
    },
    {
      id: 'phase5',
      title: 'Phase 5: Filter-Aware Payload Mutation Bypasses',
      type: 'table',
      headers: ['Bypass Strategy', 'Scenario to Test', 'XSS Boss Fuzzer Implementation'],
      items: [
        {
          id: 'p5_mixed_casing',
          technique: 'Mixed Letter Casing',
          scenario: 'Change tag or attribute casing to bypass case-sensitive WAF rules: <sCrIpT>, oNeRrOr, JaVaScRiPt.',
          details: 'Generates randomized mixed-case variations of tags and attributes when static filters are flagged.'
        },
        {
          id: 'p5_entity_encoding',
          technique: 'HTML Entity Encoding',
          scenario: 'Encode quotes or brackets when the application decodes attributes before rendering: &#60;svg/onload=...&#62;',
          details: 'Applies decimal and hexadecimal character reference mutations to bypass filters looking for raw tags.'
        },
        {
          id: 'p5_unicode_homoglyphs',
          technique: 'Unicode Homoglyphs',
          scenario: 'Substitute ASCII letters in keywords with identical-looking Cyrillic or Greek symbols: s -> \u0455.',
          details: 'Runs UNICODE_HUNT mutations, substituting letters to trick static keyword matchers while rendering correctly.'
        },
        {
          id: 'p5_full_width',
          technique: 'Full-Width Conversion',
          scenario: 'Use full-width Unicode characters that are normalized back to ASCII inside backend parameters: ＜script＞',
          details: 'Generates full-width equivalents of payload brackets and quotes to test normalization flaws.'
        },
        {
          id: 'p5_zero_width',
          technique: 'Zero-Width Char Insertion',
          scenario: 'Inject zero-width spaces or non-joiners inside critical keywords: sc\u200Bript or on\u200Cerror.',
          details: 'Injects hidden character tokens (e.g., \\u200B) inside strings to bypass regex filters without breaking render.'
        },
        {
          id: 'p5_keyword_splitting',
          technique: 'Keyword / Tag Splitting',
          scenario: 'Leverage recursive filters that strip script tag patterns once: <scr<script>ipt> or <div ononfocus=...>',
          details: 'Structures double-wrapped tags and keyword chains to reconstruct the target payload after stripping.'
        },
        {
          id: 'p5_url_encoding',
          technique: 'URL & Double Encoding',
          scenario: 'Double-encode or partially hex-encode parameters passed to client scripts: %253Csvg%2520onload...',
          details: 'Evaluates if the client decodes parameter values before evaluation, and targets double URL encoding checks.'
        }
      ]
    },
    {
      id: 'phase6',
      title: 'Phase 6: Modern DOM & Advanced Probes',
      type: 'table',
      headers: ['Advanced Technique', 'Testing Scenario', 'XSS Boss Research Pipeline'],
      items: [
        {
          id: 'p6_postmessage',
          technique: 'postMessage DOM XSS',
          scenario: 'Inspect postMessage listeners (event.data). Test for lack of origin check or loose startsWith/endsWith checks.',
          details: 'Generates parent/iframe PoC, serving local HTTP origins; uses starts_ends origin mode to spoof weak checks.'
        },
        {
          id: 'p6_prototype_pollution',
          technique: 'Client-side Prototype Pollution',
          scenario: 'Search for object attributes fuzzed via hash/query: ?__proto__[x]=y or ?constructor[prototype][x]=y.',
          details: 'Sends automated pollution parameters, monitors browser execution for modified gadgets and runtime behavior.'
        },
        {
          id: 'p6_dom_clobbering',
          technique: 'DOM Clobbering Chains',
          scenario: 'Inject elements with duplicate IDs or names to override global variables: <img id="config">.',
          details: 'Analyzes global JS references, generating clobbering tags to overwrite config variables and bypass security controls.'
        },
        {
          id: 'p6_sanitizer_mxss',
          technique: 'Sanitizer mXSS Bypass',
          scenario: 'Bypass DOMPurify or sanitize-html by feeding parser context mutations (nested MathML/SVG).',
          details: 'Deploys a specialized regression corpus targeting specific client-side parser/sanitizer version differentials.'
        },
        {
          id: 'p6_framework_expressions',
          technique: 'Framework Gadgets',
          scenario: 'Leverage rendering engine flaws in React, Angular, Vue, or template parsing to trigger XSS.',
          details: 'Detects framework signatures, applying framework-specific payloads (like React dangerouslySetInnerHTML, Angular expressions).'
        },
        {
          id: 'p6_trusted_types',
          technique: 'Trusted Types Auditing',
          scenario: 'Bypass Trusted Types policies by finding default policy flaws or loose policy rules.',
          details: 'Detects strict CSP directives (require-trusted-types-for), logs runtime policy violations, and flags policy creation.'
        }
      ]
    },
    {
      id: 'phase7',
      title: 'Phase 7: Protocol, Content-Type & Method Manipulation',
      type: 'table',
      headers: ['Manipulation', 'Target Scenario to Test', 'XSS Boss Integration'],
      items: [
        {
          id: 'p7_method_swap',
          technique: 'HTTP Method Swap',
          scenario: 'Convert GET queries containing reflections to POST request bodies, or test PUT/DELETE routes.',
          details: 'Validates reflections across different HTTP methods, verifying if filters differ depending on the verb.'
        },
        {
          id: 'p7_content_type',
          technique: 'Content-Type Mutation',
          scenario: 'Change POST content-types: switch from application/json to application/x-www-form-urlencoded.',
          details: 'Rewrites and formats payload payloads in alternative body structures to check parsing leniency.'
        },
        {
          id: 'p7_method_override',
          technique: 'X-HTTP-Method-Override',
          scenario: 'Add override headers: X-HTTP-Method-Override: POST or X-Method-Override: PUT to route traffic differently.',
          details: 'Injects method routing override headers to fuzz backend endpoints that filter based on explicit verbs.'
        },
        {
          id: 'p7_file_extension',
          technique: 'File Extension Obfuscation',
          scenario: 'Change URL suffixes: rename /profile to /profile.html, /profile.xml, or /profile.json.',
          details: 'Alters request paths to bypass content-type configuration filters and force raw HTML parsing.'
        }
      ]
    },
    {
      id: 'phase8',
      title: 'Phase 8: Detection & Telemetry (XSS Oracle Validation)',
      type: 'list',
      items: [
        {
          id: 'p8_dynamic_hooking',
          label: 'Pre-Execution Injection',
          description: 'Verify that oracle_inject.js executes before any other scripts run on the target page, hooking the global environment.'
        },
        {
          id: 'p8_token_callback',
          label: 'Token Callback Binding',
          description: 'Embed unique, cryptographically random tracking tokens ({{TOKEN}}) into payloads, linking executions back to specific inputs.'
        },
        {
          id: 'p8_multi_sink',
          label: 'Multi-Sink Monitoring',
          description: 'Ensure the Oracle receiver parses callbacks from eval, timers, writes, and HTML setters, capturing execution source logs.'
        },
        {
          id: 'p8_screenshot_capture',
          label: 'Screenshot & DOM Evidence Capture',
          description: 'Automatically take screenshots and record DOM trees at the moment of execution to create comprehensive proof-of-concept reports.'
        },
        {
          id: 'p8_filter_false_positives',
          label: 'Filter Out False Positives',
          description: 'Validate that the incoming token matches the queued test case to avoid incorrect results due to persistent stored hits.'
        }
      ]
    },
    {
      id: 'phase9',
      title: 'Phase 9: Stored XSS & Cross-Role Escalation',
      type: 'list',
      items: [
        {
          id: 'p9_data_persistence',
          label: 'Map Persistent Write Points',
          description: 'Identify inputs saved to databases (e.g., profile settings, forum comments, notifications, ticket systems).'
        },
        {
          id: 'p9_multi_session',
          label: 'Configure Multi-Session Revisit Tasks',
          description: 'Set up Celery worker queues to revisit output pages using distinct cookies representing author and viewer accounts.'
        },
        {
          id: 'p9_cross_role',
          label: 'Cross-Role Execution Auditing',
          description: 'Verify if a payload posted by a low-privilege attacker user triggers script execution inside an administrator session.'
        },
        {
          id: 'p9_upgraded_scoring',
          label: 'Upgrade Finding Classifications',
          description: 'Increase vulnerability severity weights and prioritization when cross-role or stored execution is confirmed.'
        }
      ]
    },
    {
      id: 'phase10',
      title: 'Phase 10: Detection of False Negatives',
      type: 'list',
      items: [
        {
          id: 'p10_user_interaction',
          label: 'Audit User-Interaction Dependent Vectors',
          description: 'Verify if elements require clicks or movements to trigger (e.g., autofocus + onfocus, pointer events). Keep browser workers active for at least 5 seconds.'
        },
        {
          id: 'p10_async_channels',
          label: 'Trace Real-time Channels (WebSockets / SSE)',
          description: 'Identify if inputs are delivered asynchronously via WebSockets or Server-Sent Events, and ensure the fuzzer checks these reflection paths.'
        },
        {
          id: 'p10_secondary_pages',
          label: 'Review Out-of-Band Renditions',
          description: 'Verify if inputs render on alternative endpoints (e.g., printable receipts, email templates, PDF exports, admin reporting portals).'
        },
        {
          id: 'p10_csp_configurations',
          label: 'Analyze Content Security Policy (CSP) Blockages',
          description: 'Inspect CSP headers for rules that block raw inline code. Shift fuzzer parameters to CSP-aware rules (avoiding script tags, utilizing allowlisted sources).'
        }
      ]
    },
    {
      id: 'phase11',
      title: 'Phase 11: Priority Guide for XSS Hunting',
      type: 'list',
      items: [
        {
          id: 'p11_high_value_actions',
          label: '1. High-Value Action Controls',
          description: 'Target critical pages first: password resets, profile settings, account recovery, billing details, and support tickets.'
        },
        {
          id: 'p11_stored_social',
          label: '2. Stored / Social Features',
          description: 'Fuzz fields that persist and are visible to others: comments, chat systems, activity feeds, and notification panels.'
        },
        {
          id: 'p11_implicit_trusts',
          label: '3. Multi-Tenant Implicit Trusts',
          description: 'Inspect inputs displayed in shared spaces: workspace name configs, tenant settings, and OAuth authorization screens.'
        },
        {
          id: 'p11_export_engines',
          label: '4. Document Generation Engines',
          description: 'Audit exports: CSV, PDF generators, and invoice printers (which are highly susceptible to server-side XSS / HTML injection).'
        },
        {
          id: 'p11_private_apis',
          label: '5. Private and Mobile API Services',
          description: 'Find backend endpoints by decompiling mobile apps or reading API docs, which often lack the front-end filtering found on primary websites.'
        }
      ]
    }
  ];

  // Helper to count total items
  const totalItems = sections.reduce((acc, section) => acc + section.items.length, 0);
  const completedCount = completedItems.length;
  const progressPercent = totalItems > 0 ? Math.round((completedCount / totalItems) * 100) : 0;

  // Toggle checklist item
  const toggleItem = (id: string) => {
    let updated: string[];
    if (completedItems.includes(id)) {
      updated = completedItems.filter((i) => i !== id);
    } else {
      updated = [...completedItems, id];
    }
    setCompletedItems(updated);
    localStorage.setItem('xssboss_checklist_completed', JSON.stringify(updated));
  };

  // Toggle section collapse
  const toggleSection = (id: string) => {
    setCollapsedSections((prev) => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  // Reset progress
  const resetProgress = () => {
    if (window.confirm('Are you sure you want to reset your checklist progress?')) {
      setCompletedItems([]);
      localStorage.removeItem('xssboss_checklist_completed');
    }
  };

  // Mark all as complete
  const markAllComplete = () => {
    const allIds = sections.flatMap((s) => s.items.map((i) => i.id));
    setCompletedItems(allIds);
    localStorage.setItem('xssboss_checklist_completed', JSON.stringify(allIds));
  };

  // Filter sections and items based on filterMode
  const getFilteredItems = (items: ChecklistItem[]) => {
    if (filterMode === 'pending') {
      return items.filter((item) => !completedItems.includes(item.id));
    }
    if (filterMode === 'completed') {
      return items.filter((item) => completedItems.includes(item.id));
    }
    return items;
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header section with glassmorphism dashboard */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-extrabold text-gray-900 tracking-tight">Ultimate XSS Hunting Checklist</h1>
            <p className="text-sm text-gray-500 mt-1">
              A comprehensive methodology mapping context analysis, WAF profiling, sink tracking, and payload verification in XSS Boss.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={resetProgress}
              className="px-3 py-1.5 text-xs font-semibold text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
            >
              Reset Progress
            </button>
            <button
              onClick={markAllComplete}
              className="px-3 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
            >
              Mark All Complete
            </button>
          </div>
        </div>

        {/* Progress dashboard bar */}
        <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
          <div className="space-y-1">
            <div className="flex justify-between text-sm font-semibold text-gray-700">
              <span>Overall Progress</span>
              <span>{completedCount} / {totalItems} Tasks ({progressPercent}%)</span>
            </div>
            <div className="w-full bg-gray-100 rounded-full h-3">
              <div
                className="bg-blue-600 h-3 rounded-full transition-all duration-500 ease-out"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>

          <div className="flex justify-center md:justify-end gap-2 md:col-span-2">
            <span className="text-xs font-medium text-gray-400 self-center mr-2">Filter Tasks:</span>
            {(['all', 'pending', 'completed'] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => setFilterMode(mode)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg capitalize border transition-all ${
                  filterMode === mode
                    ? 'bg-blue-50 text-blue-700 border-blue-200 shadow-sm'
                    : 'bg-white text-gray-600 border-gray-200 hover:bg-gray-50'
                }`}
              >
                {mode === 'all' ? 'Show All' : mode}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Checklist Phases */}
      <div className="space-y-6">
        {sections.map((section) => {
          const filteredItems = getFilteredItems(section.items);
          const isCollapsed = collapsedSections[section.id];
          const sectionCompletedCount = section.items.filter((item) => completedItems.includes(item.id)).length;
          const sectionTotalCount = section.items.length;

          // If filtering yields 0 items for this section, hide it
          if (filteredItems.length === 0 && filterMode !== 'all') {
            return null;
          }

          return (
            <div key={section.id} className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden transition-all">
              {/* Section Header */}
              <div
                onClick={() => toggleSection(section.id)}
                className="px-6 py-4 bg-gray-50 border-b border-gray-100 flex items-center justify-between cursor-pointer hover:bg-gray-100/75 transition-colors select-none"
              >
                <div className="flex items-center space-x-3">
                  <span className="text-lg font-bold text-gray-800">{section.title}</span>
                  <span className="px-2 py-0.5 text-xs font-semibold bg-gray-200 text-gray-600 rounded-full">
                    {sectionCompletedCount} / {sectionTotalCount} done
                  </span>
                </div>
                <div className="flex items-center space-x-2 text-gray-400">
                  <svg
                    className={`w-5 h-5 transition-transform duration-200 ${isCollapsed ? 'transform -rotate-90' : ''}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              {/* Section Body */}
              {!isCollapsed && (
                <div className="p-6">
                  {section.type === 'list' ? (
                    <div className="space-y-4">
                      {filteredItems.map((item) => {
                        const isDone = completedItems.includes(item.id);
                        return (
                          <div
                            key={item.id}
                            onClick={() => toggleItem(item.id)}
                            className={`flex items-start gap-4 p-4 rounded-lg border cursor-pointer select-none transition-all ${
                              isDone
                                ? 'bg-gray-50/50 border-gray-200 opacity-70'
                                : 'bg-white border-gray-200 hover:border-blue-300 hover:shadow-sm'
                            }`}
                          >
                            <div className="mt-1 flex items-center justify-center">
                              <input
                                type="checkbox"
                                checked={isDone}
                                readOnly
                                className="h-4.5 w-4.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                              />
                            </div>
                            <div className="space-y-1">
                              <h3 className={`font-semibold text-gray-900 text-sm md:text-base ${isDone ? 'line-through text-gray-500' : ''}`}>
                                {item.label}
                              </h3>
                              {item.description && (
                                <p className={`text-sm ${isDone ? 'text-gray-400' : 'text-gray-600'}`}>
                                  {item.description}
                                </p>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="min-w-full divide-y divide-gray-200 border border-gray-100 rounded-lg">
                        <thead className="bg-gray-50">
                          <tr>
                            <th scope="col" className="w-12 px-4 py-3 text-left">
                              {/* Empty header for checkbox */}
                            </th>
                            {section.headers?.map((header, idx) => (
                              <th
                                key={idx}
                                scope="col"
                                className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider"
                              >
                                {header}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-100">
                          {filteredItems.map((item) => {
                            const isDone = completedItems.includes(item.id);
                            return (
                              <tr
                                key={item.id}
                                onClick={() => toggleItem(item.id)}
                                className={`cursor-pointer hover:bg-gray-50/70 transition-colors select-none ${
                                  isDone ? 'bg-gray-50/30 opacity-70' : ''
                                }`}
                              >
                                <td className="px-4 py-4 whitespace-nowrap text-center" onClick={(e) => e.stopPropagation()}>
                                  <input
                                    type="checkbox"
                                    checked={isDone}
                                    onChange={() => toggleItem(item.id)}
                                    className="h-4.5 w-4.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                  />
                                </td>
                                <td className="px-4 py-4 text-sm font-semibold text-gray-900 max-w-[200px]">
                                  <span className={isDone ? 'line-through text-gray-400' : ''}>
                                    {item.technique}
                                  </span>
                                </td>
                                <td className="px-4 py-4 text-sm text-gray-600 max-w-xs md:max-w-md">
                                  <span className={isDone ? 'line-through text-gray-400' : ''}>
                                    {item.scenario}
                                  </span>
                                </td>
                                <td className="px-4 py-4 text-sm text-blue-700 bg-blue-50/20 max-w-xs font-medium">
                                  <span className={isDone ? 'line-through text-blue-400' : ''}>
                                    {item.details}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default XssChecklistPage;
