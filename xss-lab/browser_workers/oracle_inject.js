/**
 * XSS Oracle injection script.
 * Injected into pages before page scripts run to detect XSS execution.
 */
(function() {
    'use strict';
    
    // Get token and oracle URL from window (set by executor)
    const token = window.__XSS_TOKEN__ || '';
    const oracleUrl = window.__ORACLE_URL__ || '/api/v1/oracle';
    
    if (!token) {
        console.warn('XSS Oracle: No token provided');
        return;
    }
    
    // Define __XSS__ callback function with structural metadata parsing
    const taintMarkers = {
        'location.href': '__taint_loc_href__',
        'location.search': '__taint_loc_search__',
        'location.hash': '__taint_loc_hash__',
        'location.pathname': '__taint_loc_path__',
        'document.URL': '__taint_doc_url__',
        'document.documentURI': '__taint_doc_uri__',
        'document.baseURI': '__taint_doc_base__',
        'document.referrer': '__taint_doc_ref__',
        'window.name': '__taint_win_name__',
        'postMessage': '__taint_postmsg__'
    };

    function resolveDynamicInsertionContext(element) {
        if (!element || !(element instanceof Node)) {
            return 'HTML_TEXT';
        }
        try {
            let current = element;
            while (current) {
                const tagName = (current.tagName || '').toUpperCase();
                if (tagName === 'SCRIPT') return 'JS_STRING_LITERAL';
                if (tagName === 'STYLE') return 'CSS_STYLE';
                if (tagName === 'NOSCRIPT') return 'NOSCRIPT';
                if (tagName === 'TEMPLATE') return 'TEMPLATE';
                if (tagName === 'TEXTAREA') return 'TEXTAREA';
                if (tagName === 'IFRAME') return 'IFRAME';
                current = current.parentNode;
            }
        } catch (e) {}
        return 'HTML_TEXT';
    }

    window.__XSS__ = function(sinkType, value, errorStack) {
        if (Array.isArray(sinkType)) {
            const strings = sinkType;
            const values = Array.prototype.slice.call(arguments, 1);
            let fullStr = '';
            for (let i = 0; i < strings.length; i++) {
                fullStr += strings[i];
                if (i < values.length) {
                    fullStr += String(values[i]);
                }
            }
            value = fullStr;
            sinkType = 'TaggedTemplateLiteral';
        }
        if (value && typeof value === 'string' && !sinkType.startsWith('DOMSourceRead:')) {
            for (const [source, marker] of Object.entries(taintMarkers)) {
                if (value.includes(marker)) {
                    sinkType = `${sinkType} (Source: ${source})`;
                    break;
                }
            }
        }
        let filename = 'unknown';
        let line = 0;
        let column = 0;

        // Parse stack trace to find the origin of the execution
        if (errorStack && typeof errorStack === 'string') {
            const lines = errorStack.split('\n');
            // Look for the first line in the stack trace that isn't the oracle script itself
            for (let i = 1; i < lines.length; i++) {
                const traceLine = lines[i];
                if (traceLine && !traceLine.includes('oracle_inject.js') && !traceLine.includes('__XSS__')) {
                    // Match pattern: "at functionName (filename:line:col)" or "at filename:line:col"
                    const match = traceLine.match(/at\s+(?:[^\s(]+)?\s*\(?([^:]+):(\d+):(\d+)\)?/i) || 
                                  traceLine.match(/at\s+([^:]+):(\d+):(\d+)/i) ||
                                  traceLine.match(/@([^:]+):(\d+):(\d+)/i); // Firefox support
                    if (match) {
                        filename = match[1].trim();
                        line = parseInt(match[2], 10);
                        column = parseInt(match[3], 10);
                        break;
                    }
                }
            }
        }

        const sinkInfo = {
            sink: sinkType,
            value: (value || '').substring(0, 500),
            filename: filename,
            line: line,
            column: column,
            stack: errorStack || ''
        };

        const serializedData = encodeURIComponent(JSON.stringify(sinkInfo));
        const url = `${oracleUrl}?token=${encodeURIComponent(token)}&msg=${encodeURIComponent('SINK HIT: ' + sinkType)}&sink=${encodeURIComponent(sinkType)}&data=${serializedData}`;
        
        // Multi-Channel Telemetry Exfiltration (bypasses CSP and Sandbox isolation)
        const transmitMethods = [
            // Channel 1: Native Fetch API
            () => {
                if (typeof fetch !== 'undefined') {
                    fetch(url, { method: 'GET', mode: 'no-cors', credentials: 'omit' }).catch(() => {});
                    return true;
                }
                throw new Error();
            },
            // Channel 2: XMLHTTPRequest
            () => {
                if (typeof XMLHttpRequest !== 'undefined') {
                    const xhr = new XMLHttpRequest();
                    xhr.open('GET', url, true);
                    xhr.send();
                    return true;
                }
                throw new Error();
            },
            // Channel 3: DOM Image element
            () => {
                const img = new Image();
                img.src = url;
                return true;
            },
            // Channel 4: DNS Prefetching (bypasses strict connect-src directives)
            () => {
                if (typeof document !== 'undefined' && document.head) {
                    const link = document.createElement('link');
                    link.rel = 'dns-prefetch';
                    link.href = `//dns-${token}.oracle.local/`;
                    document.head.appendChild(link);
                    return true;
                }
                throw new Error();
            },
            // Channel 5: Dynamic link preconnect
            () => {
                if (typeof document !== 'undefined' && document.head) {
                    const link = document.createElement('link');
                    link.rel = 'preconnect';
                    link.href = `//conn-${token}.oracle.local/`;
                    document.head.appendChild(link);
                    return true;
                }
                throw new Error();
            },
            // Channel 6: HTML5 Audio tag source request
            () => {
                if (typeof document !== 'undefined' && document.createElement) {
                    const audio = document.createElement('audio');
                    const source = document.createElement('source');
                    source.src = url;
                    audio.appendChild(source);
                    return true;
                }
                throw new Error();
            }
        ];

        // Execute all exfiltration methods sequentially to maximize delivery probability
        transmitMethods.forEach(method => {
            try {
                method();
            } catch (e) {}
        });
        
        if (sinkType.startsWith('DOMSourceRead:') || sinkType === 'postMessage.source') {
            console.log('XSS Oracle: Source read detected', { token: token, sinkInfo: sinkInfo });
        } else {
            console.log('XSS Oracle: Execution detected', { token: token, sinkInfo: sinkInfo });
        }
    };

    // Evasion: Function.prototype.toString spoofing to prevent anti-bot detection of hooked natives
    const hookMap = new Map();
    window.__registerOracleHook__ = function(hookedFn, originalFn, name) {
        hookMap.set(hookedFn, { originalFn, name });
    };

    try {
        const originalToString = Function.prototype.toString;
        Function.prototype.toString = function() {
            if (hookMap.has(this)) {
                const info = hookMap.get(this);
                return `function ${info.name}() { [native code] }`;
            }
            return originalToString.apply(this, arguments);
        };
        window.__registerOracleHook__(Function.prototype.toString, originalToString, 'toString');
    } catch (err) {
        console.error('XSS Oracle: Failed to setup toString spoofing', err);
    }

    // Hook: Object.prototype properties for Prototype Pollution write & read detection
    try {
        const gadgetProperties = [
            // HTML / Script injection gadgets
            "html", "onload", "src", "url", "href", "sourceURL", "content", "jquery",
            "sourceMapURL", "innerHTML", "outerHTML", "iframe", "srcdoc", "tagName",
            // Template / Framework gadgets
            "template", "templateUrl", "view", "render", "compile", "interpolate",
            // Configuration / Option gadgets
            "config", "options", "settings", "setup", "env", "theme", "context",
            // Common library gadgets
            "data", "attrs", "props", "params", "headers", "transport", "fallback",
            "prefix", "suffix", "delimiter", "namespace", "callback", "sanitize",
            "allowedTags", "allowedAttributes", "hooks", "plugins"
        ];
        gadgetProperties.forEach(prop => {
            let val = undefined;
            Object.defineProperty(Object.prototype, prop, {
                get: function() {
                    if (val && typeof val === 'string' && val.includes(token)) {
                        __XSS__('PrototypePollutionRead:' + prop, val, new Error().stack);
                    }
                    return val;
                },
                set: function(newVal) {
                    if (newVal && typeof newVal === 'string' && newVal.includes(token)) {
                        __XSS__('PrototypePollutionWrite:' + prop, newVal, new Error().stack);
                    }
                    val = newVal;
                },
                configurable: true,
                enumerable: true
            });
        });
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Prototype Pollution hooks', err);
    }

    // Active Sanitizer Fingerprinting: Hook window.DOMPurify loading
    try {
        let purifyVal = window.DOMPurify;
        if (purifyVal && purifyVal.version) {
            console.warn('[TaintFlow] DOMPurify version detected: ' + purifyVal.version);
        }
        Object.defineProperty(window, 'DOMPurify', {
            get: function() { return purifyVal; },
            set: function(val) {
                purifyVal = val;
                if (val && val.version) {
                    console.warn('[TaintFlow] DOMPurify version detected: ' + val.version);
                }
            },
            configurable: true,
            enumerable: true
        });
    } catch (e) {}

    // Hook RegExp and String matching methods to extract active frontend filtering rules
    try {
        const originalTest = RegExp.prototype.test;
        RegExp.prototype.test = function(str) {
            if (typeof str === 'string' && str.includes(token)) {
                console.warn(`[TaintFlow] RegExp.test called with pattern: ${this.source} (flags: ${this.flags})`);
            }
            return originalTest.call(this, str);
        };
        window.__registerOracleHook__(RegExp.prototype.test, originalTest, 'test');

        const originalExec = RegExp.prototype.exec;
        RegExp.prototype.exec = function(str) {
            if (typeof str === 'string' && str.includes(token)) {
                console.warn(`[TaintFlow] RegExp.exec called with pattern: ${this.source} (flags: ${this.flags})`);
            }
            return originalExec.call(this, str);
        };
        window.__registerOracleHook__(RegExp.prototype.exec, originalExec, 'exec');

        const originalMatch = String.prototype.match;
        String.prototype.match = function(regexp) {
            if (this && typeof this === 'string' && this.includes(token) && regexp) {
                const pattern = regexp instanceof RegExp ? regexp.source : String(regexp);
                const flags = regexp instanceof RegExp ? regexp.flags : '';
                console.warn(`[TaintFlow] String.match called on token with pattern: ${pattern} (flags: ${flags})`);
            }
            return originalMatch.call(this, regexp);
        };
        window.__registerOracleHook__(String.prototype.match, originalMatch, 'match');

        const originalSearch = String.prototype.search;
        String.prototype.search = function(regexp) {
            if (this && typeof this === 'string' && this.includes(token) && regexp) {
                const pattern = regexp instanceof RegExp ? regexp.source : String(regexp);
                const flags = regexp instanceof RegExp ? regexp.flags : '';
                console.warn(`[TaintFlow] String.search called on token with pattern: ${pattern} (flags: ${flags})`);
            }
            return originalSearch.call(this, regexp);
        };
        window.__registerOracleHook__(String.prototype.search, originalSearch, 'search');
    } catch (err) {
        console.error('XSS Oracle: Failed to setup RegExp filter extraction hooks', err);
    }

    // Hook: Capture JS runtime errors
    window.addEventListener('error', function(event) {
        if (event.error) {
            const errorMsg = event.message || '';
            const stack = event.error.stack || '';
            if (errorMsg.includes(token) || stack.includes(token)) {
                __XSS__('JSRuntimeError', `${errorMsg}\nStack: ${stack}`, stack);
            }
        } else if (event.message && event.message.includes(token)) {
            __XSS__('JSRuntimeError', event.message, new Error().stack);
        }
    });

    window.addEventListener('unhandledrejection', function(event) {
        const reason = event.reason;
        if (reason) {
            const errorMsg = reason.message || String(reason);
            const stack = reason.stack || '';
            if (errorMsg.includes(token) || stack.includes(token)) {
                __XSS__('PromiseUnhandledRejection', `${errorMsg}\nStack: ${stack}`, stack);
            }
        }
    });

    // Hook: Capture Console Warning/Error messages mentioning token
    const originalConsoleError = console.error;
    console.error = function(...args) {
        try {
            const msg = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
            if (msg.includes(token) && !msg.includes('[TaintFlow]')) {
                __XSS__('ConsoleError', msg, new Error().stack);
            }
        } catch (e) {}
        return originalConsoleError.apply(this, args);
    };

    const originalConsoleWarn = console.warn;
    console.warn = function(...args) {
        try {
            const msg = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
            if (msg.includes(token) && !msg.includes('[TaintFlow]')) {
                __XSS__('ConsoleWarn', msg, new Error().stack);
            }
        } catch (e) {}
        return originalConsoleWarn.apply(this, args);
    };

    // Hook String prototype methods to track string manipulation/sanitization
    let inHook = false;
    const hookStringPrototype = function(methodName) {
        try {
            const originalMethod = String.prototype[methodName];
            if (!originalMethod) return;
            
            String.prototype[methodName] = function(...args) {
                if (inHook) {
                    return originalMethod.apply(this, args);
                }
                
                try {
                    inHook = true;
                    if (this && typeof this === 'string' && this.includes && this.includes(token)) {
                        const cleanArgs = args.map(arg => {
                            try {
                                return typeof arg === 'function' ? 'function' : JSON.stringify(arg);
                            } catch (e) {
                                return String(arg);
                            }
                        }).join(', ');
                        console.warn(`[TaintFlow] String.${methodName} called on "${this.substring(0, 80)}" with args: [${cleanArgs}]`);
                    }
                } catch (e) {
                    // Safe fallback
                } finally {
                    inHook = false;
                }
                return originalMethod.apply(this, args);
            };
        } catch (e) {}
    };

    ['replace', 'split', 'slice', 'substring', 'substr', 'toLowerCase', 'toUpperCase', 'concat'].forEach(hookStringPrototype);

    // Hook: Client-Side DOM Source Access Interception
    const hookDOMSource = function(object, propertyName, sourceName) {
        try {
            const descriptor = Object.getOwnPropertyDescriptor(object, propertyName);
            if (!descriptor || !descriptor.get) return;
            
            Object.defineProperty(object, propertyName, {
                get: function() {
                    let val = descriptor.get.call(this);
                    if (val && typeof val === 'string' && val.includes(token)) {
                        const marker = taintMarkers[sourceName];
                        if (marker && !val.includes(marker)) {
                            val = val + marker;
                        }
                        __XSS__('DOMSourceRead:' + sourceName, val, new Error().stack);
                    }
                    return val;
                },
                set: descriptor.set ? function(newVal) {
                    return descriptor.set.call(this, newVal);
                } : undefined,
                configurable: true,
                enumerable: true
            });
        } catch (e) {}
    };

    if (window.Location && Location.prototype) {
        hookDOMSource(Location.prototype, 'href', 'location.href');
        hookDOMSource(Location.prototype, 'search', 'location.search');
        hookDOMSource(Location.prototype, 'hash', 'location.hash');
        hookDOMSource(Location.prototype, 'pathname', 'location.pathname');
    }
    if (window.Document && Document.prototype) {
        hookDOMSource(Document.prototype, 'URL', 'document.URL');
        hookDOMSource(Document.prototype, 'documentURI', 'document.documentURI');
        hookDOMSource(Document.prototype, 'URLUnencoded', 'document.URLUnencoded');
        hookDOMSource(Document.prototype, 'baseURI', 'document.baseURI');
        hookDOMSource(Document.prototype, 'referrer', 'document.referrer');
    }
    if (window.Window && Window.prototype) {
        hookDOMSource(Window.prototype, 'name', 'window.name');
    }
    
    // Hook alert() to detect execution
    const originalAlert = window.alert;
    window.alert = function(msg) {
        __XSS__('alert', msg, new Error().stack);
        return originalAlert.call(this, msg);
    };

    function serializedMessageData(data) {
        if (typeof data === 'string') return data;
        try {
            return JSON.stringify(data);
        } catch (err) {
            return String(data);
        }
    }

    function messageEventForListener(event) {
        const fakeOrigin = window.__XSS_FAKE_MESSAGE_ORIGIN__;
        if (!event) return event;

        try {
            return new Proxy(event, {
                get: function(target, prop, receiver) {
                    if (prop === 'origin' && fakeOrigin) return fakeOrigin;
                    if (prop === 'data') {
                        let val = Reflect.get(target, prop, receiver);
                        if (val && typeof val === 'string' && val.includes(token)) {
                            const marker = '__taint_postmsg__';
                            if (!val.includes(marker)) {
                                val = val + marker;
                            }
                        }
                        return val;
                    }
                    const value = Reflect.get(target, prop, receiver);
                    return typeof value === 'function' ? value.bind(target) : value;
                }
            });
        } catch (err) {
            try {
                const wrapper = Object.create(event);
                if (fakeOrigin) {
                    Object.defineProperty(wrapper, 'origin', { value: fakeOrigin });
                }
                return wrapper;
            } catch (fallbackErr) {
                return event;
            }
        }
    }

    // Hook postMessage listener delivery as a DOM source signal
    const originalAddEventListener = EventTarget.prototype.addEventListener;
    const originalRemoveEventListener = EventTarget.prototype.removeEventListener;
    const messageListenerWrappers = new WeakMap();

    function recordMessageSource(deliveredEvent) {
        const data = serializedMessageData(deliveredEvent && deliveredEvent.data);
        if (typeof data === 'string' && data.includes(token)) {
            __XSS__('postMessage.source', data, new Error().stack);
        }
    }

    function wrapMessageListener(listener) {
        if (!listener || messageListenerWrappers.has(listener)) {
            return messageListenerWrappers.get(listener) || listener;
        }

        let wrappedListener = listener;
        if (typeof listener === 'function') {
            wrappedListener = function(event) {
                const deliveredEvent = messageEventForListener(event);
                recordMessageSource(deliveredEvent);
                return listener.call(this, deliveredEvent);
            };
        } else if (typeof listener.handleEvent === 'function') {
            wrappedListener = {
                handleEvent: function(event) {
                    const deliveredEvent = messageEventForListener(event);
                    recordMessageSource(deliveredEvent);
                    return listener.handleEvent.call(listener, deliveredEvent);
                }
            };
        }

        if (wrappedListener !== listener && (typeof listener === 'function' || typeof listener === 'object')) {
            messageListenerWrappers.set(listener, wrappedListener);
        }
        return wrappedListener;
    }

    EventTarget.prototype.addEventListener = function(type, listener, options) {
        if (type === 'message') {
            return originalAddEventListener.call(this, type, wrapMessageListener(listener), options);
        }
        return originalAddEventListener.call(this, type, listener, options);
    };
    window.__registerOracleHook__(EventTarget.prototype.addEventListener, originalAddEventListener, 'addEventListener');

    EventTarget.prototype.removeEventListener = function(type, listener, options) {
        if (type === 'message' && listener && messageListenerWrappers.has(listener)) {
            return originalRemoveEventListener.call(this, type, messageListenerWrappers.get(listener), options);
        }
        return originalRemoveEventListener.call(this, type, listener, options);
    };
    window.__registerOracleHook__(EventTarget.prototype.removeEventListener, originalRemoveEventListener, 'removeEventListener');

    const originalOnMessage = Object.getOwnPropertyDescriptor(Window.prototype, 'onmessage');
    if (originalOnMessage && originalOnMessage.set) {
        Object.defineProperty(window, 'onmessage', {
            set: function(listener) {
                if (typeof listener === 'function') {
                    const wrappedListener = function(event) {
                        const deliveredEvent = messageEventForListener(event);
                        recordMessageSource(deliveredEvent);
                        return listener.call(this, deliveredEvent);
                    };
                    return originalOnMessage.set.call(this, wrappedListener);
                }
                return originalOnMessage.set.call(this, listener);
            },
            get: originalOnMessage.get
        });
    }

    // Capture CSP and Trusted Types blocking evidence
    window.addEventListener('securitypolicyviolation', function(event) {
        const detail = [
            event.violatedDirective,
            event.effectiveDirective,
            event.blockedURI,
            event.sourceFile,
            event.sample
        ].filter(Boolean).join(' | ');
        if (detail.includes(token)) {
            __XSS__('securitypolicyviolation', detail, new Error().stack);
        }
    });

    if (window.trustedTypes && typeof window.trustedTypes.createPolicy === 'function') {
        const originalCreatePolicy = window.trustedTypes.createPolicy;
        window.trustedTypes.createPolicy = function(policyName, rules) {
            const wrappedRules = {};
            for (const key in rules || {}) {
                if (typeof rules[key] === 'function') {
                    wrappedRules[key] = function(value, ...args) {
                        if (typeof value === 'string' && value.includes(token)) {
                            __XSS__('trustedTypes.' + key, value, new Error().stack);
                        }
                        return rules[key].call(this, value, ...args);
                    };
                } else {
                    wrappedRules[key] = rules[key];
                }
            }
            return originalCreatePolicy.call(this, policyName, wrappedRules);
        };
    }
    
    // Hook eval() to detect execution
    const originalEval = window.eval;
    window.eval = function(code) {
        if (typeof code === 'string' && code.includes(token)) {
            __XSS__('eval', code, new Error().stack);
        }
        return originalEval.call(this, code);
    };
    window.__registerOracleHook__(window.eval, originalEval, 'eval');
    
    // Hook Function constructor
    const originalFunction = window.Function;
    window.Function = function(...args) {
        const code = args[args.length - 1];
        if (typeof code === 'string' && code.includes(token)) {
            __XSS__('Function', code, new Error().stack);
        }
        return originalFunction.apply(this, args);
    };
    window.__registerOracleHook__(window.Function, originalFunction, 'Function');
    
    // Hook setTimeout with string argument
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(fn, delay, ...args) {
        if (typeof fn === 'string' && fn.includes(token)) {
            __XSS__('setTimeout', fn, new Error().stack);
        }
        return originalSetTimeout.call(this, fn, delay, ...args);
    };
    
    // Hook setInterval with string argument
    const originalSetInterval = window.setInterval;
    window.setInterval = function(fn, delay, ...args) {
        if (typeof fn === 'string' && fn.includes(token)) {
            __XSS__('setInterval', fn, new Error().stack);
        }
        return originalSetInterval.call(this, fn, delay, ...args);
    };
    
    // Hook document.write
    const originalDocumentWrite = document.write;
    document.write = function(...args) {
        const content = args.join('');
        if (typeof content === 'string' && content.includes(token)) {
            __XSS__('document.write', content, new Error().stack);
        }
        return originalDocumentWrite.apply(this, args);
    };

    // Hook document.writeln
    const originalDocumentWriteln = document.writeln;
    if (originalDocumentWriteln) {
        document.writeln = function(...args) {
            const content = args.join('');
            if (typeof content === 'string' && content.includes(token)) {
                __XSS__('document.writeln', content, new Error().stack);
            }
            return originalDocumentWriteln.apply(this, args);
        };
    }
    
    // Hook innerHTML setter
    const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (originalInnerHTML && originalInnerHTML.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                if (typeof value === 'string' && value.includes(token)) {
                    const ctx = resolveDynamicInsertionContext(this);
                    __XSS__('innerHTML [ResolvedContext: ' + ctx + ']', value, new Error().stack);
                }
                originalInnerHTML.set.call(this, value);
            },
            get: originalInnerHTML.get
        });
    }
    
    // Hook outerHTML setter
    const originalOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (originalOuterHTML && originalOuterHTML.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(value) {
                if (typeof value === 'string' && value.includes(token)) {
                    const ctx = resolveDynamicInsertionContext(this);
                    __XSS__('outerHTML [ResolvedContext: ' + ctx + ']', value, new Error().stack);
                }
                originalOuterHTML.set.call(this, value);
            },
            get: originalOuterHTML.get
        });
    }
    
    // Hook insertAdjacentHTML
    const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, html) {
        if (typeof html === 'string' && html.includes(token)) {
            const ctx = resolveDynamicInsertionContext(this);
            __XSS__('insertAdjacentHTML [ResolvedContext: ' + ctx + ']', html, new Error().stack);
        }
        return originalInsertAdjacentHTML.call(this, position, html);
    };

    // Hook modern DOM parsing sinks
    if (window.Range && Range.prototype.createContextualFragment) {
        const originalCreateContextualFragment = Range.prototype.createContextualFragment;
        Range.prototype.createContextualFragment = function(fragment) {
            if (typeof fragment === 'string' && fragment.includes(token)) {
                __XSS__('Range.createContextualFragment', fragment, new Error().stack);
            }
            return originalCreateContextualFragment.call(this, fragment);
        };
    }

    if (window.DOMParser && DOMParser.prototype.parseFromString) {
        const originalParseFromString = DOMParser.prototype.parseFromString;
        DOMParser.prototype.parseFromString = function(markup, type) {
            if (typeof markup === 'string' && markup.includes(token)) {
                __XSS__('DOMParser.parseFromString', markup, new Error().stack);
            }
            return originalParseFromString.call(this, markup, type);
        };
    }

    function hookHtmlSetter(proto, propertyName, sinkName) {
        if (!proto) return;
        const descriptor = Object.getOwnPropertyDescriptor(proto, propertyName);
        if (descriptor && descriptor.set) {
            Object.defineProperty(proto, propertyName, {
                set: function(value) {
                    if (typeof value === 'string' && value.includes(token)) {
                        const ctx = resolveDynamicInsertionContext(this);
                        __XSS__(sinkName + ' [ResolvedContext: ' + ctx + ']', value, new Error().stack);
                    }
                    descriptor.set.call(this, value);
                },
                get: descriptor.get
            });
        }
    }

    function hookHtmlMethod(proto, methodName, sinkName) {
        if (!proto || typeof proto[methodName] !== 'function') return;
        const original = proto[methodName];
        proto[methodName] = function(markup, ...args) {
            if (typeof markup === 'string' && markup.includes(token)) {
                const ctx = resolveDynamicInsertionContext(this);
                __XSS__(sinkName + ' [ResolvedContext: ' + ctx + ']', markup, new Error().stack);
            }
            return original.call(this, markup, ...args);
        };
    }

    hookHtmlSetter(window.ShadowRoot && ShadowRoot.prototype, 'innerHTML', 'ShadowRoot.innerHTML');
    hookHtmlMethod(Element.prototype, 'setHTMLUnsafe', 'Element.setHTMLUnsafe');
    hookHtmlMethod(window.ShadowRoot && ShadowRoot.prototype, 'setHTMLUnsafe', 'ShadowRoot.setHTMLUnsafe');
    hookHtmlMethod(Element.prototype, 'setHTML', 'Element.setHTML');
    hookHtmlMethod(window.ShadowRoot && ShadowRoot.prototype, 'setHTML', 'ShadowRoot.setHTML');
    
    // Hook Element.prototype.setAttribute
    const originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if (typeof value === 'string' && value.includes(token)) {
            let ctx = 'ATTR_QUOTED';
            if (name.toLowerCase().startsWith('on')) {
                ctx = 'EVENT_HANDLER_ATTR';
            } else if (name.toLowerCase() === 'src' || name.toLowerCase() === 'href') {
                ctx = 'URL_QUERY';
            }
            __XSS__('setAttribute.' + name + ' [ResolvedContext: ' + ctx + ']', value, new Error().stack);
        }
        return originalSetAttribute.call(this, name, value);
    };
    
    // Hook HTMLScriptElement.prototype.src
    const originalScriptSrc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (originalScriptSrc && originalScriptSrc.set) {
        Object.defineProperty(HTMLScriptElement.prototype, 'src', {
            set: function(value) {
                if (typeof value === 'string' && value.includes(token)) {
                    __XSS__('script.src', value, new Error().stack);
                }
                originalScriptSrc.set.call(this, value);
            },
            get: originalScriptSrc.get
        });
    }
    
    // Hook HTMLIFrameElement.prototype.src
    const originalIframeSrc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    if (originalIframeSrc && originalIframeSrc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
            set: function(value) {
                if (typeof value === 'string' && value.includes(token)) {
                    __XSS__('iframe.src', value, new Error().stack);
                }
                originalIframeSrc.set.call(this, value);
            },
            get: originalIframeSrc.get
        });
    }

    const originalIframeSrcdoc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
    if (originalIframeSrcdoc && originalIframeSrcdoc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
            set: function(value) {
                if (typeof value === 'string' && value.includes(token)) {
                    __XSS__('iframe.srcdoc', value, new Error().stack);
                }
                originalIframeSrcdoc.set.call(this, value);
            },
            get: originalIframeSrcdoc.get
        });
    }
    
    // Hook jQuery dynamic load (zepto, jQuery, etc.)
    let jqueryHooked = false;
    function hookJQueryInstance(jq) {
        if (!jq || jqueryHooked) return;
        jqueryHooked = true;
        
        if (jq.fn && jq.fn.html) {
            const originalJQueryHtml = jq.fn.html;
            jq.fn.html = function(value) {
                if (typeof value === 'string' && value.includes(token)) {
                    __XSS__('jQuery.html', value, new Error().stack);
                }
                return originalJQueryHtml.apply(this, arguments);
            };
        }
        
        if (jq.fn && jq.fn.append) {
            const originalJQueryAppend = jq.fn.append;
            jq.fn.append = function(...args) {
                const content = args.join('');
                if (typeof content === 'string' && content.includes(token)) {
                    __XSS__('jQuery.append', content, new Error().stack);
                }
                return originalJQueryAppend.apply(this, arguments);
            };
        }
    }

    let currentJQuery = window.jQuery;
    Object.defineProperty(window, 'jQuery', {
        get: function() {
            return currentJQuery;
        },
        set: function(val) {
            currentJQuery = val;
            hookJQueryInstance(val);
        },
        configurable: true
    });

    let currentDollar = window.$;
    Object.defineProperty(window, '$', {
        get: function() {
            return currentDollar;
        },
        set: function(val) {
            currentDollar = val;
            hookJQueryInstance(val);
        },
        configurable: true
    });

    if (window.jQuery) {
        hookJQueryInstance(window.jQuery);
    }
    if (window.$) {
        hookJQueryInstance(window.$);
    }
    
    // Hook: Client-Side Prototype Pollution Detection
    try {
        function makeRecursiveTaintProxy(obj, path) {
            if (obj === null || obj === undefined || typeof obj !== 'object') {
                return obj;
            }
            if (obj.__isTaintProxy) return obj;
            
            try {
                return new Proxy(obj, {
                    get(target, prop, receiver) {
                        if (prop === '__isTaintProxy') return true;
                        
                        const val = Reflect.get(target, prop, receiver);
                        const currentPath = `${path}.${String(prop)}`;
                        
                        if (typeof val === 'string' && val.includes(token)) {
                            __XSS__('PrototypePollutionGadget:' + currentPath, val, new Error().stack);
                        }
                        
                        return makeRecursiveTaintProxy(val, currentPath);
                    },
                    set(target, prop, value, receiver) {
                        const currentPath = `${path}.${String(prop)}`;
                        if (value && String(value).includes(token)) {
                            __XSS__('PrototypePollutionGadgetWrite:' + currentPath, String(value), new Error().stack);
                        }
                        return Reflect.set(target, prop, value, receiver);
                    },
                    getPrototypeOf(target) { return Reflect.getPrototypeOf(target); },
                    setPrototypeOf(target, proto) { return Reflect.setPrototypeOf(target, proto); },
                    isExtensible(target) { return Reflect.isExtensible(target); },
                    preventExtensions(target) { return Reflect.preventExtensions(target); },
                    getOwnPropertyDescriptor(target, prop) { return Reflect.getOwnPropertyDescriptor(target, prop); },
                    defineProperty(target, prop, desc) { return Reflect.defineProperty(target, prop, desc); },
                    has(target, prop) { return Reflect.has(target, prop); },
                    ownKeys(target) { return Reflect.ownKeys(target); }
                });
            } catch (e) {
                return obj;
            }
        }

        const gadgetProperties = [
            'onload', 'srcdoc', 'src', 'href', 'source', 'url', 'onerror', 'cleanup',
            'transport', 'context', 'headers', 'success', 'complete', 'error', 'attrs',
            'template', 'data', 'props', 'html', 'content', 'script', 'div', 'body',
            'beforeSend', 'baseUrl', 'queryString', 'incomingHeaders', 'target', 'message'
        ];

        gadgetProperties.forEach(prop => {
            let val = undefined;
            Object.defineProperty(Object.prototype, prop, {
                get() {
                    return makeRecursiveTaintProxy(val, 'Object.prototype.' + prop);
                },
                set(newVal) {
                    val = newVal;
                    if (newVal && String(newVal).includes(token)) {
                        __XSS__('PrototypePollution:' + prop, String(newVal), new Error().stack);
                    }
                },
                configurable: true,
                enumerable: false
            });
        });

        const initialPrototypeKeys = new Set(Object.getOwnPropertyNames(Object.prototype));
        setInterval(() => {
            try {
                const currentPrototypeKeys = Object.getOwnPropertyNames(Object.prototype);
                for (let i = 0; i < currentPrototypeKeys.length; i++) {
                    const key = currentPrototypeKeys[i];
                    if (!initialPrototypeKeys.has(key)) {
                        initialPrototypeKeys.add(key);
                        __XSS__('PrototypePollution:keyInjection', key, 'Property polluted: Object.prototype.' + key);
                    }
                }
            } catch (err) {}
        }, 500);
    } catch (err) {
        console.error('XSS Oracle: Failed to setup prototype pollution hooks', err);
    }

    // Hook: Client-Side Storage & State Taint Analysis
    try {
        const hookStorageMethod = function(storageProto, storageName, methodName) {
            if (!storageProto || typeof storageProto[methodName] !== 'function') return;
            const original = storageProto[methodName];
            storageProto[methodName] = function(key, val, ...args) {
                if (typeof key === 'string' && key.includes(token)) {
                    __XSS__(storageName + '.' + methodName + ':key', key, new Error().stack);
                }
                if (typeof val === 'string' && val.includes(token)) {
                    __XSS__(storageName + '.' + methodName + ':value', val, new Error().stack);
                }
                return original.call(this, key, val, ...args);
            };
        };

        if (window.Storage && Storage.prototype) {
            hookStorageMethod(Storage.prototype, 'localStorage', 'setItem');
            hookStorageMethod(Storage.prototype, 'sessionStorage', 'setItem');
            
            // Hook getters/readers to catch retrieval of polluted storage values
            const originalGetItem = Storage.prototype.getItem;
            Storage.prototype.getItem = function(key, ...args) {
                const val = originalGetItem.call(this, key, ...args);
                if (val && typeof val === 'string' && val.includes(token)) {
                    __XSS__('Storage.getItem:read', val, new Error().stack);
                }
                return val;
            };
        }

        // Hook document.cookie
        const originalCookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
        if (originalCookieDesc && originalCookieDesc.set) {
            Object.defineProperty(document, 'cookie', {
                set: function(value) {
                    if (typeof value === 'string' && value.includes(token)) {
                        __XSS__('document.cookie:write', value, new Error().stack);
                    }
                    originalCookieDesc.set.call(this, value);
                },
                get: originalCookieDesc.get,
                configurable: true
            });
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup storage hooks', err);
    }

    // Hook: Client-Side Navigation & Open Window Redirection Audit
    try {
        const hookNavigationMethod = function(object, methodName, sinkName) {
            if (!object || typeof object[methodName] !== 'function') return;
            const original = object[methodName];
            object[methodName] = function(url, ...args) {
                if (url && typeof url === 'string' && url.includes(token)) {
                    __XSS__(sinkName, url, new Error().stack);
                }
                return original.call(this, url, ...args);
            };
        };

        hookNavigationMethod(window, 'open', 'window.open');
        
        if (window.Location && Location.prototype) {
            hookNavigationMethod(Location.prototype, 'assign', 'location.assign');
            hookNavigationMethod(Location.prototype, 'replace', 'location.replace');
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup navigation hooks', err);
    }

    // Hook: WebSocket Transmission & Receiver Taint Monitoring
    try {
        if (window.WebSocket) {
            const originalSend = WebSocket.prototype.send;
            WebSocket.prototype.send = function(data) {
                if (data && typeof data === 'string' && data.includes(token)) {
                    __XSS__('WebSocket.send', data, new Error().stack);
                }
                return originalSend.call(this, data);
            };

            const originalAddEventListener = WebSocket.prototype.addEventListener;
            WebSocket.prototype.addEventListener = function(type, listener, options) {
                if (type === 'message' && typeof listener === 'function') {
                    const wrappedListener = function(event) {
                        if (event && event.data && typeof event.data === 'string' && event.data.includes(token)) {
                            __XSS__('WebSocket.message:receive', event.data, new Error().stack);
                        }
                        return listener.call(this, event);
                    };
                    return originalAddEventListener.call(this, type, wrappedListener, options);
                }
                return originalAddEventListener.call(this, type, listener, options);
            };

            const originalOnMessageDesc = Object.getOwnPropertyDescriptor(WebSocket.prototype, 'onmessage');
            if (originalOnMessageDesc && originalOnMessageDesc.set) {
                Object.defineProperty(WebSocket.prototype, 'onmessage', {
                    set: function(listener) {
                        if (typeof listener === 'function') {
                            const wrappedListener = function(event) {
                                if (event && event.data && typeof event.data === 'string' && event.data.includes(token)) {
                                    __XSS__('WebSocket.onmessage:receive', event.data, new Error().stack);
                                }
                                return listener.call(this, event);
                            };
                            return originalOnMessageDesc.set.call(this, wrappedListener);
                        }
                        return originalOnMessageDesc.set.call(this, listener);
                    },
                    get: originalOnMessageDesc.get,
                    configurable: true
                });
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup WebSocket hooks', err);
    }

    // Hook: HTTP Request & Response Data Taint Monitoring (fetch & XMLHttpRequest)
    try {
        // Hook fetch
        if (window.fetch) {
            const originalFetch = window.fetch;
            window.fetch = function(input, init) {
                // Monitor URL/Request input
                let urlStr = '';
                if (typeof input === 'string') {
                    urlStr = input;
                } else if (input && typeof input.url === 'string') {
                    urlStr = input.url;
                }
                
                // Exclude oracle reporting to prevent infinite recursive loop
                if (urlStr.includes(oracleUrl)) {
                    return originalFetch.call(this, input, init);
                }

                if (urlStr.includes(token)) {
                    __XSS__('fetch.request:url', urlStr, new Error().stack);
                }

                // Monitor Request Body/Headers
                if (init && init.body && typeof init.body === 'string' && init.body.includes(token)) {
                    __XSS__('fetch.request:body', init.body, new Error().stack);
                }

                return originalFetch.call(this, input, init).then(response => {
                    // Inspect responses if they contain the token
                    try {
                        const clone = response.clone();
                        clone.text().then(text => {
                            if (text && text.includes(token)) {
                                __XSS__('fetch.response:body', text.substring(0, 500), new Error().stack);
                            }
                        }).catch(() => {});
                    } catch (e) {}
                    return response;
                });
            };
        }

        // Hook XMLHttpRequest
        if (window.XMLHttpRequest) {
            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url, ...args) {
                // Ignore oracle reporting url to prevent recursion
                const isOracle = typeof url === 'string' && url.includes(oracleUrl);
                this.__isOracleRequest = isOracle;

                if (typeof url === 'string' && url.includes(token) && !isOracle) {
                    __XSS__('XMLHttpRequest.open:url', url, new Error().stack);
                }
                return originalOpen.call(this, method, url, ...args);
            };

            const originalSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.send = function(body) {
                if (body && typeof body === 'string' && body.includes(token) && !this.__isOracleRequest) {
                    __XSS__('XMLHttpRequest.send:body', body, new Error().stack);
                }
                return originalSend.call(this, body);
            };

            // Monitor Response Text
            const originalAddEventListener = XMLHttpRequest.prototype.addEventListener;
            XMLHttpRequest.prototype.addEventListener = function(type, listener, options) {
                if (type === 'readystatechange' || type === 'load') {
                    const self = this;
                    const wrappedListener = function(event) {
                        if (!self.__isOracleRequest && self.responseText && self.responseText.includes(token)) {
                            __XSS__('XMLHttpRequest.response:body', self.responseText.substring(0, 500), new Error().stack);
                        }
                        return listener.call(this, event);
                    };
                    return originalAddEventListener.call(this, type, wrappedListener, options);
                }
                return originalAddEventListener.call(this, type, listener, options);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup HTTP request hooks', err);
    }

    // Hook: Client-Side IndexedDB Database Taint Auditing
    try {
        if (window.indexedDB) {
            const originalOpen = IDBFactory.prototype.open;
            IDBFactory.prototype.open = function(name, ...args) {
                if (typeof name === 'string' && name.includes(token)) {
                    __XSS__('indexedDB.open:dbName', name, new Error().stack);
                }
                return originalOpen.call(this, name, ...args);
            };

            // Monitor add and put writes inside object stores
            if (window.IDBObjectStore) {
                const hookIDBWrite = function(proto, methodName) {
                    const original = proto[methodName];
                    proto[methodName] = function(value, key, ...args) {
                        const checkTaint = function(val, path) {
                            if (!val) return;
                            if (typeof val === 'string' && val.includes(token)) {
                                __XSS__('indexedDB.write:' + methodName + (path ? '.' + path : ''), val, new Error().stack);
                            } else if (typeof val === 'object') {
                                for (const k in val) {
                                    if (Object.prototype.hasOwnProperty.call(val, k)) {
                                        checkTaint(val[k], path ? path + '.' + k : k);
                                    }
                                }
                            }
                        };
                        checkTaint(value);
                        if (typeof key === 'string' && key.includes(token)) {
                            __XSS__('indexedDB.write:' + methodName + ':key', key, new Error().stack);
                        }
                        return original.call(this, value, key, ...args);
                    };
                };

                hookIDBWrite(IDBObjectStore.prototype, 'add');
                hookIDBWrite(IDBObjectStore.prototype, 'put');
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup IndexedDB hooks', err);
    }

    // Hook: Clipboard & Drag-and-Drop Interaction Data Transfer Taint Auditing
    try {
        // Redefine DataTransfer.prototype methods if available
        if (window.DataTransfer) {
            const originalGetData = DataTransfer.prototype.getData;
            DataTransfer.prototype.getData = function(format) {
                const data = originalGetData.call(this, format);
                if (data && typeof data === 'string' && data.includes(token)) {
                    __XSS__('DataTransfer.getData', data, new Error().stack);
                }
                return data;
            };

            const originalSetData = DataTransfer.prototype.setData;
            DataTransfer.prototype.setData = function(format, data) {
                if (data && typeof data === 'string' && data.includes(token)) {
                    __XSS__('DataTransfer.setData', data, new Error().stack);
                }
                return originalSetData.call(this, format, data);
            };
        }

        // Hook ClipboardEvent getter accessors to catch clipboard API pastes
        if (window.ClipboardEvent) {
            const originalClipDesc = Object.getOwnPropertyDescriptor(ClipboardEvent.prototype, 'clipboardData');
            if (originalClipDesc && originalClipDesc.get) {
                Object.defineProperty(ClipboardEvent.prototype, 'clipboardData', {
                    get: function() {
                        const dataTransfer = originalClipDesc.get.call(this);
                        if (dataTransfer) {
                            // Wrap dynamic methods for this instance if they weren't wrapped on prototype
                            const originalInstGetData = dataTransfer.getData;
                            dataTransfer.getData = function(format) {
                                const data = originalInstGetData.call(this, format);
                                if (data && typeof data === 'string' && data.includes(token)) {
                                    __XSS__('ClipboardEvent.clipboardData.getData', data, new Error().stack);
                                }
                                return data;
                            };
                        }
                        return dataTransfer;
                    },
                    configurable: true
                });
            }
        }

        // Hook DragEvent getter accessors to catch drag-and-drop item transfers
        if (window.DragEvent) {
            const originalDragDesc = Object.getOwnPropertyDescriptor(DragEvent.prototype, 'dataTransfer');
            if (originalDragDesc && originalDragDesc.get) {
                Object.defineProperty(DragEvent.prototype, 'dataTransfer', {
                    get: function() {
                        const dataTransfer = originalDragDesc.get.call(this);
                        if (dataTransfer) {
                            const originalInstGetData = dataTransfer.getData;
                            dataTransfer.getData = function(format) {
                                const data = originalInstGetData.call(this, format);
                                if (data && typeof data === 'string' && data.includes(token)) {
                                    __XSS__('DragEvent.dataTransfer.getData', data, new Error().stack);
                                }
                                return data;
                            };
                        }
                        return dataTransfer;
                    },
                    configurable: true
                });
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup DataTransfer/Clipboard hooks', err);
    }

    // Hook: Client-Side MessagePort & MessageChannel Communication Taint Auditing
    try {
        if (window.MessagePort) {
            const originalPostMessage = MessagePort.prototype.postMessage;
            MessagePort.prototype.postMessage = function(message, transfer, ...args) {
                const checkTaint = function(val, path) {
                    if (!val) return;
                    if (typeof val === 'string' && val.includes(token)) {
                        __XSS__('MessagePort.postMessage' + (path ? '.' + path : ''), val, new Error().stack);
                    } else if (typeof val === 'object') {
                        for (const k in val) {
                            if (Object.prototype.hasOwnProperty.call(val, k)) {
                                checkTaint(val[k], path ? path + '.' + k : k);
                            }
                        }
                    }
                };
                checkTaint(message);
                return originalPostMessage.call(this, message, transfer, ...args);
            };

            const originalAddEventListener = MessagePort.prototype.addEventListener;
            MessagePort.prototype.addEventListener = function(type, listener, options) {
                if (type === 'message' && typeof listener === 'function') {
                    const wrappedListener = function(event) {
                        if (event && event.data) {
                            const checkTaint = function(val, path) {
                                if (!val) return;
                                if (typeof val === 'string' && val.includes(token)) {
                                    __XSS__('MessagePort.message:receive' + (path ? '.' + path : ''), val, new Error().stack);
                                } else if (typeof val === 'object') {
                                    for (const k in val) {
                                        if (Object.prototype.hasOwnProperty.call(val, k)) {
                                            checkTaint(val[k], path ? path + '.' + k : k);
                                        }
                                    }
                                }
                            };
                            checkTaint(event.data);
                        }
                        return listener.call(this, event);
                    };
                    return originalAddEventListener.call(this, type, wrappedListener, options);
                }
                return originalAddEventListener.call(this, type, listener, options);
            };

            const originalOnMessageDesc = Object.getOwnPropertyDescriptor(MessagePort.prototype, 'onmessage');
            if (originalOnMessageDesc && originalOnMessageDesc.set) {
                Object.defineProperty(MessagePort.prototype, 'onmessage', {
                    set: function(listener) {
                        if (typeof listener === 'function') {
                            const wrappedListener = function(event) {
                                if (event && event.data) {
                                    const checkTaint = function(val, path) {
                                        if (!val) return;
                                        if (typeof val === 'string' && val.includes(token)) {
                                            __XSS__('MessagePort.onmessage:receive' + (path ? '.' + path : ''), val, new Error().stack);
                                        } else if (typeof val === 'object') {
                                            for (const k in val) {
                                                if (Object.prototype.hasOwnProperty.call(val, k)) {
                                                    checkTaint(val[k], path ? path + '.' + k : k);
                                                }
                                            }
                                        }
                                    };
                                    checkTaint(event.data);
                                }
                                return listener.call(this, event);
                            };
                            return originalOnMessageDesc.set.call(this, wrappedListener);
                        }
                        return originalOnMessageDesc.set.call(this, listener);
                    },
                    get: originalOnMessageDesc.get,
                    configurable: true
                });
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup MessagePort hooks', err);
    }

    // Hook: Client-Side HTML5 History API State Taint Auditing
    try {
        if (window.history) {
            const hookHistoryState = function(proto, methodName) {
                const original = proto[methodName];
                proto[methodName] = function(state, unused, url, ...args) {
                    const checkTaint = function(val, path) {
                        if (!val) return;
                        if (typeof val === 'string' && val.includes(token)) {
                            __XSS__('history.' + methodName + ':state' + (path ? '.' + path : ''), val, new Error().stack);
                        } else if (typeof val === 'object') {
                            for (const k in val) {
                                if (Object.prototype.hasOwnProperty.call(val, k)) {
                                    checkTaint(val[k], path ? path + '.' + k : k);
                                }
                            }
                        }
                    };
                    checkTaint(state);
                    if (typeof url === 'string' && url.includes(token)) {
                        __XSS__('history.' + methodName + ':url', url, new Error().stack);
                    }
                    return original.call(this, state, unused, url, ...args);
                };
            };

            hookHistoryState(History.prototype, 'pushState');
            hookHistoryState(History.prototype, 'replaceState');
        }

        // Hook popstate event listeners
        const originalAddEventListener = window.addEventListener;
        window.addEventListener = function(type, listener, options) {
            if (type === 'popstate' && typeof listener === 'function') {
                const wrappedListener = function(event) {
                    if (event && event.state) {
                        const checkTaint = function(val, path) {
                            if (!val) return;
                            if (typeof val === 'string' && val.includes(token)) {
                                __XSS__('window.popstate:state' + (path ? '.' + path : ''), val, new Error().stack);
                            } else if (typeof val === 'object') {
                                for (const k in val) {
                                    if (Object.prototype.hasOwnProperty.call(val, k)) {
                                        checkTaint(val[k], path ? path + '.' + k : k);
                                    }
                                }
                            }
                        };
                        checkTaint(event.state);
                    }
                    return listener.call(this, event);
                };
                return originalAddEventListener.call(this, type, wrappedListener, options);
            }
            return originalAddEventListener.call(this, type, listener, options);
        };
    } catch (err) {
        console.error('XSS Oracle: Failed to setup HTML5 History API hooks', err);
    }

    // Hook: Client-Side HTML5 BroadcastChannel Messaging Taint Auditing
    try {
        if (window.BroadcastChannel) {
            const originalPostMessage = BroadcastChannel.prototype.postMessage;
            BroadcastChannel.prototype.postMessage = function(message, ...args) {
                const checkTaint = function(val, path) {
                    if (!val) return;
                    if (typeof val === 'string' && val.includes(token)) {
                        __XSS__('BroadcastChannel.postMessage' + (path ? '.' + path : ''), val, new Error().stack);
                    } else if (typeof val === 'object') {
                        for (const k in val) {
                            if (Object.prototype.hasOwnProperty.call(val, k)) {
                                checkTaint(val[k], path ? path + '.' + k : k);
                            }
                        }
                    }
                };
                checkTaint(message);
                return originalPostMessage.call(this, message, ...args);
            };

            const originalAddEventListener = BroadcastChannel.prototype.addEventListener;
            BroadcastChannel.prototype.addEventListener = function(type, listener, options) {
                if (type === 'message' && typeof listener === 'function') {
                    const wrappedListener = function(event) {
                        if (event && event.data) {
                            const checkTaint = function(val, path) {
                                if (!val) return;
                                if (typeof val === 'string' && val.includes(token)) {
                                    __XSS__('BroadcastChannel.message:receive' + (path ? '.' + path : ''), val, new Error().stack);
                                } else if (typeof val === 'object') {
                                    for (const k in val) {
                                        if (Object.prototype.hasOwnProperty.call(val, k)) {
                                            checkTaint(val[k], path ? path + '.' + k : k);
                                        }
                                    }
                                }
                            };
                            checkTaint(event.data);
                        }
                        return listener.call(this, event);
                    };
                    return originalAddEventListener.call(this, type, wrappedListener, options);
                }
                return originalAddEventListener.call(this, type, listener, options);
            };

            const originalOnMessageDesc = Object.getOwnPropertyDescriptor(BroadcastChannel.prototype, 'onmessage');
            if (originalOnMessageDesc && originalOnMessageDesc.set) {
                Object.defineProperty(BroadcastChannel.prototype, 'onmessage', {
                    set: function(listener) {
                        if (typeof listener === 'function') {
                            const wrappedListener = function(event) {
                                if (event && event.data) {
                                    const checkTaint = function(val, path) {
                                        if (!val) return;
                                        if (typeof val === 'string' && val.includes(token)) {
                                            __XSS__('BroadcastChannel.onmessage:receive' + (path ? '.' + path : ''), val, new Error().stack);
                                        } else if (typeof val === 'object') {
                                            for (const k in val) {
                                                if (Object.prototype.hasOwnProperty.call(val, k)) {
                                                    checkTaint(val[k], path ? path + '.' + k : k);
                                                }
                                            }
                                        }
                                    };
                                    checkTaint(event.data);
                                }
                                return listener.call(this, event);
                            };
                            return originalOnMessageDesc.set.call(this, wrappedListener);
                        }
                        return originalOnMessageDesc.set.call(this, listener);
                    },
                    get: originalOnMessageDesc.get,
                    configurable: true
                });
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup BroadcastChannel hooks', err);
    }

    // Hook: Client-Side WebWorker & SharedWorker Script Execution Auditing
    try {
        if (window.Worker) {
            const originalWorker = window.Worker;
            window.Worker = function(scriptURL, options) {
                if (typeof scriptURL === 'string' && scriptURL.includes(token)) {
                    __XSS__('Worker.constructor:scriptURL', scriptURL, new Error().stack);
                }
                const workerInstance = new originalWorker(scriptURL, options);
                
                // Hook the worker instance postMessage and message listeners
                const originalPostMessage = workerInstance.postMessage;
                workerInstance.postMessage = function(message, transfer, ...args) {
                    const checkTaint = function(val, path) {
                        if (!val) return;
                        if (typeof val === 'string' && val.includes(token)) {
                            __XSS__('Worker.instance.postMessage' + (path ? '.' + path : ''), val, new Error().stack);
                        } else if (typeof val === 'object') {
                            for (const k in val) {
                                if (Object.prototype.hasOwnProperty.call(val, k)) {
                                    checkTaint(val[k], path ? path + '.' + k : k);
                                }
                            }
                        }
                    };
                    checkTaint(message);
                    return originalPostMessage.call(this, message, transfer, ...args);
                };

                const originalAddEventListener = workerInstance.addEventListener;
                workerInstance.addEventListener = function(type, listener, options) {
                    if (type === 'message' && typeof listener === 'function') {
                        const wrappedListener = function(event) {
                            if (event && event.data) {
                                const checkTaint = function(val, path) {
                                    if (!val) return;
                                    if (typeof val === 'string' && val.includes(token)) {
                                        __XSS__('Worker.instance.message:receive' + (path ? '.' + path : ''), val, new Error().stack);
                                    } else if (typeof val === 'object') {
                                        for (const k in val) {
                                            if (Object.prototype.hasOwnProperty.call(val, k)) {
                                                checkTaint(val[k], path ? path + '.' + k : k);
                                            }
                                        }
                                    }
                                };
                                checkTaint(event.data);
                            }
                            return listener.call(this, event);
                        };
                        return originalAddEventListener.call(this, type, wrappedListener, options);
                    }
                    return originalAddEventListener.call(this, type, listener, options);
                };

                return workerInstance;
            };
            // Preserve prototype and static properties
            window.Worker.prototype = originalWorker.prototype;
            Object.assign(window.Worker, originalWorker);
        }

        if (window.SharedWorker) {
            const originalSharedWorker = window.SharedWorker;
            window.SharedWorker = function(scriptURL, options) {
                if (typeof scriptURL === 'string' && scriptURL.includes(token)) {
                    __XSS__('SharedWorker.constructor:scriptURL', scriptURL, new Error().stack);
                }
                const sharedWorkerInstance = new originalSharedWorker(scriptURL, options);
                
                // sharedWorker communication occurs via its port
                if (sharedWorkerInstance.port) {
                    const port = sharedWorkerInstance.port;
                    const originalPortPost = port.postMessage;
                    port.postMessage = function(message, transfer, ...args) {
                        const checkTaint = function(val, path) {
                            if (!val) return;
                            if (typeof val === 'string' && val.includes(token)) {
                                __XSS__('SharedWorker.port.postMessage' + (path ? '.' + path : ''), val, new Error().stack);
                            } else if (typeof val === 'object') {
                                for (const k in val) {
                                    if (Object.prototype.hasOwnProperty.call(val, k)) {
                                        checkTaint(val[k], path ? path + '.' + k : k);
                                    }
                                }
                            }
                        };
                        checkTaint(message);
                        return originalPortPost.call(this, message, transfer, ...args);
                    };

                    const originalPortAddListener = port.addEventListener;
                    port.addEventListener = function(type, listener, options) {
                        if (type === 'message' && typeof listener === 'function') {
                            const wrappedListener = function(event) {
                                if (event && event.data) {
                                    const checkTaint = function(val, path) {
                                        if (!val) return;
                                        if (typeof val === 'string' && val.includes(token)) {
                                            __XSS__('SharedWorker.port.message:receive' + (path ? '.' + path : ''), val, new Error().stack);
                                        } else if (typeof val === 'object') {
                                            for (const k in val) {
                                                if (Object.prototype.hasOwnProperty.call(val, k)) {
                                                    checkTaint(val[k], path ? path + '.' + k : k);
                                                }
                                            }
                                        }
                                    };
                                    checkTaint(event.data);
                                }
                                return listener.call(this, event);
                            };
                            return originalPortAddListener.call(this, type, wrappedListener, options);
                        }
                        return originalPortAddListener.call(this, type, listener, options);
                    };
                }
                return sharedWorkerInstance;
            };
            window.SharedWorker.prototype = originalSharedWorker.prototype;
            Object.assign(window.SharedWorker, originalSharedWorker);
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Worker hooks', err);
    }

    // Hook: Client-Side Trusted Types API Policy Sanitization Auditing
    try {
        if (window.trustedTypes && window.trustedTypes.createPolicy) {
            const originalCreatePolicy = window.trustedTypes.createPolicy;
            window.trustedTypes.createPolicy = function(name, rules, ...args) {
                const wrappedRules = {};
                
                if (rules.createHTML) {
                    wrappedRules.createHTML = function(input, ...ruleArgs) {
                        if (typeof input === 'string' && input.includes(token)) {
                            __XSS__('trustedTypes.createHTML:policy:' + name, input, new Error().stack);
                        }
                        return rules.createHTML.call(this, input, ...ruleArgs);
                    };
                }
                
                if (rules.createScript) {
                    wrappedRules.createScript = function(input, ...ruleArgs) {
                        if (typeof input === 'string' && input.includes(token)) {
                            __XSS__('trustedTypes.createScript:policy:' + name, input, new Error().stack);
                        }
                        return rules.createScript.call(this, input, ...ruleArgs);
                    };
                }

                if (rules.createScriptURL) {
                    wrappedRules.createScriptURL = function(input, ...ruleArgs) {
                        if (typeof input === 'string' && input.includes(token)) {
                            __XSS__('trustedTypes.createScriptURL:policy:' + name, input, new Error().stack);
                        }
                        return rules.createScriptURL.call(this, input, ...ruleArgs);
                    };
                }

                // Copy any missing properties to satisfy dynamic policy objects
                for (const key in rules) {
                    if (!wrappedRules[key]) {
                        wrappedRules[key] = rules[key];
                    }
                }

                return originalCreatePolicy.call(this, name, wrappedRules, ...args);
            };
            
            // Re-assign prototype methods to preserve API compliance
            window.trustedTypes.createPolicy.prototype = originalCreatePolicy.prototype;
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Trusted Types hooks', err);
    }

    // Hook: Client-Side ServiceWorker Registration & Cache Storage Taint Auditing
    try {
        if (navigator.serviceWorker && navigator.serviceWorker.register) {
            const originalRegister = navigator.serviceWorker.register;
            navigator.serviceWorker.register = function(scriptURL, options, ...args) {
                if (typeof scriptURL === 'string' && scriptURL.includes(token)) {
                    __XSS__('navigator.serviceWorker.register:scriptURL', scriptURL, new Error().stack);
                }
                if (options && typeof options.scope === 'string' && options.scope.includes(token)) {
                    __XSS__('navigator.serviceWorker.register:scope', options.scope, new Error().stack);
                }
                return originalRegister.call(this, scriptURL, options, ...args);
            };
        }

        if (window.caches && window.caches.open) {
            const originalOpen = window.caches.open;
            window.caches.open = function(cacheName, ...args) {
                if (typeof cacheName === 'string' && cacheName.includes(token)) {
                    __XSS__('caches.open:cacheName', cacheName, new Error().stack);
                }
                return originalOpen.call(this, cacheName, ...args).then(function(cacheInstance) {
                    if (cacheInstance) {
                        const originalPut = cacheInstance.put;
                        cacheInstance.put = function(request, response, ...putArgs) {
                            // Inspect request URLs
                            if (typeof request === 'string' && request.includes(token)) {
                                __XSS__('cache.put:requestURL', request, new Error().stack);
                            } else if (request && typeof request.url === 'string' && request.url.includes(token)) {
                                __XSS__('cache.put:requestURL', request.url, new Error().stack);
                            }
                            // Inspect response content if readable
                            if (response && typeof response.clone === 'function') {
                                try {
                                    const respClone = response.clone();
                                    respClone.text().then(function(bodyText) {
                                        if (bodyText && bodyText.includes(token)) {
                                            __XSS__('cache.put:responseBody', bodyText, new Error().stack);
                                        }
                                    });
                                } catch (e) {}
                            }
                            return originalPut.call(this, request, response, ...putArgs);
                        };

                        const originalAdd = cacheInstance.add;
                        cacheInstance.add = function(request, ...addArgs) {
                            if (typeof request === 'string' && request.includes(token)) {
                                __XSS__('cache.add:requestURL', request, new Error().stack);
                            } else if (request && typeof request.url === 'string' && request.url.includes(token)) {
                                __XSS__('cache.add:requestURL', request.url, new Error().stack);
                            }
                            return originalAdd.call(this, request, ...addArgs);
                        };
                    }
                    return cacheInstance;
                });
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup ServiceWorker and Cache Storage hooks', err);
    }

    // Hook: Client-Side MutationObserver DOM Modification Taint Auditing
    try {
        if (window.MutationObserver) {
            const originalMutationObserver = window.MutationObserver;
            window.MutationObserver = function(callback) {
                const wrappedCallback = function(mutations, observer) {
                    for (let i = 0; i < mutations.length; i++) {
                        const mutation = mutations[i];
                        // 1. Audit node insertions
                        if (mutation.addedNodes) {
                            for (let j = 0; j < mutation.addedNodes.length; j++) {
                                const node = mutation.addedNodes[j];
                                if (node.nodeType === Node.ELEMENT_NODE) {
                                    // Check element outerHTML
                                    const html = node.outerHTML;
                                    if (html && html.includes(token)) {
                                        __XSS__('MutationObserver.addedNode:ELEMENT', html, new Error().stack);
                                    }
                                } else if (node.nodeType === Node.TEXT_NODE) {
                                    const text = node.textContent;
                                    if (text && text.includes(token)) {
                                        __XSS__('MutationObserver.addedNode:TEXT', text, new Error().stack);
                                    }
                                }
                            }
                        }
                        // 2. Audit attribute changes
                        if (mutation.type === 'attributes') {
                            const attrName = mutation.attributeName;
                            const targetElement = mutation.target;
                            if (targetElement && targetElement.getAttribute) {
                                const attrVal = targetElement.getAttribute(attrName);
                                if (attrVal && attrVal.includes(token)) {
                                    __XSS__('MutationObserver.attributeChanged:' + attrName, attrVal, new Error().stack);
                                }
                            }
                        }
                        // 3. Audit character data modifications (text updates)
                        if (mutation.type === 'characterData') {
                            const charData = mutation.target.textContent;
                            if (charData && charData.includes(token)) {
                                __XSS__('MutationObserver.characterDataChanged', charData, new Error().stack);
                            }
                        }
                    }
                    return callback.call(this, mutations, observer);
                };
                
                const observerInstance = new originalMutationObserver(wrappedCallback);
                return observerInstance;
            };
            
            // Preserve prototype chain compliance
            window.MutationObserver.prototype = originalMutationObserver.prototype;
            Object.assign(window.MutationObserver, originalMutationObserver);
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup MutationObserver hooks', err);
    }

    // Hook: Client-Side WebRTC Peer Connection & DataChannel Taint Auditing
    try {
        if (window.RTCPeerConnection) {
            const originalCreateDataChannel = window.RTCPeerConnection.prototype.createDataChannel;
            window.RTCPeerConnection.prototype.createDataChannel = function(label, options, ...args) {
                if (typeof label === 'string' && label.includes(token)) {
                    __XSS__('RTCPeerConnection.createDataChannel:label', label, new Error().stack);
                }
                const channelInstance = originalCreateDataChannel.call(this, label, options, ...args);
                if (channelInstance) {
                    wrapRTCDataChannel(channelInstance);
                }
                return channelInstance;
            };

            // Hook incoming channels
            const originalAddEventListener = window.RTCPeerConnection.prototype.addEventListener;
            window.RTCPeerConnection.prototype.addEventListener = function(type, listener, options, ...args) {
                if (type === 'datachannel') {
                    const wrappedListener = function(event) {
                        if (event && event.channel) {
                            wrapRTCDataChannel(event.channel);
                        }
                        return listener.call(this, event);
                    };
                    return originalAddEventListener.call(this, type, wrappedListener, options, ...args);
                }
                return originalAddEventListener.call(this, type, listener, options, ...args);
            };

            // Hook inline ondatachannel descriptor
            const descriptor = Object.getOwnPropertyDescriptor(window.RTCPeerConnection.prototype, 'ondatachannel');
            if (descriptor && descriptor.set) {
                const originalSet = descriptor.set;
                Object.defineProperty(window.RTCPeerConnection.prototype, 'ondatachannel', {
                    set: function(val) {
                        const wrappedVal = function(event) {
                            if (event && event.channel) {
                                wrapRTCDataChannel(event.channel);
                            }
                            return val.call(this, event);
                        };
                        return originalSet.call(this, wrappedVal);
                    },
                    configurable: true,
                    enumerable: true
                });
            }

            function wrapRTCDataChannel(channel) {
                try {
                    // Hook outgoing channel messages
                    const originalSend = channel.send;
                    channel.send = function(data, ...sendArgs) {
                        if (typeof data === 'string' && data.includes(token)) {
                            __XSS__('RTCDataChannel.send', data, new Error().stack);
                        }
                        return originalSend.call(this, data, ...sendArgs);
                    };

                    // Hook incoming channel messages
                    const originalChannelAddEventListener = channel.addEventListener;
                    channel.addEventListener = function(type, listener, options, ...args) {
                        if (type === 'message') {
                            const wrappedListener = function(event) {
                                if (event && typeof event.data === 'string' && event.data.includes(token)) {
                                    __XSS__('RTCDataChannel.onmessage', event.data, new Error().stack);
                                }
                                return listener.call(this, event);
                            };
                            return originalChannelAddEventListener.call(this, type, wrappedListener, options, ...args);
                        }
                        return originalChannelAddEventListener.call(this, type, listener, options, ...args);
                    };

                    const channelDescriptor = Object.getOwnPropertyDescriptor(RTCDataChannel.prototype, 'onmessage');
                    if (channelDescriptor && channelDescriptor.set) {
                        const originalChannelSet = channelDescriptor.set;
                        Object.defineProperty(channel, 'onmessage', {
                            set: function(val) {
                                const wrappedVal = function(event) {
                                    if (event && typeof event.data === 'string' && event.data.includes(token)) {
                                        __XSS__('RTCDataChannel.onmessage', event.data, new Error().stack);
                                    }
                                    return val.call(this, event);
                                };
                                return originalChannelSet.call(this, wrappedVal);
                            },
                            configurable: true,
                            enumerable: true
                        });
                    }
                } catch (e) {
                    console.error('XSS Oracle: Failed to wrap RTCDataChannel', e);
                }
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup WebRTC hooks', err);
    }

    // Hook: Client-Side Web Share API & Async Clipboard API Taint Auditing
    try {
        if (navigator.share) {
            const originalShare = navigator.share;
            navigator.share = function(data, ...args) {
                if (data) {
                    if (typeof data.url === 'string' && data.url.includes(token)) {
                        __XSS__('navigator.share:url', data.url, new Error().stack);
                    }
                    if (typeof data.text === 'string' && data.text.includes(token)) {
                        __XSS__('navigator.share:text', data.text, new Error().stack);
                    }
                    if (typeof data.title === 'string' && data.title.includes(token)) {
                        __XSS__('navigator.share:title', data.title, new Error().stack);
                    }
                }
                return originalShare.call(this, data, ...args);
            };
        }

        if (navigator.clipboard) {
            if (navigator.clipboard.writeText) {
                const originalWriteText = navigator.clipboard.writeText;
                navigator.clipboard.writeText = function(text, ...args) {
                    if (typeof text === 'string' && text.includes(token)) {
                        __XSS__('navigator.clipboard.writeText', text, new Error().stack);
                    }
                    return originalWriteText.call(this, text, ...args);
                };
            }
            if (navigator.clipboard.write) {
                const originalWrite = navigator.clipboard.write;
                navigator.clipboard.write = function(data, ...args) {
                    if (Array.isArray(data)) {
                        for (let i = 0; i < data.length; i++) {
                            const item = data[i];
                            if (item && item.types) {
                                for (let j = 0; j < item.types.length; j++) {
                                    const type = item.types[j];
                                    item.getType(type).then(function(blob) {
                                        if (blob) {
                                            blob.text().then(function(blobText) {
                                                if (blobText && blobText.includes(token)) {
                                                    __XSS__('navigator.clipboard.write:blobText', blobText, new Error().stack);
                                                }
                                            });
                                        }
                                    }).catch(function() {});
                                }
                            }
                        }
                    }
                    return originalWrite.call(this, data, ...args);
                };
            }
            if (navigator.clipboard.readText) {
                const originalReadText = navigator.clipboard.readText;
                navigator.clipboard.readText = function(...args) {
                    return originalReadText.call(this, ...args).then(function(text) {
                        if (typeof text === 'string' && text.includes(token)) {
                            __XSS__('navigator.clipboard.readText', text, new Error().stack);
                        }
                        return text;
                    });
                };
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Web Share and Clipboard hooks', err);
    }

    // Hook: Client-Side Payment Request API & Web MIDI API Taint Auditing
    try {
        if (window.PaymentRequest) {
            const originalPaymentRequest = window.PaymentRequest;
            window.PaymentRequest = function(methodData, details, options) {
                if (methodData && Array.isArray(methodData)) {
                    for (let i = 0; i < methodData.length; i++) {
                        const m = methodData[i];
                        if (typeof m.supportedMethods === 'string' && m.supportedMethods.includes(token)) {
                            __XSS__('PaymentRequest:methodData', m.supportedMethods, new Error().stack);
                        }
                    }
                }
                if (details) {
                    if (details.total && details.total.label && details.total.label.includes(token)) {
                        __XSS__('PaymentRequest:label', details.total.label, new Error().stack);
                    }
                    if (details.displayItems && Array.isArray(details.displayItems)) {
                        for (let i = 0; i < details.displayItems.length; i++) {
                            const item = details.displayItems[i];
                            if (item && item.label && item.label.includes(token)) {
                                __XSS__('PaymentRequest:label', item.label, new Error().stack);
                            }
                        }
                    }
                }
                const paymentInstance = new originalPaymentRequest(methodData, details, options);
                return paymentInstance;
            };
            window.PaymentRequest.prototype = originalPaymentRequest.prototype;
            Object.assign(window.PaymentRequest, originalPaymentRequest);
        }

        if (navigator.requestMIDIAccess) {
            const originalRequestMIDIAccess = navigator.requestMIDIAccess;
            navigator.requestMIDIAccess = function(options) {
                if (options) {
                    try {
                        const serializedOptions = JSON.stringify(options);
                        if (serializedOptions.includes(token)) {
                            __XSS__('navigator.requestMIDIAccess:options', serializedOptions, new Error().stack);
                        }
                    } catch (e) {}
                }
                return originalRequestMIDIAccess.call(this, options).then(function(midiAccess) {
                    if (midiAccess && midiAccess.inputs) {
                        const originalInputsForEach = midiAccess.inputs.forEach;
                        if (originalInputsForEach) {
                            midiAccess.inputs.forEach = function(callback, thisArg) {
                                return originalInputsForEach.call(this, function(port, key, map) {
                                    if (port) {
                                        if (port.name && port.name.includes(token)) {
                                            __XSS__('MIDIAccess.input:name', port.name, new Error().stack);
                                        }
                                        if (port.manufacturer && port.manufacturer.includes(token)) {
                                            __XSS__('MIDIAccess.input:manufacturer', port.manufacturer, new Error().stack);
                                        }
                                    }
                                    return callback.call(thisArg, port, key, map);
                                });
                            };
                        }
                    }
                    return midiAccess;
                });
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Payment and MIDI hooks', err);
    }

    // Hook: Client-Side Navigation API Taint Auditing
    try {
        if (window.navigation) {
            // Hook navigate event
            window.navigation.addEventListener('navigate', function(event) {
                if (event) {
                    if (event.destination && event.destination.url && event.destination.url.includes(token)) {
                        __XSS__('navigation.navigate:url', event.destination.url, new Error().stack);
                    }
                    if (event.info && typeof event.info === 'string' && event.info.includes(token)) {
                        __XSS__('navigation.navigate:info', event.info, new Error().stack);
                    }
                    // Extract state parameters if present
                    if (event.destination && event.destination.getState) {
                        try {
                            const state = event.destination.getState();
                            if (state) {
                                const serializedState = JSON.stringify(state);
                                if (serializedState.includes(token)) {
                                    __XSS__('navigation.navigate:state', serializedState, new Error().stack);
                                }
                            }
                        } catch (e) {}
                    }
                }
            });

            // Hook navigate method
            if (window.navigation.navigate) {
                const originalNavigate = window.navigation.navigate;
                window.navigation.navigate = function(url, options, ...args) {
                    if (typeof url === 'string' && url.includes(token)) {
                        __XSS__('navigation.navigate', url, new Error().stack);
                    }
                    if (options && options.info && typeof options.info === 'string' && options.info.includes(token)) {
                        __XSS__('navigation.navigate:info', options.info, new Error().stack);
                    }
                    if (options && options.state) {
                        try {
                            const serializedState = JSON.stringify(options.state);
                            if (serializedState.includes(token)) {
                                __XSS__('navigation.navigate:state', serializedState, new Error().stack);
                            }
                        } catch (e) {}
                    }
                    return originalNavigate.call(this, url, options, ...args);
                };
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Navigation API hooks', err);
    }

    // Hook: Client-Side CustomEvent Taint Auditing
    try {
        if (window.CustomEvent) {
            const originalCustomEvent = window.CustomEvent;
            window.CustomEvent = function(typeArg, eventInitDict, ...args) {
                if (typeof typeArg === 'string' && typeArg.includes(token)) {
                    __XSS__('CustomEvent:type', typeArg, new Error().stack);
                }
                if (eventInitDict && eventInitDict.detail) {
                    try {
                        const serializedDetail = typeof eventInitDict.detail === 'string' ? eventInitDict.detail : JSON.stringify(eventInitDict.detail);
                        if (serializedDetail && serializedDetail.includes(token)) {
                            __XSS__('CustomEvent:detail', serializedDetail, new Error().stack);
                        }
                    } catch (e) {}
                }
                const customEventInstance = new originalCustomEvent(typeArg, eventInitDict, ...args);
                return customEventInstance;
            };
            window.CustomEvent.prototype = originalCustomEvent.prototype;
            Object.assign(window.CustomEvent, originalCustomEvent);
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup CustomEvent hooks', err);
    }

    // Hook 26: EventSource (Server-Sent Events) Taint Auditing
    try {
        if (window.EventSource) {
            const originalEventSource = window.EventSource;
            window.EventSource = function(url, eventSourceInitDict) {
                if (typeof url === 'string' && url.includes(token)) {
                    __XSS__('EventSource:url', url, new Error().stack);
                }
                const instance = new originalEventSource(url, eventSourceInitDict);
                // Wrap onmessage
                const origOnMessageDesc = Object.getOwnPropertyDescriptor(EventSource.prototype, 'onmessage');
                if (origOnMessageDesc && origOnMessageDesc.set) {
                    const origSet = origOnMessageDesc.set;
                    Object.defineProperty(instance, 'onmessage', {
                        set: function(handler) {
                            const wrapped = function(event) {
                                if (event && typeof event.data === 'string' && event.data.includes(token)) {
                                    __XSS__('EventSource.onmessage', event.data, new Error().stack);
                                }
                                return handler.call(this, event);
                            };
                            return origSet.call(this, wrapped);
                        },
                        configurable: true, enumerable: true
                    });
                }
                // Wrap addEventListener for 'message'
                const origAddEL = instance.addEventListener;
                instance.addEventListener = function(type, listener, opts) {
                    if (type === 'message') {
                        const wrappedListener = function(event) {
                            if (event && typeof event.data === 'string' && event.data.includes(token)) {
                                __XSS__('EventSource.message', event.data, new Error().stack);
                            }
                            return listener.call(this, event);
                        };
                        return origAddEL.call(this, type, wrappedListener, opts);
                    }
                    return origAddEL.call(this, type, listener, opts);
                };
                return instance;
            };
            window.EventSource.prototype = originalEventSource.prototype;
            Object.assign(window.EventSource, originalEventSource);
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup EventSource hooks', err);
    }

    // Hook 27: Notification API Taint Auditing
    try {
        if (window.Notification) {
            const originalNotification = window.Notification;
            window.Notification = function(title, options) {
                if (typeof title === 'string' && title.includes(token)) {
                    __XSS__('Notification:title', title, new Error().stack);
                }
                if (options) {
                    if (typeof options.body === 'string' && options.body.includes(token)) {
                        __XSS__('Notification:body', options.body, new Error().stack);
                    }
                    if (typeof options.icon === 'string' && options.icon.includes(token)) {
                        __XSS__('Notification:icon', options.icon, new Error().stack);
                    }
                    if (typeof options.image === 'string' && options.image.includes(token)) {
                        __XSS__('Notification:image', options.image, new Error().stack);
                    }
                    if (typeof options.tag === 'string' && options.tag.includes(token)) {
                        __XSS__('Notification:tag', options.tag, new Error().stack);
                    }
                    if (typeof options.data === 'string' && options.data.includes(token)) {
                        __XSS__('Notification:data', options.data, new Error().stack);
                    }
                }
                const notifInstance = new originalNotification(title, options);
                return notifInstance;
            };
            window.Notification.prototype = originalNotification.prototype;
            // Preserve static properties like permission, requestPermission
            Object.keys(originalNotification).forEach(function(key) {
                try { window.Notification[key] = originalNotification[key]; } catch (e) {}
            });
            Object.defineProperty(window.Notification, 'permission', {
                get: function() { return originalNotification.permission; },
                configurable: true
            });
            if (originalNotification.requestPermission) {
                window.Notification.requestPermission = originalNotification.requestPermission.bind(originalNotification);
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Notification hooks', err);
    }

    // Hook 28: URL.createObjectURL & Blob Content Taint Auditing
    try {
        if (window.URL && window.URL.createObjectURL) {
            const originalCreateObjectURL = window.URL.createObjectURL;
            window.URL.createObjectURL = function(obj) {
                if (obj instanceof Blob) {
                    // Read the blob text asynchronously to check for token
                    obj.text().then(function(blobText) {
                        if (blobText && blobText.includes(token)) {
                            __XSS__('URL.createObjectURL:blobContent', blobText.substring(0, 500), new Error().stack);
                        }
                    }).catch(function() {});
                }
                return originalCreateObjectURL.call(this, obj);
            };
        }
        // Also hook Blob constructor to catch tainted blob creation
        if (window.Blob) {
            const originalBlob = window.Blob;
            window.Blob = function(blobParts, options) {
                if (Array.isArray(blobParts)) {
                    for (let i = 0; i < blobParts.length; i++) {
                        const part = blobParts[i];
                        if (typeof part === 'string' && part.includes(token)) {
                            __XSS__('Blob:content', part.substring(0, 500), new Error().stack);
                        }
                    }
                }
                const blobInstance = new originalBlob(blobParts, options);
                return blobInstance;
            };
            window.Blob.prototype = originalBlob.prototype;
            Object.assign(window.Blob, originalBlob);
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Blob/ObjectURL hooks', err);
    }

    // Hook 29: IntersectionObserver Lazy-Load Content Taint Auditing
    try {
        if (window.IntersectionObserver) {
            const originalIntersectionObserver = window.IntersectionObserver;
            window.IntersectionObserver = function(callback, options) {
                const wrappedCallback = function(entries, observer) {
                    for (let i = 0; i < entries.length; i++) {
                        const entry = entries[i];
                        if (entry.isIntersecting && entry.target) {
                            // Check if the intersecting element contains tainted content
                            const el = entry.target;
                            if (el.nodeType === Node.ELEMENT_NODE) {
                                const html = el.outerHTML;
                                if (html && html.includes(token)) {
                                    __XSS__('IntersectionObserver.intersecting', html.substring(0, 500), new Error().stack);
                                }
                                // Check data-src or lazy attributes
                                var attrs = ['data-src', 'data-href', 'data-url', 'data-content'];
                                for (var a = 0; a < attrs.length; a++) {
                                    var attrVal = el.getAttribute(attrs[a]);
                                    if (attrVal && attrVal.includes(token)) {
                                        __XSS__('IntersectionObserver.lazyAttr:' + attrs[a], attrVal, new Error().stack);
                                    }
                                }
                            }
                        }
                    }
                    return callback.call(this, entries, observer);
                };
                const observerInstance = new originalIntersectionObserver(wrappedCallback, options);
                return observerInstance;
            };
            window.IntersectionObserver.prototype = originalIntersectionObserver.prototype;
            Object.assign(window.IntersectionObserver, originalIntersectionObserver);
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup IntersectionObserver hooks', err);
    }

    // Hook 30: Web Animations API Keyframe Taint Auditing
    try {
        if (Element.prototype.animate) {
            const originalAnimate = Element.prototype.animate;
            Element.prototype.animate = function(keyframes, options) {
                // Check keyframe values for tainted strings (e.g. content, background-image url)
                try {
                    const serialized = JSON.stringify(keyframes);
                    if (serialized && serialized.includes(token)) {
                        __XSS__('Element.animate:keyframes', serialized.substring(0, 500), new Error().stack);
                    }
                } catch (e) {}
                if (options && typeof options === 'object') {
                    try {
                        const serializedOpts = JSON.stringify(options);
                        if (serializedOpts && serializedOpts.includes(token)) {
                            __XSS__('Element.animate:options', serializedOpts.substring(0, 500), new Error().stack);
                        }
                    } catch (e) {}
                }
                return originalAnimate.call(this, keyframes, options);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Web Animations hooks', err);
    }

    // Hook 31: TreeWalker & NodeIterator DOM Traversal Taint Auditing
    try {
        if (document.createTreeWalker) {
            const originalCreateTreeWalker = document.createTreeWalker;
            document.createTreeWalker = function(root, whatToShow, filter, entityReferenceExpansion) {
                const treeWalker = originalCreateTreeWalker.call(this, root, whatToShow, filter, entityReferenceExpansion);
                const originalNextNode = treeWalker.nextNode;
                treeWalker.nextNode = function() {
                    const node = originalNextNode.call(this);
                    if (node) {
                        if (node.nodeType === Node.ELEMENT_NODE && node.outerHTML && node.outerHTML.includes(token)) {
                            __XSS__('TreeWalker.nextNode:ELEMENT', node.outerHTML.substring(0, 500), new Error().stack);
                        } else if (node.nodeType === Node.TEXT_NODE && node.textContent && node.textContent.includes(token)) {
                            __XSS__('TreeWalker.nextNode:TEXT', node.textContent, new Error().stack);
                        }
                    }
                    return node;
                };
                return treeWalker;
            };
        }
        if (document.createNodeIterator) {
            const originalCreateNodeIterator = document.createNodeIterator;
            document.createNodeIterator = function(root, whatToShow, filter) {
                const nodeIterator = originalCreateNodeIterator.call(this, root, whatToShow, filter);
                const originalNextNode = nodeIterator.nextNode;
                nodeIterator.nextNode = function() {
                    const node = originalNextNode.call(this);
                    if (node) {
                        if (node.nodeType === Node.ELEMENT_NODE && node.outerHTML && node.outerHTML.includes(token)) {
                            __XSS__('NodeIterator.nextNode:ELEMENT', node.outerHTML.substring(0, 500), new Error().stack);
                        } else if (node.nodeType === Node.TEXT_NODE && node.textContent && node.textContent.includes(token)) {
                            __XSS__('NodeIterator.nextNode:TEXT', node.textContent, new Error().stack);
                        }
                    }
                    return node;
                };
                return nodeIterator;
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup TreeWalker/NodeIterator hooks', err);
    }

    // Hook 32: document.createElement Dynamic Element Injection Taint Auditing
    try {
        const originalCreateElement = document.createElement;
        document.createElement = function(tagName, options) {
            const element = originalCreateElement.call(this, tagName, options);
            // Watch for dangerous element types being created with tainted tag names
            if (typeof tagName === 'string' && tagName.includes(token)) {
                __XSS__('document.createElement:tagName', tagName, new Error().stack);
            }
            // Hook the textContent setter on the newly created element
            const origTextContentDesc = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
            if (origTextContentDesc && origTextContentDesc.set) {
                Object.defineProperty(element, 'textContent', {
                    set: function(val) {
                        if (typeof val === 'string' && val.includes(token)) {
                            __XSS__('createElement.' + tagName + '.textContent', val.substring(0, 500), new Error().stack);
                        }
                        return origTextContentDesc.set.call(this, val);
                    },
                    get: origTextContentDesc.get ? function() { return origTextContentDesc.get.call(this); } : undefined,
                    configurable: true
                });
            }
            return element;
        };
    } catch (err) {
        console.error('XSS Oracle: Failed to setup createElement hooks', err);
    }

    // Hook 33: ReportingObserver & SecurityPolicyViolation Detail Taint Auditing
    try {
        if (window.ReportingObserver) {
            const originalReportingObserver = window.ReportingObserver;
            window.ReportingObserver = function(callback, options) {
                const wrappedCallback = function(reports, observer) {
                    for (let i = 0; i < reports.length; i++) {
                        const report = reports[i];
                        try {
                            const serialized = JSON.stringify(report.body);
                            if (serialized && serialized.includes(token)) {
                                __XSS__('ReportingObserver:report', serialized.substring(0, 500), new Error().stack);
                            }
                        } catch (e) {}
                    }
                    return callback.call(this, reports, observer);
                };
                const observerInstance = new originalReportingObserver(wrappedCallback, options);
                return observerInstance;
            };
            window.ReportingObserver.prototype = originalReportingObserver.prototype;
            Object.assign(window.ReportingObserver, originalReportingObserver);
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup ReportingObserver hooks', err);
    }

    // Hook 34: requestAnimationFrame / requestIdleCallback String Eval Taint Auditing
    try {
        const originalRAF = window.requestAnimationFrame;
        if (originalRAF) {
            window.requestAnimationFrame = function(callback) {
                if (typeof callback === 'string' && callback.includes(token)) {
                    __XSS__('requestAnimationFrame:stringEval', callback, new Error().stack);
                }
                return originalRAF.call(this, callback);
            };
        }
        if (window.requestIdleCallback) {
            const originalRIC = window.requestIdleCallback;
            window.requestIdleCallback = function(callback, options) {
                if (typeof callback === 'string' && callback.includes(token)) {
                    __XSS__('requestIdleCallback:stringEval', callback, new Error().stack);
                }
                return originalRIC.call(this, callback, options);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup rAF/rIC hooks', err);
    }

    // Hook 35: EventTarget.dispatchEvent Synthetic Event Detail Taint Auditing
    try {
        const originalDispatchEvent = EventTarget.prototype.dispatchEvent;
        EventTarget.prototype.dispatchEvent = function(event) {
            if (event) {
                // Check CustomEvent detail
                if (event.detail) {
                    try {
                        const serialized = typeof event.detail === 'string' ? event.detail : JSON.stringify(event.detail);
                        if (serialized && serialized.includes(token)) {
                            __XSS__('dispatchEvent:detail:' + event.type, serialized.substring(0, 500), new Error().stack);
                        }
                    } catch (e) {}
                }
                // Check event type name
                if (typeof event.type === 'string' && event.type.includes(token)) {
                    __XSS__('dispatchEvent:type', event.type, new Error().stack);
                }
            }
            return originalDispatchEvent.call(this, event);
        };
    } catch (err) {
        console.error('XSS Oracle: Failed to setup dispatchEvent hooks', err);
    }

    // Hook 36: Proxy/Reflect Object Trap Taint Auditing
    try {
        if (window.Proxy) {
            const originalProxy = window.Proxy;
            window.Proxy = function(target, handler) {
                const wrappedHandler = {};
                for (const trap in handler) {
                    if (typeof handler[trap] === 'function') {
                        const originalTrap = handler[trap];
                        wrappedHandler[trap] = function(...args) {
                            // Check if any string argument contains the token
                            for (let i = 0; i < args.length; i++) {
                                if (typeof args[i] === 'string' && args[i].includes(token)) {
                                    __XSS__('Proxy.' + trap, args[i], new Error().stack);
                                }
                            }
                            return originalTrap.apply(this, args);
                        };
                    } else {
                        wrappedHandler[trap] = handler[trap];
                    }
                }
                return new originalProxy(target, wrappedHandler);
            };
            window.Proxy.revocable = originalProxy.revocable;
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Proxy hooks', err);
    }

    // Hook 37: CSS StyleSheet insertRule & cssText Injection Taint Auditing
    try {
        if (CSSStyleSheet.prototype.insertRule) {
            const originalInsertRule = CSSStyleSheet.prototype.insertRule;
            CSSStyleSheet.prototype.insertRule = function(rule, index) {
                if (typeof rule === 'string' && rule.includes(token)) {
                    __XSS__('CSSStyleSheet.insertRule', rule.substring(0, 500), new Error().stack);
                }
                return originalInsertRule.call(this, rule, index);
            };
        }
        if (CSSStyleSheet.prototype.replaceSync) {
            const originalReplaceSync = CSSStyleSheet.prototype.replaceSync;
            CSSStyleSheet.prototype.replaceSync = function(text) {
                if (typeof text === 'string' && text.includes(token)) {
                    __XSS__('CSSStyleSheet.replaceSync', text.substring(0, 500), new Error().stack);
                }
                return originalReplaceSync.call(this, text);
            };
        }
        // Hook style.cssText property
        const cssTextDesc = Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype, 'cssText');
        if (cssTextDesc && cssTextDesc.set) {
            const origCssTextSet = cssTextDesc.set;
            Object.defineProperty(CSSStyleDeclaration.prototype, 'cssText', {
                set: function(val) {
                    if (typeof val === 'string' && val.includes(token)) {
                        __XSS__('CSSStyleDeclaration.cssText', val.substring(0, 500), new Error().stack);
                    }
                    return origCssTextSet.call(this, val);
                },
                get: cssTextDesc.get,
                configurable: true
            });
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup CSS injection hooks', err);
    }

    // Hook 38: document.adoptNode & importNode Cross-Document Taint Auditing
    try {
        if (document.adoptNode) {
            const originalAdoptNode = document.adoptNode;
            document.adoptNode = function(node) {
                if (node && node.nodeType === Node.ELEMENT_NODE) {
                    const html = node.outerHTML;
                    if (html && html.includes(token)) {
                        __XSS__('document.adoptNode', html.substring(0, 500), new Error().stack);
                    }
                }
                return originalAdoptNode.call(this, node);
            };
        }
        if (document.importNode) {
            const originalImportNode = document.importNode;
            document.importNode = function(node, deep) {
                if (node && node.nodeType === Node.ELEMENT_NODE) {
                    const html = node.outerHTML;
                    if (html && html.includes(token)) {
                        __XSS__('document.importNode', html.substring(0, 500), new Error().stack);
                    }
                }
                return originalImportNode.call(this, node, deep);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup adoptNode/importNode hooks', err);
    }

    // Hook 39: Selection API & window.getSelection Taint Auditing
    try {
        if (window.getSelection) {
            const originalGetSelection = window.getSelection;
            window.getSelection = function() {
                const selection = originalGetSelection.call(this);
                if (selection) {
                    const origToString = selection.toString;
                    selection.toString = function() {
                        const text = origToString.call(this);
                        if (text && text.includes(token)) {
                            __XSS__('Selection.toString', text, new Error().stack);
                        }
                        return text;
                    };
                }
                return selection;
            };
        }
        // Hook Selection.prototype.addRange for programmatic selection manipulation
        if (window.Selection && Selection.prototype.addRange) {
            const originalAddRange = Selection.prototype.addRange;
            Selection.prototype.addRange = function(range) {
                if (range) {
                    try {
                        const content = range.toString();
                        if (content && content.includes(token)) {
                            __XSS__('Selection.addRange', content, new Error().stack);
                        }
                    } catch (e) {}
                }
                return originalAddRange.call(this, range);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Selection API hooks', err);
    }

    // Hook 40: FormData Append/Set Taint Auditing
    try {
        if (window.FormData) {
            const originalAppend = FormData.prototype.append;
            FormData.prototype.append = function(name, value, filename) {
                if (typeof name === 'string' && name.includes(token)) {
                    __XSS__('FormData.append:name', name, new Error().stack);
                }
                if (typeof value === 'string' && value.includes(token)) {
                    __XSS__('FormData.append:value', value, new Error().stack);
                }
                if (typeof filename === 'string' && filename.includes(token)) {
                    __XSS__('FormData.append:filename', filename, new Error().stack);
                }
                return originalAppend.call(this, name, value, filename);
            };
            if (FormData.prototype.set) {
                const originalSet = FormData.prototype.set;
                FormData.prototype.set = function(name, value, filename) {
                    if (typeof name === 'string' && name.includes(token)) {
                        __XSS__('FormData.set:name', name, new Error().stack);
                    }
                    if (typeof value === 'string' && value.includes(token)) {
                        __XSS__('FormData.set:value', value, new Error().stack);
                    }
                    if (typeof filename === 'string' && filename.includes(token)) {
                        __XSS__('FormData.set:filename', filename, new Error().stack);
                    }
                    return originalSet.call(this, name, value, filename);
                };
            }
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup FormData hooks', err);
    }

    // Hook 41: HTMLTemplateElement Content Fragment Taint Auditing
    try {
        const templateContentDesc = Object.getOwnPropertyDescriptor(HTMLTemplateElement.prototype, 'content');
        if (templateContentDesc && templateContentDesc.get) {
            const origContentGet = templateContentDesc.get;
            Object.defineProperty(HTMLTemplateElement.prototype, 'content', {
                get: function() {
                    const fragment = origContentGet.call(this);
                    if (fragment) {
                        // Check the template's innerHTML for token
                        const templateHTML = this.innerHTML;
                        if (templateHTML && templateHTML.includes(token)) {
                            __XSS__('HTMLTemplateElement.content', templateHTML.substring(0, 500), new Error().stack);
                        }
                    }
                    return fragment;
                },
                configurable: true
            });
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup HTMLTemplateElement hooks', err);
    }

    // Hook 42: Attr Node Value & document.createAttribute Taint Auditing
    try {
        const attrValueDesc = Object.getOwnPropertyDescriptor(Attr.prototype, 'value');
        if (attrValueDesc && attrValueDesc.set) {
            const origAttrValueSet = attrValueDesc.set;
            Object.defineProperty(Attr.prototype, 'value', {
                set: function(val) {
                    if (typeof val === 'string' && val.includes(token)) {
                        __XSS__('Attr.value', val, new Error().stack);
                    }
                    return origAttrValueSet.call(this, val);
                },
                get: attrValueDesc.get,
                configurable: true
            });
        }
        if (document.createAttribute) {
            const originalCreateAttribute = document.createAttribute;
            document.createAttribute = function(name) {
                if (typeof name === 'string' && name.includes(token)) {
                    __XSS__('document.createAttribute:name', name, new Error().stack);
                }
                return originalCreateAttribute.call(this, name);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Attr hooks', err);
    }

    // Hook 43: CSSStyleDeclaration setProperty Inline Style Taint Auditing
    try {
        if (CSSStyleDeclaration.prototype.setProperty) {
            const originalSetProperty = CSSStyleDeclaration.prototype.setProperty;
            CSSStyleDeclaration.prototype.setProperty = function(propertyName, value, priority) {
                if (typeof value === 'string' && value.includes(token)) {
                    __XSS__('CSSStyleDeclaration.setProperty:' + propertyName, value, new Error().stack);
                }
                if (typeof propertyName === 'string' && propertyName.includes(token)) {
                    __XSS__('CSSStyleDeclaration.setProperty:name', propertyName, new Error().stack);
                }
                return originalSetProperty.call(this, propertyName, value, priority);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup CSSStyleDeclaration.setProperty hooks', err);
    }

    // Hook 44: structuredClone Deep Copy Taint Auditing
    try {
        if (window.structuredClone) {
            const originalStructuredClone = window.structuredClone;
            window.structuredClone = function(value, options) {
                try {
                    const serialized = JSON.stringify(value);
                    if (serialized && serialized.includes(token)) {
                        __XSS__('structuredClone', serialized.substring(0, 500), new Error().stack);
                    }
                } catch (e) {}
                return originalStructuredClone.call(this, value, options);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup structuredClone hooks', err);
    }

    // Hook 45: URL & URLSearchParams Constructor Taint Auditing
    try {
        if (window.URL) {
            const originalURL = window.URL;
            window.URL = function(url, base) {
                if (typeof url === 'string' && url.includes(token)) {
                    __XSS__('URL:constructor', url, new Error().stack);
                }
                if (typeof base === 'string' && base.includes(token)) {
                    __XSS__('URL:base', base, new Error().stack);
                }
                const instance = new originalURL(url, base);
                return instance;
            };
            window.URL.prototype = originalURL.prototype;
            // Preserve static methods
            window.URL.createObjectURL = originalURL.createObjectURL;
            window.URL.revokeObjectURL = originalURL.revokeObjectURL;
            window.URL.canParse = originalURL.canParse;
        }
        if (window.URLSearchParams) {
            const originalURLSearchParams = window.URLSearchParams;
            window.URLSearchParams = function(init) {
                if (typeof init === 'string' && init.includes(token)) {
                    __XSS__('URLSearchParams:init', init, new Error().stack);
                }
                const instance = new originalURLSearchParams(init);
                // Wrap append and set
                const origAppend = instance.append;
                instance.append = function(name, value) {
                    if (typeof value === 'string' && value.includes(token)) {
                        __XSS__('URLSearchParams.append:' + name, value, new Error().stack);
                    }
                    return origAppend.call(this, name, value);
                };
                const origSet = instance.set;
                instance.set = function(name, value) {
                    if (typeof value === 'string' && value.includes(token)) {
                        __XSS__('URLSearchParams.set:' + name, value, new Error().stack);
                    }
                    return origSet.call(this, name, value);
                };
                return instance;
            };
            window.URLSearchParams.prototype = originalURLSearchParams.prototype;
            Object.assign(window.URLSearchParams, originalURLSearchParams);
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup URL/URLSearchParams hooks', err);
    }

    // Hook 46: attachShadow Closed Shadow-DOM-Aware Auditing Bypass
    try {
        if (window.Element && Element.prototype.attachShadow) {
            const originalAttachShadow = Element.prototype.attachShadow;
            Element.prototype.attachShadow = function(init) {
                // If closed mode is requested, force it to 'open' to allow DOM interaction traversal
                if (init && init.mode === 'closed') {
                    return originalAttachShadow.call(this, { ...init, mode: 'open' });
                }
                return originalAttachShadow.call(this, init);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup attachShadow override', err);
    }

    // Hook 47: CSS/XS-Leaks Style Rule Injection Auditing
    try {
        if (window.CSSStyleSheet && CSSStyleSheet.prototype.insertRule) {
            const originalInsertRule = CSSStyleSheet.prototype.insertRule;
            CSSStyleSheet.prototype.insertRule = function(rule, ...args) {
                if (typeof rule === 'string' && rule.includes(token)) {
                    __XSS__('CSSStyleSheet.insertRule', rule, new Error().stack);
                }
                return originalInsertRule.call(this, rule, ...args);
            };
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup stylesheet insertion hooks', err);
    }

    // Hook 48: Trusted Types API Hijacking for CSP Bypass
    try {
        if (window.trustedTypes && window.trustedTypes.createPolicy) {
            const originalCreatePolicy = window.trustedTypes.createPolicy;
            window.trustedTypes.createPolicy = function(name, rules) {
                const wrappedRules = {};
                if (rules.createHTML) {
                    wrappedRules.createHTML = function(html, ...args) {
                        if (typeof html === 'string' && html.includes(token)) {
                            __XSS__('TrustedType:createHTML:' + name, html, new Error().stack);
                        }
                        return rules.createHTML.call(rules, html, ...args);
                    };
                } else {
                    wrappedRules.createHTML = (html) => html;
                }
                if (rules.createScript) {
                    wrappedRules.createScript = function(script, ...args) {
                        if (typeof script === 'string' && script.includes(token)) {
                            __XSS__('TrustedType:createScript:' + name, script, new Error().stack);
                        }
                        return rules.createScript.call(rules, script, ...args);
                    };
                } else {
                    wrappedRules.createScript = (script) => script;
                }
                if (rules.createScriptURL) {
                    wrappedRules.createScriptURL = function(url, ...args) {
                        if (typeof url === 'string' && url.includes(token)) {
                            __XSS__('TrustedType:createScriptURL:' + name, url, new Error().stack);
                        }
                        return rules.createScriptURL.call(rules, url, ...args);
                    };
                } else {
                    wrappedRules.createScriptURL = (url) => url;
                }
                const policy = originalCreatePolicy.call(window.trustedTypes, name, wrappedRules);
                return policy;
            };
            window.__registerOracleHook__(window.trustedTypes.createPolicy, originalCreatePolicy, 'createPolicy');
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Trusted Types hooks', err);
    }

    console.log('XSS Oracle: Injected successfully', { token: token.substring(0, 8) + '...' });
})();
