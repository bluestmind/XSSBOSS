/**
 * XSS Oracle injection script.
 * Injected into pages before page scripts run to detect XSS execution.
 */
(function() {
    'use strict';
    
    // Get token and oracle URL from window (set by executor)
    const token = window.__XSS_TOKEN__ || '';
    const oracleUrl = window.__ORACLE_URL__ || '/api/v1/oracle';
    const lineageProbe = window.__XSS_LINEAGE_PROBE__ === true;
    
    if (!token) {
        console.warn('XSS Oracle: No token provided');
        return;
    }
    
    // Runtime causal lineage is deliberately observational. Source getters return
    // the browser's exact value; correlation is kept in a bounded side ledger so
    // strict equality checks, signatures, parsing, and application control flow
    // retain native semantics.
    const CAUSAL_MAX_EVENTS = 256;
    const CAUSAL_MAX_DEPTH = 8;
    const CAUSAL_TTL_MS = 5000;
    // Page code is untrusted and may replace mutable prototype methods after
    // initialization. Capture the intrinsics used by the evidence ledger.
    const causalReflectApply = Reflect.apply;
    const causalObjectDefineProperty = Object.defineProperty;
    const causalJson = JSON;
    const causalJsonStringify = JSON.stringify;
    const causalStringIncludes = String.prototype.includes;
    const causalStringCharCodeAt = String.prototype.charCodeAt;
    const causalStringIndexOf = String.prototype.indexOf;
    const causalStringLastIndexOf = String.prototype.lastIndexOf;
    const causalStringMatch = String.prototype.match;
    const causalStringReplace = String.prototype.replace;
    const causalStringSlice = String.prototype.slice;
    const causalStringSplit = String.prototype.split;
    const causalStringSubstring = String.prototype.substring;
    const causalStringToLowerCase = String.prototype.toLowerCase;
    const causalStringTrim = String.prototype.trim;
    const causalNumberIsNaN = Number.isNaN;
    const causalObjectIs = Object.is;
    const causalNativeString = String;
    const causalNativeNumber = Number;
    const causalNativeParseInt = parseInt;
    const causalNumberToString = Number.prototype.toString;
    const causalPerformanceNow = performance && performance.now;
    const causalDateNow = Date.now;
    const causalMathCeil = Math.ceil;
    const causalMathFloor = Math.floor;
    const causalMathMax = Math.max;
    const causalSetHas = Set.prototype.has;
    const causalRegExpTest = RegExp.prototype.test;
    const causalNativeUint8Array = Uint8Array;
    const causalNativeUint32Array = Uint32Array;
    const causalUint8ArraySet = Uint8Array.prototype.set;
    const causalNativeURL = window.URL;
    const causalNativeTextEncoder = window.TextEncoder;
    const causalNativeTextEncoderEncode = causalNativeTextEncoder
        ? causalNativeTextEncoder.prototype.encode
        : null;
    const causalNativeQueueMicrotask = typeof window.queueMicrotask === 'function'
        ? window.queueMicrotask.bind(window)
        : null;
    const causalNativePromiseThen = window.Promise && Promise.prototype.then;
    const causalNativePromiseResolve = window.Promise && Promise.resolve;
    const causalAllowedSources = new Set([
        'location.href', 'location.search', 'location.hash', 'location.pathname',
        'document.URL', 'document.documentURI', 'document.URLUnencoded',
        'document.baseURI', 'document.referrer', 'window.name', 'postMessage'
    ]);
    const causalState = {
        events: [],
        droppedEvents: 0,
        nextEventId: 1,
        nextContextId: 1,
        activeContext: null,
        syncContext: null,
        syncClearPending: false
    };

    function causalApply(fn, receiver, args) {
        return causalReflectApply(fn, receiver, args);
    }

    function causalIncludes(value, search) {
        return typeof value === 'string'
            && typeof search === 'string'
            && causalApply(causalStringIncludes, value, [search]);
    }

    function causalIncludesToken(value) {
        return causalIncludes(value, token);
    }

    function causalStringCall(method, value, args) {
        return causalApply(method, value, args);
    }

    function causalIndexOf(value, search) {
        return causalStringCall(causalStringIndexOf, value, [search]);
    }

    function causalRegExpMatches(pattern, value) {
        return causalApply(causalRegExpTest, pattern, [value]);
    }

    function causalAppend(array, value) {
        causalObjectDefineProperty(array, array.length, {
            value: value,
            configurable: true,
            enumerable: true,
            writable: true
        });
    }

    function causalSuppressToJSON(value) {
        // Native JSON.stringify consults inherited toJSON properties before it
        // visits fields. Shadow both Object.prototype.toJSON and
        // Array.prototype.toJSON so page code cannot rewrite the export.
        causalObjectDefineProperty(value, 'toJSON', {
            value: undefined,
            configurable: false,
            enumerable: false,
            writable: false
        });
        return value;
    }

    function causalNow() {
        try {
            return causalApply(causalMathMax, Math, [
                0,
                causalApply(causalMathFloor, Math, [
                    causalApply(causalPerformanceNow, performance, [])
                ])
            ]);
        } catch (err) {
            return causalApply(causalDateNow, Date, []);
        }
    }

    const causalSha256Constants = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function causalUtf8Bytes(text) {
        if (causalNativeTextEncoder) {
            try {
                return causalApply(
                    causalNativeTextEncoderEncode,
                    new causalNativeTextEncoder(),
                    [text]
                );
            } catch (err) {}
        }
        const bytes = [];
        for (let index = 0; index < text.length; index++) {
            let code = causalStringCall(causalStringCharCodeAt, text, [index]);
            if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length) {
                const low = causalStringCall(causalStringCharCodeAt, text, [index + 1]);
                if (low >= 0xdc00 && low <= 0xdfff) {
                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                    index++;
                }
            }
            if (code < 0x80) {
                causalAppend(bytes, code);
            } else if (code < 0x800) {
                causalAppend(bytes, 0xc0 | (code >>> 6));
                causalAppend(bytes, 0x80 | (code & 0x3f));
            } else if (code < 0x10000) {
                causalAppend(bytes, 0xe0 | (code >>> 12));
                causalAppend(bytes, 0x80 | ((code >>> 6) & 0x3f));
                causalAppend(bytes, 0x80 | (code & 0x3f));
            } else {
                causalAppend(bytes, 0xf0 | (code >>> 18));
                causalAppend(bytes, 0x80 | ((code >>> 12) & 0x3f));
                causalAppend(bytes, 0x80 | ((code >>> 6) & 0x3f));
                causalAppend(bytes, 0x80 | (code & 0x3f));
            }
        }
        return new causalNativeUint8Array(bytes);
    }

    function causalRotateRight(value, bits) {
        return (value >>> bits) | (value << (32 - bits));
    }

    // Synchronous SHA-256 keeps hooks observational while replacing the prior
    // short custom hash with a standard collision-resistant commitment.
    function causalFingerprint(value) {
        const bytes = causalUtf8Bytes(causalNativeString(value));
        const bitLength = bytes.length * 8;
        const paddedLength = causalApply(
            causalMathCeil, Math, [(bytes.length + 9) / 64]
        ) * 64;
        const padded = new causalNativeUint8Array(paddedLength);
        causalApply(causalUint8ArraySet, padded, [bytes]);
        padded[bytes.length] = 0x80;
        const highLength = causalApply(
            causalMathFloor, Math, [bitLength / 0x100000000]
        );
        const lowLength = bitLength >>> 0;
        for (let index = 0; index < 4; index++) {
            padded[paddedLength - 8 + index] = (highLength >>> (24 - index * 8)) & 0xff;
            padded[paddedLength - 4 + index] = (lowLength >>> (24 - index * 8)) & 0xff;
        }
        const state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ];
        const words = new causalNativeUint32Array(64);
        for (let offset = 0; offset < padded.length; offset += 64) {
            for (let index = 0; index < 16; index++) {
                const base = offset + index * 4;
                words[index] = (
                    (padded[base] << 24)
                    | (padded[base + 1] << 16)
                    | (padded[base + 2] << 8)
                    | padded[base + 3]
                ) >>> 0;
            }
            for (let index = 16; index < 64; index++) {
                const prior = words[index - 15];
                const recent = words[index - 2];
                const sigma0 = causalRotateRight(prior, 7) ^ causalRotateRight(prior, 18) ^ (prior >>> 3);
                const sigma1 = causalRotateRight(recent, 17) ^ causalRotateRight(recent, 19) ^ (recent >>> 10);
                words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
            }
            let a = state[0];
            let b = state[1];
            let c = state[2];
            let d = state[3];
            let e = state[4];
            let f = state[5];
            let g = state[6];
            let h = state[7];
            for (let index = 0; index < 64; index++) {
                const sum1 = causalRotateRight(e, 6) ^ causalRotateRight(e, 11) ^ causalRotateRight(e, 25);
                const choose = (e & f) ^ (~e & g);
                const temporary1 = (h + sum1 + choose + causalSha256Constants[index] + words[index]) >>> 0;
                const sum0 = causalRotateRight(a, 2) ^ causalRotateRight(a, 13) ^ causalRotateRight(a, 22);
                const majority = (a & b) ^ (a & c) ^ (b & c);
                const temporary2 = (sum0 + majority) >>> 0;
                h = g;
                g = f;
                f = e;
                e = (d + temporary1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temporary1 + temporary2) >>> 0;
            }
            state[0] = (state[0] + a) >>> 0;
            state[1] = (state[1] + b) >>> 0;
            state[2] = (state[2] + c) >>> 0;
            state[3] = (state[3] + d) >>> 0;
            state[4] = (state[4] + e) >>> 0;
            state[5] = (state[5] + f) >>> 0;
            state[6] = (state[6] + g) >>> 0;
            state[7] = (state[7] + h) >>> 0;
        }
        let digest = '';
        for (let index = 0; index < state.length; index++) {
            let part = causalApply(causalNumberToString, state[index] >>> 0, [16]);
            while (part.length < 8) part = '0' + part;
            digest += part;
        }
        return digest;
    }

    function causalObservationMaterial(value) {
        if (value === null) return 'null:';
        if (value === undefined) return 'undefined:';
        const valueType = typeof value;
        if (valueType === 'number') {
            if (causalNumberIsNaN(value)) return 'number:NaN';
            if (causalObjectIs(value, -0)) return 'number:-0';
            if (value === Infinity) return 'number:+Infinity';
            if (value === -Infinity) return 'number:-Infinity';
        }
        try {
            return valueType + ':' + causalNativeString(value);
        } catch (err) {
            return valueType + ':<unprintable>';
        }
    }

    function causalSanitizeLocation(value) {
        const raw = causalStringCall(
            causalStringTrim, causalNativeString(value || ''), []
        );
        if (!raw) return 'unknown';
        if (causalRegExpMatches(/^blob:/i, raw)) return 'blob:';
        try {
            if (causalNativeURL && causalRegExpMatches(/^(?:https?|file):/i, raw)) {
                const parsed = new causalNativeURL(raw, location.href);
                parsed.username = '';
                parsed.password = '';
                parsed.search = '';
                parsed.hash = '';
                return (parsed.origin === 'null' ? parsed.protocol : parsed.origin) + parsed.pathname;
            }
        } catch (err) {}
        if (causalRegExpMatches(/^(?:data|javascript):/i, raw)) {
            const scheme = causalStringCall(causalStringSplit, raw, [':', 1])[0];
            return causalStringCall(causalStringToLowerCase, scheme, []) + ':';
        }
        const withoutHash = causalStringCall(causalStringSplit, raw, ['#', 1])[0];
        const withoutQuery = causalStringCall(
            causalStringSplit, withoutHash, ['?', 1]
        )[0];
        return causalStringCall(causalStringSlice, withoutQuery, [-512]) || 'unknown';
    }

    function causalStackLocation(errorStack) {
        if (!errorStack || typeof errorStack !== 'string') {
            return { filename: 'unknown', line: 0, column: 0 };
        }
        const lines = causalStringCall(causalStringSplit, errorStack, ['\n']);
        for (let index = 1; index < lines.length; index++) {
            const traceLine = lines[index] || '';
            if (
                causalIndexOf(traceLine, 'oracle_inject.js') !== -1
                || causalIndexOf(traceLine, '__XSS__') !== -1
            ) {
                continue;
            }
            // Greedy location capture intentionally anchors the final numeric
            // line/column pair, so schemes and Windows drive letters are safe.
            const match = causalStringCall(
                causalStringMatch,
                traceLine,
                [/^(.*):(\d+):(\d+)\)?\s*$/]
            );
            if (!match) continue;
            let filename = causalStringCall(causalStringTrim, match[1], []);
            const openParen = causalStringCall(
                causalStringLastIndexOf, filename, ['(']
            );
            if (openParen !== -1) {
                filename = causalStringCall(
                    causalStringSubstring, filename, [openParen + 1]
                );
            }
            const atSign = causalStringCall(causalStringLastIndexOf, filename, ['@']);
            if (atSign !== -1) {
                filename = causalStringCall(
                    causalStringSubstring, filename, [atSign + 1]
                );
            }
            filename = causalStringCall(
                causalStringTrim,
                causalStringCall(causalStringReplace, filename, [/^at\s+/, '']),
                []
            );
            return {
                filename: filename || 'unknown',
                line: causalApply(causalMathMax, Math, [
                    0, causalNativeParseInt(match[2], 10) || 0
                ]),
                column: causalApply(causalMathMax, Math, [
                    0, causalNativeParseInt(match[3], 10) || 0
                ])
            };
        }
        return { filename: 'unknown', line: 0, column: 0 };
    }

    function causalStackFingerprint(errorStack, category) {
        const locationInfo = causalStackLocation(errorStack);
        return causalFingerprint(
            causalNativeString(category || '') + '|'
            + causalSanitizeLocation(locationInfo.filename) + '|'
            + locationInfo.line + '|' + locationInfo.column
        );
    }

    function causalSafeSource(sourceName) {
        const normalized = causalNativeString(sourceName || '');
        return causalApply(causalSetHas, causalAllowedSources, [normalized])
            ? normalized
            : 'other';
    }

    function causalSourceCategory(sourceName) {
        const categories = {
            'location.href': 'location_href',
            'location.search': 'location_search',
            'location.hash': 'location_hash',
            'location.pathname': 'navigation_state',
            'document.URL': 'document_url',
            'document.documentURI': 'document_uri',
            'document.URLUnencoded': 'document_url',
            'document.baseURI': 'url',
            'document.referrer': 'referrer',
            'window.name': 'window_name',
            'postMessage': 'postmessage'
        };
        return categories[sourceName] || 'url';
    }

    function causalSafeSink(sinkType) {
        let normalized = causalNativeString(sinkType || 'other');
        if (token && causalIncludesToken(normalized)) {
            const pieces = causalStringCall(causalStringSplit, normalized, [token]);
            normalized = '';
            for (let index = 0; index < pieces.length; index++) {
                if (index) normalized += 'marker';
                normalized += pieces[index];
            }
        }
        normalized = causalStringCall(causalStringSplit, normalized, [' (Source:', 1])[0];
        const lowered = causalStringCall(causalStringToLowerCase, normalized, []);
        if (causalIndexOf(lowered, 'insertadjacenthtml') !== -1) return 'insertadjacenthtml';
        if (causalIndexOf(lowered, 'innerhtml') !== -1) return 'innerhtml';
        if (causalIndexOf(lowered, 'outerhtml') !== -1) return 'outerhtml';
        if (causalIndexOf(lowered, 'document.write') !== -1) return 'document_write';
        if (causalIndexOf(lowered, 'createcontextualfragment') !== -1) return 'range_fragment';
        if (causalIndexOf(lowered, 'jquery.html') !== -1 || causalIndexOf(lowered, 'jquery.append') !== -1) return 'jquery_html';
        if (causalIndexOf(lowered, 'jquery') !== -1 && causalIndexOf(lowered, 'selector') !== -1) return 'jquery_selector';
        if (causalIndexOf(lowered, 'srcdoc') !== -1) return 'srcdoc';
        if (causalIndexOf(lowered, 'iframe.src') !== -1) return 'iframe_src';
        if (causalIndexOf(lowered, 'script.src') !== -1 || causalIndexOf(lowered, 'createscripturl') !== -1) return 'script_src';
        if (causalIndexOf(lowered, 'script.text') !== -1 || causalIndexOf(lowered, 'createscript') !== -1) return 'script_text';
        if (lowered === 'eval') return 'eval';
        if (lowered === 'function' || causalIndexOf(lowered, 'functionconstructor') !== -1) return 'function_ctor';
        if (lowered === 'settimeout' || lowered === 'setinterval' || causalIndexOf(lowered, 'stringeval') !== -1) return 'timer_string';
        if (causalIndexOf(lowered, 'setattribute') !== -1) {
            return causalIndexOf(lowered, 'href') !== -1 ? 'set_href_attr' : 'setattribute';
        }
        if (causalIndexOf(lowered, 'location.assign') !== -1) return 'location_assign';
        if (causalIndexOf(lowered, 'location.replace') !== -1) return 'location_replace';
        if (causalIndexOf(lowered, 'location.href') !== -1) return 'location_href';
        if (causalIndexOf(lowered, 'location') !== -1 || causalIndexOf(lowered, 'history.') !== -1 || causalIndexOf(lowered, 'navigation.') !== -1) return 'navigation';
        if (causalIndexOf(lowered, 'window.open') !== -1) return 'window_open';
        if (causalIndexOf(lowered, 'postmessage') !== -1) return 'postmessage';
        if (causalIndexOf(lowered, 'css') !== -1 || causalIndexOf(lowered, 'style') !== -1) return 'style';
        if (causalIndexOf(lowered, 'attr') !== -1) return 'attribute';
        return null;
    }

    function causalContextAlive(context, now) {
        return !!context && context.depth <= CAUSAL_MAX_DEPTH && now <= context.expiresAt;
    }

    function causalCurrentContext() {
        const now = causalNow();
        if (causalContextAlive(causalState.activeContext, now)) {
            return causalState.activeContext;
        }
        if (causalContextAlive(causalState.syncContext, now)) {
            return causalState.syncContext;
        }
        return null;
    }

    function causalPush(event) {
        if (causalState.events.length >= CAUSAL_MAX_EVENTS) {
            causalState.droppedEvents++;
            return;
        }
        causalAppend(causalState.events, event);
    }

    function causalScheduleSyncClear() {
        if (causalState.syncClearPending) return;
        causalState.syncClearPending = true;
        const clear = function() {
            causalState.syncClearPending = false;
            causalState.syncContext = null;
        };
        try {
            if (causalNativeQueueMicrotask) {
                causalNativeQueueMicrotask(clear);
            } else if (causalNativePromiseThen) {
                causalNativePromiseThen.call(Promise.resolve(), clear);
            } else {
                setTimeout(clear, 0);
            }
        } catch (err) {
            causalState.syncClearPending = false;
            causalState.syncContext = null;
        }
    }

    function recordCausalSource(sourceName, errorStack, observationKind) {
        const now = causalNow();
        const source = causalSafeSource(sourceName);
        let context = causalCurrentContext();
        if (!context) {
            context = {
                contextId: 'ctx-' + causalState.nextContextId++,
                parentContextId: null,
                createdAt: now,
                expiresAt: now + CAUSAL_TTL_MS,
                depth: 0,
                relation: 'direct'
            };
            causalState.syncContext = context;
            causalScheduleSyncClear();
        }
        const eventId = 'src-' + causalState.nextEventId++;
        const stackFingerprint = causalStackFingerprint(errorStack, source);
        causalPush({
            kind: 'source',
            event_id: eventId,
            source_id: eventId,
            context_id: context.contextId,
            parent_context_id: context.parentContextId,
            ts_ms: now,
            relation: context.relation,
            depth: context.depth,
            source: source,
            source_category: causalSourceCategory(source),
            source_observation: ['getter_read', 'listener_delivery', 'ambient_match'].indexOf(observationKind) !== -1
                ? observationKind
                : 'getter_read',
            fingerprint: stackFingerprint,
            source_fingerprint: stackFingerprint,
            stack_fingerprint: stackFingerprint
        });
        return context;
    }

    function captureCausalContext() {
        const context = causalCurrentContext();
        if (!context || context.depth >= CAUSAL_MAX_DEPTH) return null;
        return {
            // Retaining the root context id lets the reducer match a source to a
            // sink without exporting every intermediate callback as an event.
            contextId: context.contextId,
            parentContextId: context.parentContextId,
            createdAt: context.createdAt,
            expiresAt: context.expiresAt,
            depth: context.depth + 1,
            relation: 'async'
        };
    }

    function runWithCausalContext(context, callback, receiver, args) {
        if (!causalContextAlive(context, causalNow())) {
            return callback.apply(receiver, args);
        }
        const previous = causalState.activeContext;
        causalState.activeContext = context;
        try {
            return callback.apply(receiver, args);
        } finally {
            causalState.activeContext = previous;
        }
    }

    function wrapCausalCallback(callback, context) {
        if (typeof callback !== 'function' || !context) return callback;
        return function() {
            return runWithCausalContext(context, callback, this, arguments);
        };
    }

    function causalAmbientSource(value) {
        if (!causalIncludesToken(value)) return null;
        const candidates = [
            ['location.hash', function() { return location.hash; }],
            ['location.search', function() { return location.search; }],
            ['location.pathname', function() { return location.pathname; }],
            ['location.href', function() { return location.href; }],
            ['document.referrer', function() { return document.referrer; }],
            ['document.URL', function() { return document.URL; }],
            ['document.documentURI', function() { return document.documentURI; }],
            ['window.name', function() { return window.name; }]
        ];
        for (let index = 0; index < candidates.length; index++) {
            try {
                const candidateValue = candidates[index][1]();
                if (causalIncludesToken(candidateValue)) {
                    return candidates[index][0];
                }
            } catch (err) {}
        }
        return null;
    }

    function recordCausalSink(sinkType, classification, value, filename, line, column, errorStack) {
        let context = causalCurrentContext();
        if (!context) {
            const ambientSource = causalAmbientSource(value);
            // A few browser sources, most notably Location's unforgeable own
            // accessors in Chromium, cannot be wrapped. Matching the inert
            // marker at a sink records a weak causal candidate without altering
            // the source value; only A/A/B may later establish value influence.
            if (!causalCurrentContext() && ambientSource) {
                recordCausalSource(ambientSource, errorStack, 'ambient_match');
            }
            context = causalCurrentContext();
        }
        const now = causalNow();
        if (!causalContextAlive(context, now)) return;
        const sink = causalSafeSink(sinkType);
        if (!sink) return;
        const eventId = 'sink-' + causalState.nextEventId++;
        const siteMaterial = sink + '|' + causalSanitizeLocation(filename) + '|' + Number(line || 0) + '|' + Number(column || 0);
        const sinkFingerprint = causalFingerprint(siteMaterial);
        causalPush({
            kind: 'sink',
            event_id: eventId,
            sink_id: eventId,
            context_id: context.contextId,
            parent_context_id: context.parentContextId,
            ts_ms: now,
            relation: context.relation,
            depth: context.depth,
            sink: sink,
            sink_category: sink,
            fingerprint: sinkFingerprint,
            sink_fingerprint: sinkFingerprint,
            stack_fingerprint: causalStackFingerprint(errorStack, sink),
            observation_fingerprint: causalFingerprint(causalObservationMaterial(value)),
            browser_classification: ['source', 'taint', 'execution'].indexOf(classification) !== -1
                ? classification
                : 'taint'
        });
    }

    function causalExportEvent(event) {
        if (!event || event.kind === 'source') {
            if (!event || event.kind !== 'source') return null;
            return causalSuppressToJSON({
                kind: event.kind,
                event_id: event.event_id,
                source_id: event.source_id,
                context_id: event.context_id,
                parent_context_id: event.parent_context_id,
                ts_ms: event.ts_ms,
                relation: event.relation,
                depth: event.depth,
                source: event.source,
                source_category: event.source_category,
                source_observation: event.source_observation,
                fingerprint: event.fingerprint,
                source_fingerprint: event.source_fingerprint,
                stack_fingerprint: event.stack_fingerprint
            });
        }
        if (event.kind !== 'sink') return null;
        return causalSuppressToJSON({
            kind: event.kind,
            event_id: event.event_id,
            sink_id: event.sink_id,
            context_id: event.context_id,
            parent_context_id: event.parent_context_id,
            ts_ms: event.ts_ms,
            relation: event.relation,
            depth: event.depth,
            sink: event.sink,
            sink_category: event.sink_category,
            fingerprint: event.fingerprint,
            sink_fingerprint: event.sink_fingerprint,
            stack_fingerprint: event.stack_fingerprint,
            observation_fingerprint: event.observation_fingerprint,
            browser_classification: event.browser_classification
        });
    }

    function causalExportLedger() {
        const exportedEvents = causalSuppressToJSON([]);
        const limit = causalApply(causalMathFloor, Math, [
            causalState.events.length < CAUSAL_MAX_EVENTS
                ? causalState.events.length
                : CAUSAL_MAX_EVENTS
        ]);
        for (let index = 0; index < limit; index++) {
            const event = causalExportEvent(causalState.events[index]);
            if (event) causalAppend(exportedEvents, event);
        }
        const limits = causalSuppressToJSON({
            max_events: CAUSAL_MAX_EVENTS,
            max_depth: CAUSAL_MAX_DEPTH,
            ttl_ms: CAUSAL_TTL_MS
        });
        return causalSuppressToJSON({
            schema_version: 'runtime-causal-lineage-events/v1',
            value_free: true,
            limits: limits,
            dropped_events: causalState.droppedEvents,
            events: exportedEvents
        });
    }

    causalObjectDefineProperty(window, '__XSS_CAUSAL_LINEAGE__', {
        value: causalExportLedger,
        configurable: false,
        enumerable: false,
        writable: false
    });
    // Cross the automation boundary as a primitive string. Playwright and
    // WebDriver otherwise serialize the returned arrays through page-controlled
    // prototypes, so a hostile page can suppress an intact private ledger by
    // replacing Array.prototype.map/push after initialization.
    causalObjectDefineProperty(window, '__XSS_CAUSAL_LINEAGE_JSON__', {
        value: function() {
            return causalApply(causalJsonStringify, causalJson, [
                causalExportLedger()
            ]);
        },
        configurable: false,
        enumerable: false,
        writable: false
    });

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

    function isTokenInCodeContext(jsString, tokenVal) {
        if (!jsString || !tokenVal || typeof jsString !== 'string') return false;
        let state = 'CODE';
        let escape = false;
        let index = 0;
        while (index < jsString.length) {
            if (state === 'CODE') {
                if (jsString.substring(index, index + tokenVal.length) === tokenVal) {
                    return true;
                }
                if (jsString.substring(index, index + 7) === '__XSS__') {
                    return true;
                }
            }
            const char = jsString[index];
            const nextChar = jsString[index + 1];
            if (escape) {
                escape = false;
                index++;
                continue;
            }
            if (char === '\\') {
                escape = true;
                index++;
                continue;
            }
            switch (state) {
                case 'CODE':
                    if (char === '/' && nextChar === '/') {
                        state = 'SL_COMMENT';
                        index++;
                    } else if (char === '/' && nextChar === '*') {
                        state = 'ML_COMMENT';
                        index++;
                    } else if (char === "'") {
                        state = 'SINGLE_QUOTE';
                    } else if (char === '"') {
                        state = 'DOUBLE_QUOTE';
                    } else if (char === '`') {
                        state = 'TEMPLATE_LITERAL';
                    }
                    break;
                case 'SINGLE_QUOTE':
                    if (char === "'") state = 'CODE';
                    break;
                case 'DOUBLE_QUOTE':
                    if (char === '"') state = 'CODE';
                    break;
                case 'TEMPLATE_LITERAL':
                    if (char === '`') state = 'CODE';
                    break;
                case 'SL_COMMENT':
                    if (char === '\n' || char === '\r') state = 'CODE';
                    break;
                case 'ML_COMMENT':
                    if (char === '*' && nextChar === '/') {
                        state = 'CODE';
                        index++;
                    }
                    break;
            }
            index++;
        }
        return false;
    }

    function classifyExecution(sinkType, value, tokenVal) {
        // Return one of:
        //   'source'    - a tainted DOM source was read (informational, not a hit)
        //   'execution' - attacker-controlled script actually ran (confirmed XSS)
        //   'taint'     - the token reached a sink as data, but nothing executed
        //
        // Only 'execution' is a confirmed vulnerability. Merely observing the token
        // pass through a DOM sink (innerHTML, setAttribute, storage, network, ...) is
        // NOT proof of execution and must never be reported as a hit, or every
        // reflection of the token becomes a false positive.
        if (sinkType && (String(sinkType).indexOf('DOMSourceRead:') === 0 || sinkType === 'postMessage.source')) {
            return 'source';
        }
        // Primary, unambiguous proof: the payload's own __XSS__(token) beacon fired
        // (sinkType is the token itself), or a tagged-template / direct-execution sink.
        if (sinkType === 'TaggedTemplateLiteral' || sinkType === 'DirectExecution' ||
            sinkType === tokenVal || (tokenVal && String(sinkType).indexOf(tokenVal) !== -1)) {
            return 'execution';
        }
        var sinkLower = String(sinkType).toLowerCase();
        // Native dialog primitives prove script ran - but only when they carry our
        // token, otherwise the page's own alert()/confirm() would be a false positive.
        if ((sinkLower === 'alert' || sinkLower === 'prompt' || sinkLower === 'confirm') &&
            tokenVal && String(value).indexOf(tokenVal) !== -1) {
            return 'execution';
        }
        // Code-string execution sinks: the token must sit in an executable code
        // position (not inside a string literal or comment within the evaluated code).
        if (sinkLower === 'eval' || sinkLower === 'function' || sinkLower === 'asyncfunction' ||
            sinkLower === 'generatorfunction' || sinkLower === 'asyncgeneratorfunction' ||
            sinkLower === 'settimeout' || sinkLower === 'setinterval') {
            return isTokenInCodeContext(value, tokenVal) ? 'execution' : 'taint';
        }
        // Everything else (innerHTML/outerHTML/srcdoc/setAttribute/document.write/
        // storage/network/navigation/prototype-pollution/...) is the token reaching a
        // sink as data. If that markup were actually executable in this browser, its
        // own onerror/onload/script would have fired the __XSS__(token) beacon and been
        // confirmed above. Reporting it here would be a false positive.
        return 'taint';
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
        let filename = 'unknown';
        let line = 0;
        let column = 0;

        // Parse from the final numeric line/column pair so URL schemes and
        // Windows paths do not collapse to an unknown location.
        const stackLocation = causalStackLocation(errorStack);
        filename = stackLocation.filename;
        line = stackLocation.line;
        column = stackLocation.column;

        const sinkInfo = {
            sink: sinkType,
            value: (value || '').substring(0, 500),
            filename: filename,
            line: line,
            column: column,
            stack: errorStack || ''
        };

        const classification = classifyExecution(sinkType, value, token);
        if (classification !== 'source') {
            recordCausalSink(
                sinkType,
                classification,
                value,
                filename,
                line,
                column,
                errorStack
            );
        }
        // Controlled lineage arms use an unregistered inert marker. Their only
        // output is the in-memory bounded ledger; never emit oracle network or
        // console-hit signals for these prioritization observations.
        if (lineageProbe) return;
        const serializedData = encodeURIComponent(JSON.stringify(sinkInfo));
        const url = `${oracleUrl}?token=${encodeURIComponent(token)}&msg=${encodeURIComponent('SINK HIT: ' + sinkType)}&sink=${encodeURIComponent(sinkType)}&kind=${encodeURIComponent(classification)}&data=${serializedData}`;

        const isHttpsPage = typeof location !== 'undefined' && location.protocol === 'https:';
        const isHttpOracle = oracleUrl.startsWith('http://');

        const transmitMethods = [
            () => {
                if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
                    navigator.sendBeacon(url);
                    return true;
                }
                throw new Error();
            },
            () => {
                if (typeof fetch !== 'undefined') {
                    fetch(url, { method: 'GET', mode: 'no-cors', credentials: 'omit' }).catch(() => {});
                    return true;
                }
                throw new Error();
            },
            () => {
                if (typeof XMLHttpRequest !== 'undefined') {
                    const xhr = new XMLHttpRequest();
                    xhr.open('GET', url, true);
                    xhr.send();
                    return true;
                }
                throw new Error();
            },
            () => {
                if (!isHttpsPage || !isHttpOracle) {
                    const img = new Image();
                    img.src = url;
                    return true;
                }
                throw new Error();
            }
        ];

        transmitMethods.forEach(method => {
            try {
                method();
            } catch (e) {}
        });

        if (sinkType.startsWith('DOMSourceRead:') || sinkType === 'postMessage.source') {
            console.log('XSS Oracle: Source read detected', { token: token, sinkInfo: sinkInfo });
        } else {
            const isExecutable = (classification === 'execution');
            if (isExecutable) {
                console.log('XSS Oracle: Execution detected', { token: token, sinkInfo: sinkInfo });
            } else {
                console.log('XSS Oracle: Taint reached sink', { token: token, sinkInfo: sinkInfo });
            }
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

    // Preserve causal context through common callback boundaries. Context is
    // short-lived, capped, and only labels co-occurrence; it never upgrades a
    // sink to confirmed execution.
    try {
        const originalThen = Promise.prototype.then;
        Promise.prototype.then = function(onFulfilled, onRejected) {
            const context = captureCausalContext();
            return originalThen.call(
                this,
                wrapCausalCallback(onFulfilled, context),
                wrapCausalCallback(onRejected, context)
            );
        };
        window.__registerOracleHook__(Promise.prototype.then, originalThen, 'then');

        if (Promise.prototype.catch) {
            const originalCatch = Promise.prototype.catch;
            Promise.prototype.catch = function(onRejected) {
                const context = captureCausalContext();
                return originalCatch.call(this, wrapCausalCallback(onRejected, context));
            };
            window.__registerOracleHook__(Promise.prototype.catch, originalCatch, 'catch');
        }

        if (Promise.prototype.finally) {
            const originalFinally = Promise.prototype.finally;
            Promise.prototype.finally = function(onFinally) {
                const context = captureCausalContext();
                return originalFinally.call(this, wrapCausalCallback(onFinally, context));
            };
            window.__registerOracleHook__(Promise.prototype.finally, originalFinally, 'finally');
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup Promise causal propagation', err);
    }

    try {
        const originalSetTimeout = window.setTimeout;
        window.setTimeout = function(callback, delay) {
            const context = captureCausalContext();
            const args = Array.prototype.slice.call(arguments, 2);
            return originalSetTimeout.apply(this, [wrapCausalCallback(callback, context), delay].concat(args));
        };
        window.__registerOracleHook__(window.setTimeout, originalSetTimeout, 'setTimeout');

        const originalSetInterval = window.setInterval;
        window.setInterval = function(callback, delay) {
            const context = captureCausalContext();
            const args = Array.prototype.slice.call(arguments, 2);
            return originalSetInterval.apply(this, [wrapCausalCallback(callback, context), delay].concat(args));
        };
        window.__registerOracleHook__(window.setInterval, originalSetInterval, 'setInterval');

        if (typeof window.queueMicrotask === 'function') {
            const originalQueueMicrotask = window.queueMicrotask;
            window.queueMicrotask = function(callback) {
                const context = captureCausalContext();
                return originalQueueMicrotask.call(this, wrapCausalCallback(callback, context));
            };
            window.__registerOracleHook__(window.queueMicrotask, originalQueueMicrotask, 'queueMicrotask');
        }

        if (typeof window.requestAnimationFrame === 'function') {
            const originalRequestAnimationFrame = window.requestAnimationFrame;
            window.requestAnimationFrame = function(callback) {
                const context = captureCausalContext();
                return originalRequestAnimationFrame.call(this, wrapCausalCallback(callback, context));
            };
            window.__registerOracleHook__(window.requestAnimationFrame, originalRequestAnimationFrame, 'requestAnimationFrame');
        }

        if (typeof window.requestIdleCallback === 'function') {
            const originalRequestIdleCallback = window.requestIdleCallback;
            window.requestIdleCallback = function(callback, options) {
                const context = captureCausalContext();
                return originalRequestIdleCallback.call(this, wrapCausalCallback(callback, context), options);
            };
            window.__registerOracleHook__(window.requestIdleCallback, originalRequestIdleCallback, 'requestIdleCallback');
        }
    } catch (err) {
        console.error('XSS Oracle: Failed to setup callback causal propagation', err);
    }

    // Observe explicit Object.defineProperty calls without predefining common
    // gadget names on Object.prototype. Predefining config/url/html changes named
    // property lookup and can suppress real DOM-clobbering vulnerabilities.
    try {
        // Next-Gen Telemetry: Hook Object.defineProperty/defineProperties to capture bypasses
        const originalDefineProperty = Object.defineProperty;
        Object.defineProperty = function(obj, prop, descriptor) {
            if ((obj === Object.prototype || obj === Array.prototype) && descriptor) {
                let val = descriptor.value;
                if (val && typeof val === 'string' && val.includes(token)) {
                    __XSS__('PrototypePollutionDefineProperty:' + prop, val, new Error().stack);
                }
            }
            return originalDefineProperty.call(Object, obj, prop, descriptor);
        };

        const originalDefineProperties = Object.defineProperties;
        Object.defineProperties = function(obj, properties) {
            if ((obj === Object.prototype || obj === Array.prototype) && properties) {
                for (let prop in properties) {
                    let descriptor = properties[prop];
                    if (descriptor) {
                        let val = descriptor.value;
                        if (val && typeof val === 'string' && val.includes(token)) {
                            __XSS__('PrototypePollutionDefineProperties:' + prop, val, new Error().stack);
                        }
                    }
                }
            }
            return originalDefineProperties.call(Object, obj, properties);
        };
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
                    const val = descriptor.get.call(this);
                    if (val && typeof val === 'string' && val.includes(token)) {
                        const stack = new Error().stack;
                        recordCausalSource(sourceName, stack, 'getter_read');
                        __XSS__('DOMSourceRead:' + sourceName, val, stack);
                    }
                    return val;
                },
                set: descriptor.set ? function(newVal) {
                    return descriptor.set.call(this, newVal);
                } : undefined,
                configurable: true,
                enumerable: descriptor.enumerable
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
        if (!fakeOrigin) return event;

        try {
            return new Proxy(event, {
                get: function(target, prop) {
                    if (prop === 'origin' && fakeOrigin) return fakeOrigin;
                    if (prop === 'data') {
                        // MessageEvent accessors require the real event as their
                        // receiver. A Proxy receiver throws "Illegal invocation"
                        // and prevents the application listener from running.
                        return Reflect.get(target, prop, target);
                    }
                    const value = Reflect.get(target, prop, target);
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
            const stack = new Error().stack;
            recordCausalSource('postMessage', stack, 'listener_delivery');
            __XSS__('postMessage.source', data, stack);
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
    
    // Hook Function and other native function constructors to detect obfuscated prototype-chain lookup executions
    const originalFunction = window.Function;
    function makeHookedConstructor(OriginalConstructor, name) {
        try {
            const Hooked = function(...args) {
                const code = args[args.length - 1];
                if (typeof code === 'string' && code.includes(token)) {
                    __XSS__(name, code, new Error().stack);
                }
                if (new.target) {
                    return Reflect.construct(OriginalConstructor, args, new.target);
                }
                return OriginalConstructor.apply(this, args);
            };
            Hooked.prototype = OriginalConstructor.prototype;
            Object.defineProperty(OriginalConstructor.prototype, 'constructor', {
                value: Hooked,
                writable: true,
                configurable: true
            });
            return Hooked;
        } catch (e) {
            return OriginalConstructor;
        }
    }

    try {
        window.Function = makeHookedConstructor(originalFunction, 'Function');
        window.__registerOracleHook__(window.Function, originalFunction, 'Function');
    } catch (e) {}

    try {
        const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
        makeHookedConstructor(AsyncFunction, 'AsyncFunction');
    } catch (e) {}

    try {
        const GeneratorFunction = Object.getPrototypeOf(function*(){}).constructor;
        makeHookedConstructor(GeneratorFunction, 'GeneratorFunction');
    } catch (e) {}

    try {
        const AsyncGeneratorFunction = Object.getPrototypeOf(async function*(){}).constructor;
        makeHookedConstructor(AsyncGeneratorFunction, 'AsyncGeneratorFunction');
    } catch (e) {}
    
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

    // Closed shadow roots keep native semantics. The browser-native DOMSnapshot
    // differential observes their flattened structure without changing mode.

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
//# sourceURL=xssboss_oracle_inject.js
