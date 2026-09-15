"""
Enhanced Reflection Context Classifier for XSS Boss.

Performs lexical and structural DOM/AST parsing to classify reflection contexts
across HTML5, SVG, MathML, JavaScript literals, template literals, JSON scripts,
and Client-Side Template Injection (CSTI) environments.
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from backend_api.models.context import ContextType
from backend_api.utils.logger import logger


@dataclass
class ClassifiedContext:
    """Detailed classification of a single reflection site."""
    context_type: ContextType
    tag: Optional[str] = None
    attribute: Optional[str] = None
    quote_char: Optional[str] = None
    parent_namespace: str = "html"  # html, svg, mathml
    snippet: str = ""
    breakout_sequence: str = ""
    is_html_entity_decoded: bool = False
    is_js_executable: bool = False
    requires_closing_tag: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


RCDATA_TAGS = {"title", "textarea"}
RAW_TEXT_TAGS = {"xmp", "iframe", "noembed", "noframes"}
URL_ATTRIBUTES = {"href", "src", "action", "formaction", "data", "poster", "codebase", "cite", "background", "ping"}
SVG_TAGS = {"svg", "path", "g", "text", "tspan", "circle", "rect", "use", "animate", "set"}
MATHML_TAGS = {"math", "mtext", "mn", "mo", "ms", "mspace", "mrow"}


class EnhancedContextClassifier:
    """State-of-the-art classifier for reflection and injection contexts."""

    @staticmethod
    def classify_all_reflections(html_content: str, marker: str) -> List[ClassifiedContext]:
        """
        Scan and classify all occurrences of a probe marker within an HTML document.
        """
        if not html_content or not marker or marker not in html_content:
            return []

        # Parse repeated reflections independently in source order. A DOM-wide
        # "attributes first, text second" traversal otherwise reports a later
        # attribute before an earlier text reflection and steers the fuzzer at
        # the wrong breakout grammar.
        positions = [match.start() for match in re.finditer(re.escape(marker), html_content)]
        if len(positions) > 1:
            masked_all = html_content.replace(marker, "_" * len(marker))
            ordered: List[ClassifiedContext] = []
            for position in positions:
                isolated = (
                    masked_all[:position]
                    + marker
                    + masked_all[position + len(marker):]
                )
                ordered.extend(EnhancedContextClassifier.classify_all_reflections(isolated, marker))
            return ordered

        results: List[ClassifiedContext] = []

        # 1. Check HTML Comments
        comment_contexts = EnhancedContextClassifier._detect_comment_reflections(html_content, marker)
        results.extend(comment_contexts)

        # 2. Parse with BeautifulSoup for DOM structure
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            dom_contexts = EnhancedContextClassifier._parse_soup_dom(soup, html_content, marker)
            results.extend(dom_contexts)
        except Exception as e:
            logger.debug(f"Soup DOM parsing fallback triggered: {e}")

        # 3. If DOM parsing missed reflections (e.g. malformed tags or raw regex), run lexical scanner
        if not results:
            fallback = EnhancedContextClassifier._lexical_fallback_scan(html_content, marker)
            results.extend(fallback)

        # 4. Check for Client-Side Template Injection delimiters ({{marker}})
        csti_contexts = EnhancedContextClassifier._detect_csti_reflections(html_content, marker)
        # Framework/template execution is more specific than the underlying
        # HTML text/attribute container, so it must be considered first.
        results = [*csti_contexts, *results]

        # Deduplicate results by (context_type, tag, attribute, quote_char)
        seen = set()
        deduped = []
        for c in results:
            key = (c.context_type.value, c.tag, c.attribute, c.quote_char, c.snippet[:60])
            if key not in seen:
                seen.add(key)
                deduped.append(c)

        return deduped

    @staticmethod
    def _parse_soup_dom(soup: BeautifulSoup, raw_html: str, marker: str) -> List[ClassifiedContext]:
        """Parse structured DOM tree for marker reflections."""
        contexts = []

        # A. Traverse all tags and check attributes
        for tag in soup.find_all(True):
            tag_name = tag.name.lower()
            namespace = EnhancedContextClassifier._get_namespace(tag)

            # Check tag attributes
            for attr_name, attr_val in list(tag.attrs.items()):
                val_str = " ".join(attr_val) if isinstance(attr_val, list) else str(attr_val)
                if marker in val_str:
                    attr_ctx = EnhancedContextClassifier._classify_attribute(tag_name, attr_name, val_str, raw_html, marker, namespace)
                    if attr_ctx:
                        contexts.append(attr_ctx)

            # Check special tag content (script, style, rcdata, raw text)
            if tag_name in RCDATA_TAGS and tag.string and marker in tag.string:
                snippet = EnhancedContextClassifier._extract_snippet(raw_html, marker)
                contexts.append(
                    ClassifiedContext(
                        context_type=ContextType.HTML_RCDATA,
                        tag=tag_name,
                        snippet=snippet,
                        breakout_sequence=f"</{tag_name}>",
                        is_html_entity_decoded=True,
                        requires_closing_tag=True,
                    )
                )

            elif tag_name in RAW_TEXT_TAGS and tag.string and marker in tag.string:
                snippet = EnhancedContextClassifier._extract_snippet(raw_html, marker)
                contexts.append(
                    ClassifiedContext(
                        context_type=ContextType.HTML_RAW_TEXT,
                        tag=tag_name,
                        snippet=snippet,
                        breakout_sequence=f"</{tag_name}>",
                        requires_closing_tag=True,
                    )
                )

            elif tag_name == "noscript" and marker in str(tag):
                snippet = EnhancedContextClassifier._extract_snippet(raw_html, marker)
                contexts.append(
                    ClassifiedContext(
                        context_type=ContextType.HTML_NOSCRIPT,
                        tag="noscript",
                        snippet=snippet,
                        breakout_sequence="</noscript>",
                        requires_closing_tag=True,
                    )
                )

            elif tag_name == "style" and tag.string and marker in tag.string:
                snippet = EnhancedContextClassifier._extract_snippet(raw_html, marker)
                contexts.append(
                    ClassifiedContext(
                        context_type=ContextType.CSS_STYLE_BLOCK,
                        tag="style",
                        snippet=snippet,
                        breakout_sequence="</style>",
                        requires_closing_tag=True,
                    )
                )

            elif tag_name == "script" and tag.string and marker in tag.string:
                script_type = (tag.get("type") or "").lower().strip()
                if "json" in script_type:
                    snippet = EnhancedContextClassifier._extract_snippet(raw_html, marker)
                    contexts.append(
                        ClassifiedContext(
                            context_type=ContextType.JSON_IN_SCRIPT,
                            tag="script",
                            snippet=snippet,
                            breakout_sequence="</script>",
                            requires_closing_tag=True,
                            metadata={"script_type": script_type},
                        )
                    )
                else:
                    # Deep JavaScript lexical classification
                    js_contexts = EnhancedContextClassifier._classify_js_content(tag.string, marker, namespace)
                    contexts.extend(js_contexts)

        # B. Check HTML Text nodes
        for text_node in soup.find_all(string=True):
            if isinstance(text_node, Comment):
                continue
            if marker in str(text_node):
                parent = text_node.parent
                parent_tag = parent.name.lower() if parent else "body"
                if parent_tag in (RCDATA_TAGS | RAW_TEXT_TAGS | {"script", "style", "noscript"}):
                    continue  # Handled above

                namespace = EnhancedContextClassifier._get_namespace(parent)
                snippet = EnhancedContextClassifier._extract_snippet(raw_html, marker)

                if namespace == "svg":
                    if parent_tag == "foreignobject":
                        ctx_type = ContextType.FOREIGN_OBJECT
                    else:
                        ctx_type = ContextType.SVG_TEXT
                elif namespace == "mathml":
                    if parent_tag == "annotation-xml":
                        ctx_type = ContextType.ANNOTATION_XML
                    else:
                        ctx_type = ContextType.MATHML_TEXT
                else:
                    ctx_type = ContextType.HTML_TEXT

                contexts.append(
                    ClassifiedContext(
                        context_type=ctx_type,
                        tag=parent_tag,
                        parent_namespace=namespace,
                        snippet=snippet,
                        is_html_entity_decoded=True,
                    )
                )

        return contexts

    @staticmethod
    def _classify_attribute(
        tag: str,
        attr: str,
        val: str,
        raw_html: str,
        marker: str,
        namespace: str
    ) -> Optional[ClassifiedContext]:
        """Classify an attribute reflection site."""
        attr_lower = attr.lower()
        quote_char = EnhancedContextClassifier._detect_attribute_quote(raw_html, attr, marker)
        snippet = EnhancedContextClassifier._extract_snippet(raw_html, marker)

        # 1. srcdoc double-decoding context
        if tag == "iframe" and attr_lower == "srcdoc":
            return ClassifiedContext(
                context_type=ContextType.SRC_DOC_ATTR,
                tag=tag,
                attribute=attr,
                quote_char=quote_char,
                snippet=snippet,
                breakout_sequence=f"{quote_char}>" if quote_char else " >",
                is_html_entity_decoded=True,
                metadata={"double_decoding": True},
            )

        # 2. Inline Event Handler (onclick, onload, etc.)
        if attr_lower.startswith("on") or attr_lower in {"behavior", "dynsrc"}:
            return ClassifiedContext(
                context_type=ContextType.EVENT_HANDLER_ATTR,
                tag=tag,
                attribute=attr,
                quote_char=quote_char,
                snippet=snippet,
                breakout_sequence=f"{quote_char}>" if quote_char else " >",
                is_html_entity_decoded=True,
                is_js_executable=True,
            )

        # Vue template directives are executable framework contexts, not
        # ordinary quoted attributes.
        if attr_lower in {"v-html", "v-text"} or attr_lower.startswith("v-bind:"):
            return ClassifiedContext(
                context_type=ContextType.CSTI_VUE,
                tag=tag,
                attribute=attr,
                quote_char=quote_char,
                snippet=snippet,
                breakout_sequence=f"{quote_char}>" if quote_char else " >",
                is_html_entity_decoded=True,
                is_js_executable=attr_lower == "v-html",
                metadata={"directive": attr_lower},
            )

        # 3. URL Attributes (href, src, action, formaction)
        if attr_lower in URL_ATTRIBUTES and "#" in val and val.find("#") < val.find(marker):
            return ClassifiedContext(
                context_type=ContextType.URL_FRAGMENT,
                tag=tag,
                attribute=attr,
                quote_char=quote_char,
                snippet=snippet,
                breakout_sequence=f"{quote_char}>" if quote_char else " >",
                is_html_entity_decoded=True,
                metadata={"supports_javascript_pseudourl": True},
            )

        if attr_lower in URL_ATTRIBUTES and "?" in val and val.find("?") < val.find(marker):
            return ClassifiedContext(
                context_type=ContextType.URL_QUERY,
                tag=tag,
                attribute=attr,
                quote_char=quote_char,
                snippet=snippet,
                breakout_sequence=f"{quote_char}>" if quote_char else " >",
                is_html_entity_decoded=True,
                metadata={"supports_javascript_pseudourl": True},
            )

        # 4. Inline CSS (style="...")
        if attr_lower == "style":
            return ClassifiedContext(
                context_type=ContextType.CSS_INLINE_STYLE,
                tag=tag,
                attribute=attr,
                quote_char=quote_char,
                snippet=snippet,
                breakout_sequence=f"{quote_char}>" if quote_char else " >",
                is_html_entity_decoded=True,
            )

        # 5. Standard Quoted / Unquoted Attribute
        if quote_char:
            return ClassifiedContext(
                context_type=ContextType.ATTR_QUOTED,
                tag=tag,
                attribute=attr,
                quote_char=quote_char,
                snippet=snippet,
                breakout_sequence=f"{quote_char}>",
                is_html_entity_decoded=True,
            )
        else:
            return ClassifiedContext(
                context_type=ContextType.ATTR_UNQUOTED,
                tag=tag,
                attribute=attr,
                quote_char=None,
                snippet=snippet,
                breakout_sequence=" >",
                is_html_entity_decoded=True,
            )

    @staticmethod
    def _classify_js_content(script_text: str, marker: str, namespace: str = "html") -> List[ClassifiedContext]:
        """Lexically parse JavaScript inside <script> tags for all marker occurrences."""
        contexts = []
        for m in re.finditer(re.escape(marker), script_text):
            pos = m.start()

            # Find enclosing line / tokens
            line_start = script_text.rfind("\n", 0, pos)
            line_start = 0 if line_start == -1 else line_start + 1
            line_end = script_text.find("\n", pos)
            line_end = len(script_text) if line_end == -1 else line_end
            line_snippet = script_text[line_start:line_end].strip()

            prefix_line = script_text[line_start:pos]
            prefix = script_text[:pos]

            # 1. Check for single-line or multi-line comment
            if "//" in prefix_line or ("/*" in prefix and "*/" not in prefix[prefix.rfind("/*"):]):
                contexts.append(
                    ClassifiedContext(
                        context_type=ContextType.JS_COMMENT,
                        tag="script",
                        snippet=line_snippet,
                        breakout_sequence="\n",
                        is_js_executable=False,
                        requires_closing_tag=True,
                    )
                )
                continue

            # 2. Check for template literal (backtick)
            backtick_count = prefix.count("`")
            if backtick_count % 2 == 1:
                contexts.append(
                    ClassifiedContext(
                        context_type=ContextType.JS_TEMPLATE_LITERAL,
                        tag="script",
                        quote_char="`",
                        snippet=line_snippet,
                        breakout_sequence="${",
                        is_js_executable=True,
                        requires_closing_tag=True,
                    )
                )
                continue

            # 3. Check for double/single quoted string literal
            quote = None
            for char in reversed(prefix_line):
                if char in ('"', "'"):
                    quote = char
                    break

            if quote:
                contexts.append(
                    ClassifiedContext(
                        context_type=ContextType.JS_STRING_LITERAL,
                        tag="script",
                        quote_char=quote,
                        snippet=line_snippet,
                        breakout_sequence=f"{quote};",
                        is_js_executable=True,
                        requires_closing_tag=True,
                    )
                )
            else:
                ctx_t = ContextType.SVG_SCRIPT if namespace == "svg" else ContextType.JS_IDENTIFIER
                contexts.append(
                    ClassifiedContext(
                        context_type=ctx_t,
                        tag="script",
                        snippet=line_snippet,
                        breakout_sequence=";",
                        is_js_executable=True,
                        requires_closing_tag=True,
                    )
                )

        return contexts

    @staticmethod
    def _detect_comment_reflections(html_content: str, marker: str) -> List[ClassifiedContext]:
        """Detect reflections inside HTML comments <!-- ... -->."""
        contexts = []
        comment_matches = re.finditer(r'<!--(.*?)-->', html_content, re.DOTALL)
        for cm in comment_matches:
            if marker in cm.group(1):
                snippet = cm.group(0)[:200]
                contexts.append(
                    ClassifiedContext(
                        context_type=ContextType.HTML_COMMENT,
                        snippet=snippet,
                        breakout_sequence="-->",
                        requires_closing_tag=True,
                    )
                )
        return contexts

    @staticmethod
    def _detect_csti_reflections(html_content: str, marker: str) -> List[ClassifiedContext]:
        """Detect expressions matching Client-Side Template Injection delimiters."""
        contexts = []
        # Pattern: {{...marker...}}
        csti_matches = re.finditer(r'\{\{([^}]*' + re.escape(marker) + r'[^}]*)\}\}', html_content)
        for cm in csti_matches:
            snippet = cm.group(0)
            expression = cm.group(1)
            lower_html = html_content.lower()
            contains_rendered_markup = "<" in expression or ">" in expression
            # Require executable framework signatures. A literal {{...}} in a
            # <pre>, chat message, or Ember-rendered note is only text and must
            # never be promoted to a JavaScript execution context by itself.
            angular_signature = bool(
                re.search(r'\bng-(?:app|controller|bind|init)\b', lower_html)
                or re.search(r'\bangular\s*\.\s*(?:module|bootstrap)\s*\(', lower_html)
            )
            vue_signature = bool(
                re.search(r'\bv-(?:html|text|bind|model|if|for)\b', lower_html)
                or re.search(r'\b(?:new\s+vue|vue\s*\.\s*createapp)\s*\(', lower_html)
            )
            if angular_signature:
                ctx_type = ContextType.CSTI_ANGULAR
            elif vue_signature:
                ctx_type = ContextType.CSTI_VUE
            else:
                ctx_type = ContextType.CSTI_GENERIC

            executable = (
                ctx_type in {ContextType.CSTI_ANGULAR, ContextType.CSTI_VUE}
                and not contains_rendered_markup
            )

            contexts.append(
                ClassifiedContext(
                    context_type=ctx_type,
                    snippet=snippet,
                    is_js_executable=executable,
                    metadata={
                        "delimiter": "{{...}}",
                        "framework_signature": ctx_type.value if executable else None,
                        "confidence": "firm" if executable else "tentative",
                        "requires_runtime_compiler": True,
                    },
                )
            )
        return contexts

    @staticmethod
    def _detect_attribute_quote(raw_html: str, attr_name: str, marker: str) -> Optional[str]:
        """Determine whether attribute value is enclosed in \", \', or unquoted."""
        # Pattern: attr="...marker..."
        dq_match = re.search(r'\b' + re.escape(attr_name) + r'\s*=\s*"[^"]*' + re.escape(marker), raw_html)
        if dq_match:
            return '"'
        sq_match = re.search(r'\b' + re.escape(attr_name) + r'\s*=\s*\'[^\']*' + re.escape(marker), raw_html)
        if sq_match:
            return "'"
        return None

    @staticmethod
    def _get_namespace(tag: Optional[Tag]) -> str:
        """Determine whether DOM node resides within SVG or MathML namespace."""
        if not tag:
            return "html"
        curr = tag
        first = tag
        while curr and hasattr(curr, "name"):
            name = (curr.name or "").lower()
            # HTML integration point: descendants of SVG foreignObject are
            # parsed in the HTML namespace, while the foreignObject element
            # itself remains part of SVG.
            if name == "foreignobject" and curr is not first:
                return "html"
            if name == "svg":
                return "svg"
            if name == "math":
                return "mathml"
            curr = curr.parent
        return "html"

    @staticmethod
    def _extract_snippet(html_text: str, marker: str, window: int = 80) -> str:
        """Extract a clean snippet surrounding the marker reflection."""
        pos = html_text.find(marker)
        if pos == -1:
            return ""
        start = max(0, pos - window)
        end = min(len(html_text), pos + len(marker) + window)
        return html_text[start:end].replace("\n", " ").strip()

    @staticmethod
    def _lexical_fallback_scan(html_content: str, marker: str) -> List[ClassifiedContext]:
        """Regex fallback for raw reflection classification when DOM parse is incomplete."""
        contexts = []
        snippet = EnhancedContextClassifier._extract_snippet(html_content, marker)
        contexts.append(
            ClassifiedContext(
                context_type=ContextType.HTML_TEXT,
                snippet=snippet,
                is_html_entity_decoded=True,
            )
        )
        return contexts
