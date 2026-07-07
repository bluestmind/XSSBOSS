"""Unit tests for EnhancedContextClassifier."""
import pytest
from backend_api.models.context import ContextType
from analysis_engine.enhanced_context_classifier import EnhancedContextClassifier, ClassifiedContext


def test_html_text_and_comment_classification():
    """Test standard HTML text and HTML comment classification."""
    marker = "CANARY_TEXT_99"
    html = f"<div>Hello <span>{marker}</span></div><!-- Some comment with {marker} -->"

    results = EnhancedContextClassifier.classify_all_reflections(html, marker)
    assert len(results) >= 2

    # Check text context
    text_ctx = next((c for c in results if c.context_type == ContextType.HTML_TEXT), None)
    assert text_ctx is not None
    assert text_ctx.tag in ["span", "div"]
    assert text_ctx.is_html_entity_decoded is True

    # Check comment context
    comment_ctx = next((c for c in results if c.context_type == ContextType.HTML_COMMENT), None)
    assert comment_ctx is not None
    assert comment_ctx.breakout_sequence == "-->"
    assert comment_ctx.requires_closing_tag is True


def test_rcdata_and_raw_text_classification():
    """Test RCDATA (<title>, <textarea>) and Raw Text (<xmp>, <style>) tags."""
    marker = "CANARY_RCDATA_1"
    html = f"<title>Search: {marker}</title><textarea>{marker}</textarea><style>body {{ font-family: '{marker}'; }}</style>"

    results = EnhancedContextClassifier.classify_all_reflections(html, marker)
    assert len(results) >= 3

    # Title & Textarea
    rcdata_ctxs = [c for c in results if c.context_type == ContextType.HTML_RCDATA]
    assert len(rcdata_ctxs) >= 2
    assert any(c.tag == "title" for c in rcdata_ctxs)
    assert any(c.tag == "textarea" for c in rcdata_ctxs)

    # Style block
    css_ctx = next((c for c in results if c.context_type == ContextType.CSS_STYLE_BLOCK), None)
    assert css_ctx is not None
    assert css_ctx.breakout_sequence == "</style>"


def test_attribute_classification_matrix():
    """Test double quoted, single quoted, unquoted, event handlers, and srcdoc attributes."""
    marker = "CANARY_ATTR_55"
    html = f"""
    <input type="text" name="user" value="{marker}">
    <a href='https://example.com/search?q={marker}'>Link</a>
    <div data-val={marker}>Unquoted</div>
    <button onclick="doAction('{marker}')">Click</button>
    <iframe srcdoc="<h1>Hello {marker}</h1>"></iframe>
    """

    results = EnhancedContextClassifier.classify_all_reflections(html, marker)
    assert len(results) >= 5

    # Double quoted attribute
    dq_ctx = next(c for c in results if c.attribute == "value")
    assert dq_ctx.context_type == ContextType.ATTR_QUOTED
    assert dq_ctx.quote_char == '"'

    # URL attribute
    href_ctx = next(c for c in results if c.attribute == "href")
    assert href_ctx.context_type == ContextType.URL_QUERY
    assert href_ctx.quote_char == "'"

    # Unquoted attribute
    unquoted_ctx = next(c for c in results if c.attribute == "data-val")
    assert unquoted_ctx.context_type == ContextType.ATTR_UNQUOTED
    assert unquoted_ctx.quote_char is None

    # Event handler attribute
    event_ctx = next(c for c in results if c.attribute == "onclick")
    assert event_ctx.context_type == ContextType.EVENT_HANDLER_ATTR
    assert event_ctx.is_js_executable is True

    # srcdoc double decoding attribute
    srcdoc_ctx = next(c for c in results if c.attribute == "srcdoc")
    assert srcdoc_ctx.context_type == ContextType.SRC_DOC_ATTR
    assert srcdoc_ctx.metadata.get("double_decoding") is True


def test_javascript_lexical_contexts():
    """Test JS string literals, template literals, comments, and JSON in script."""
    marker = "CANARY_JS_77"
    html = f"""
    <script>
        var str = "{marker}";
        var tpl = `User profile for ${{name}}: {marker}`;
        // Debug comment: {marker}
    </script>
    <script type="application/json" id="__NEXT_DATA__">
        {{"user": "{marker}"}}
    </script>
    """

    results = EnhancedContextClassifier.classify_all_reflections(html, marker)
    assert len(results) >= 3

    # Template literal
    tpl_ctx = next((c for c in results if c.context_type == ContextType.JS_TEMPLATE_LITERAL), None)
    assert tpl_ctx is not None
    assert tpl_ctx.quote_char == "`"
    assert tpl_ctx.breakout_sequence == "${"

    # JSON in script
    json_ctx = next((c for c in results if c.context_type == ContextType.JSON_IN_SCRIPT), None)
    assert json_ctx is not None
    assert json_ctx.breakout_sequence == "</script>"


def test_svg_and_csti_contexts():
    """Test SVG text namespace and CSTI {{marker}} delimiter reflection."""
    marker = "CANARY_SVG_12"
    html = f"""
    <svg><text>{marker}</text></svg>
    <div ng-app="myApp">Hello {{{{ {marker} }}}}</div>
    """

    results = EnhancedContextClassifier.classify_all_reflections(html, marker)
    assert len(results) >= 2

    # SVG text
    svg_ctx = next(c for c in results if c.context_type == ContextType.SVG_TEXT)
    assert svg_ctx.parent_namespace == "svg"

    # CSTI Angular
    csti_ctx = next(c for c in results if c.context_type == ContextType.CSTI_ANGULAR)
    assert csti_ctx.is_js_executable is True
