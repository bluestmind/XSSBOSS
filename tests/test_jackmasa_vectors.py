"""
Unit tests verifying the integration of Jack Masa mind map vector taxonomy
into PayloadKnowledgeBase and MutationEngine.
"""
import pytest
from fuzzer.payload_knowledge_base import (
    PayloadKnowledgeBase,
    XSSCategory,
    InjectionContext,
)
from fuzzer.mutation_engine import MutationEngine


def test_jackmasa_knowledge_base_entries():
    """Verify all 10 Jack Masa mind map entries are properly registered and queryable."""
    entries = {p.id: p for p in PayloadKnowledgeBase.get_all_payloads()}
    
    # 1. Unicode line terminator comment breakouts
    assert "comment_breakout_unicode_line_separator_2028" in entries
    p_2028 = entries["comment_breakout_unicode_line_separator_2028"]
    assert "\u2028" in p_2028.template
    assert p_2028.category == XSSCategory.CHAR_RESTRICTED

    assert "comment_breakout_unicode_para_separator_2029" in entries
    p_2029 = entries["comment_breakout_unicode_para_separator_2029"]
    assert "\u2029" in p_2029.template

    # 2. Multi-byte GBK backslash eating
    assert "multibyte_gbk_quote_eating_escape" in entries
    p_gbk = entries["multibyte_gbk_quote_eating_escape"]
    assert "%bb\"" in p_gbk.template
    assert p_gbk.category == XSSCategory.WAF_EVASION

    # 3. Attribute inline event entity resolution
    assert "attr_inline_event_named_entity_breakout" in entries
    p_named = entries["attr_inline_event_named_entity_breakout"]
    assert "&quot;" in p_named.template

    assert "attr_inline_event_numeric_entity_breakout" in entries
    p_num = entries["attr_inline_event_numeric_entity_breakout"]
    assert "&#34;" in p_num.template

    # 4. XML / SVG / MathML xlink sinks
    assert "xml_svg_xlink_href_script_data_uri" in entries
    p_svg_xlink = entries["xml_svg_xlink_href_script_data_uri"]
    assert "xlink:href" in p_svg_xlink.template
    assert InjectionContext.SVG_NAMESPACE in p_svg_xlink.contexts

    assert "xml_mathml_xlink_href_javascript_uri" in entries
    p_math = entries["xml_mathml_xlink_href_javascript_uri"]
    assert "xlink:href" in p_math.template
    assert InjectionContext.MATHML_NAMESPACE in p_math.contexts

    # 5. SVG Style block font-family mXSS
    assert "xml_svg_style_font_family_mutation" in entries
    p_font = entries["xml_svg_style_font_family_mutation"]
    assert "font-family" in p_font.template

    # 6. DOM Clobbering window.name
    assert "dom_clobbering_form_window_name" in entries
    p_clobber = entries["dom_clobbering_form_window_name"]
    assert "id=\"window\"" in p_clobber.template

    # 7. Non-standard whitespace / token delimiter
    assert "html_token_delimiter_formfeed_vertical_tab" in entries
    p_delim = entries["html_token_delimiter_formfeed_vertical_tab"]
    assert "\x0c" in p_delim.template


def test_jackmasa_rendering_with_oracle_tokens():
    """Verify templates correctly substitute the deterministic oracle token."""
    token = "CANARY_JACKMASA_777"
    
    # Render line separator breakout
    rendered_2028 = PayloadKnowledgeBase.render_payload("comment_breakout_unicode_line_separator_2028", token)
    assert token in rendered_2028
    assert "{{TOKEN}}" not in rendered_2028
    assert "\u2028" in rendered_2028

    # Render GBK escape
    rendered_gbk = PayloadKnowledgeBase.render_payload("multibyte_gbk_quote_eating_escape", token)
    assert token in rendered_gbk
    assert "%bb\"" in rendered_gbk

    # Render SVG xlink
    rendered_xlink = PayloadKnowledgeBase.render_payload("xml_svg_xlink_href_script_data_uri", token)
    assert token in rendered_xlink
    assert "xlink:href=\"data:," in rendered_xlink


def test_jackmasa_mutation_engine_operators():
    """Verify all newly integrated mutation operators generate valid variants."""
    base_payload = "<script>__XSS__('CANARY_OP_123')</script>"
    
    # 1. Unicode line separators
    line_sep_vars = MutationEngine.apply_unicode_line_separator_breakout(base_payload)
    assert len(line_sep_vars) == 4
    assert any("\u2028" in v for v in line_sep_vars)
    assert any("\u2029" in v for v in line_sep_vars)
    assert all("CANARY_OP_123" in v for v in line_sep_vars)

    # 2. Multi-byte GBK backslash escape
    gbk_vars = MutationEngine.apply_multibyte_gbk_backslash_escape(base_payload)
    assert len(gbk_vars) == 4
    assert any("%bb\"" in v for v in gbk_vars)
    assert any("%81\"" in v for v in gbk_vars)

    # 3. Attribute inline entity encoding
    entity_vars = MutationEngine.apply_attribute_inline_entity_encoding(base_payload)
    assert len(entity_vars) == 6
    assert any("&quot;" in v for v in entity_vars)
    assert any("&#34;" in v for v in entity_vars)
    assert any("&#x22;" in v for v in entity_vars)

    # 4. Non-standard whitespace delimiters
    delim_vars = MutationEngine.apply_nonstandard_whitespace_delimiters(base_payload)
    assert len(delim_vars) == 5
    assert any("\x0c" in v for v in delim_vars)
    assert any("\x0b" in v for v in delim_vars)
    assert any("\x09" in v for v in delim_vars)

    # 5. XML xlink namespace sinks
    xlink_vars = MutationEngine.apply_xml_xlink_namespace_sinks(base_payload)
    assert len(xlink_vars) == 4
    assert any("xlink:href" in v for v in xlink_vars)
    assert any("font-family" in v for v in xlink_vars)

    # 6. Form window clobbering
    clobber_vars = MutationEngine.apply_form_window_clobbering(base_payload)
    assert len(clobber_vars) == 3
    assert any("id=\"window\"" in v for v in clobber_vars)
