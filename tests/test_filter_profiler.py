"""Unit tests for FilterProfiler."""
import pytest
from analysis_engine.filter_profiler import FilterProfiler, FilterProfile, CharacterState


def test_character_reflection_analysis():
    """Test analyzing individual character reflection states."""
    # 1. Allowed raw
    resp_raw = "<div>Hello xB0ss<Zz9 world</div>"
    assert FilterProfiler.analyze_reflection(resp_raw, "<", "xB0ss") == CharacterState.ALLOWED_RAW

    # 2. HTML entity encoded
    resp_encoded = "<div>Hello xB0ss&lt;Zz9 world</div>"
    assert FilterProfiler.analyze_reflection(resp_encoded, "<", "xB0ss") == CharacterState.HTML_ENTITY_ENCODED

    # 3. Backslash escaped
    resp_escaped = 'var x = "xB0ss\\"Zz9";'
    assert FilterProfiler.analyze_reflection(resp_escaped, '"', "xB0ss") == CharacterState.BACKSLASH_ESCAPED

    # 4. Stripped
    resp_stripped = "<div>Hello xB0ssZz9 world</div>"
    assert FilterProfiler.analyze_reflection(resp_stripped, "<", "xB0ss") == CharacterState.STRIPPED


def test_profile_matrix_construction_and_evasions():
    """Test building a structured FilterProfile with evasion recommendations."""
    matrix = {
        "<": CharacterState.HTML_ENTITY_ENCODED,
        ">": CharacterState.HTML_ENTITY_ENCODED,
        '"': CharacterState.BACKSLASH_ESCAPED,
        "'": CharacterState.BACKSLASH_ESCAPED,
        "(": CharacterState.STRIPPED,
        ")": CharacterState.STRIPPED,
        "`": CharacterState.ALLOWED_RAW,
        "/": CharacterState.ALLOWED_RAW,
        ";": CharacterState.ALLOWED_RAW,
    }

    profile = FilterProfiler.build_profile_from_matrix(matrix)

    assert profile.quotes_escaped is True
    assert profile.angle_brackets_encoded is True
    assert profile.parentheses_allowed is False
    assert profile.backticks_allowed is True

    # Check evasion recommendations
    assert "parentheseless_throw_onerror" in profile.recommended_evasions
    assert "backtick_template_literals" in profile.recommended_evasions
    assert "tagged_template_literals" in profile.recommended_evasions
