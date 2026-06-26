"""Fuzzing strategy definitions."""
from enum import Enum
from typing import Dict, Any, List


class Strategy(str, Enum):
    """Fuzzing strategy enum."""
    QUICK_LIGHT = "quick_light"
    UNICODE_HUNT = "unicode_hunt"
    JS_STRING_SPECIALIST = "js_string_specialist"
    CSP_AWARE = "csp_aware"
    MAX_COVERAGE = "max_coverage"
    GENETIC_EVOLUTIONARY = "genetic_evolutionary"


class StrategyProfile:
    """Strategy profile configuration."""
    
    PROFILES: Dict[Strategy, Dict[str, Any]] = {
        Strategy.QUICK_LIGHT: {
            'name': 'Quick & Light',
            'description': 'Fast fuzzing with minimal mutations',
            'max_payloads_per_context': 3,
            'mutation_probability': 0.2,
            'use_unicode': False,
            'use_encoding': False,
            'use_keyword_splitting': False,
            'preferred_contexts': ['HTML_TEXT', 'ATTR_QUOTED', 'EVENT_HANDLER_ATTR'],
            'mutation_strategy': 'default'
        },
        Strategy.UNICODE_HUNT: {
            'name': 'Unicode Hunt',
            'description': 'Aggressive Unicode-based bypass attempts',
            'max_payloads_per_context': 90,
            'mutation_probability': 0.8,
            'use_unicode': True,
            'use_encoding': True,
            'use_keyword_splitting': True,
            'preferred_contexts': ['HTML_TEXT', 'ATTR_QUOTED', 'ATTR_UNQUOTED'],
            'mutation_strategy': 'unicode_hunt'
        },
        Strategy.JS_STRING_SPECIALIST: {
            'name': 'JS String Specialist',
            'description': 'Focus on JavaScript string context bypasses',
            'max_payloads_per_context': 70,
            'mutation_probability': 0.5,
            'use_unicode': True,
            'use_encoding': True,
            'use_keyword_splitting': True,
            'preferred_contexts': ['JS_STRING_LITERAL', 'JS_IDENTIFIER', 'EVENT_HANDLER_ATTR'],
            'mutation_strategy': 'encoding_hunt'
        },
        Strategy.CSP_AWARE: {
            'name': 'CSP Aware',
            'description': 'Avoid <script> tags, use inline handlers and existing gadgets',
            'max_payloads_per_context': 55,
            'mutation_probability': 0.3,
            'use_unicode': False,
            'use_encoding': False,
            'use_keyword_splitting': False,
            'preferred_contexts': ['ATTR_QUOTED', 'ATTR_UNQUOTED', 'EVENT_HANDLER_ATTR'],
            'mutation_strategy': 'csp_aware'
        },
        Strategy.MAX_COVERAGE: {
            'name': 'Max Coverage Special',
            'description': 'Full scale auditing. Combines Unicode, encoding, and CSP bypass techniques.',
            'max_payloads_per_context': 1000,
            'mutation_probability': 0.9,
            'use_unicode': True,
            'use_encoding': True,
            'use_keyword_splitting': True,
            'preferred_contexts': ['HTML_TEXT', 'ATTR_QUOTED', 'ATTR_UNQUOTED', 'EVENT_HANDLER_ATTR', 'JS_STRING_LITERAL', 'JS_IDENTIFIER', 'URL_QUERY'],
            'mutation_strategy': 'max_coverage'
        },
        Strategy.GENETIC_EVOLUTIONARY: {
            'name': 'Genetic Evolutionary',
            'description': 'Evolutionary feedback-driven mutation engine targeting browser sinks',
            'max_payloads_per_context': 500,
            'mutation_probability': 0.6,
            'use_unicode': True,
            'use_encoding': True,
            'use_keyword_splitting': True,
            'preferred_contexts': ['HTML_TEXT', 'ATTR_QUOTED', 'ATTR_UNQUOTED', 'EVENT_HANDLER_ATTR', 'JS_STRING_LITERAL', 'JS_IDENTIFIER', 'URL_QUERY'],
            'mutation_strategy': 'genetic_evolutionary'
        }
    }
    
    @staticmethod
    def get_profile(strategy: Strategy) -> Dict[str, Any]:
        """Get strategy profile configuration.
        
        Args:
            strategy: Strategy enum
            
        Returns:
            Strategy profile dictionary
        """
        return StrategyProfile.PROFILES.get(strategy, StrategyProfile.PROFILES[Strategy.QUICK_LIGHT])
    
    @staticmethod
    def get_mutation_strategy(strategy: Strategy) -> str:
        """Get mutation strategy name for a fuzzing strategy.
        
        Args:
            strategy: Strategy enum
            
        Returns:
            Mutation strategy name
        """
        profile = StrategyProfile.get_profile(strategy)
        return profile.get('mutation_strategy', 'default')
    
    @staticmethod
    def should_use_payload(strategy: Strategy, context_type: str, payload: str) -> bool:
        """Check if payload should be used for given strategy and context.
        
        Args:
            strategy: Strategy enum
            context_type: Context type string
            payload: Payload string
            
        Returns:
            True if payload should be used
        """
        profile = StrategyProfile.get_profile(strategy)
        preferred = profile.get('preferred_contexts', [])
        
        # If context is preferred, use it
        if context_type in preferred:
            return True
        
        # CSP-aware: reject <script> tags
        if strategy == Strategy.CSP_AWARE and '<script' in payload.lower():
            return False
        
        # Default: use all payloads
        return True
