"""Contextual Thompson Sampling & Cross-Tenant WAF Bandit Memory.

Provides:
1. ThompsonSelector: Privacy-safe multi-tenant bandit memory keyed by (WAF, Framework, Context).
2. WAFBlockWeaponizer: Turns 403/429 block responses into active WAF fingerprinting and strategy re-targeting.
"""
import random
import re
from typing import Any, Dict, List, Optional, Tuple


class ThompsonSelector:
    """Contextual Thompson Sampling (Multi-Armed Bandit) selector to optimize mutation allocation."""

    # Shared class-level memory across scans and tenants (keyed on WAF/framework, zero target data)
    _GLOBAL_FINGERPRINT_MEMORY: Dict[str, Dict[str, Tuple[float, float]]] = {}

    def __init__(self, actions: List[str]):
        self.actions = actions
        # Store context-specific alphas and betas
        self.alphas: Dict[str, Dict[str, float]] = {}
        self.betas: Dict[str, Dict[str, float]] = {}
        self._ensure_context("global")

    @classmethod
    def make_fingerprint_key(
        cls,
        waf: Optional[str] = None,
        framework: Optional[str] = None,
        context: Optional[str] = None
    ) -> str:
        """Create a privacy-safe, cross-tenant fingerprint key without any tenant or domain info."""
        parts = []
        if waf:
            parts.append(f"waf:{waf.lower().strip()}")
        if framework:
            parts.append(f"fw:{framework.lower().strip()}")
        if context:
            parts.append(f"ctx:{context.strip()}")
        return "|".join(parts) if parts else "global"

    def _ensure_context(self, context: str):
        if context not in self.alphas:
            # Check if global cross-tenant memory has pre-trained weights for this fingerprint
            if context in self._GLOBAL_FINGERPRINT_MEMORY:
                mem = self._GLOBAL_FINGERPRINT_MEMORY[context]
                self.alphas[context] = {action: mem.get(action, (1.0, 1.0))[0] for action in self.actions}
                self.betas[context] = {action: mem.get(action, (1.0, 1.0))[1] for action in self.actions}
            else:
                self.alphas[context] = {action: 1.0 for action in self.actions}
                self.betas[context] = {action: 1.0 for action in self.actions}

    def select_action(self, context: str = "global") -> str:
        """Samples from Beta distributions and selects optimal mutation primitive."""
        self._ensure_context(context)
        
        best_action = self.actions[0]
        max_sample = -1.0
        
        for action in self.actions:
            alpha = max(1.0, self.alphas[context].get(action, 1.0))
            beta = max(1.0, self.betas[context].get(action, 1.0))
            sample = random.betavariate(alpha, beta)
            
            if sample > max_sample:
                max_sample = sample
                best_action = action
                
        return best_action

    def update(self, action: str, success: bool, context: str = "global"):
        """Updates posterior Beta distribution parameters for the context and persists to memory."""
        self._ensure_context(context)
        
        if action not in self.alphas[context]:
            return
            
        if success:
            self.alphas[context][action] += 1.0
        else:
            self.betas[context][action] += 1.0

        # Persist to global cross-tenant fingerprint memory
        if context not in self._GLOBAL_FINGERPRINT_MEMORY:
            self._GLOBAL_FINGERPRINT_MEMORY[context] = {}
        self._GLOBAL_FINGERPRINT_MEMORY[context][action] = (
            self.alphas[context][action],
            self.betas[context][action]
        )


class WAFBlockWeaponizer:
    """Analyzes 403/429/503 HTTP block responses to fingerprint WAFs and pivot mutation strategy."""

    WAF_SIGNATURES = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "expect-ct", "__cfduid"],
            "server": ["cloudflare"],
            "body": ["cloudflare ray id", "error 1020", "attention required! | cloudflare", "cf-browser-verification"],
            "recommended_evasion": "apply_comment_obfuscation"
        },
        "akamai": {
            "headers": ["x-akamai-transformed", "akamai-origin-hop", "x-akamai-session-info"],
            "server": ["akamaighost", "akamaiglobalhost"],
            "body": ["akamaighost", "the requested url was not recognized", "access denied"],
            "recommended_evasion": "apply_homoglyphs"
        },
        "aws_waf": {
            "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2"],
            "server": ["awselb", "amazon"],
            "body": ["request blocked by aws waf", "403 forbidden"],
            "recommended_evasion": "apply_alternative_whitespace"
        },
        "imperva": {
            "headers": ["x-iinfo", "x-cdn"],
            "server": ["imperva", "incapsula"],
            "body": ["incapsula incident id", "powered by incapsula"],
            "recommended_evasion": "apply_zero_width"
        },
        "sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "server": ["sucuri"],
            "body": ["access denied - sucuri website firewall"],
            "recommended_evasion": "apply_mixed_case"
        }
    }

    @classmethod
    def fingerprint_block(
        cls,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body: str = ""
    ) -> Optional[Dict[str, Any]]:
        """Identify WAF from HTTP block response and recommend optimal evasion strategy."""
        if status_code not in (403, 429, 406, 503):
            return None

        headers_lower = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
        body_lower = (body or "").lower()
        server_val = headers_lower.get("server", "")

        for waf_name, sig in cls.WAF_SIGNATURES.items():
            # Check headers
            if any(h in headers_lower for h in sig["headers"]):
                return {
                    "waf_detected": waf_name,
                    "matched_via": "header",
                    "recommended_evasion": sig["recommended_evasion"],
                    "bandit_context": f"waf:{waf_name}"
                }
            # Check server header
            if any(s in server_val for s in sig["server"]):
                return {
                    "waf_detected": waf_name,
                    "matched_via": "server_header",
                    "recommended_evasion": sig["recommended_evasion"],
                    "bandit_context": f"waf:{waf_name}"
                }
            # Check body text
            if any(b in body_lower for b in sig["body"]):
                return {
                    "waf_detected": waf_name,
                    "matched_via": "body_signature",
                    "recommended_evasion": sig["recommended_evasion"],
                    "bandit_context": f"waf:{waf_name}"
                }

        return {
            "waf_detected": "generic_waf",
            "matched_via": "status_code",
            "recommended_evasion": "apply_comment_obfuscation",
            "bandit_context": "waf:generic"
        }
