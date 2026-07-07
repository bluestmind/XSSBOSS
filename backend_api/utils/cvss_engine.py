"""Official CVSS v3.1 Calculation Engine & Vector Generator.

Complies strictly with the FIRST.org Common Vulnerability Scoring System v3.1 specification.
"""
import math
from typing import Dict, Any, Optional, Tuple


class CVSSEngine:
    """Calculates official CVSS 3.1 base score, severity rating, and vector strings."""

    # CVSS 3.1 Metric Constants
    AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_VALUES = {"L": 0.77, "H": 0.44}
    
    # Privileges Required depends on Scope
    PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    
    UI_VALUES = {"N": 0.85, "R": 0.62}
    
    CIA_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}

    @staticmethod
    def roundup(val: float) -> float:
        """Official CVSS v3.1 RoundUp function to 1 decimal place."""
        val_rounded = round(val * 100000)
        if val_rounded % 10000 == 0:
            return val_rounded / 100000.0
        else:
            return (math.floor(val_rounded / 10000) + 1) / 10.0

    @classmethod
    def calculate_from_metrics(
        cls,
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "R",
        scope: str = "U",
        c: str = "H",
        i: str = "H",
        a: str = "N"
    ) -> Tuple[float, str, str]:
        """Calculate CVSS 3.1 Base Score, Severity, and Vector String."""
        av = av.upper()
        ac = ac.upper()
        pr = pr.upper()
        ui = ui.upper()
        scope = scope.upper()
        c = c.upper()
        i = i.upper()
        a = a.upper()

        # Build Vector String
        vector_str = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"

        # 1. Exploitability Subscore
        pr_val = cls.PR_CHANGED.get(pr, 0.85) if scope == "C" else cls.PR_UNCHANGED.get(pr, 0.85)
        av_val = cls.AV_VALUES.get(av, 0.85)
        ac_val = cls.AC_VALUES.get(ac, 0.77)
        ui_val = cls.UI_VALUES.get(ui, 0.62)
        
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # 2. Impact Subscore
        c_val = cls.CIA_VALUES.get(c, 0.0)
        i_val = cls.CIA_VALUES.get(i, 0.0)
        a_val = cls.CIA_VALUES.get(a, 0.0)

        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        if iss <= 0.0:
            base_score = 0.0
        else:
            if scope == "U":
                impact = 6.42 * iss
                base_score = cls.roundup(min(impact + exploitability, 10.0))
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
                base_score = cls.roundup(min(1.08 * (impact + exploitability), 10.0))

        severity = cls.get_severity_rating(base_score)
        return base_score, severity, vector_str

    @classmethod
    def calculate_from_vector(cls, vector_str: str) -> Tuple[float, str, str]:
        """Parse vector string and calculate CVSS 3.1 score."""
        metrics = {}
        parts = vector_str.strip().split("/")
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k.upper()] = v.upper()

        return cls.calculate_from_metrics(
            av=metrics.get("AV", "N"),
            ac=metrics.get("AC", "L"),
            pr=metrics.get("PR", "N"),
            ui=metrics.get("UI", "R"),
            scope=metrics.get("S", "U"),
            c=metrics.get("C", "L"),
            i=metrics.get("I", "L"),
            a=metrics.get("A", "N")
        )

    @classmethod
    def score_xss_finding(
        cls,
        is_stored: bool = False,
        is_authenticated: bool = False,
        is_cross_role: bool = False,
        can_hijack_session: bool = True,
        can_modify_state: bool = True,
        scope_changed: bool = False
    ) -> Dict[str, Any]:
        """Automatically score an XSS finding based on confirmed exploitation evidence."""
        av = "N"  # Network
        ac = "L"  # Low complexity
        pr = "L" if is_authenticated else "N"  # None unless attacker requires account
        ui = "N" if (is_stored and is_cross_role) else "R"  # User interaction required for reflected/DOM
        scope = "C" if scope_changed else "U"

        # Impact evaluation
        c = "H" if can_hijack_session else "L"
        i = "H" if can_modify_state else "L"
        a = "N"

        score, severity, vector = cls.calculate_from_metrics(
            av=av, ac=ac, pr=pr, ui=ui, scope=scope, c=c, i=i, a=a
        )

        return {
            "score": score,
            "severity": severity,
            "vector": vector,
            "metrics": {
                "AV": av, "AC": ac, "PR": pr, "UI": ui,
                "S": scope, "C": c, "I": i, "A": a
            }
        }

    @staticmethod
    def get_severity_rating(score: float) -> str:
        """Map score to official CVSS 3.1 qualitative severity rating."""
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"
        return "Unknown"
