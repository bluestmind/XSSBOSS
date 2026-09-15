"""Program prioritization — rank the *best* synced programs to hunt.

Across hundreds of synced HackerOne programs, a solo hunter's time is the scarce resource, so this
ranks programs by expected value: does it pay cash, how much bounty-eligible web surface it exposes,
how high the severities go, and how much broad wildcard scope it opens. The dashboard uses this to
show programs best-first, each with a one-click "start find".

Pure scoring over ``Target.scope_tags`` (via :class:`ProgramScope`) — no network, fully testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend_api.services.program_scope import ProgramScope, ScopeAsset

_SEV_WEIGHT = {"critical": 8, "high": 4, "medium": 1, "low": 0, "none": 0, "": 0}
_SEV_ORDER = ["critical", "high", "medium", "low", "none"]


@dataclass
class ProgramRank:
    target_id: Optional[int]
    handle: str
    name: str
    priority_score: float
    offers_bounties: bool
    web_asset_count: int
    bounty_eligible_count: int
    wildcard_count: int
    top_severity: str
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "handle": self.handle,
            "name": self.name,
            "priority_score": round(self.priority_score, 1),
            "offers_bounties": self.offers_bounties,
            "web_asset_count": self.web_asset_count,
            "bounty_eligible_count": self.bounty_eligible_count,
            "wildcard_count": self.wildcard_count,
            "top_severity": self.top_severity,
            "reasons": self.reasons,
        }


class ProgramRanker:
    """Scores and orders programs by how worthwhile they are to hunt."""

    @staticmethod
    def _top_severity(assets: List[ScopeAsset]) -> str:
        best = "none"
        best_rank = -1
        for a in assets:
            r = _SEV_ORDER.index(a.max_severity.lower()) if a.max_severity.lower() in _SEV_ORDER else len(_SEV_ORDER)
            # lower index = more severe
            sev = a.max_severity.lower() if a.max_severity.lower() in _SEV_ORDER else "none"
            if _SEV_WEIGHT.get(sev, 0) > _SEV_WEIGHT.get(best, 0):
                best = sev
        return best

    @classmethod
    def score(cls, scope: ProgramScope, name: str = "", target_id: Optional[int] = None,
              submission_open: bool = True) -> ProgramRank:
        assets = scope.web_assets()
        bounty_eligible = [a for a in assets if a.eligible_for_bounty]
        wildcards = [a for a in assets if a.is_wildcard]
        reasons: List[str] = []

        score = 0.0
        if scope.offers_bounties:
            score += 50.0
            reasons.append("pays cash bounties (+50)")
        else:
            reasons.append("VDP — no bounty")

        surface = min(30.0, len(bounty_eligible) * 2.0)
        if surface:
            score += surface
            reasons.append(f"{len(bounty_eligible)} bounty-eligible web assets (+{surface:.0f})")

        sev_points = sum(_SEV_WEIGHT.get(a.max_severity.lower(), 0) for a in assets)
        sev_points = min(40.0, float(sev_points))
        if sev_points:
            score += sev_points
            reasons.append(f"high max-severity assets (+{sev_points:.0f})")

        if wildcards:
            wc = min(15.0, len(wildcards) * 3.0)
            score += wc
            reasons.append(f"{len(wildcards)} wildcard scopes — broad surface (+{wc:.0f})")

        if not submission_open:
            score *= 0.3
            reasons.append("submissions not open (×0.3)")

        return ProgramRank(
            target_id=target_id,
            handle=scope.handle,
            name=name or scope.handle,
            priority_score=score,
            offers_bounties=scope.offers_bounties,
            web_asset_count=len(assets),
            bounty_eligible_count=len(bounty_eligible),
            wildcard_count=len(wildcards),
            top_severity=cls._top_severity(assets),
            reasons=reasons,
        )

    @classmethod
    def rank_targets(cls, targets: List[Any]) -> List[ProgramRank]:
        ranks = []
        for t in targets:
            scope_tags = getattr(t, "scope_tags", None) or {}
            scope = ProgramScope.from_scope_tags(scope_tags)
            submission_open = str(scope_tags.get("submission_state", "open")).lower() == "open"
            ranks.append(cls.score(scope, name=getattr(t, "name", ""), target_id=getattr(t, "id", None),
                                   submission_open=submission_open))
        ranks.sort(key=lambda r: r.priority_score, reverse=True)
        return ranks

    @classmethod
    def rank_from_db(cls, db: Any, limit: int = 500, bounty_only: bool = False, query: Optional[str] = None) -> List[ProgramRank]:
        from backend_api.models.target import Target

        q = db.query(Target).filter(Target.bounty_platform == "hackerone")
        ranks = cls.rank_targets(q.all())
        if bounty_only:
            ranks = [r for r in ranks if r.offers_bounties]
        if query:
            q_clean = query.lower().strip()
            ranks = [r for r in ranks if q_clean in r.name.lower() or q_clean in r.handle.lower()]
        return ranks[:limit]
