"""Program-run orchestrator — "give it a program, walk away".

Consumes a :class:`ProgramScope` worklist and hunts a whole bug-bounty program asset-by-asset in
priority order (bounty-eligible + highest max-severity first), under a global request budget, with
per-asset isolation so one bad asset never sinks the run. This is the control loop that turns the
scope/prioritization/Burp foundation into an autonomous program hunt.

The core :meth:`run` takes an injected ``hunt_asset_fn`` (recon+fuzz for one asset), so the loop is
fully testable without network or a browser; the CLI binds it to the real crawl→experiment path.
Budget discipline is first-class: the scanner's hard request cap is the true bottleneck, so the
orchestrator spends it on the highest-value assets first and stops cleanly when exhausted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from backend_api.services.program_scope import ProgramScope, ScopeAsset

# hunt_asset_fn(asset, request_cap) -> dict with keys: endpoints, findings, requests_used
HuntAssetFn = Callable[[ScopeAsset, int], Dict[str, Any]]


@dataclass
class RunBudget:
    max_assets: int = 25
    # Logical active-request allocations: an asynchronous experiment reserves
    # its cap until it reaches a terminal state, preventing cross-asset overspend.
    # Recon page limits are tracked separately by their own stage counters.
    max_requests_total: int = 1500
    per_asset_request_cap: int = 300
    stop_after_findings: Optional[int] = None  # early-exit once N confirmed findings land


@dataclass
class AssetOutcome:
    host: str
    status: str = "pending"    # completed | failed | budget_exhausted | planned
    endpoints: int = 0
    findings: int = 0
    requests_used: int = 0
    eligible_for_bounty: bool = False
    max_severity: str = ""
    error: str = ""
    identifier: str = ""
    source_identifier: str = ""
    seed_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host, "status": self.status, "endpoints": self.endpoints,
            "findings": self.findings, "requests_used": self.requests_used,
            "eligible_for_bounty": self.eligible_for_bounty, "max_severity": self.max_severity,
            "error": self.error, "identifier": self.identifier,
            "source_identifier": self.source_identifier, "seed_url": self.seed_url,
        }


@dataclass
class ProgramRunReport:
    handle: str = ""
    outcomes: List[AssetOutcome] = field(default_factory=list)
    total_findings: int = 0
    total_requests: int = 0
    assets_run: int = 0
    assets_skipped: int = 0
    stopped_reason: str = "completed"
    unresolved_scope_rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handle": self.handle,
            "total_findings": self.total_findings,
            "total_requests": self.total_requests,
            "assets_run": self.assets_run,
            "assets_skipped": self.assets_skipped,
            "stopped_reason": self.stopped_reason,
            "unresolved_scope_rules": list(self.unresolved_scope_rules),
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


class ProgramRunOrchestrator:
    """Drives an autonomous, budget-bounded hunt across a program's prioritized assets."""

    @classmethod
    def plan(
        cls,
        scope: ProgramScope,
        budget: RunBudget,
        candidate_urls: Optional[List[str]] = None,
    ) -> List[ScopeAsset]:
        """Concrete, revalidated execution seeds capped at ``max_assets``."""
        return scope.concrete_worklist(candidate_urls)[: max(0, int(budget.max_assets))]

    @classmethod
    def run(
        cls,
        scope: ProgramScope,
        hunt_asset_fn: HuntAssetFn,
        budget: Optional[RunBudget] = None,
        *,
        dry_run: bool = False,
        on_progress: Optional[Callable[[AssetOutcome], None]] = None,
        checkpoint: Optional[Any] = None,
        resume: bool = False,
        run_key: Optional[str] = None,
        candidate_urls: Optional[List[str]] = None,
    ) -> ProgramRunReport:
        budget = budget or RunBudget()
        assets = cls.plan(scope, budget, candidate_urls)
        report = ProgramRunReport(handle=scope.handle)
        resolved_sources = {a.source_identifier or a.identifier for a in assets}
        report.unresolved_scope_rules = [
            a.identifier for a in scope.worklist()
            if a.seed_url is None and a.identifier not in resolved_sources
        ]

        if dry_run:
            report.outcomes = [
                AssetOutcome(
                    host=a.host, status="planned", eligible_for_bounty=a.eligible_for_bounty,
                    max_severity=a.max_severity, identifier=a.identifier,
                    source_identifier=a.source_identifier or a.identifier,
                    seed_url=a.seed_url or "",
                )
                for a in assets
            ]
            report.assets_skipped = len(assets)
            report.stopped_reason = "dry_run"
            return report

        key = run_key or scope.handle or "program"
        # Resume: replay already-completed assets from the durable checkpoint so we skip them.
        prior: Dict[str, dict] = checkpoint.load(key) if (checkpoint and resume) else {}
        for scope_key, saved in prior.items():
            o = AssetOutcome(
                host=saved.get("host") or scope_key, status=saved.get("status", "completed"),
                endpoints=int(saved.get("endpoints", 0)), findings=int(saved.get("findings", 0)),
                requests_used=int(saved.get("requests_used", 0)),
                eligible_for_bounty=bool(saved.get("eligible_for_bounty", False)),
                max_severity=saved.get("max_severity", ""),
                identifier=saved.get("identifier", scope_key),
                source_identifier=saved.get("source_identifier", saved.get("identifier", scope_key)),
                seed_url=saved.get("seed_url", ""),
            )
            report.outcomes.append(o)
            report.assets_run += 1
            report.total_findings += o.findings
            report.total_requests += o.requests_used

        # Budget spans the whole program across resumes: subtract what prior sessions already spent.
        max_requests_total = max(0, int(budget.max_requests_total))
        per_asset_cap = max(0, int(budget.per_asset_request_cap))
        requests_left = max(0, max_requests_total - report.total_requests)
        for index, asset in enumerate(assets):
            prior_keys = {asset.scope_key, asset.host}
            if prior_keys.intersection(prior):
                continue  # already hunted in a previous session
            if requests_left <= 0:
                # Budget spent — record the not-yet-done rest as skipped without touching the target.
                remaining = [a for a in assets[index:] if not {a.scope_key, a.host}.intersection(prior)]
                for r in remaining:
                    report.outcomes.append(AssetOutcome(
                        host=r.host, status="budget_exhausted",
                        eligible_for_bounty=r.eligible_for_bounty,
                        max_severity=r.max_severity, identifier=r.identifier,
                        source_identifier=r.source_identifier or r.identifier,
                        seed_url=r.seed_url or "",
                    ))
                report.assets_skipped += len(remaining)
                report.stopped_reason = "request_budget_exhausted"
                break

            cap = min(per_asset_cap, requests_left)
            if cap <= 0:
                report.stopped_reason = "request_budget_exhausted"
                break
            outcome = AssetOutcome(
                host=asset.host, eligible_for_bounty=asset.eligible_for_bounty,
                max_severity=asset.max_severity, identifier=asset.identifier,
                source_identifier=asset.source_identifier or asset.identifier,
                seed_url=asset.seed_url or "",
            )
            try:
                result = hunt_asset_fn(asset, cap) or {}
                outcome.status = "completed"
                outcome.endpoints = int(result.get("endpoints", 0))
                outcome.findings = int(result.get("findings", 0))
                # Never let a stage report more spend than it was budgeted.
                outcome.requests_used = min(max(0, int(result.get("requests_used", 0))), cap)
            except Exception as e:  # one asset failing must not sink the program run
                outcome.status = "failed"
                outcome.error = str(e)

            report.outcomes.append(outcome)
            report.assets_run += 1
            report.total_findings += outcome.findings
            report.total_requests += outcome.requests_used
            requests_left -= outcome.requests_used
            # Durably checkpoint this asset so a crash/restart resumes past it.
            if checkpoint:
                checkpoint.record(key, asset.scope_key, outcome.to_dict())
            if on_progress:
                on_progress(outcome)

            if budget.stop_after_findings and report.total_findings >= budget.stop_after_findings:
                report.assets_skipped += sum(
                    1 for a in assets[index + 1:]
                    if not {a.scope_key, a.host}.intersection(prior)
                )
                report.stopped_reason = "findings_target_reached"
                break

        if checkpoint:
            checkpoint.finalize(key, report.to_dict())
        return report

    @classmethod
    def run_for_target(
        cls,
        db: Any,
        target_id: int,
        hunt_asset_fn: HuntAssetFn,
        budget: Optional[RunBudget] = None,
        **kw: Any,
    ) -> ProgramRunReport:
        """Convenience: build the scope from a synced program Target and run.

        ``hunt_asset_fn`` is supplied by the caller (the CLI binds it to the real crawl→experiment
        path) so this service stays free of browser/network coupling.
        """
        from backend_api.models.target import Target

        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise ValueError(f"Target {target_id} not found")
        scope = ProgramScope.from_target(target)
        return cls.run(scope, hunt_asset_fn, budget, **kw)
