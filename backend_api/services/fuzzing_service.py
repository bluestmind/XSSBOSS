"""Fuzzing pipeline orchestration service."""
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from backend_api.models.experiment import Experiment, ExperimentStatus
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.context import Context, ContextType
from backend_api.models.filter_profile import FilterProfile
from backend_api.models.sink import Sink
from backend_api.models.finding import Severity
from backend_api.models.execution import Execution, OracleStatus
from backend_api.services.experiment_service import ExperimentService
from backend_api.utils.scope_guard import is_endpoint_in_scope
from backend_api.utils.impact_scorer import ImpactScorer
from backend_api.utils.log_serializer import (
    parse_execution_logs,
    sanitize_execution_logs,
)
from backend_api.services.result_service import ResultService
from backend_api.utils.tokenizer import Tokenizer
from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.services.run_state_service import RunStateService
import sys
import os
import gc
import threading
import time

# Add workspace root to path for cross-module imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from analysis_engine.detect_context import ContextDetectorEngine
from analysis_engine.detect_filter import FilterDetectorEngine
from fuzzer.generator import PayloadGenerator
from fuzzer.strategy import Strategy, StrategyProfile


class FuzzingService:
    """Service for orchestrating the fuzzing pipeline."""
    
    def __init__(self, db: Session):
        """Initialize with database session."""
        self.db = db
        self.context_detector = ContextDetectorEngine(db)
        self.filter_detector = FilterDetectorEngine(db)
        self.payload_generator = PayloadGenerator()

    @staticmethod
    def _payload_limit_for_strategy(strategy: Strategy) -> int:
        """Honor the selected strategy budget within the global safety cap."""
        profile = StrategyProfile.get_profile(strategy)
        strategy_limit = max(
            1,
            int(profile.get("max_payloads_per_context", 1)),
        )
        return min(
            max(1, settings.MAX_PAYLOADS_PER_CONTEXT),
            strategy_limit,
        )

    @staticmethod
    def _diversity_order(endpoints: List[Endpoint]) -> List[Endpoint]:
        """Round-robin route families so one parameter-heavy path cannot monopolize a run."""
        from urllib.parse import urlsplit

        families: Dict[tuple[str, str, str], List[Endpoint]] = {}
        for endpoint in endpoints:
            parsed = urlsplit(str(endpoint.url_pattern or ""))
            key = (
                str(endpoint.method or "GET").upper(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/") or "/",
            )
            families.setdefault(key, []).append(endpoint)

        ordered: List[Endpoint] = []
        offset = 0
        while True:
            added = False
            for family in families.values():
                if offset < len(family):
                    ordered.append(family[offset])
                    added = True
            if not added:
                return ordered
            offset += 1
    
    def run_experiment(self, experiment_id: int, progress_callback=None) -> Dict[str, Any]:
        """Run a complete fuzzing experiment."""

        from concurrent.futures import ThreadPoolExecutor, as_completed
        from backend_api.db.base import SessionLocal

        def progress(
            phase: str,
            message: str,
            *,
            tool: str = "fuzzing orchestrator",
            state: str = "working",
            completed: Optional[int] = None,
            total: Optional[int] = None,
            overall_percent: Optional[float] = None,
            detail: Optional[str] = None,
            doing_status: Optional[str] = None,
            micro_state: Optional[dict] = None,
            river_stage: Optional[str] = None,
        ) -> None:
            logger.info("Scan progress [%s]: %s", phase, message)
            try:
                RunStateService.record_progress(
                    self.db,
                    experiment_id,
                    phase=phase,
                    tool=tool,
                    message=message,
                    state=state,
                    completed=completed,
                    total=total,
                    overall_percent=overall_percent,
                    detail=detail,
                    doing_status=doing_status,
                    micro_state=micro_state,
                    river_stage=river_stage,
                )
            except Exception:
                logger.debug("Could not persist scan progress", exc_info=True)
            if progress_callback:
                try:
                    import inspect
                    sig = inspect.signature(progress_callback)
                    if len(sig.parameters) >= 3:
                        progress_callback(phase, message, doing_status=doing_status, micro_state=micro_state, river_stage=river_stage)
                    else:
                        progress_callback(phase, message)
                except Exception:
                    try:
                        progress_callback(phase, message)
                    except Exception:
                        logger.debug("Progress callback failed", exc_info=True)
        
        experiment = self.db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        # Start or resume experiment status to RUNNING
        experiment = ExperimentService.start_experiment(self.db, experiment_id)
        progress(
            "preflight",
            "Checking target reachability",
            tool="HTTP preflight",
            overall_percent=22,
            doing_status=f"Verifying target reachability for {experiment.target.base_url}",
            river_stage="springs",
        )

        # Pre-scan reachability check
        try:
            from backend_api.utils.stealth import preflight_check
            target_url = experiment.target.base_url
            logger.info(f"Performing preflight check on target: {target_url}")
            probe = preflight_check(target_url)
            if not probe["reachable"]:
                logger.error(f"Preflight check failed: target {target_url} is unreachable. Error: {probe['error']}")
                experiment.status = ExperimentStatus.FAILED
                limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
                warnings = list(limits.get("warnings", []))
                warnings.append({
                    "level": "error",
                    "phase": "probe",
                    "message": "Preflight check failed: target is unreachable.",
                    "detail": f"Target URL: {target_url}. Error: {probe['error'] or 'Connection failed'}. Please verify target availability.",
                })
                limits["warnings"] = warnings[-12:]
                experiment.limits = limits
                self.db.commit()
                return {
                    "status": "failed",
                    "message": f"Target is unreachable: {probe['error']}",
                    "test_cases_created": 0
                }
        except Exception as preflight_err:
            logger.warning(f"Pre-scan preflight check failed to execute: {preflight_err}")

        # Auto-sync with the Burp Suite REST task created by the scan router.
        # Do not start another Burp scan here; one UI click must map to one Burp task.
        try:
            from backend_api.services.burp_service import BurpService
            limits = experiment.limits if isinstance(experiment.limits, dict) else {}
            burp_task_id = limits.get("burp_task_id")
            if burp_task_id:
                BurpService.import_from_rest(
                    db=self.db,
                    target_id=experiment.target_id,
                    api_url=settings.BURP_API_URL,
                    api_key=settings.BURP_API_KEY,
                    task_id=burp_task_id,
                )
                logger.info(f"Synced existing Burp REST task {burp_task_id} before beginning experiment.")
            else:
                logger.info("No Burp task ID recorded yet; continuing with local crawler/imported endpoints.")
        except Exception as burp_sync_err:
            logger.warning(f"Auto Burp REST sync disabled or failed: {burp_sync_err}")
        
        # Get target endpoints and keep execution constrained to configured scope.
        # One Flow should profile only endpoints collected for the current run;
        # otherwise stale Burp imports from the same target can dominate the run
        # and turn a single URL scan into a long timeout parade.
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        scoped_endpoint_ids = RunStateService.endpoint_ids(self.db, experiment_id)
        if not scoped_endpoint_ids:
            scoped_endpoint_ids = limits.get("endpoint_ids") or []
        if scoped_endpoint_ids:
            endpoints = (
                self.db.query(Endpoint)
                .filter(Endpoint.target_id == experiment.target_id)
                .filter(Endpoint.id.in_(scoped_endpoint_ids))
                .all()
            )
            logger.info(
                f"One Flow endpoint scope active for experiment {experiment_id}: {len(endpoints)} endpoint(s)"
            )
        else:
            endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == experiment.target_id).all()
        skipped_out_of_scope = 0
        in_scope_endpoints = []
        for endpoint in endpoints:
            if is_endpoint_in_scope(endpoint):
                in_scope_endpoints.append(endpoint)
            else:
                skipped_out_of_scope += 1

        if skipped_out_of_scope:
            logger.warning(
                f"Skipping {skipped_out_of_scope} endpoint(s) outside the target's configured scope"
            )

        endpoints = self._diversity_order(in_scope_endpoints)
        endpoint_ids = [ep.id for ep in endpoints]
        recon_dossier = None
        try:
            from backend_api.services.recon_dossier_service import ReconDossierService

            recon_dossier = ReconDossierService.build(
                self.db,
                experiment.target_id,
                endpoint_ids=endpoint_ids,
            )
            updated_limits = dict(limits)
            updated_limits["recon_dossier"] = {
                "summary": recon_dossier["summary"],
                "coverage_matrix": recon_dossier["coverage_matrix"],
                "integrity_sha256": recon_dossier["integrity_sha256"],
            }
            experiment.limits = updated_limits
            self.db.commit()
            active_classes = sum(
                1 for item in recon_dossier["coverage_matrix"].values() if item["kind"] in {"fuzz", "auditor"}
            )
            research_classes = sum(
                1 for item in recon_dossier["coverage_matrix"].values() if item["kind"] == "research"
            )
            routed_candidates = sum(
                item["candidate_count"] for item in recon_dossier["coverage_matrix"].values()
            )
            progress(
                "recon-routing",
                f"Mapped {routed_candidates} recon candidate(s) into {active_classes} active and {research_classes} research bug classes",
                tool="cross-bug recon router",
                overall_percent=24,
                doing_status="Recon Intelligence: Building the reusable cross-bug coverage map",
                detail="Candidate endpoints run first; all in-scope endpoints remain covered to avoid blind spots.",
                river_stage="recon",
            )
        except Exception as dossier_error:
            logger.warning("Could not build reusable recon dossier: %s", dossier_error)
            progress(
                "recon-routing",
                "Cross-bug recon map could not be built; retaining full endpoint coverage",
                tool="cross-bug recon router",
                overall_percent=24,
                doing_status="Recon Intelligence: Falling back to unranked endpoint coverage",
                detail=str(dossier_error)[:500],
                river_stage="recon",
            )

        def routed(bug_key: str):
            if recon_dossier is None:
                return endpoints
            return ReconDossierService.prioritize_endpoints(endpoints, recon_dossier, bug_key)

        progress(
            "auditors",
            f"Running nine focused HTTP auditors across {len(endpoint_ids)} endpoint(s)",
            tool="auditor suite",
            completed=0,
            total=9,
            overall_percent=25,
            doing_status="Auditor Cascades: Initializing specialized security auditor suite",
            river_stage="auditors",
        )

        progress("auditors", "Testing cross-origin trust behavior", tool="CORS auditor", completed=0, total=9, overall_percent=25, doing_status="Auditor Cascades: Testing CORS trust configurations", river_stage="auditors")
        try:
            from backend_api.services.auditors.cors import CorsAuditor
            cors_findings = CorsAuditor.audit_endpoints(self.db, routed("cors"))
            if cors_findings:
                self._tag_findings_for_experiment(cors_findings, experiment_id)
                logger.info(f"CORS auditor created/updated {len(cors_findings)} finding(s).")
                self._auto_forward_auditor_findings(cors_findings)
        except Exception as cors_err:
            logger.warning(f"CORS auditor failed: {cors_err}")
        progress("auditors", "CORS audit finished", tool="CORS auditor", completed=1, total=9, overall_percent=27, doing_status="Auditor Cascades: CORS audit completed", river_stage="auditors")

        progress("auditors", "Testing path traversal and local-file patterns", tool="path traversal auditor", completed=1, total=9, overall_percent=27, doing_status="Auditor Cascades: Testing path traversal and LFI patterns", river_stage="auditors")
        try:
            from backend_api.services.auditors.path_traversal import PathTraversalAuditor
            lfi_findings = PathTraversalAuditor.audit_endpoints(self.db, routed("path_traversal"))
            if lfi_findings:
                self._tag_findings_for_experiment(lfi_findings, experiment_id)
                logger.info(f"Path traversal auditor created/updated {len(lfi_findings)} finding(s).")
                self._auto_forward_auditor_findings(lfi_findings)
        except Exception as lfi_err:
            logger.warning(f"Path traversal auditor failed: {lfi_err}")
        progress("auditors", "Path traversal audit finished", tool="path traversal auditor", completed=2, total=9, overall_percent=29, doing_status="Auditor Cascades: Path traversal audit completed", river_stage="auditors")

        progress("auditors", "Testing error-based SQL injection signatures", tool="SQL injection auditor", completed=2, total=9, overall_percent=29, doing_status="Auditor Cascades: Testing SQL injection signatures", river_stage="auditors")
        try:
            from backend_api.services.auditors.sqli import ErrorBasedSqliAuditor
            sqli_findings = ErrorBasedSqliAuditor.audit_endpoints(self.db, routed("sqli"))
            if sqli_findings:
                self._tag_findings_for_experiment(sqli_findings, experiment_id)
                logger.info(f"SQLi auditor created/updated {len(sqli_findings)} finding(s).")
                self._auto_forward_auditor_findings(sqli_findings)
        except Exception as sqli_err:
            logger.warning(f"SQLi auditor failed: {sqli_err}")
        progress("auditors", "SQL injection audit finished", tool="SQL injection auditor", completed=3, total=9, overall_percent=32, doing_status="Auditor Cascades: SQL injection audit completed", river_stage="auditors")

        progress("auditors", "Sending controlled server-side request canaries", tool="SSRF canary auditor", completed=3, total=9, overall_percent=32, doing_status="Auditor Cascades: Sending SSRF canary probes", river_stage="auditors")
        try:
            from backend_api.services.auditors.ssrf import SsrfCanaryAuditor
            ssrf_canaries = SsrfCanaryAuditor.audit_endpoints(self.db, experiment_id, routed("ssrf"))
            if ssrf_canaries:
                logger.info(f"SSRF canary auditor sent {ssrf_canaries} collaborator probe(s).")
        except Exception as ssrf_err:
            logger.warning(f"SSRF canary auditor failed: {ssrf_err}")
        progress("auditors", "SSRF audit finished", tool="SSRF canary auditor", completed=4, total=9, overall_percent=34, doing_status="Auditor Cascades: SSRF audit completed", river_stage="auditors")
        
        progress("auditors", "Testing redirect-like parameters", tool="redirect auditor", completed=4, total=9, overall_percent=34, doing_status="Auditor Cascades: Testing open redirect candidates", river_stage="auditors")
        try:
            from backend_api.services.auditors.redirect import RedirectAuditor
            redirect_findings = RedirectAuditor.audit_endpoints(self.db, routed("open_redirect"))
            if redirect_findings:
                self._tag_findings_for_experiment(redirect_findings, experiment_id)
                logger.info(f"Redirect auditor created/updated {len(redirect_findings)} finding(s).")
                self._auto_forward_auditor_findings(redirect_findings)
        except Exception as redir_err:
            logger.warning(f"Redirect auditor failed: {redir_err}")
        progress("auditors", "Redirect audit finished", tool="redirect auditor", completed=5, total=9, overall_percent=36, doing_status="Auditor Cascades: Open redirect audit completed", river_stage="auditors")

        progress("auditors", "Testing response-header injection", tool="CRLF auditor", completed=5, total=9, overall_percent=36, doing_status="Auditor Cascades: Testing CRLF response-header injection", river_stage="auditors")
        try:
            from backend_api.services.auditors.crlf_injection import CRLFInjectionAuditor
            crlf_findings = CRLFInjectionAuditor.audit_endpoints(self.db, routed("crlf"))
            if crlf_findings:
                self._tag_findings_for_experiment(crlf_findings, experiment_id)
                logger.info(f"CRLF auditor created/updated {len(crlf_findings)} finding(s).")
                self._auto_forward_auditor_findings(crlf_findings)
        except Exception as crlf_err:
            logger.warning(f"CRLF auditor failed: {crlf_err}")
        progress("auditors", "CRLF audit finished", tool="CRLF auditor", completed=6, total=9, overall_percent=38, doing_status="Auditor Cascades: CRLF audit completed", river_stage="auditors")

        progress("auditors", "Testing parsed markup exfiltration candidates", tool="dangling markup auditor", completed=6, total=9, overall_percent=38, doing_status="Auditor Cascades: Testing dangling markup exfiltration", river_stage="auditors")
        try:
            from backend_api.services.auditors.dangling_markup import DanglingMarkupAuditor
            dm_findings = DanglingMarkupAuditor.audit_endpoints(self.db, routed("dangling_markup"))
            if dm_findings:
                self._tag_findings_for_experiment(dm_findings, experiment_id)
                logger.info(f"Dangling markup auditor created/updated {len(dm_findings)} finding(s).")
                self._auto_forward_auditor_findings(dm_findings)
        except Exception as dm_err:
            logger.warning(f"Dangling markup auditor failed: {dm_err}")
        progress("auditors", "Dangling markup audit finished", tool="dangling markup auditor", completed=7, total=9, overall_percent=41, doing_status="Auditor Cascades: Dangling markup audit completed", river_stage="auditors")

        progress("auditors", "Testing cache deception behavior", tool="cache deception auditor", completed=7, total=9, overall_percent=41, doing_status="Auditor Cascades: Testing cache deception vulnerabilities", river_stage="auditors")
        try:
            from backend_api.services.auditors.cache_deception import CacheDeceptionAuditor
            cd_findings = CacheDeceptionAuditor.audit_endpoints(self.db, routed("cache_deception"))
            if cd_findings:
                self._tag_findings_for_experiment(cd_findings, experiment_id)
                logger.info(f"Cache deception auditor created/updated {len(cd_findings)} finding(s).")
                self._auto_forward_auditor_findings(cd_findings)
        except Exception as cd_err:
            logger.warning(f"Cache deception auditor failed: {cd_err}")
        progress("auditors", "Cache deception audit finished", tool="cache deception auditor", completed=8, total=9, overall_percent=43, doing_status="Auditor Cascades: Cache deception audit completed", river_stage="auditors")

        try:
            from backend_api.services.auditors.http_param import HttpParamPollutionAuditor
            progress("auditors", "Testing duplicate-parameter interpretation", tool="HTTP parameter pollution auditor", completed=8, total=9, overall_percent=43, doing_status="Auditor Cascades: Testing HTTP parameter pollution", river_stage="auditors")
            hpp_findings = HttpParamPollutionAuditor.audit_endpoints(self.db, routed("http_param"))
            if hpp_findings:
                self._tag_findings_for_experiment(hpp_findings, experiment_id)
                logger.info(f"HTTP parameter pollution auditor created/updated {len(hpp_findings)} finding(s).")
                self._auto_forward_auditor_findings(hpp_findings)
        except Exception as hpp_err:
            logger.warning(f"HTTP parameter pollution auditor failed: {hpp_err}")
        progress("auditors", "HTTP parameter pollution audit finished", tool="HTTP parameter pollution auditor", completed=9, total=9, overall_percent=45, doing_status="Auditor Cascades: Specialized auditor suite finished", river_stage="auditors")
        
        test_cases_created = 0
        strategy_val = experiment.strategy.value
        autonomous_research = bool(
            limits.get("autonomous_research", strategy_val == Strategy.SMART_ADAPTIVE.value)
        )

        # Enforce one global case budget across all profiling threads. The previous
        # per-payload COUNT query was both O(n^2) and racy, allowing concurrent
        # workers to exceed the configured cap.
        max_total_cases = max(1, settings.MAX_TEST_CASES_PER_EXPERIMENT)
        requested_case_limit = limits.get("max_test_cases")
        if requested_case_limit is not None:
            try:
                max_total_cases = min(max_total_cases, max(1, int(requested_case_limit)))
            except (TypeError, ValueError):
                logger.warning(f"Ignoring invalid max_test_cases limit: {requested_case_limit!r}")

        existing_case_count = self.db.query(TestCase).filter(
            TestCase.experiment_id == experiment_id
        ).count()
        case_budget_remaining = max(0, max_total_cases - existing_case_count)
        case_budget_lock = threading.Lock()

        def reserve_case_slot() -> bool:
            nonlocal case_budget_remaining
            with case_budget_lock:
                if case_budget_remaining <= 0:
                    return False
                case_budget_remaining -= 1
                return True

        def has_case_budget() -> bool:
            with case_budget_lock:
                return case_budget_remaining > 0
        
        def process_endpoint(ep_id: int) -> int:
            """Target-profiling worker function running in a separate thread."""
            local_db = SessionLocal()
            endpoint_started = time.monotonic()
            endpoint_url = None
            endpoint_param_count = 0
            context_count = 0
            try:
                # Refresh experiment status to check if it has been paused
                exp = local_db.query(Experiment).filter(Experiment.id == experiment_id).first()
                if not exp or exp.status != ExperimentStatus.RUNNING:
                    return 0
                
                # Check if we have already generated test cases for this endpoint
                existing_count = local_db.query(TestCase).filter(
                    TestCase.experiment_id == experiment_id,
                    TestCase.endpoint_id == ep_id
                ).count()
                if existing_count > 0:
                    return 0

                ep = local_db.query(Endpoint).filter(Endpoint.id == ep_id).first()
                if not ep or not is_endpoint_in_scope(ep):
                    logger.warning(f"Skipping out-of-scope endpoint {ep_id}")
                    return 0
                endpoint_url = ep.url_pattern
                discovered_params = local_db.query(Param).filter(Param.endpoint_id == ep_id).all()
                from urllib.parse import parse_qs, urlsplit

                query_names = set(parse_qs(urlsplit(endpoint_url).query, keep_blank_values=True))
                params = [
                    param for param in discovered_params
                    if param.location != "query" or param.name in query_names or bool(param.burp_flagged)
                ]
                ignored_unbacked_params = len(discovered_params) - len(params)
                endpoint_param_count = len(params)
                from backend_api.services.log_service import LogService

                LogService.info(
                    "profiling.endpoint",
                    f"Started profiling endpoint #{ep_id}",
                    detail=endpoint_url,
                    experiment_id=experiment_id,
                    target_id=experiment.target_id,
                    data={
                        "event_type": "endpoint_profiling_started",
                        "endpoint_id": ep_id,
                        "url": endpoint_url,
                        "method": ep.method,
                        "parameter_count": endpoint_param_count,
                        "ignored_unbacked_parameters": ignored_unbacked_params,
                    },
                )
                
                # Load detectors with thread-local db session
                flt_detector = FilterDetectorEngine(local_db)

                # Step 1: Use already-stored contexts from DB (set by recon phase).
                # Re-probing via HTTP misses JS-rendered sinks, and duplicates work.
                # Only fall back to live probing when the DB has nothing yet.
                valid_param_ids = [param.id for param in params]
                contexts = (
                    local_db.query(Context)
                    .filter(Context.endpoint_id == ep_id)
                    .filter(Context.param_id.in_(valid_param_ids))
                    .all()
                    if valid_param_ids else []
                )
                if not contexts:
                    ctx_detector = ContextDetectorEngine(local_db)
                    contexts = []
                    for candidate_param in params:
                        contexts.extend(ctx_detector.detect_contexts_for_param(candidate_param.id))
                context_count = len(contexts or [])
                LogService.info(
                    "profiling.endpoint",
                    f"Context detection completed for endpoint #{ep_id}",
                    detail=endpoint_url,
                    experiment_id=experiment_id,
                    target_id=experiment.target_id,
                    data={
                        "event_type": "endpoint_contexts_detected",
                        "endpoint_id": ep_id,
                        "url": endpoint_url,
                        "context_count": context_count,
                    },
                )
                if not contexts:
                    return 0
                
                # Step 2: Profile filters
                filter_profile = None
                try:
                    filter_profiles = flt_detector.profile_endpoint(ep_id)
                    if filter_profiles:
                        filter_profile_obj = filter_profiles[0]
                        filter_profile = {
                            'blocked_tokens': filter_profile_obj.blocked_tokens or [],
                            'allowed_tokens': filter_profile_obj.allowed_tokens or [],
                            'normalization_behavior': filter_profile_obj.normalization_behavior or [],
                            'waf_detected': filter_profile_obj.waf_detected,
                            'sanitizer_detected': filter_profile_obj.sanitizer_detected,
                            'csp_rules': filter_profile_obj.csp_rules or {}
                        }
                except Exception as err:
                    logger.error(f"Error profiling endpoint {ep_id}: {err}")

                local_cases = 0
                
                # Step 4: Generate payloads and create test cases
                for param in params:
                    param_contexts = [c for c in contexts if c.param_id == param.id]
                    if not param_contexts:
                        continue
                    
                    base_strategy = Strategy(strategy_val)
                    for context in param_contexts:
                        token = Tokenizer.generate_token()
                        try:
                            context_type_enum = ContextType(context.context_type)
                        except ValueError:
                            continue
                        
                        hypothesis = None
                        selected_technique = None
                        research_context_fingerprint = None
                        strategy = base_strategy
                        if autonomous_research:
                            try:
                                from backend_api.services.research_service import ResearchService

                                hypothesis = ResearchService.hypothesis_for_context(
                                    local_db, experiment_id, ep_id, param.id, context.id
                                )
                                if hypothesis:
                                    selected_technique = ResearchService.select_technique(
                                        local_db, hypothesis, context, filter_profile
                                    )
                                    research_context_fingerprint = ResearchService.context_fingerprint(
                                        hypothesis, context, filter_profile
                                    )
                                strategy = ResearchService.recommended_strategy(
                                    hypothesis, context, filter_profile, base_strategy
                                )
                            except Exception as research_error:
                                logger.warning(
                                    "Research recommendation failed for endpoint %s parameter %s: %s",
                                    ep_id, param.id, research_error,
                                )

                        max_p = self._payload_limit_for_strategy(strategy)
                        payloads = self.payload_generator.generate_payloads(
                            context_type=context_type_enum,
                            token=token,
                            strategy=strategy,
                            filter_profile=filter_profile,
                            max_payloads=max_p,
                        )
                        
                        for payload in payloads:
                            if not reserve_case_slot():
                                logger.warning(
                                    f"Stopping generation; experiment case cap {max_total_cases} reached"
                                )
                                break
                            
                            test_token = Tokenizer.generate_token()
                            payload_with_token = Tokenizer.replace_token(payload, token, test_token)
                            
                            # Calculate priority score
                            priority = 0
                            if getattr(param, 'burp_flagged', False):
                                priority += 100
                            if getattr(param, 'taint_reachable', False):
                                priority += 25
                            if "/*__XSS_POLYGLOT__*/" in payload_with_token or "<!--'" in payload_with_token:
                                priority += 50
                                
                            sinks = local_db.query(Sink).filter(Sink.context_id == context.id).all()
                            if sinks:
                                priority += 10
                            if context.context_type in ['JS_STRING_LITERAL', 'EVENT_HANDLER_ATTR']:
                                priority += 5
                            
                            if ep.method.upper() == 'POST':
                                priority += 3

                            priority += ImpactScorer.score_attack_surface(
                                endpoint=ep,
                                param=param,
                                context=context,
                            )["score"]
                            if hypothesis:
                                priority += min(20, int(hypothesis.priority / 5))
                            
                            test_case = TestCase(
                                experiment_id=experiment_id,
                                endpoint_id=ep_id,
                                param_id=param.id,
                                context_id=context.id,
                                payload=payload_with_token,
                                token=test_token,
                                priority=priority,
                                status=TestCaseStatus.PENDING
                            )
                            if hypothesis:
                                ResearchService.attach_test_case(
                                    local_db,
                                    test_case,
                                    hypothesis,
                                    selected_technique,
                                    research_context_fingerprint,
                                )
                            local_db.add(test_case)
                            local_db.flush()
                            local_cases += 1

                        if not has_case_budget():
                            break
                    if not has_case_budget():
                        break
                
                local_db.commit()
                LogService.info(
                    "profiling.endpoint",
                    f"Finished profiling endpoint #{ep_id}",
                    detail=endpoint_url,
                    experiment_id=experiment_id,
                    target_id=experiment.target_id,
                    data={
                        "event_type": "endpoint_profiling_complete",
                        "endpoint_id": ep_id,
                        "url": endpoint_url,
                        "parameter_count": endpoint_param_count,
                        "context_count": context_count,
                        "test_cases_created": local_cases,
                        "duration_ms": round((time.monotonic() - endpoint_started) * 1000),
                    },
                )
                return local_cases
            except Exception as e:
                logger.error(f"Error in process_endpoint {ep_id}: {e}", exc_info=True)
                try:
                    from backend_api.services.log_service import LogService

                    LogService.error(
                        "profiling.endpoint",
                        f"Profiling failed for endpoint #{ep_id}",
                        detail=str(e),
                        experiment_id=experiment_id,
                        target_id=experiment.target_id,
                        data={
                            "event_type": "endpoint_profiling_error",
                            "endpoint_id": ep_id,
                            "url": endpoint_url,
                            "parameter_count": endpoint_param_count,
                            "context_count": context_count,
                            "duration_ms": round((time.monotonic() - endpoint_started) * 1000),
                        },
                    )
                except Exception:
                    logger.debug("Could not persist endpoint profiling failure", exc_info=True)
                return 0
            finally:
                local_db.close()
        
        # Run thread pool for concurrent context detection and filter profiling
        max_workers = min(settings.MAX_PROFILING_WORKERS, len(endpoint_ids)) if endpoint_ids else 1
        endpoint_lookup = {endpoint.id: endpoint for endpoint in endpoints}
        logger.info(f"Starting concurrent profiling for {len(endpoint_ids)} endpoints with {max_workers} workers...")
        
        profiled_count = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_endpoint, ep_id): ep_id for ep_id in endpoint_ids}
            for future in as_completed(futures):
                ep_id = futures[future]
                created_count = 0
                try:
                    created_count = future.result()
                    test_cases_created += created_count
                except Exception as e:
                    logger.error(f"Thread execution error for endpoint {ep_id}: {e}", exc_info=True)
                profiled_count += 1
                completed_endpoint = endpoint_lookup.get(ep_id)
                completed_url = completed_endpoint.url_pattern if completed_endpoint else None
                progress(
                    "profiling",
                    f"Profiled endpoint {profiled_count} of {len(endpoint_ids)}",
                    tool="context and filter profiler",
                    completed=profiled_count,
                    total=len(endpoint_ids),
                    overall_percent=45 + (10 * profiled_count / max(1, len(endpoint_ids))),
                    detail=f"Endpoint #{ep_id}: {completed_url or 'unknown URL'}; generated {created_count} case(s).",
                    doing_status=f"Context Confluence: Profiling endpoint {profiled_count}/{len(endpoint_ids)}",
                    micro_state={
                        "action": "profile_endpoint_complete",
                        "endpoint_id": ep_id,
                        "endpoint": completed_url,
                        "result": {"test_cases_created": created_count},
                    },
                    river_stage="contexts",
                )

        progress(
            "generation",
            f"Generated {test_cases_created} prioritized browser test case(s)",
            tool="context-aware payload generator",
            completed=test_cases_created,
            total=max_total_cases,
            overall_percent=55,
            detail=f"Declared run cap: {max_total_cases}",
            doing_status=f"Payload Generation: Created {test_cases_created} prioritized test cases",
            river_stage="contexts",
        )
        
        self.db.commit()

        scoped_param_count = (
            self.db.query(Param)
            .filter(Param.endpoint_id.in_(endpoint_ids))
            .count()
            if endpoint_ids else 0
        )
        scoped_context_count = (
            self.db.query(Context)
            .filter(Context.endpoint_id.in_(endpoint_ids))
            .count()
            if endpoint_ids else 0
        )
        if scoped_param_count > 0 and scoped_context_count == 0 and test_cases_created == 0:
            self.db.refresh(experiment)
            limits = experiment.limits if isinstance(experiment.limits, dict) else {}
            warnings = limits.get("warnings") if isinstance(limits.get("warnings"), list) else []
            warning = {
                "level": "warning",
                "phase": "probe",
                "message": "No reflection contexts were detected.",
                "detail": (
                    f"Checked {scoped_param_count} parameter(s) across {len(endpoint_ids)} scoped endpoint(s), "
                    "but Burp/proxy probes timed out or did not reflect markers."
                ),
            }
            if not any(isinstance(item, dict) and item.get("message") == warning["message"] for item in warnings):
                warnings.append(warning)
            updated_limits = dict(limits)
            updated_limits["warnings"] = warnings[-12:]
            updated_limits["context_probe_failures"] = scoped_param_count
            experiment.limits = updated_limits
            self.db.commit()

        redirect_cases_created = self._seed_open_redirect_test_cases(experiment_id, endpoint_ids)
        test_cases_created += redirect_cases_created
        if redirect_cases_created:
            logger.info(f"Seeded {redirect_cases_created} Open Redirect auditor test case(s).")
        
        # Queue and run test cases
        is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
        if strategy_val == Strategy.GENETIC_EVOLUTIONARY.value:
            # Multi-generation genetic evolution loop
            import time
            from fuzzer.genetic import GeneticEvolutionEngine
            from browser_workers.worker import _check_experiment_completion
            
            logger.info("Starting Genetic Evolutionary Fuzzing Loop...")
            max_generations = 5
            engine = GeneticEvolutionEngine(self.db)
            
            # Retrieve unique (endpoint_id, param_id, context_id) we are targeting
            active_contexts = self.db.query(
                TestCase.endpoint_id, TestCase.param_id, TestCase.context_id
            ).filter(
                TestCase.experiment_id == experiment_id
            ).distinct().all()
            
            for gen in range(1, max_generations + 1):
                logger.info(f"--- Processing Generation {gen}/{max_generations} ---")
                
                # Wait for all current test cases to finish execution
                while True:
                    self.db.commit()
                    self.db.refresh(experiment)
                    if experiment.status != ExperimentStatus.RUNNING:
                        logger.info("Experiment status is no longer RUNNING. Exiting evolution loop.")
                        break
                        
                    remaining = self.db.query(TestCase).filter(
                        TestCase.experiment_id == experiment_id,
                        TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED, TestCaseStatus.RUNNING])
                    ).count()
                    
                    if remaining == 0:
                        break
                        
                    # Maintain active queue slots
                    FuzzingService.queue_next_batch(self.db, experiment_id, max_active=1 if is_eager else None)
                    time.sleep(1)
                
                # Check if we have found any XSS hits (Oracle Status = HIT) in the current database
                xss_hits = self.db.query(Execution).join(TestCase).filter(
                    TestCase.experiment_id == experiment_id,
                    Execution.oracle_status == OracleStatus.HIT
                ).count()
                
                if xss_hits > 0:
                    logger.info("Verified XSS vulnerability found! Stopping genetic loop early.")
                    break
                    
                if gen == max_generations:
                    logger.info("Reached maximum generation limit. Exiting genetic loop.")
                    break
                
                # Breed next generation of payloads
                new_cases_count = 0
                for ep_id, param_id, context_id in active_contexts:
                    filter_profile = None
                    try:
                        from backend_api.models.filter_profile import FilterProfile
                        flt_obj = self.db.query(FilterProfile).filter(FilterProfile.endpoint_id == ep_id).first()
                        if flt_obj:
                            filter_profile = {
                                'blocked_tokens': flt_obj.blocked_tokens or [],
                                'allowed_tokens': flt_obj.allowed_tokens or [],
                                'normalization_behavior': flt_obj.normalization_behavior or [],
                                'waf_detected': flt_obj.waf_detected,
                                'sanitizer_detected': flt_obj.sanitizer_detected,
                                'csp_rules': flt_obj.csp_rules or {}
                            }
                            
                            # Gather recent execution telemetry logs
                            recent_executions = (
                                self.db.query(Execution)
                                .join(TestCase)
                                .filter(TestCase.experiment_id == experiment_id)
                                .filter(TestCase.endpoint_id == ep_id)
                                .filter(TestCase.param_id == param_id)
                                .filter(TestCase.context_id == context_id)
                                .all()
                            )
                            
                            errors = []
                            console = []
                            sinks = []
                            for exec_obj in recent_executions:
                                if exec_obj.logs:
                                    logs_dict = sanitize_execution_logs(
                                        parse_execution_logs(exec_obj.logs),
                                        test_case_id=exec_obj.test_case_id,
                                        attempt_no=exec_obj.attempt_no,
                                    )
                                    if logs_dict:
                                        errors.extend(logs_dict.get('errors', []))
                                        console.extend(logs_dict.get('console', []))
                                        if logs_dict.get('sink'):
                                            sinks.append(logs_dict.get('sink'))
                            
                            if errors or console or sinks:
                                telemetry_logs = {
                                    "errors": list(set(errors))[:10],
                                    "console": list(set(console))[:10],
                                    "sinks": list(set(sinks))[:10]
                                }
                                from backend_api.services.llm_service import LLMService
                                analysis = LLMService.analyze_telemetry_errors(telemetry_logs)
                                if analysis:
                                    norm_behaviors = list(set(filter_profile['normalization_behavior'] + analysis.get('normalization_behavior', [])))
                                    blocked_toks = list(set(filter_profile['blocked_tokens'] + analysis.get('blocked_tokens', [])))
                                    flt_obj.normalization_behavior = norm_behaviors
                                    flt_obj.blocked_tokens = blocked_toks
                                    if analysis.get('summary'):
                                        flt_obj.summary = (flt_obj.summary or "") + "\n[Telemetry Update] " + analysis.get('summary')
                                    self.db.commit()
                                    
                                    filter_profile['normalization_behavior'] = norm_behaviors
                                    filter_profile['blocked_tokens'] = blocked_toks
                    except Exception as telemetry_err:
                        logger.warning(f"Telemetry analysis failed to update filter profile: {telemetry_err}")
                        
                    # Evolve next generation payloads
                    next_token = Tokenizer.generate_token()
                    evolved_payloads = engine.evolve_next_generation(
                        experiment_id=experiment_id,
                        endpoint_id=ep_id,
                        param_id=param_id,
                        context_id=context_id,
                        generation_number=gen,
                        token=next_token,
                        filter_profile=filter_profile,
                        population_size=15
                    )
                    
                    # Insert new test cases
                    for payload in evolved_payloads:
                        test_token = Tokenizer.generate_token()
                        payload_with_token = Tokenizer.replace_token(payload, next_token, test_token)
                        
                        param = self.db.query(Param).filter(Param.id == param_id).first()
                        ep = self.db.query(Endpoint).filter(Endpoint.id == ep_id).first()
                        context = self.db.query(Context).filter(Context.id == context_id).first()
                        
                        priority = 0
                        if param and getattr(param, 'burp_flagged', False):
                            priority += 100
                        sinks = self.db.query(Sink).filter(Sink.context_id == context_id).all()
                        if sinks:
                            priority += 10
                        if context and context.context_type in ['JS_STRING_LITERAL', 'EVENT_HANDLER_ATTR']:
                            priority += 5
                        if ep and ep.method.upper() == 'POST':
                            priority += 3
                        if ep and param and context:
                            priority += ImpactScorer.score_attack_surface(
                                endpoint=ep,
                                param=param,
                                context=context
                            )["score"]
                            
                        new_case = TestCase(
                            experiment_id=experiment_id,
                            endpoint_id=ep_id,
                            param_id=param_id,
                            context_id=context_id,
                            payload=payload_with_token,
                            token=test_token,
                            priority=priority,
                            status=TestCaseStatus.PENDING
                        )
                        self.db.add(new_case)
                        new_cases_count += 1
                
                self.db.commit()
                logger.info(f"Bred and queued {new_cases_count} new test cases for Generation {gen + 1}.")
                
                # If no new cases were bred (e.g. parents had no fitness), break
                if new_cases_count == 0:
                    break

            # Sync experiment status and correlate findings
            _check_experiment_completion(self.db, experiment.id)
            
        else:
            if is_eager:
                logger.info("Eager mode detected. Running test cases sequentially to prevent connection pool exhaustion...")
                batches = 0
                while FuzzingService.queue_next_batch(self.db, experiment.id, max_active=1) > 0:
                    batches += 1
                    finished_cases = self.db.query(TestCase.id).filter(
                        TestCase.experiment_id == experiment.id,
                        TestCase.status.in_([
                            TestCaseStatus.COMPLETED,
                            TestCaseStatus.FAILED,
                            TestCaseStatus.CANCELLED,
                            TestCaseStatus.SKIPPED,
                        ]),
                    ).count()
                    total_cases = self.db.query(TestCase.id).filter(
                        TestCase.experiment_id == experiment.id
                    ).count()
                    progress(
                        "browser",
                        f"Browser evidence updated: {finished_cases}/{total_cases} cases terminal",
                        tool="Chromium execution oracle",
                        completed=finished_cases,
                        total=total_cases,
                        overall_percent=55 + (35 * finished_cases / max(1, total_cases)),
                        doing_status=f"Browser Whirlpool: Executing payload #{batches} ({finished_cases}/{total_cases} finished)",
                        river_stage="browser",
                    )
                    if batches % 10 == 0:
                        gc.collect()
                # Sync experiment status and correlate findings
                from browser_workers.worker import _check_experiment_completion
                _check_experiment_completion(self.db, experiment.id)
            else:
                FuzzingService.queue_next_batch(self.db, experiment.id)

                # Use the same completion path as browser workers so a zero-case
                # run still correlates results and produces its final report.
                from browser_workers.worker import _check_experiment_completion
                _check_experiment_completion(self.db, experiment.id)
                self.db.refresh(experiment)
                
        self.db.commit()
        
        return {
            'experiment_id': experiment_id,
            'test_cases_created': test_cases_created,
            'skipped_out_of_scope': skipped_out_of_scope,
            'status': experiment.status.value
        }

    def _seed_open_redirect_test_cases(self, experiment_id: int, endpoint_ids: List[int]) -> int:
        """Add small, targeted Open Redirect checks for redirect-like parameters."""
        if not endpoint_ids:
            return 0

        try:
            from backend_api.services.auditors.browser_result import is_redirect_candidate_param
        except Exception:
            return 0

        created = 0
        payloads = [
            ("https://example.com/xssboss-open-redirect", "open_redirect_absolute_url"),
            ("//example.com/xssboss-open-redirect", "open_redirect_scheme_relative"),
        ]
        params = (
            self.db.query(Param)
            .filter(Param.endpoint_id.in_(endpoint_ids))
            .filter(Param.location.in_(["query", "body", "json"]))
            .all()
        )

        for param in params:
            if not is_redirect_candidate_param(param.name):
                continue

            for payload, technique in payloads:
                existing = (
                    self.db.query(TestCase)
                    .filter(TestCase.experiment_id == experiment_id)
                    .filter(TestCase.endpoint_id == param.endpoint_id)
                    .filter(TestCase.param_id == param.id)
                    .filter(TestCase.context_id.is_(None))
                    .filter(TestCase.payload == payload)
                    .first()
                )
                if existing:
                    continue

                test_case = TestCase(
                    experiment_id=experiment_id,
                    endpoint_id=param.endpoint_id,
                    param_id=param.id,
                    context_id=None,
                    payload=payload,
                    token=Tokenizer.generate_token(),
                    priority=25,
                    status=TestCaseStatus.PENDING,
                    technique=technique,
                    research_metadata={
                        "auditor": "open_redirect",
                        "classification": "redirect_probe",
                        "evidence_requirement": "browser_final_origin_changed_to_probe_origin",
                        "generated_from": "redirect_like_parameter_name",
                    },
                )
                self.db.add(test_case)
                created += 1

        if created:
            self.db.commit()
        return created

    def _auto_forward_auditor_findings(self, findings: List[Any]) -> None:
        """Forward direct auditor findings to Burp queues using the existing bridge."""
        try:
            from backend_api.services.burp_service import BurpService
            for finding in findings:
                BurpService.auto_forward_finding(self.db, finding)
        except Exception as err:
            logger.error(f"Failed to auto-forward auditor findings to Burp: {err}")

    def _tag_findings_for_experiment(self, findings: List[Any], experiment_id: int) -> None:
        """Associate deduplicated auditor findings with every run that observed them."""
        for finding in findings:
            refs = dict(finding.evidence_refs) if isinstance(finding.evidence_refs, dict) else {}
            raw_experiment_ids = refs.get("experiment_ids", [])
            if not isinstance(raw_experiment_ids, (list, tuple, set)):
                raw_experiment_ids = []
            experiment_ids = set()
            for value in raw_experiment_ids:
                try:
                    experiment_ids.add(int(value))
                except (TypeError, ValueError):
                    continue
            experiment_ids.add(experiment_id)
            refs["experiment_ids"] = sorted(experiment_ids)
            finding.evidence_refs = refs
        self.db.commit()
        for finding in findings:
            RunStateService.observe_finding(
                self.db,
                experiment_id,
                finding.id,
                evidence=finding.evidence_refs if isinstance(finding.evidence_refs, dict) else None,
            )
        try:
            from backend_api.services.research_service import ResearchService

            ResearchService.learn_from_findings(self.db, experiment_id, findings)
        except Exception as research_error:
            logger.warning("Failed to feed direct-auditor findings into research planner: %s", research_error)
    
    def _calculate_priority(self, context: Context, endpoint: Endpoint) -> int:
        """Calculate priority score for a test case."""
        priority = 0
        
        # Check if parameter was flagged by Burp Suite
        if context.param and getattr(context.param, 'burp_flagged', False):
            priority += 100
            
        # Higher priority for contexts with sinks
        sinks = self.db.query(Sink).filter(Sink.context_id == context.id).all()
        if sinks:
            priority += 10
        
        # Higher priority for certain context types
        if context.context_type in ['JS_STRING_LITERAL', 'EVENT_HANDLER_ATTR']:
            priority += 5
        
        # Higher priority for POST endpoints (more likely to be stored)
        if endpoint.method.upper() == 'POST':
            priority += 3

        priority += ImpactScorer.score_attack_surface(
            endpoint=endpoint,
            param=context.param,
            context=context,
        )["score"]
        
        return priority
    
    def correlate_and_create_findings(self, experiment_id: int) -> List[Dict[str, Any]]:
        """Correlate execution results and create findings."""
        experiment = self.db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        # Invoke ResultService to build and map findings
        findings = ResultService.correlate_executions(self.db, experiment_id)
        
        findings_created = []
        for finding in findings:
            findings_created.append({
                'finding_id': finding.id,
                'endpoint_id': finding.endpoint_id,
                'param_id': finding.param_id,
                'payload': finding.best_payload
            })
        
        return findings_created

    @staticmethod
    def queue_next_batch(db: Session, experiment_id: int, max_active: int = None) -> int:
        """Queue the next batch of pending test cases if experiment is running.
        
        Args:
            db: Database session
            experiment_id: Experiment ID
            max_active: Maximum number of concurrent active test cases
            
        Returns:
            Number of test cases queued in this batch
        """
        from datetime import datetime, timedelta
        from backend_api.utils.logger import logger
        from backend_api.models.experiment import Experiment, ExperimentStatus
        from backend_api.models.test_case import TestCase, TestCaseStatus
        from backend_api.utils.scope_guard import is_endpoint_in_scope
        from backend_api.services.log_service import LogService
        from browser_workers.worker import execute_test_case_task

        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment or experiment.status != ExperimentStatus.RUNNING:
            return 0

        if max_active is None:
            requested_concurrency = None
            limits = experiment.limits if isinstance(experiment.limits, dict) else {}
            try:
                requested_concurrency = int(limits.get("concurrency")) if limits.get("concurrency") is not None else None
            except (TypeError, ValueError):
                logger.warning(f"Ignoring invalid concurrency limit: {limits.get('concurrency')!r}")
            max_active = settings.MAX_QUEUE_ACTIVE
            if requested_concurrency is not None:
                max_active = min(max_active, max(1, requested_concurrency))
        max_active = max(1, int(max_active))

        # Browser navigation plus a Celery retry countdown can legitimately take
        # more than 60 seconds. A five-minute lease avoids failing live work and
        # then executing its already-scheduled retry a second time.
        timeout_threshold = datetime.utcnow() - timedelta(minutes=5)
        stuck_tasks = db.query(TestCase).filter(
            TestCase.experiment_id == experiment_id,
            TestCase.status.in_([TestCaseStatus.QUEUED, TestCaseStatus.RUNNING]),
            TestCase.updated_at < timeout_threshold
        ).all()
        
        if stuck_tasks:
            logger.warning(f"Detected {len(stuck_tasks)} stuck test cases. Marking as FAILED to recover slots.")
            for task in stuck_tasks:
                task.status = TestCaseStatus.FAILED
            db.commit()
            LogService.error(
                "queue",
                f"Marked {len(stuck_tasks)} stale browser case(s) failed",
                experiment_id=experiment_id,
                target_id=experiment.target_id,
                data={
                    "event_type": "stale_cases_failed",
                    "test_case_ids": [task.id for task in stuck_tasks],
                },
                db=db,
            )

        # Count active test cases
        active_count = db.query(TestCase).filter(
            TestCase.experiment_id == experiment_id,
            TestCase.status.in_([TestCaseStatus.QUEUED, TestCaseStatus.RUNNING])
        ).count()
        
        slots_available = max_active - active_count
        if slots_available <= 0:
            return 0
            
        # Get next pending test cases sorted by priority
        next_tasks = db.query(TestCase).filter(
            TestCase.experiment_id == experiment_id,
            TestCase.status == TestCaseStatus.PENDING
        ).order_by(TestCase.priority.desc()).limit(slots_available).all()
        
        queued_count = 0
        for task in next_tasks:
            if not task.endpoint or not is_endpoint_in_scope(task.endpoint):
                logger.warning(f"Failing out-of-scope test case {task.id} before queueing")
                task.status = TestCaseStatus.FAILED
                db.commit()
                LogService.error(
                    "queue",
                    f"Rejected out-of-scope test case #{task.id}",
                    experiment_id=experiment_id,
                    target_id=experiment.target_id,
                    data={
                        "event_type": "queue_rejected_out_of_scope",
                        "test_case_id": task.id,
                        "endpoint": task.endpoint.url_pattern if task.endpoint else None,
                    },
                    db=db,
                )
                continue

            task.status = TestCaseStatus.QUEUED
            db.commit()
            LogService.debug(
                "queue",
                f"Queued test case #{task.id}",
                experiment_id=experiment_id,
                target_id=experiment.target_id,
                data={
                    "event_type": "test_case_queued",
                    "test_case_id": task.id,
                    "priority": task.priority,
                    "endpoint": task.endpoint.url_pattern if task.endpoint else None,
                    "param": task.param.name if task.param else None,
                    "param_location": task.param.location if task.param else None,
                    "context": task.context.context_type if task.context else None,
                    "technique": task.technique,
                    "payload": task.payload,
                },
                db=db,
            )
            execute_test_case_task.delay(task.id)
            queued_count += 1
            
        if queued_count > 0:
            logger.info(f"Queued {queued_count} test cases for experiment {experiment_id} (active: {active_count + queued_count}/{max_active})")
            
        return queued_count

