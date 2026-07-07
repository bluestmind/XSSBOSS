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
from backend_api.services.result_service import ResultService
from backend_api.utils.tokenizer import Tokenizer
from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.services.run_state_service import RunStateService
import sys
import os
import gc
import threading

# Add workspace root to path for cross-module imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from analysis_engine.detect_context import ContextDetectorEngine
from analysis_engine.detect_filter import FilterDetectorEngine
from fuzzer.generator import PayloadGenerator
from fuzzer.strategy import Strategy


class FuzzingService:
    """Service for orchestrating the fuzzing pipeline."""
    
    def __init__(self, db: Session):
        """Initialize with database session."""
        self.db = db
        self.context_detector = ContextDetectorEngine(db)
        self.filter_detector = FilterDetectorEngine(db)
        self.payload_generator = PayloadGenerator()
    
    def run_experiment(self, experiment_id: int) -> Dict[str, Any]:
        """Run a complete fuzzing experiment."""

        from concurrent.futures import ThreadPoolExecutor, as_completed
        from backend_api.db.base import SessionLocal
        
        experiment = self.db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        # Start or resume experiment status to RUNNING
        experiment = ExperimentService.start_experiment(self.db, experiment_id)

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

        endpoints = in_scope_endpoints
        endpoint_ids = [ep.id for ep in endpoints]

        try:
            from backend_api.services.auditors.cors import CorsAuditor
            cors_findings = CorsAuditor.audit_endpoints(self.db, endpoints)
            if cors_findings:
                self._tag_findings_for_experiment(cors_findings, experiment_id)
                logger.info(f"CORS auditor created/updated {len(cors_findings)} finding(s).")
                self._auto_forward_auditor_findings(cors_findings)
        except Exception as cors_err:
            logger.warning(f"CORS auditor failed: {cors_err}")

        try:
            from backend_api.services.auditors.path_traversal import PathTraversalAuditor
            lfi_findings = PathTraversalAuditor.audit_endpoints(self.db, endpoints)
            if lfi_findings:
                self._tag_findings_for_experiment(lfi_findings, experiment_id)
                logger.info(f"Path traversal auditor created/updated {len(lfi_findings)} finding(s).")
                self._auto_forward_auditor_findings(lfi_findings)
        except Exception as lfi_err:
            logger.warning(f"Path traversal auditor failed: {lfi_err}")

        try:
            from backend_api.services.auditors.sqli import ErrorBasedSqliAuditor
            sqli_findings = ErrorBasedSqliAuditor.audit_endpoints(self.db, endpoints)
            if sqli_findings:
                self._tag_findings_for_experiment(sqli_findings, experiment_id)
                logger.info(f"SQLi auditor created/updated {len(sqli_findings)} finding(s).")
                self._auto_forward_auditor_findings(sqli_findings)
        except Exception as sqli_err:
            logger.warning(f"SQLi auditor failed: {sqli_err}")


        try:
            from backend_api.services.auditors.ssrf import SsrfCanaryAuditor
            ssrf_canaries = SsrfCanaryAuditor.audit_endpoints(self.db, experiment_id, endpoints)
            if ssrf_canaries:
                logger.info(f"SSRF canary auditor sent {ssrf_canaries} collaborator probe(s).")
        except Exception as ssrf_err:
            logger.warning(f"SSRF canary auditor failed: {ssrf_err}")
        
        try:
            from backend_api.services.auditors.redirect import RedirectAuditor
            redirect_findings = RedirectAuditor.audit_endpoints(self.db, endpoints)
            if redirect_findings:
                self._tag_findings_for_experiment(redirect_findings, experiment_id)
                logger.info(f"Redirect auditor created/updated {len(redirect_findings)} finding(s).")
                self._auto_forward_auditor_findings(redirect_findings)
        except Exception as redir_err:
            logger.warning(f"Redirect auditor failed: {redir_err}")

        try:
            from backend_api.services.auditors.crlf_injection import CRLFInjectionAuditor
            crlf_findings = CRLFInjectionAuditor.audit_endpoints(self.db, endpoints)
            if crlf_findings:
                self._tag_findings_for_experiment(crlf_findings, experiment_id)
                logger.info(f"CRLF auditor created/updated {len(crlf_findings)} finding(s).")
                self._auto_forward_auditor_findings(crlf_findings)
        except Exception as crlf_err:
            logger.warning(f"CRLF auditor failed: {crlf_err}")

        try:
            from backend_api.services.auditors.dangling_markup import DanglingMarkupAuditor
            dm_findings = DanglingMarkupAuditor.audit_endpoints(self.db, endpoints)
            if dm_findings:
                self._tag_findings_for_experiment(dm_findings, experiment_id)
                logger.info(f"Dangling markup auditor created/updated {len(dm_findings)} finding(s).")
                self._auto_forward_auditor_findings(dm_findings)
        except Exception as dm_err:
            logger.warning(f"Dangling markup auditor failed: {dm_err}")

        try:
            from backend_api.services.auditors.cache_deception import CacheDeceptionAuditor
            cd_findings = CacheDeceptionAuditor.audit_endpoints(self.db, endpoints)
            if cd_findings:
                self._tag_findings_for_experiment(cd_findings, experiment_id)
                logger.info(f"Cache deception auditor created/updated {len(cd_findings)} finding(s).")
                self._auto_forward_auditor_findings(cd_findings)
        except Exception as cd_err:
            logger.warning(f"Cache deception auditor failed: {cd_err}")
        
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
                
                # Load detectors with thread-local db session
                flt_detector = FilterDetectorEngine(local_db)

                # Step 1: Use already-stored contexts from DB (set by recon phase).
                # Re-probing via HTTP misses JS-rendered sinks, and duplicates work.
                # Only fall back to live probing when the DB has nothing yet.
                contexts = local_db.query(Context).filter(Context.endpoint_id == ep_id).all()
                if not contexts:
                    ctx_detector = ContextDetectorEngine(local_db)
                    contexts = ctx_detector.detect_contexts_for_endpoint(ep_id)
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

                params = local_db.query(Param).filter(Param.endpoint_id == ep_id).all()
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

                        max_p = max(1, settings.MAX_PAYLOADS_PER_CONTEXT)
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
                return local_cases
            except Exception as e:
                logger.error(f"Error in process_endpoint {ep_id}: {e}", exc_info=True)
                return 0
            finally:
                local_db.close()
        
        # Run thread pool for concurrent context detection and filter profiling
        max_workers = min(settings.MAX_PROFILING_WORKERS, len(endpoint_ids)) if endpoint_ids else 1
        logger.info(f"Starting concurrent profiling for {len(endpoint_ids)} endpoints with {max_workers} workers...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_endpoint, ep_id): ep_id for ep_id in endpoint_ids}
            for future in as_completed(futures):
                ep_id = futures[future]
                try:
                    created_count = future.result()
                    test_cases_created += created_count
                except Exception as e:
                    logger.error(f"Thread execution error for endpoint {ep_id}: {e}", exc_info=True)
        
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
                                    from backend_api.utils.log_serializer import parse_execution_logs
                                    logs_dict = parse_execution_logs(exec_obj.logs)
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
            "https://example.com/xssboss-open-redirect",
            "//example.com/xssboss-open-redirect",
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

            for payload in payloads:
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
                continue

            task.status = TestCaseStatus.QUEUED
            db.commit()
            execute_test_case_task.delay(task.id)
            queued_count += 1
            
        if queued_count > 0:
            logger.info(f"Queued {queued_count} test cases for experiment {experiment_id} (active: {active_count + queued_count}/{max_active})")
            
        return queued_count

