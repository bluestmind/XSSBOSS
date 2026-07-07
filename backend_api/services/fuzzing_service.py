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
import sys
import os
import gc

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
                logger.info(f"CORS auditor created/updated {len(cors_findings)} finding(s).")
                self._auto_forward_auditor_findings(cors_findings)
        except Exception as cors_err:
            logger.warning(f"CORS auditor failed: {cors_err}")

        try:
            from backend_api.services.auditors.path_traversal import PathTraversalAuditor
            lfi_findings = PathTraversalAuditor.audit_endpoints(self.db, endpoints)
            if lfi_findings:
                logger.info(f"Path traversal auditor created/updated {len(lfi_findings)} finding(s).")
                self._auto_forward_auditor_findings(lfi_findings)
        except Exception as lfi_err:
            logger.warning(f"Path traversal auditor failed: {lfi_err}")

        try:
            from backend_api.services.auditors.sqli import ErrorBasedSqliAuditor
            sqli_findings = ErrorBasedSqliAuditor.audit_endpoints(self.db, endpoints)
            if sqli_findings:
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
        
        test_cases_created = 0
        strategy_val = experiment.strategy.value
        if strategy_val in ["max_coverage", "genetic_evolutionary"]:
            max_total_cases = 100000
        else:
            max_total_cases = max(1, settings.MAX_TEST_CASES_PER_EXPERIMENT)
        
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
                    
                    strategy = Strategy(strategy_val)
                    for context in param_contexts:
                        token = Tokenizer.generate_token()
                        try:
                            context_type_enum = ContextType(context.context_type)
                        except ValueError:
                            continue
                        
                        max_p = None if strategy_val in ["max_coverage", "genetic_evolutionary"] else settings.MAX_PAYLOADS_PER_CONTEXT
                        payloads = self.payload_generator.generate_payloads(
                            context_type=context_type_enum,
                            token=token,
                            strategy=strategy,
                            filter_profile=filter_profile,
                            max_payloads=max_p,
                        )
                        
                        for payload in payloads:
                            experiment_case_count = local_db.query(TestCase).filter(
                                TestCase.experiment_id == experiment_id
                            ).count()
                            if experiment_case_count >= max_total_cases:
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
                            local_db.add(test_case)
                            local_db.flush()
                            local_cases += 1

                        if local_cases >= max_total_cases:
                            break
                    if local_cases >= max_total_cases:
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
                    # Get filter profile for endpoint and update with telemetry error analysis
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
                                    try:
                                        import ast
                                        logs_dict = ast.literal_eval(exec_obj.logs)
                                        if isinstance(logs_dict, dict):
                                            errors.extend(logs_dict.get('errors', []))
                                            console.extend(logs_dict.get('console', []))
                                            if logs_dict.get('sink'):
                                                sinks.append(logs_dict.get('sink'))
                                    except Exception:
                                        try:
                                            import json
                                            logs_dict = json.loads(exec_obj.logs)
                                            if isinstance(logs_dict, dict):
                                                errors.extend(logs_dict.get('errors', []))
                                                console.extend(logs_dict.get('console', []))
                                                if logs_dict.get('sink'):
                                                    sinks.append(logs_dict.get('sink'))
                                        except Exception:
                                            pass
                            
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
                        
                        # Calculate priority score
                        
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
                
                # Check if experiment is completed (all generated test cases completed/failed)
                total_remaining = self.db.query(TestCase).filter(
                    TestCase.experiment_id == experiment.id,
                    TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED, TestCaseStatus.RUNNING])
                ).count()
                
                if total_remaining == 0 and experiment.status == ExperimentStatus.RUNNING:
                    experiment.status = ExperimentStatus.COMPLETED
                    experiment.completed_at = datetime.utcnow()
                
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
        max_active = max_active or settings.MAX_QUEUE_ACTIVE
        
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment or experiment.status != ExperimentStatus.RUNNING:
            return 0
            
        # Timeout Recovery: Recover stuck tasks (running/queued for >60s) to prevent queue locks
        timeout_threshold = datetime.utcnow() - timedelta(seconds=60)
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

