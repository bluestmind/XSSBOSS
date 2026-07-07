"""Celery worker for browser execution."""
from celery import Celery
from sqlalchemy.orm import Session
from pathlib import Path
from typing import Dict, Any
import os

from backend_api.db.session import get_db
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from browser_workers.executor import BrowserExecutor
from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.utils.scope_guard import is_endpoint_in_scope
from backend_api.utils.rate_limiter import rate_limiter, CircuitOpenError

# Initialize Celery app
is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')

celery_app = Celery(
    'browser_workers',
    broker=settings.REDIS_URL,
    backend=None if is_eager else settings.REDIS_URL
)

# Celery configuration
celery_app.conf.update(
    task_always_eager=is_eager,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

def _check_experiment_completion(db: Session, experiment_id: int):
    """Check if all test cases for the experiment are completed/failed, and mark experiment COMPLETED."""
    try:
        from datetime import datetime
        from backend_api.models.experiment import Experiment, ExperimentStatus
        from backend_api.models.test_case import TestCase, TestCaseStatus
        from backend_api.services.fuzzing_service import FuzzingService
        
        non_final_count = db.query(TestCase).filter(
            TestCase.experiment_id == experiment_id,
            TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED, TestCaseStatus.RUNNING])
        ).count()
        
        if non_final_count == 0:
            experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
            if experiment and experiment.status == ExperimentStatus.RUNNING:
                experiment.status = ExperimentStatus.COMPLETED
                experiment.completed_at = datetime.utcnow()
                db.commit()
                logger.info(f"Experiment {experiment_id} status updated to COMPLETED. Correlating findings...")
                
                # Automatically correlate and create findings
                fuzzer = FuzzingService(db)
                findings = fuzzer.correlate_and_create_findings(experiment_id)
                logger.info(f"Created/correlated {len(findings)} findings for experiment {experiment_id}.")
                
                # Automatically generate campaign HTML and Markdown reports
                try:
                    from backend_api.services.campaign_report_service import CampaignReportService
                    CampaignReportService.generate_report(db, experiment_id)
                except Exception as rep_err:
                    logger.error(f"Failed to generate automated campaign report: {rep_err}", exc_info=True)
    except Exception as e:
        logger.error(f"Error checking experiment completion for {experiment_id}: {e}", exc_info=True)

import threading
_local_storage = threading.local()

def get_browser_executor():
    """Retrieve or initialize the persistent thread-local browser executor."""
    if not hasattr(_local_storage, 'executor') or _local_storage.executor is None:
        logger.info("Initializing persistent thread-local browser executor...")
        _local_storage.executor = BrowserExecutor(oracle_url=settings.ORACLE_SERVER_URL + "/api/v1/oracle")
        _local_storage.executor.start()
        _local_storage.runs = 0
    else:
        try:
            # Check responsiveness by checking browser connection status
            if settings.USE_UNDETECTED_CHROME:
                if not _local_storage.executor.uc_driver or _local_storage.executor.uc_driver.service.process.poll() is not None:
                    raise RuntimeError("Undetected Chrome disconnected")
            else:
                if not _local_storage.executor.browser or not _local_storage.executor.browser.is_connected():
                    raise RuntimeError("Browser disconnected")
        except Exception:
            logger.warning("Thread-local worker browser is unresponsive. Recreating...")
            stop_browser_executor()
            _local_storage.executor = BrowserExecutor(oracle_url=settings.ORACLE_SERVER_URL + "/api/v1/oracle")
            _local_storage.executor.start()
            _local_storage.runs = 0
            
    return _local_storage.executor


def stop_browser_executor():
    """Shutdown thread-local browser executor cleanly."""
    if hasattr(_local_storage, 'executor') and _local_storage.executor is not None:
        try:
            _local_storage.executor.stop()
        except Exception as err:
            logger.warning(f"Failed to stop thread-local browser: {err}")
        _local_storage.executor = None
        _local_storage.runs = 0


def recycle_browser_if_needed():
    """Periodically restart Chrome so long scans do not retain renderer memory."""
    runs = getattr(_local_storage, 'runs', 0)
    restart_every = max(0, settings.BROWSER_RESTART_EVERY_TESTS)
    if not restart_every or runs < restart_every:
        return

    logger.info(f"Restarting thread-local browser after {runs} payload checks to release memory...")
    stop_browser_executor()


from celery.signals import worker_process_shutdown

@worker_process_shutdown.connect
def shutdown_worker_browser(**kwargs):
    """Shutdown persistent browser driver cleanly when worker process terminates."""
    logger.info("Stopping thread-local browser executor on worker process shutdown...")
    stop_browser_executor()



@celery_app.task(name='execute_test_case', bind=True, max_retries=3)
def execute_test_case_task(self, test_case_id: int, worker_id: str = None):
    """Execute a test case in browser.
    
    Args:
        test_case_id: Test case ID
        worker_id: Worker identifier
        
    Returns:
        Execution result dictionary
    """
    db: Session = next(get_db())
    
    
    try:
        # Get test case
        test_case = db.query(TestCase).filter(TestCase.id == test_case_id).first()
        if not test_case:
            raise ValueError(f"Test case {test_case_id} not found")
        
        # Check if experiment is paused
        from backend_api.models.experiment import ExperimentStatus
        if test_case.experiment.status == ExperimentStatus.PAUSED:
            test_case.status = TestCaseStatus.PENDING
            db.commit()
            logger.info(f"Test case {test_case_id} execution deferred because experiment {test_case.experiment_id} is PAUSED.")
            return {
                'test_case_id': test_case_id,
                'status': 'deferred_paused'
            }

        if not test_case.endpoint or not is_endpoint_in_scope(test_case.endpoint):
            test_case.status = TestCaseStatus.FAILED
            db.commit()
            logger.warning(f"Blocked out-of-scope test case {test_case_id} before browser execution.")

            is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
            if not is_eager:
                from backend_api.services.fuzzing_service import FuzzingService
                FuzzingService.queue_next_batch(db, test_case.experiment_id)
                _check_experiment_completion(db, test_case.experiment_id)

            return {
                'test_case_id': test_case_id,
                'status': 'blocked_out_of_scope'
            }
        
        # Update status
        test_case.status = TestCaseStatus.RUNNING
        db.commit()
        
        # Get endpoint and param
        endpoint = test_case.endpoint
        param = test_case.param
        
        # Build request data
        url = endpoint.url_pattern
        method = endpoint.method
        
        # Get headers and cookies
        headers = (endpoint.auth_context or {}).copy()
        cookies = {}
        if 'Cookie' in headers:
            cookie_str = headers.pop('Cookie')
            for cookie_pair in cookie_str.split(';'):
                if '=' in cookie_pair:
                    key, value = cookie_pair.split('=', 1)
                    cookies[key.strip()] = value.strip()
        
        # Build request body/params based on param location
        body = None
        json_data = None
        params = {}
        
        # Get all parameters of the endpoint to preserve other parameters
        all_params = db.query(Param).filter(Param.endpoint_id == endpoint.id).all()
        
        # Build path parameter values map
        path_params = {
            p.name: (p.sample_value or "1")
            for p in all_params
            if p.location == "path"
        }
        for p_name, p_val in path_params.items():
            placeholder = f"{{{p_name}}}"
            if param.location == "path" and param.name == p_name:
                url = url.replace(placeholder, test_case.payload)
            else:
                url = url.replace(placeholder, p_val)
        
        # Load sample request body or JSON
        if endpoint.sample_request_body and isinstance(endpoint.sample_request_body, dict):
            if any(p.location == "json" for p in all_params) or param.location == "json":
                json_data = endpoint.sample_request_body.copy()
            elif any(p.location == "body" for p in all_params) or param.location == "body":
                body = endpoint.sample_request_body.copy()

        # Fill in other parameters
        for p in all_params:
            if p.location == param.location and p.name == param.name:
                continue
            if p.location == "query":
                params[p.name] = p.sample_value or ""
            elif p.location == "body":
                if body is None:
                    body = {}
                body[p.name] = p.sample_value or ""
            elif p.location == "json":
                if json_data is None:
                    json_data = {}
                keys = p.name.split('.')
                current = json_data
                for key in keys[:-1]:
                    if key not in current or not isinstance(current[key], dict):
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = p.sample_value or ""
            elif p.location == "header":
                headers[p.name] = p.sample_value or ""
            elif p.location == "cookie":
                cookies[p.name] = p.sample_value or ""

        # Set the active fuzzed parameter (parsing Prototype Pollution key-values if applicable)
        is_proto_pollution = False
        if "=" in test_case.payload:
            key_candidate, val_candidate = test_case.payload.split("=", 1)
            if "__proto__" in key_candidate or "constructor" in key_candidate:
                is_proto_pollution = True

        if is_proto_pollution:
            key_candidate, val_candidate = test_case.payload.split("=", 1)
            if param.location == "query":
                params[key_candidate] = val_candidate
            elif param.location == "body":
                if body is None:
                    body = {}
                body[key_candidate] = val_candidate
            elif param.location == "json":
                if json_data is None:
                    json_data = {}
                json_data[key_candidate] = val_candidate
            elif param.location == "cookie":
                cookies[key_candidate] = val_candidate
            elif param.location == "header":
                headers[key_candidate] = val_candidate
        else:
            if param.location == "query":
                params[param.name] = test_case.payload
            elif param.location == "body":
                if body is None:
                    body = {}
                body[param.name] = test_case.payload
            elif param.location == "json":
                if json_data is None:
                    json_data = {}
                keys = param.name.split('.')
                current = json_data
                for key in keys[:-1]:
                    if key not in current or not isinstance(current[key], dict):
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = test_case.payload
            elif param.location == "header":
                headers[param.name] = test_case.payload
            elif param.location == "cookie":
                cookies[param.name] = test_case.payload
        
        # Automatically discover and associate stored GET view endpoints for POST test cases
        stored_view_url = None
        if method == 'POST':
            try:
                sibling_endpoints = db.query(Endpoint).filter(
                    Endpoint.target_id == endpoint.target_id,
                    Endpoint.method == 'GET'
                ).all()
                for sib in sibling_endpoints:
                    if 'view' in sib.url_pattern.lower() or 'show' in sib.url_pattern.lower():
                        from urllib.parse import urlparse, urlunparse
                        parsed_root = urlparse(url)
                        parsed_sib = urlparse(sib.url_pattern)
                        stored_view_url = urlunparse((
                            parsed_root.scheme,
                            parsed_root.netloc,
                            parsed_sib.path,
                            parsed_sib.params,
                            parsed_sib.query,
                            parsed_sib.fragment
                        ))
                        logger.info(f"Associated Stored XSS view URL: {stored_view_url} for POST endpoint {endpoint.url_pattern}")
                        break
            except Exception as e:
                logger.warning(f"Failed to resolve Stored XSS sibling endpoints: {e}")

        # Prepare test case data
        test_case_data = {
            'test_case_id': test_case_id,
            'method': method,
            'url': url,
            'headers': headers,
            'cookies': cookies,
            'params': params,
            'body': body,
            'json': json_data,
            'token': test_case.token,
            'stored_view_url': stored_view_url,
            'payload': test_case.payload,
            'steps': endpoint.custom_steps,
        }
        
        # Screenshot directory
        screenshot_dir = Path(os.getenv('SCREENSHOT_DIR', './screenshots'))
        
        # Retrieve persistent browser executor
        executor = get_browser_executor()
        
        # Reset browser session to prevent state leakage (cookies and DOM)
        try:
            if settings.USE_UNDETECTED_CHROME:
                if not executor.uc_driver or executor.uc_driver.service.process.poll() is not None:
                    raise RuntimeError("Undetected Chrome disconnected")
            else:
                if not executor.browser or not executor.browser.is_connected():
                    raise RuntimeError("Browser disconnected")
        except Exception as reset_err:
            logger.warning(f"Failed to verify browser connection status: {reset_err}. Recreating browser...")
            stop_browser_executor()
            executor = get_browser_executor()
            
        # --- Rate limiter: wait for a slot before hitting the target ---
        target_url = test_case_data['url']
        try:
            waited_s = rate_limiter.wait_for_slot(target_url)
            if waited_s > 0.1:
                logger.info(f"Rate limiter: waited {waited_s:.1f}s before test case {test_case_id}")
        except CircuitOpenError as cb_err:
            logger.warning(f"Circuit breaker blocks execution: {cb_err}")
            # Mark test case as FAILED
            test_case.status = TestCaseStatus.FAILED
            db.commit()
            
            # Record warning in experiment limits
            try:
                experiment = test_case.experiment
                limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
                warnings = list(limits.get("warnings", []))
                warning = {
                    "level": "error",
                    "phase": "execution",
                    "message": f"Circuit breaker tripped for {rate_limiter._host_from_url(target_url)}",
                    "detail": str(cb_err),
                }
                if not any(isinstance(item, dict) and item.get("message") == warning["message"] for item in warnings):
                    warnings.append(warning)
                limits["warnings"] = warnings[-12:]
                experiment.limits = limits
                db.commit()
            except Exception as db_err:
                logger.error(f"Failed to record circuit breaker warning to DB: {db_err}")
                
            # Queue next batch of pending tasks
            is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
            if not is_eager:
                from backend_api.services.fuzzing_service import FuzzingService
                FuzzingService.queue_next_batch(db, test_case.experiment_id)
                _check_experiment_completion(db, test_case.experiment_id)
                
            if hasattr(_local_storage, 'runs'):
                _local_storage.runs += 1
            else:
                _local_storage.runs = 1
            recycle_browser_if_needed()
            
            return {
                'test_case_id': test_case_id,
                'error': str(cb_err),
                'status': 'skipped_circuit_open'
            }
        
        try:
            result = executor.execute_test_case(test_case_data, screenshot_dir)
            try:
                from backend_api.services.auditors.browser_result import BrowserResultAuditor
                auditor_vuln = BrowserResultAuditor.audit(test_case, test_case_data, result)
                if auditor_vuln:
                    result["oracle_hit"] = True
                    logs = result.get("logs") if isinstance(result.get("logs"), dict) else {}
                    logs["auditor_vuln"] = auditor_vuln
                    result["logs"] = logs
                    logger.info(
                        "Auditor confirmed %s for test case %s",
                        auditor_vuln.get("title", auditor_vuln.get("vuln_type", "vulnerability")),
                        test_case_id,
                    )
            except Exception as audit_err:
                logger.warning(f"Browser result auditor failed for test case {test_case_id}: {audit_err}")
            
            # Create execution record
            execution = Execution(
                test_case_id=test_case_id,
                browser_worker_id=worker_id or os.getenv('HOSTNAME', 'unknown'),
                oracle_status=OracleStatus.HIT if result['oracle_hit'] else OracleStatus.MISSED,
                oracle_token=test_case.token if result['oracle_hit'] else None,
                logs=str(result.get('logs', {})),
                screenshot_path=result.get('screenshot_path'),
                dom_snapshot=result.get('dom_snapshot'),
                duration_ms=result.get('duration_ms'),
            )
            db.add(execution)
            
            # Update test case status
            test_case.status = TestCaseStatus.COMPLETED
            db.commit()

            # Correlate findings live on hit
            if result['oracle_hit']:
                try:
                    from backend_api.services.fuzzing_service import FuzzingService
                    fuzzer = FuzzingService(db)
                    fuzzer.correlate_and_create_findings(test_case.experiment_id)
                except Exception as corr_err:
                    logger.warning(f"Live findings correlation failed for test case {test_case_id}: {corr_err}")
            
            # Queue next batch of pending tasks
            is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
            if not is_eager:
                from backend_api.services.fuzzing_service import FuzzingService
                FuzzingService.queue_next_batch(db, test_case.experiment_id)
                _check_experiment_completion(db, test_case.experiment_id)
            
            logger.info(f"Test case {test_case_id} executed: oracle_hit={result['oracle_hit']}")
            
            # --- Rate limiter: check response status and headers ---
            status_code = result.get('status_code')
            headers = result.get('headers') or {}
            
            is_rate_limited = False
            retry_after_secs = None
            
            if status_code in [429, 403]:
                is_rate_limited = True
                retry_after_str = headers.get('retry-after')
                if retry_after_str:
                    try:
                        retry_after_secs = float(retry_after_str)
                    except ValueError:
                        pass
            
            if not is_rate_limited and result.get('logs'):
                logs_data = result['logs']
                errors = logs_data.get('errors', []) if isinstance(logs_data, dict) else []
                for err in errors:
                    err_lower = str(err).lower()
                    if any(kw in err_lower for kw in ['429', 'too many requests', 'rate limit', 'access denied', 'forbidden']):
                        is_rate_limited = True
                        break
            
            if is_rate_limited:
                rate_limiter.report_error(target_url, is_rate_limit=True, retry_after_secs=retry_after_secs)
                try:
                    experiment = test_case.experiment
                    limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
                    warnings = list(limits.get("warnings", []))
                    warning = {
                        "level": "warning",
                        "phase": "execution",
                        "message": f"Rate limit / WAF warning from {rate_limiter._host_from_url(target_url)}",
                        "detail": f"Status: {status_code}. Retry-After: {retry_after_secs}s. Adaptive delay increased.",
                    }
                    if not any(isinstance(item, dict) and item.get("message") == warning["message"] for item in warnings):
                        warnings.append(warning)
                    limits["warnings"] = warnings[-12:]
                    experiment.limits = limits
                    db.commit()
                except Exception as db_err:
                    logger.error(f"Failed to record rate limit warning to DB: {db_err}")
            else:
                rate_limiter.report_success(target_url)
            
            if hasattr(_local_storage, 'runs'):
                _local_storage.runs += 1
            else:
                _local_storage.runs = 1
            recycle_browser_if_needed()
            
            return {
                'test_case_id': test_case_id,
                'execution_id': execution.id,
                'oracle_hit': result['oracle_hit'],
                'duration_ms': result.get('duration_ms'),
            }
        
        except Exception as run_err:
            # Recreate browser on unexpected runner errors
            logger.error(f"Execution run error: {run_err}. Restarting driver...")
            # --- Rate limiter: report error with timeout detection ---
            err_str = str(run_err).lower()
            is_rate_signal = any(kw in err_str for kw in [
                'timeout', 'timed out', '429', 'rate limit', 'connection refused',
                'connection reset', 'err_connection', 'access denied'
            ])
            rate_limiter.report_error(target_url, is_rate_limit=is_rate_signal)
            stop_browser_executor()
            raise run_err
    
    except Exception as e:
        logger.error(f"Error executing test case {test_case_id}: {e}", exc_info=True)
        
        # Update test case status
        if 'test_case' in locals():
            test_case.status = TestCaseStatus.FAILED
            db.commit()
            if hasattr(_local_storage, 'runs'):
                _local_storage.runs += 1
            else:
                _local_storage.runs = 1
            recycle_browser_if_needed()
            
            # Queue next batch of pending tasks
            is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
            if not is_eager:
                from backend_api.services.fuzzing_service import FuzzingService
                FuzzingService.queue_next_batch(db, test_case.experiment_id)
                _check_experiment_completion(db, test_case.experiment_id)
        
        # Retry if not max retries
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e, countdown=60)
        
        raise
    
    finally:
        db.close()
