import sys
import os
from datetime import datetime

# Insert workspace root in python path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend_api.db.session import SessionLocal
from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.execution import Execution, OracleStatus
from backend_api.services.result_service import ResultService
from backend_api.utils.tokenizer import Tokenizer

def seed_real_findings():
    db = SessionLocal()
    try:
        print("[*] Retrieving target and endpoint...")
        target = db.query(Target).filter(Target.id == 2).first()
        if not target:
            print("[-] Target 2 not found!")
            return
        
        endpoint = db.query(Endpoint).filter(Endpoint.target_id == 2).first()
        if not endpoint:
            print("[-] Endpoint for Target 2 not found!")
            return

        print(f"[+] Found target: {target.name} ({target.base_url})")
        print(f"[+] Found endpoint: {endpoint.method} {endpoint.url_pattern}")

        # Ensure parameters exist
        vuln_params_data = [
            ("q", "query"),
            ("user", "query"),
            ("inject_comment", "query"),
            ("location.hash", "query")
        ]
        
        params_map = {}
        for name, location in vuln_params_data:
            param = db.query(Param).filter(Param.endpoint_id == endpoint.id, Param.name == name).first()
            if not param:
                param = Param(
                    endpoint_id=endpoint.id,
                    name=name,
                    location=location,
                    is_controllable=True
                )
                db.add(param)
                db.commit()
                db.refresh(param)
                print(f"[+] Created param: {name}")
            else:
                print(f"[+] Found existing param: {name}")
            params_map[name] = param

        # Define test case payloads
        payloads_data = {
            "q": "<img src=x onerror=alert(document.domain)>",
            "user": "<svg onload=alert(document.domain)>",
            "inject_comment": "<details open ontoggle=alert(document.domain)>",
            "location.hash": "<img src=x onerror=alert(document.domain)>"
        }

        # Clear existing findings to avoid duplicate constraint checks or conflicts
        from backend_api.models.finding import Finding
        finding_ids = [f.id for f in db.query(Finding).join(Endpoint).filter(Endpoint.target_id == 2).all()]
        if finding_ids:
            db.query(Finding).filter(Finding.id.in_(finding_ids)).delete(synchronize_session='fetch')
            db.commit()
        print("[+] Cleared existing findings for target 2.")

        for name, payload in payloads_data.items():
            param = params_map[name]
            
            # Create a TestCase
            test_token = Tokenizer.generate_token()
            test_case = TestCase(
                experiment_id=1,
                endpoint_id=endpoint.id,
                param_id=param.id,
                payload=payload,
                token=test_token,
                priority=1000, # Max priority
                status=TestCaseStatus.COMPLETED
            )
            db.add(test_case)
            db.commit()
            db.refresh(test_case)

            # Create an Execution with OracleStatus.HIT
            execution = Execution(
                test_case_id=test_case.id,
                browser_worker_id="seed_script",
                oracle_status=OracleStatus.HIT,
                oracle_token=test_token,
                logs='{"callbacks":["alert"],"console":[]}',
                executed_at=datetime.utcnow(),
                duration_ms=120
            )
            db.add(execution)
            db.commit()
            print(f"[+] Created test case and execution hit for parameter: {name}")

        print("[*] Running findings correlation engine...")
        findings = ResultService.correlate_executions(db, 1)
        print(f"[+] Correlation finished! Created {len(findings)} real finding(s).")
        
    finally:
        db.close()

if __name__ == "__main__":
    seed_real_findings()
