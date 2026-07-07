"""Two-tenant HTTP isolation, quota, and audit-chain acceptance gate."""
import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import uuid

import httpx


ROOT = Path(__file__).resolve().parents[1]


def _wait_ready(url: str, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("tenant gate API did not become ready")


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove tenant HTTP isolation and audit controls")
    parser.add_argument("--base-url", default="http://127.0.0.1:8125")
    parser.add_argument("--artifact", type=Path, default=ROOT / "reports" / "tenant_isolation.json")
    args = parser.parse_args()

    suffix = uuid.uuid4().hex[:10]
    alpha_slug = f"alpha-{suffix}"
    beta_slug = f"beta-{suffix}"
    alpha_token = f"alpha-{uuid.uuid4().hex}-{uuid.uuid4().hex}"
    beta_token = f"beta-{uuid.uuid4().hex}-{uuid.uuid4().hex}"
    env = os.environ.copy()
    env.pop("API_AUTH_TOKEN", None)
    env["TENANT_API_TOKENS"] = json.dumps({alpha_slug: alpha_token, beta_slug: beta_token})
    env["AUDIT_MODE"] = "celery"
    env["EVIDENCE_DIR"] = str(args.artifact.parent / f"tenant_evidence_{suffix}")
    env.setdefault("ORCHESTRATION_MODE", "celery")
    env.setdefault("ENVIRONMENT", "test")
    env.setdefault("PYTHONPATH", str(ROOT))

    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    log_path = args.artifact.with_suffix(".server.log")
    log_handle = log_path.open("w", encoding="utf-8")
    from urllib.parse import urlparse

    parsed = urlparse(args.base_url)
    audit_process = subprocess.Popen(
        [
            sys.executable, "-m", "celery", "-A", "backend_api.task_queue:task_app",
            "worker", "-Q", "audit", "--pool=solo", "--concurrency=1",
            "--loglevel=WARNING", "--without-gossip", "--without-mingle",
            "-n", "tenant-audit-gate@%h",
        ],
        cwd=ROOT,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    process = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "backend_api.main:app",
            "--host", parsed.hostname or "127.0.0.1", "--port", str(parsed.port or 8125),
            "--log-level", "warning",
        ],
        cwd=ROOT,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    report = {"schema_version": 1, "started_at": datetime.now(UTC).isoformat(), "passed": False}
    try:
        _wait_ready(f"{args.base_url}/ready")
        alpha_headers = {"Authorization": f"Bearer {alpha_token}"}
        beta_headers = {"Authorization": f"Bearer {beta_token}"}
        with httpx.Client(timeout=10) as client:
            alpha_created = client.post(
                f"{args.base_url}/api/v1/targets/",
                headers=alpha_headers,
                json={"name": f"alpha-target-{suffix}", "base_url": "https://alpha.example"},
            )
            beta_created = client.post(
                f"{args.base_url}/api/v1/targets/",
                headers=beta_headers,
                json={"name": f"beta-target-{suffix}", "base_url": "https://beta.example"},
            )
            alpha_created.raise_for_status()
            beta_created.raise_for_status()
            alpha_id = alpha_created.json()["id"]
            beta_id = beta_created.json()["id"]

            alpha_list = client.get(f"{args.base_url}/api/v1/targets/", headers=alpha_headers)
            beta_list = client.get(f"{args.base_url}/api/v1/targets/", headers=beta_headers)
            alpha_cross_read = client.get(f"{args.base_url}/api/v1/targets/{beta_id}", headers=alpha_headers)
            beta_cross_update = client.put(
                f"{args.base_url}/api/v1/targets/{alpha_id}", headers=beta_headers, json={"name": "stolen"}
            )
            unauthenticated_static = client.get(f"{args.base_url}/reports/nonexistent")

        # Apply and verify a small tenant-specific fixed-window quota.
        os.environ.update({
            "DATABASE_URL": env["DATABASE_URL"],
            "REDIS_URL": env["REDIS_URL"],
            "TENANT_API_TOKENS": env["TENANT_API_TOKENS"],
            "EVIDENCE_DIR": env["EVIDENCE_DIR"],
        })
        sys.path.insert(0, str(ROOT))
        from redis import Redis
        from backend_api.db.base import SessionLocal
        from backend_api.models.tenant import Tenant
        from backend_api.models.audit import AuditEvent
        from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
        from backend_api.services.audit_service import AuditService
        from backend_api.services.evidence_service import EvidenceService

        db = SessionLocal()
        alpha_tenant = db.query(Tenant).filter(Tenant.slug == alpha_slug).one()
        beta_tenant = db.query(Tenant).filter(Tenant.slug == beta_slug).one()
        alpha_experiment = Experiment(
            target_id=alpha_id, name="alpha-artifact", strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.COMPLETED,
        )
        beta_experiment = Experiment(
            target_id=beta_id, name="beta-artifact", strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.COMPLETED,
        )
        db.add_all([alpha_experiment, beta_experiment])
        db.commit()
        alpha_artifact = EvidenceService.register_bytes(
            db, alpha_experiment.id, None, "campaign_report_html", b"alpha-private-report"
        )
        beta_artifact = EvidenceService.register_bytes(
            db, beta_experiment.id, None, "campaign_report_html", b"beta-private-report"
        )
        with httpx.Client(timeout=10) as client:
            alpha_own_artifact = client.get(
                f"{args.base_url}/api/v1/artifacts/{alpha_artifact.id}/download", headers=alpha_headers
            )
            alpha_cross_artifact = client.get(
                f"{args.base_url}/api/v1/artifacts/{beta_artifact.id}/download", headers=alpha_headers
            )
            beta_own_artifact = client.get(
                f"{args.base_url}/api/v1/artifacts/{beta_artifact.id}/download", headers=beta_headers
            )
        alpha_tenant.quotas = {"api_requests_per_minute": 2}
        db.commit()
        redis_client = Redis.from_url(env["REDIS_URL"])
        for key in redis_client.scan_iter(f"xssboss:quota:{alpha_tenant.id}:*"):
            redis_client.delete(key)

        with httpx.Client(timeout=10) as client:
            quota_statuses = [
                client.get(f"{args.base_url}/api/v1/targets/", headers=alpha_headers).status_code
                for _ in range(3)
            ]

        audit_deadline = time.monotonic() + 60
        while time.monotonic() < audit_deadline:
            db.expire_all()
            alpha_count = db.query(AuditEvent).filter(AuditEvent.tenant_id == alpha_tenant.id).count()
            beta_count = db.query(AuditEvent).filter(AuditEvent.tenant_id == beta_tenant.id).count()
            if alpha_count >= 7 and beta_count >= 4:
                break
            time.sleep(0.25)
        db.expire_all()
        alpha_audit = AuditService.verify_chain(db, alpha_tenant.id)
        beta_audit = AuditService.verify_chain(db, beta_tenant.id)
        db.close()

        checks = {
            "alpha_create": alpha_created.status_code == 201,
            "beta_create": beta_created.status_code == 201,
            "alpha_sees_only_alpha": [row["id"] for row in alpha_list.json()] == [alpha_id],
            "beta_sees_only_beta": [row["id"] for row in beta_list.json()] == [beta_id],
            "cross_tenant_read_hidden": alpha_cross_read.status_code == 404,
            "cross_tenant_update_hidden": beta_cross_update.status_code == 404,
            "static_requires_auth": unauthenticated_static.status_code == 401,
            "alpha_own_artifact": alpha_own_artifact.status_code == 200 and alpha_own_artifact.content == b"alpha-private-report",
            "beta_own_artifact": beta_own_artifact.status_code == 200 and beta_own_artifact.content == b"beta-private-report",
            "cross_tenant_artifact_hidden": alpha_cross_artifact.status_code == 404,
            "tenant_quota": quota_statuses == [200, 200, 429],
            "alpha_audit_chain": alpha_audit["passed"] and alpha_audit["checked"] >= 7,
            "beta_audit_chain": beta_audit["passed"] and beta_audit["checked"] >= 4,
        }
        report.update({
            "tenant_ids": {"alpha": alpha_tenant.id, "beta": beta_tenant.id},
            "target_ids": {"alpha": alpha_id, "beta": beta_id},
            "quota_statuses": quota_statuses,
            "audit": {"alpha": alpha_audit, "beta": beta_audit},
            "checks": checks,
            "passed": all(checks.values()),
        })
    except Exception as error:
        import traceback

        report["error"] = f"{type(error).__name__}: {error}"
        report["traceback"] = traceback.format_exc()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        if audit_process.poll() is None:
            audit_process.kill()
            audit_process.wait(timeout=15)
        log_handle.close()
        report["finished_at"] = datetime.now(UTC).isoformat()
        args.artifact.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
