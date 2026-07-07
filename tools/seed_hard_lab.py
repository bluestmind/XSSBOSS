"""Seed the local hard XSS lab into the XSS Boss database."""
import argparse
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tools" / "hard_lab_manifest.json"


def _load_manifest() -> dict:
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _absolute_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _set_database_url(database_url: str | None) -> str:
    resolved = database_url or f"sqlite:///{(ROOT / 'xssboss.db').as_posix()}"
    os.environ.setdefault("DATABASE_URL", resolved)
    return os.environ["DATABASE_URL"]


def _import_backend_models():
    try:
        from backend_api.db.base import init_db, SessionLocal
        from backend_api.models.context import Context
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.execution import Execution
        from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
        from backend_api.models.filter_profile import FilterProfile
        from backend_api.models.finding import Finding
        from backend_api.models.param import Param
        from backend_api.models.sink import Sink
        from backend_api.models.target import Target, TargetStatus
        from backend_api.models.test_case import TestCase

        return {
            "init_db": init_db,
            "SessionLocal": SessionLocal,
            "Context": Context,
            "Endpoint": Endpoint,
            "Execution": Execution,
            "Experiment": Experiment,
            "ExperimentStatus": ExperimentStatus,
            "ExperimentStrategy": ExperimentStrategy,
            "FilterProfile": FilterProfile,
            "Finding": Finding,
            "Param": Param,
            "Sink": Sink,
            "Target": Target,
            "TargetStatus": TargetStatus,
            "TestCase": TestCase,
        }
    except ModuleNotFoundError as exc:
        missing = exc.name or "backend dependency"
        print(f"[!] Missing Python dependency: {missing}")
        print("[!] Run setup_backend.bat first, then rerun this seed script.")
        raise SystemExit(1) from exc


def seed_hard_lab(base_url: str, database_url: str | None, reset: bool, create_experiments: bool) -> dict:
    sys.path.insert(0, str(ROOT))
    db_url = _set_database_url(database_url)
    manifest = _load_manifest()
    models = _import_backend_models()

    init_db = models["init_db"]
    SessionLocal = models["SessionLocal"]
    Context = models["Context"]
    Endpoint = models["Endpoint"]
    Execution = models["Execution"]
    Experiment = models["Experiment"]
    ExperimentStatus = models["ExperimentStatus"]
    ExperimentStrategy = models["ExperimentStrategy"]
    FilterProfile = models["FilterProfile"]
    Finding = models["Finding"]
    Param = models["Param"]
    Sink = models["Sink"]
    Target = models["Target"]
    TargetStatus = models["TargetStatus"]
    TestCase = models["TestCase"]

    init_db()
    db = SessionLocal()

    created = {
        "database_url": db_url,
        "target_id": None,
        "endpoints": 0,
        "params": 0,
        "contexts": 0,
        "experiments": 0,
    }

    try:
        target_cfg = dict(manifest["target"])
        target_name = target_cfg["name"]
        target_cfg["base_url"] = base_url

        if reset:
            target_ids = [row[0] for row in db.query(Target.id).filter(Target.name == target_name).all()]
            if target_ids:
                endpoint_ids = [
                    row[0] for row in db.query(Endpoint.id).filter(Endpoint.target_id.in_(target_ids)).all()
                ]
                experiment_ids = [
                    row[0] for row in db.query(Experiment.id).filter(Experiment.target_id.in_(target_ids)).all()
                ]
                param_ids = [
                    row[0] for row in db.query(Param.id).filter(Param.endpoint_id.in_(endpoint_ids)).all()
                ] if endpoint_ids else []
                context_ids = [
                    row[0] for row in db.query(Context.id).filter(Context.endpoint_id.in_(endpoint_ids)).all()
                ] if endpoint_ids else []
                test_case_ids = [
                    row[0] for row in db.query(TestCase.id).filter(TestCase.experiment_id.in_(experiment_ids)).all()
                ] if experiment_ids else []

                if test_case_ids:
                    db.query(Execution).filter(Execution.test_case_id.in_(test_case_ids)).delete(synchronize_session=False)
                if endpoint_ids:
                    db.query(Finding).filter(Finding.endpoint_id.in_(endpoint_ids)).delete(synchronize_session=False)
                    db.query(FilterProfile).filter(FilterProfile.endpoint_id.in_(endpoint_ids)).delete(synchronize_session=False)
                    db.query(TestCase).filter(TestCase.endpoint_id.in_(endpoint_ids)).delete(synchronize_session=False)
                if context_ids:
                    db.query(Sink).filter(Sink.context_id.in_(context_ids)).delete(synchronize_session=False)
                    db.query(Context).filter(Context.id.in_(context_ids)).delete(synchronize_session=False)
                if param_ids:
                    db.query(Param).filter(Param.id.in_(param_ids)).delete(synchronize_session=False)
                if endpoint_ids:
                    db.query(Endpoint).filter(Endpoint.id.in_(endpoint_ids)).delete(synchronize_session=False)
                if experiment_ids:
                    db.query(Experiment).filter(Experiment.id.in_(experiment_ids)).delete(synchronize_session=False)
                db.query(Target).filter(Target.id.in_(target_ids)).delete(synchronize_session=False)
            db.commit()

        target = db.query(Target).filter(Target.name == target_name).first()
        if not target:
            target = Target(
                name=target_name,
                base_url=target_cfg["base_url"],
                bounty_platform=target_cfg.get("bounty_platform"),
                scope_tags=target_cfg.get("scope_tags"),
                notes="Local hard-mode XSS test target. Authorized local testing only.",
                status=TargetStatus.FUZZING,
            )
            db.add(target)
            db.flush()
        else:
            target.base_url = target_cfg["base_url"]
            target.bounty_platform = target_cfg.get("bounty_platform")
            target.scope_tags = target_cfg.get("scope_tags")
            target.status = TargetStatus.FUZZING
            db.flush()

        created["target_id"] = target.id

        for case in manifest["cases"]:
            url = _absolute_url(base_url, case["path"])
            method = case["method"].upper()

            endpoint = (
                db.query(Endpoint)
                .filter(Endpoint.target_id == target.id)
                .filter(Endpoint.method == method)
                .filter(Endpoint.url_pattern == url)
                .first()
            )
            if not endpoint:
                endpoint = Endpoint(
                    target_id=target.id,
                    method=method,
                    url_pattern=url,
                    sample_request_body=case.get("sample_request_body"),
                    auth_context=case.get("headers") or {},
                    custom_steps=case.get("steps"),
                )
                db.add(endpoint)
                db.flush()
                created["endpoints"] += 1
            else:
                endpoint.sample_request_body = case.get("sample_request_body")
                endpoint.auth_context = case.get("headers") or {}
                endpoint.custom_steps = case.get("steps")
                db.flush()

            param = (
                db.query(Param)
                .filter(Param.endpoint_id == endpoint.id)
                .filter(Param.name == case["param_name"])
                .filter(Param.location == case["param_location"])
                .first()
            )
            if not param:
                param = Param(
                    endpoint_id=endpoint.id,
                    name=case["param_name"],
                    location=case["param_location"],
                    sample_value="hard-lab-sample",
                    is_controllable=True,
                )
                db.add(param)
                db.flush()
                created["params"] += 1

            context = (
                db.query(Context)
                .filter(Context.endpoint_id == endpoint.id)
                .filter(Context.param_id == param.id)
                .filter(Context.context_type == case["context_type"])
                .first()
            )
            if not context:
                context = Context(
                    endpoint_id=endpoint.id,
                    param_id=param.id,
                    context_type=case["context_type"],
                    tag=case.get("tag"),
                    attribute=case.get("attribute"),
                    snippet=f"hard-lab:{case['slug']} expected_vulnerable={case['expected_vulnerable']}",
                )
                db.add(context)
                db.flush()
                created["contexts"] += 1

        if create_experiments:
            for experiment_cfg in manifest.get("experiments", []):
                experiment = (
                    db.query(Experiment)
                    .filter(Experiment.target_id == target.id)
                    .filter(Experiment.name == experiment_cfg["name"])
                    .first()
                )
                if not experiment:
                    experiment = Experiment(
                        target_id=target.id,
                        name=experiment_cfg["name"],
                        strategy=ExperimentStrategy(experiment_cfg["strategy"]),
                        status=ExperimentStatus.PENDING,
                        limits={
                            "lab": "hard-local-xss",
                            "expected_vulnerable_cases": len(
                                [case for case in manifest["cases"] if case["expected_vulnerable"]]
                            ),
                        },
                    )
                    db.add(experiment)
                    db.flush()
                    created["experiments"] += 1

        db.commit()
        return created
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the hard local XSS lab into XSS Boss.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8099", help="Base URL of hard_mock_target.py")
    parser.add_argument("--database-url", default=None, help="Override DATABASE_URL")
    parser.add_argument("--reset", action="store_true", help="Delete existing Hard Local XSS Lab target before seeding")
    parser.add_argument("--no-experiments", action="store_true", help="Do not create pending lab experiments")
    args = parser.parse_args()

    result = seed_hard_lab(
        base_url=args.base_url,
        database_url=args.database_url,
        reset=args.reset,
        create_experiments=not args.no_experiments,
    )

    print("[+] Hard lab seeded")
    print(f"    database_url: {result['database_url']}")
    print(f"    target_id: {result['target_id']}")
    print(f"    new endpoints: {result['endpoints']}")
    print(f"    new params: {result['params']}")
    print(f"    new contexts: {result['contexts']}")
    print(f"    new experiments: {result['experiments']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
