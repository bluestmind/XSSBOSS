"""Verify database state and content-addressed evidence after a restore."""
import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a restored XSS Boss database and evidence volume")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--minimum-evidence", type=int, default=1)
    args = parser.parse_args()

    from sqlalchemy import func

    from backend_api.db.base import SessionLocal
    from backend_api.models.evidence import EvidenceArtifact
    from backend_api.models.execution import Execution
    from backend_api.models.experiment import Experiment
    from backend_api.models.run_state import RunStage
    from backend_api.models.test_case import TestCase
    from backend_api.services.evidence_service import EvidenceService

    db = SessionLocal()
    try:
        counts = {
            "experiments": db.query(func.count(Experiment.id)).scalar(),
            "test_cases": db.query(func.count(TestCase.id)).scalar(),
            "executions": db.query(func.count(Execution.id)).scalar(),
            "run_stages": db.query(func.count(RunStage.id)).scalar(),
            "evidence_artifacts": db.query(func.count(EvidenceArtifact.id)).scalar(),
        }
        evidence = EvidenceService.verify_all(db)
        manifest = [
            {
                "experiment_id": row.experiment_id,
                "kind": row.kind,
                "sha256": row.sha256,
                "size_bytes": row.size_bytes,
                "uri": row.uri,
            }
            for row in db.query(EvidenceArtifact).order_by(
                EvidenceArtifact.experiment_id,
                EvidenceArtifact.kind,
                EvidenceArtifact.sha256,
            )
        ]
    finally:
        db.close()

    report = {
        "schema_version": 1,
        "verified_at": datetime.now(UTC).isoformat(),
        "counts": counts,
        "evidence": evidence,
        "evidence_manifest": manifest,
    }
    comparisons = {}
    if args.compare:
        expected = json.loads(args.compare.read_text(encoding="utf-8"))
        comparisons = {
            "counts_equal": counts == expected.get("counts"),
            "evidence_manifest_equal": manifest == expected.get("evidence_manifest"),
        }
    report["comparisons"] = comparisons
    report["passed"] = all([
        counts["evidence_artifacts"] >= args.minimum_evidence,
        evidence["passed"],
        all(comparisons.values()) if comparisons else True,
    ])
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    args.artifact.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({
        "passed": report["passed"],
        "counts": counts,
        "evidence_valid": evidence["valid"],
        "evidence_invalid": evidence["invalid"],
        "comparisons": comparisons,
    }, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
