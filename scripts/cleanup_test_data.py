"""Clean up synthetic test targets, fixtures, and mock test data from production xssboss.db."""
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure we operate on production xssboss.db
os.environ["DATABASE_URL"] = "sqlite:///./xssboss.db"
os.environ["ENVIRONMENT"] = "development"

from backend_api.db.session import SessionLocal
from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.context import Context
from backend_api.models.sink import Sink
from backend_api.models.experiment import Experiment
from backend_api.models.test_case import TestCase
from backend_api.models.execution import Execution
from backend_api.models.finding import Finding
from backend_api.models.filter_profile import FilterProfile
from backend_api.models.research import AttackSurfaceNode, AttackSurfaceEdge, ResearchHypothesis, ResearchObservation


def identify_and_purge_test_data(dry_run=False):
    db = SessionLocal()
    try:
        targets = db.query(Target).all()
        test_target_ids = []
        test_target_names = []

        for t in targets:
            name_lower = (t.name or "").lower()
            base_lower = (t.base_url or "").lower()
            
            is_test = False
            # Check for synthetic test target names
            if t.name in ["Hunt Test Target", "httpbin.org", "Test Target Benchmark", "Test Target", "Mock Target", "Example Target"]:
                is_test = True
            elif "httpbin.org" in base_lower or "xssboss.local" in base_lower or "example.com" in base_lower or "localhost" in base_lower:
                is_test = True
            elif name_lower.startswith("test ") or name_lower.endswith(" test") or name_lower == "test":
                is_test = True

            if is_test:
                test_target_ids.append(t.id)
                test_target_names.append(f"#{t.id} {t.name} ({t.base_url})")

        print(f"Identified {len(test_target_ids)} test targets to purge from real database:")
        for name in test_target_names:
            print(f"  - {name}")

        if not test_target_ids:
            print("No test targets found in database.")
            return

        # Count records to be deleted
        endpoints = db.query(Endpoint).filter(Endpoint.target_id.in_(test_target_ids)).all()
        ep_ids = [ep.id for ep in endpoints]
        
        experiments = db.query(Experiment).filter(Experiment.target_id.in_(test_target_ids)).all()
        exp_ids = [exp.id for exp in experiments]

        test_cases = []
        if exp_ids:
            test_cases = db.query(TestCase).filter(TestCase.experiment_id.in_(exp_ids)).all()
        tc_ids = [tc.id for tc in test_cases]

        findings = []
        if ep_ids:
            findings = db.query(Finding).filter(Finding.endpoint_id.in_(ep_ids)).all()
        
        print("\nRelated test artifacts to remove:")
        print(f"  - Endpoints: {len(endpoints)}")
        print(f"  - Experiments: {len(experiments)}")
        print(f"  - Test Cases: {len(test_cases)}")
        print(f"  - Findings: {len(findings)}")

        if dry_run:
            print("\n[DRY RUN] No records were deleted.")
            return

        # Perform cascade delete
        if tc_ids:
            db.query(Execution).filter(Execution.test_case_id.in_(tc_ids)).delete(synchronize_session=False)

        if exp_ids:
            hypotheses = db.query(ResearchHypothesis).filter(ResearchHypothesis.experiment_id.in_(exp_ids)).all()
            hyp_ids = [h.id for h in hypotheses]
            if hyp_ids:
                db.query(ResearchObservation).filter(ResearchObservation.hypothesis_id.in_(hyp_ids)).delete(synchronize_session=False)
                db.query(ResearchHypothesis).filter(ResearchHypothesis.id.in_(hyp_ids)).delete(synchronize_session=False)

            db.query(AttackSurfaceEdge).filter(AttackSurfaceEdge.experiment_id.in_(exp_ids)).delete(synchronize_session=False)
            db.query(AttackSurfaceNode).filter(AttackSurfaceNode.experiment_id.in_(exp_ids)).delete(synchronize_session=False)
            db.query(TestCase).filter(TestCase.experiment_id.in_(exp_ids)).delete(synchronize_session=False)
            db.query(Experiment).filter(Experiment.id.in_(exp_ids)).delete(synchronize_session=False)

        if ep_ids:
            db.query(Finding).filter(Finding.endpoint_id.in_(ep_ids)).delete(synchronize_session=False)
            contexts = db.query(Context).filter(Context.endpoint_id.in_(ep_ids)).all()
            ctx_ids = [c.id for c in contexts]
            if ctx_ids:
                db.query(Sink).filter(Sink.context_id.in_(ctx_ids)).delete(synchronize_session=False)
                db.query(Context).filter(Context.id.in_(ctx_ids)).delete(synchronize_session=False)
            db.query(Param).filter(Param.endpoint_id.in_(ep_ids)).delete(synchronize_session=False)
            db.query(FilterProfile).filter(FilterProfile.endpoint_id.in_(ep_ids)).delete(synchronize_session=False)
            db.query(Endpoint).filter(Endpoint.id.in_(ep_ids)).delete(synchronize_session=False)

        db.query(Target).filter(Target.id.in_(test_target_ids)).delete(synchronize_session=False)

        db.commit()
        print("\nSUCCESS! Successfully purged all test-related targets and artifacts from the real database.")
    except Exception as e:
        db.rollback()
        print(f"Error during cleanup: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    identify_and_purge_test_data(dry_run=False)
