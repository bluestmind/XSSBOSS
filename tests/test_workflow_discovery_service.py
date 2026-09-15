"""The form workflow bridge reaches real executor steps without expanding authority."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend_api.models  # noqa: F401
from backend_api.models.base import BaseModel
from backend_api.models.endpoint import Endpoint
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.param import Param
from backend_api.models.target import Target
from backend_api.models.tenant import Tenant
from backend_api.services.workflow_discovery_service import WorkflowDiscoveryService


def _world(button_label: str = "Save changes"):
    engine = create_engine("sqlite:///:memory:")
    BaseModel.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    tenant = Tenant(slug="workflow", name="Workflow")
    db.add(tenant)
    db.flush()
    target = Target(tenant_id=tenant.id, name="app", base_url="https://app.test")
    db.add(target)
    db.flush()
    page = Endpoint(
        target_id=target.id,
        method="GET",
        url_pattern="https://app.test/profile/edit",
        sample_response_body=f"""
        <form method="post" action="/profile">
          <input name="display_name" required>
          <textarea name="bio"></textarea>
          <select name="visibility"><option>Private</option><option>Public</option></select>
          <button id="save-profile" type="submit">{button_label}</button>
        </form>
        """,
    )
    submit = Endpoint(
        target_id=target.id,
        method="POST",
        url_pattern="https://app.test/profile",
    )
    db.add_all([page, submit])
    db.flush()
    db.add_all([
        Param(endpoint_id=submit.id, name="display_name", location="body"),
        Param(endpoint_id=submit.id, name="bio", location="body"),
        Param(endpoint_id=submit.id, name="visibility", location="body"),
    ])
    experiment = Experiment(
        target_id=target.id,
        name="workflow run",
        strategy=ExperimentStrategy.SMART_ADAPTIVE,
        status=ExperimentStatus.RUNNING,
        limits={"autonomous_research": True},
    )
    db.add(experiment)
    db.commit()
    return db, experiment, page, submit


def test_discovery_attaches_parameter_specific_safe_steps():
    db, experiment, page, submit = _world()
    summary = WorkflowDiscoveryService.discover_for_experiment(
        db, experiment.id, [page.id, submit.id]
    )
    db.refresh(submit)

    assert summary["attached"] == 2
    assert submit.custom_steps["source"] == "autonomous_form_discovery_v1"
    by_param = submit.custom_steps["by_param"]
    assert set(by_param) == {"bio", "display_name"}
    for param_name, steps in by_param.items():
        assert steps[0] == {"action": "navigate", "url": "https://app.test/profile/edit"}
        payload_steps = [step for step in steps if step.get("value") == "{{PAYLOAD}}"]
        assert payload_steps == [{"action": "fill", "selector": f"[name='{param_name}']", "value": "{{PAYLOAD}}"}]
        assert steps[-1]["safety"] == "safe"
    assert "visibility" not in by_param


def test_discovery_rejects_destructive_submit_flow():
    db, experiment, page, submit = _world("Delete account")
    summary = WorkflowDiscoveryService.discover_for_experiment(
        db, experiment.id, [page.id, submit.id]
    )
    db.refresh(submit)

    assert summary["attached"] == 0
    assert summary["rejected"] == 2
    assert submit.custom_steps is None


def test_discovery_rejects_out_of_scope_submit_target():
    db, experiment, page, submit = _world()
    submit.url_pattern = "https://evil.test/profile"
    page.sample_response_body = page.sample_response_body.replace(
        'action="/profile"', 'action="https://evil.test/profile"'
    )
    db.commit()
    summary = WorkflowDiscoveryService.discover_for_experiment(
        db, experiment.id, [page.id, submit.id]
    )
    db.refresh(submit)

    assert summary["attached"] == 0
    assert summary["rejected"] >= 1
    assert submit.custom_steps is None
