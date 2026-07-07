"""Central application-layer tenant isolation for ORM sessions."""
from contextvars import ContextVar
from typing import Optional

from sqlalchemy import event
from sqlalchemy.orm import Session, with_loader_criteria


current_tenant_id: ContextVar[Optional[int]] = ContextVar("current_tenant_id", default=None)


def _criteria(tenant_id: int):
    from backend_api.models.context import Context
    from backend_api.models.audit import AuditEvent
    from backend_api.models.endpoint import Endpoint
    from backend_api.models.evidence import EvidenceArtifact
    from backend_api.models.execution import Execution
    from backend_api.models.filter_profile import FilterProfile
    from backend_api.models.finding import Finding
    from backend_api.models.param import Param
    from backend_api.models.run_state import FindingObservation, RunEndpoint, RunStage
    from backend_api.models.sink import Sink
    from backend_api.models.target import Target
    from backend_api.models.test_case import TestCase
    from backend_api.models.experiment import Experiment
    from backend_api.models.research import (
        AttackSurfaceEdge, AttackSurfaceNode, ResearchHypothesis,
        ResearchObservation, ResearchTechniqueStat,
    )

    target_owned = Target.tenant_id == tenant_id
    endpoint_owned = Endpoint.target.has(Target.tenant_id == tenant_id)
    experiment_owned = Experiment.target.has(Target.tenant_id == tenant_id)
    context_owned = Context.endpoint.has(Endpoint.target.has(Target.tenant_id == tenant_id))
    test_case_owned = TestCase.experiment.has(Experiment.target.has(Target.tenant_id == tenant_id))
    return {
        AuditEvent: AuditEvent.tenant_id == tenant_id,
        Target: target_owned,
        Endpoint: endpoint_owned,
        Param: Param.endpoint.has(Endpoint.target.has(Target.tenant_id == tenant_id)),
        Context: context_owned,
        Sink: Sink.context.has(context_owned),
        FilterProfile: FilterProfile.endpoint.has(Endpoint.target.has(Target.tenant_id == tenant_id)),
        Experiment: experiment_owned,
        TestCase: test_case_owned,
        Execution: Execution.test_case.has(test_case_owned),
        Finding: Finding.endpoint.has(Endpoint.target.has(Target.tenant_id == tenant_id)),
        RunEndpoint: RunEndpoint.experiment.has(experiment_owned),
        RunStage: RunStage.experiment.has(experiment_owned),
        FindingObservation: FindingObservation.experiment.has(experiment_owned),
        EvidenceArtifact: EvidenceArtifact.experiment.has(experiment_owned),
        AttackSurfaceNode: AttackSurfaceNode.experiment.has(experiment_owned),
        AttackSurfaceEdge: AttackSurfaceEdge.experiment.has(experiment_owned),
        ResearchHypothesis: ResearchHypothesis.experiment.has(experiment_owned),
        ResearchObservation: ResearchObservation.hypothesis.has(
            ResearchHypothesis.experiment.has(experiment_owned)
        ),
        ResearchTechniqueStat: ResearchTechniqueStat.tenant_id == tenant_id,
    }


@event.listens_for(Session, "do_orm_execute")
def _apply_tenant_boundary(execute_state):
    tenant_id = execute_state.session.info.get("tenant_id")
    if tenant_id is None or execute_state.execution_options.get("skip_tenant_scope"):
        return
    criteria = _criteria(int(tenant_id))
    if execute_state.is_select:
        execute_state.statement = execute_state.statement.options(*[
            with_loader_criteria(model, expression, include_aliases=True)
            for model, expression in criteria.items()
        ])
    elif execute_state.is_update or execute_state.is_delete:
        mapper = execute_state.bind_mapper
        if mapper is not None and mapper.class_ in criteria:
            execute_state.statement = execute_state.statement.where(criteria[mapper.class_])


@event.listens_for(Session, "before_flush")
def _assign_new_target_tenant(session, _flush_context, _instances):
    tenant_id = session.info.get("tenant_id")
    if tenant_id is None:
        return
    from backend_api.models.target import Target

    for instance in session.new:
        if isinstance(instance, Target):
            if instance.tenant_id not in (None, int(tenant_id)):
                raise PermissionError("Cannot create a target for another tenant")
            instance.tenant_id = int(tenant_id)
