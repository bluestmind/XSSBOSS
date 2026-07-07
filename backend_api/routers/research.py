"""Transparent API for autonomous research plans and evidence feedback."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.models.experiment import Experiment
from backend_api.models.research import AttackSurfaceEdge, AttackSurfaceNode, ResearchHypothesis
from backend_api.services.research_service import ResearchService


router = APIRouter(prefix="/research", tags=["research"])


def _owned_experiment(db: Session, experiment_id: int) -> Experiment:
    experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
    if experiment is None:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return experiment


@router.post("/experiments/{experiment_id}/plan")
def plan_research(experiment_id: int, db: Session = Depends(get_db)):
    _owned_experiment(db, experiment_id)
    return ResearchService.plan_experiment(db, experiment_id)


@router.get("/experiments/{experiment_id}")
def get_research_state(
    experiment_id: int,
    hypothesis_limit: int = Query(default=100, ge=1, le=500),
    graph_limit: int = Query(default=500, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    experiment = _owned_experiment(db, experiment_id)
    hypotheses = db.query(ResearchHypothesis).filter_by(experiment_id=experiment_id).order_by(
        ResearchHypothesis.priority.desc(), ResearchHypothesis.id
    ).limit(hypothesis_limit).all()
    nodes = db.query(AttackSurfaceNode).filter_by(experiment_id=experiment_id).order_by(
        AttackSurfaceNode.risk_score.desc(), AttackSurfaceNode.id
    ).limit(graph_limit).all()
    node_ids = [node.id for node in nodes]
    edges = db.query(AttackSurfaceEdge).filter(
        AttackSurfaceEdge.experiment_id == experiment_id,
        AttackSurfaceEdge.source_node_id.in_(node_ids),
        AttackSurfaceEdge.target_node_id.in_(node_ids),
    ).limit(graph_limit * 2).all() if node_ids else []
    return {
        "experiment_id": experiment.id,
        "summary": (experiment.limits or {}).get("research", {}),
        "hypotheses": [
            {
                "id": row.id, "type": row.hypothesis_type, "title": row.title,
                "rationale": row.rationale, "status": row.status,
                "confidence": row.confidence, "impact_score": row.impact_score,
                "priority": row.priority, "endpoint_id": row.endpoint_id,
                "param_id": row.param_id, "context_id": row.context_id,
                "techniques": row.technique_candidates or [],
                "observations": len(row.observations),
            }
            for row in hypotheses
        ],
        "graph": {
            "nodes": [
                {"id": node.id, "type": node.node_type, "label": node.label,
                 "risk_score": node.risk_score, "attributes": node.attributes or {}}
                for node in nodes
            ],
            "edges": [
                {"source": edge.source_node_id, "target": edge.target_node_id,
                 "relation": edge.relation, "confidence": edge.confidence}
                for edge in edges
            ],
        },
    }
