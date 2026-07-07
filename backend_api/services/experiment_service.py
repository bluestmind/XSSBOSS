"""Experiment service."""
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime
from backend_api.models.experiment import Experiment, ExperimentStatus
from backend_api.models.target import Target
from backend_api.utils.errors import NotFoundError, ValidationError


class ExperimentService:
    """Service for experiment operations."""
    
    @staticmethod
    def create_experiment(db: Session, experiment_data: dict) -> Experiment:
        """Create a new experiment."""
        # Verify target exists
        target = db.query(Target).filter(Target.id == experiment_data['target_id']).first()
        if not target:
            raise NotFoundError("Target", experiment_data['target_id'])
        
        experiment = Experiment(**experiment_data)
        db.add(experiment)
        db.commit()
        db.refresh(experiment)
        return experiment
    
    @staticmethod
    def get_experiment(db: Session, experiment_id: int) -> Experiment:
        """Get experiment by ID."""
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise NotFoundError("Experiment", experiment_id)
        return experiment
    
    @staticmethod
    def list_experiments(
        db: Session,
        target_id: Optional[int] = None,
        status: Optional[ExperimentStatus] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Experiment]:
        """List experiments, optionally filtered by target or status."""
        query = db.query(Experiment)
        if target_id:
            query = query.filter(Experiment.target_id == target_id)
        if status:
            query = query.filter(Experiment.status == status)
        return query.offset(skip).limit(limit).all()
    
    @staticmethod
    def update_experiment(
        db: Session,
        experiment_id: int,
        update_data: dict
    ) -> Experiment:
        """Update an experiment."""
        experiment = ExperimentService.get_experiment(db, experiment_id)
        
        for field, value in update_data.items():
            if hasattr(experiment, field):
                setattr(experiment, field, value)
        
        db.commit()
        db.refresh(experiment)
        return experiment
    
    @staticmethod
    def start_experiment(db: Session, experiment_id: int) -> Experiment:
        """Start an experiment."""
        experiment = ExperimentService.get_experiment(db, experiment_id)
        
        if experiment.status == ExperimentStatus.RUNNING:
            return experiment
            
        if experiment.status != ExperimentStatus.PENDING:
            raise ValidationError(
                f"Cannot start experiment in status: {experiment.status.value}"
            )
        
        experiment.status = ExperimentStatus.RUNNING
        experiment.started_at = datetime.utcnow()
        db.commit()
        db.refresh(experiment)
        return experiment
    
    @staticmethod
    def stop_experiment(db: Session, experiment_id: int) -> Experiment:
        """Stop/pause an experiment."""
        experiment = ExperimentService.get_experiment(db, experiment_id)
        
        if experiment.status != ExperimentStatus.RUNNING:
            raise ValidationError(
                f"Cannot stop experiment in status: {experiment.status.value}"
            )
        
        experiment.status = ExperimentStatus.PAUSED
        db.commit()
        db.refresh(experiment)
        return experiment
    
    @staticmethod
    def continue_experiment(db: Session, experiment_id: int) -> Experiment:
        """Continue/resume a paused experiment."""
        experiment = ExperimentService.get_experiment(db, experiment_id)
        
        if experiment.status != ExperimentStatus.PAUSED:
            raise ValidationError(
                f"Cannot continue experiment in status: {experiment.status.value}"
            )
        
        experiment.status = ExperimentStatus.RUNNING
        db.commit()
        db.refresh(experiment)
        return experiment
    
    @staticmethod
    def delete_experiment(db: Session, experiment_id: int) -> None:
        """Delete an experiment."""
        experiment = ExperimentService.get_experiment(db, experiment_id)
        db.delete(experiment)
        db.commit()
    
    @staticmethod
    def get_experiment_stats(db: Session, experiment_id: int) -> Dict[str, Any]:
        """Get statistics for an experiment."""
        from backend_api.models.test_case import TestCase, TestCaseStatus
        
        experiment = ExperimentService.get_experiment(db, experiment_id)
        test_cases = db.query(TestCase).filter(TestCase.experiment_id == experiment_id).all()
        
        return {
            'total_test_cases': len(test_cases),
            'pending': len([tc for tc in test_cases if tc.status == TestCaseStatus.PENDING]),
            'queued': len([tc for tc in test_cases if tc.status == TestCaseStatus.QUEUED]),
            'running': len([tc for tc in test_cases if tc.status == TestCaseStatus.RUNNING]),
            'completed': len([tc for tc in test_cases if tc.status == TestCaseStatus.COMPLETED]),
            'failed': len([tc for tc in test_cases if tc.status == TestCaseStatus.FAILED]),
        }
