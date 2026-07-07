"""Baseline current schema and add durable run ownership.

Revision ID: 0001_durable_run_ownership
Revises:
Create Date: 2026-08-27
"""
from alembic import op
import sqlalchemy as sa


revision = "0001_durable_run_ownership"
down_revision = None
branch_labels = None
depends_on = None


def _index_names(inspector: sa.Inspector, table: str) -> set[str]:
    return {index["name"] for index in inspector.get_indexes(table)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # This repository previously bootstrapped through metadata.create_all and
    # had no Alembic history. On a fresh database, establish that baseline from
    # the exact model metadata. Existing installations take the additive path.
    if "experiments" not in inspector.get_table_names():
        from backend_api.models.base import Base
        import backend_api.models  # noqa: F401

        Base.metadata.create_all(bind=bind)
        return

    # Fold the former best-effort startup ALTER statements into versioned,
    # inspectable migration steps for installations created before Alembic.
    param_columns = {column["name"] for column in inspector.get_columns("params")}
    if "burp_flagged" not in param_columns:
        with op.batch_alter_table("params") as batch:
            batch.add_column(sa.Column("burp_flagged", sa.Boolean(), server_default=sa.false(), nullable=True))
    finding_columns = {column["name"] for column in inspector.get_columns("findings")}
    with op.batch_alter_table("findings") as batch:
        if "vuln_type" not in finding_columns:
            batch.add_column(sa.Column("vuln_type", sa.String(length=80), server_default="xss", nullable=False))
        if "scanner_module" not in finding_columns:
            batch.add_column(sa.Column("scanner_module", sa.String(length=120), server_default="xss_fuzzer", nullable=False))
        if "confidence" not in finding_columns:
            batch.add_column(sa.Column("confidence", sa.String(length=40), server_default="firm", nullable=False))
        if "evidence_summary" not in finding_columns:
            batch.add_column(sa.Column("evidence_summary", sa.Text(), nullable=True))

    execution_columns = {column["name"] for column in inspector.get_columns("executions")}
    with op.batch_alter_table("executions") as batch:
        if "attempt_no" not in execution_columns:
            batch.add_column(sa.Column("attempt_no", sa.Integer(), nullable=True))
        if "idempotency_key" not in execution_columns:
            batch.add_column(sa.Column("idempotency_key", sa.String(length=180), nullable=True))

    inspector = sa.inspect(bind)
    execution_indexes = _index_names(inspector, "executions")
    if "ix_executions_idempotency_key" not in execution_indexes:
        op.create_index(
            "ix_executions_idempotency_key",
            "executions",
            ["idempotency_key"],
            unique=True,
        )
    execution_constraints = {
        constraint["name"] for constraint in inspector.get_unique_constraints("executions")
    }
    if "uq_execution_attempt" not in execution_constraints:
        with op.batch_alter_table("executions") as batch:
            batch.create_unique_constraint("uq_execution_attempt", ["test_case_id", "attempt_no"])

    stage_name = sa.Enum(
        "RECON", "PROFILING", "EXECUTION", "CORRELATION", "REPORTING",
        name="runstagename",
    )
    stage_status = sa.Enum(
        "PENDING", "RUNNING", "COMPLETED", "FAILED",
        name="runstagestatus",
    )

    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "run_endpoints" not in tables:
        op.create_table(
            "run_endpoints",
            sa.Column("experiment_id", sa.Integer(), nullable=False),
            sa.Column("endpoint_id", sa.Integer(), nullable=False),
            sa.Column("discovery_source", sa.String(length=80), nullable=False),
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["experiment_id"], ["experiments.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("experiment_id", "endpoint_id", name="uq_run_endpoint"),
        )
        op.create_index("ix_run_endpoints_id", "run_endpoints", ["id"])
        op.create_index("ix_run_endpoints_endpoint_id", "run_endpoints", ["endpoint_id"])
        op.create_index("ix_run_endpoints_experiment_id", "run_endpoints", ["experiment_id"])

    if "finding_observations" not in tables:
        op.create_table(
            "finding_observations",
            sa.Column("experiment_id", sa.Integer(), nullable=False),
            sa.Column("finding_id", sa.Integer(), nullable=False),
            sa.Column("test_case_id", sa.Integer(), nullable=True),
            sa.Column("execution_id", sa.Integer(), nullable=True),
            sa.Column("evidence", sa.JSON(), nullable=True),
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.ForeignKeyConstraint(["execution_id"], ["executions.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["experiment_id"], ["experiments.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["test_case_id"], ["test_cases.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("experiment_id", "finding_id", name="uq_run_finding"),
        )
        for column in ("id", "execution_id", "experiment_id", "finding_id", "test_case_id"):
            op.create_index(f"ix_finding_observations_{column}", "finding_observations", [column])

    if "run_stages" not in tables:
        op.create_table(
            "run_stages",
            sa.Column("experiment_id", sa.Integer(), nullable=False),
            sa.Column("name", stage_name, nullable=False),
            sa.Column("status", stage_status, nullable=False),
            sa.Column("attempt_count", sa.Integer(), nullable=False),
            sa.Column("lease_owner", sa.String(length=160), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("output", sa.JSON(), nullable=True),
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.ForeignKeyConstraint(["experiment_id"], ["experiments.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("experiment_id", "name", name="uq_run_stage"),
        )
        for column in ("id", "experiment_id", "lease_expires_at", "status"):
            op.create_index(f"ix_run_stages_{column}", "run_stages", [column])


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for table in ("finding_observations", "run_stages", "run_endpoints"):
        if table in tables:
            op.drop_table(table)
    if "executions" in tables:
        with op.batch_alter_table("executions") as batch:
            batch.drop_constraint("uq_execution_attempt", type_="unique")
            batch.drop_index("ix_executions_idempotency_key")
            batch.drop_column("idempotency_key")
            batch.drop_column("attempt_no")
