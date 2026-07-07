"""Add content-addressed evidence and expiring oracle tokens.

Revision ID: 0002_evidence_integrity
Revises: 0001_durable_run_ownership
"""
from alembic import op
import sqlalchemy as sa


revision = "0002_evidence_integrity"
down_revision = "0001_durable_run_ownership"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    test_case_columns = {column["name"] for column in inspector.get_columns("test_cases")}
    with op.batch_alter_table("test_cases") as batch:
        if "token_expires_at" not in test_case_columns:
            batch.add_column(sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True))
        if "token_consumed_at" not in test_case_columns:
            batch.add_column(sa.Column("token_consumed_at", sa.DateTime(timezone=True), nullable=True))

    if "evidence_artifacts" not in inspector.get_table_names():
        op.create_table(
            "evidence_artifacts",
            sa.Column("experiment_id", sa.Integer(), nullable=False),
            sa.Column("execution_id", sa.Integer(), nullable=True),
            sa.Column("finding_id", sa.Integer(), nullable=True),
            sa.Column("kind", sa.String(length=40), nullable=False),
            sa.Column("uri", sa.String(length=1024), nullable=True),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("size_bytes", sa.Integer(), nullable=False),
            sa.Column("artifact_metadata", sa.JSON(), nullable=True),
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.ForeignKeyConstraint(["execution_id"], ["executions.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["experiment_id"], ["experiments.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("experiment_id", "kind", "sha256", name="uq_run_evidence_hash"),
        )
        for column in ("id", "experiment_id", "execution_id", "finding_id", "kind", "sha256"):
            op.create_index(f"ix_evidence_artifacts_{column}", "evidence_artifacts", [column])


def downgrade() -> None:
    op.drop_table("evidence_artifacts")
    with op.batch_alter_table("test_cases") as batch:
        batch.drop_column("token_consumed_at")
        batch.drop_column("token_expires_at")
