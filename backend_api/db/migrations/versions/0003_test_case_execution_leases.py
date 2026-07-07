"""Add recoverable browser execution leases.

Revision ID: 0003_test_case_execution_leases
Revises: 0002_evidence_integrity
"""
from alembic import op
import sqlalchemy as sa


revision = "0003_test_case_execution_leases"
down_revision = "0002_evidence_integrity"
branch_labels = None
depends_on = None


def _index_names(inspector: sa.Inspector) -> set[str]:
    return {index["name"] for index in inspector.get_indexes("test_cases")}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("test_cases")}
    with op.batch_alter_table("test_cases") as batch:
        if "lease_owner" not in columns:
            batch.add_column(sa.Column("lease_owner", sa.String(length=120), nullable=True))
        if "lease_expires_at" not in columns:
            batch.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        if "attempt_count" not in columns:
            batch.add_column(sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False))

    inspector = sa.inspect(bind)
    indexes = _index_names(inspector)
    if "ix_test_cases_lease_owner" not in indexes:
        op.create_index("ix_test_cases_lease_owner", "test_cases", ["lease_owner"])
    if "ix_test_cases_lease_expires_at" not in indexes:
        op.create_index("ix_test_cases_lease_expires_at", "test_cases", ["lease_expires_at"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    indexes = _index_names(inspector)
    if "ix_test_cases_lease_expires_at" in indexes:
        op.drop_index("ix_test_cases_lease_expires_at", table_name="test_cases")
    if "ix_test_cases_lease_owner" in indexes:
        op.drop_index("ix_test_cases_lease_owner", table_name="test_cases")
    with op.batch_alter_table("test_cases") as batch:
        batch.drop_column("attempt_count")
        batch.drop_column("lease_expires_at")
        batch.drop_column("lease_owner")
