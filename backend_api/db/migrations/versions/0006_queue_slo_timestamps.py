"""Persist first-claim timestamps for queue-delay SLOs.

Revision ID: 0006_queue_slo_timestamps
Revises: 0005_audit_events
"""
from alembic import op
import sqlalchemy as sa


revision = "0006_queue_slo_timestamps"
down_revision = "0005_audit_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("test_cases")}
    if "first_claimed_at" not in columns:
        op.add_column("test_cases", sa.Column("first_claimed_at", sa.DateTime(timezone=True), nullable=True))
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("test_cases")}
    if "ix_test_cases_first_claimed_at" not in indexes:
        op.create_index("ix_test_cases_first_claimed_at", "test_cases", ["first_claimed_at"])


def downgrade() -> None:
    op.drop_index("ix_test_cases_first_claimed_at", table_name="test_cases")
    op.drop_column("test_cases", "first_claimed_at")
