"""Add an atomic one-shot reservation for controlled lineage probes.

Revision ID: 0010_runtime_lineage_probe_reservation
Revises: 0009_encrypt_endpoint_auth_context
"""
from alembic import op
import sqlalchemy as sa


revision = "0010_runtime_lineage_probe_reservation"
down_revision = "0009_encrypt_endpoint_auth_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("test_cases")}
    if "runtime_lineage_probe_reserved_at" not in columns:
        op.add_column(
            "test_cases",
            sa.Column(
                "runtime_lineage_probe_reserved_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("test_cases")}
    if "runtime_lineage_probe_reserved_at" in columns:
        op.drop_column("test_cases", "runtime_lineage_probe_reserved_at")
