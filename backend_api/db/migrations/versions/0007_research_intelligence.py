"""Add attack-surface graph, hypotheses, observations, and technique learning.

Revision ID: 0007_research_intelligence
Revises: 0006_queue_slo_timestamps
"""
from alembic import op
import sqlalchemy as sa


revision = "0007_research_intelligence"
down_revision = "0006_queue_slo_timestamps"
branch_labels = None
depends_on = None


_RESEARCH_TABLES = (
    "attack_surface_nodes",
    "research_hypotheses",
    "research_technique_stats",
    "attack_surface_edges",
    "research_observations",
)


def upgrade() -> None:
    bind = op.get_bind()
    from backend_api.models.base import Base
    import backend_api.models  # noqa: F401

    existing_tables = set(sa.inspect(bind).get_table_names())
    for table_name in _RESEARCH_TABLES:
        if table_name not in existing_tables:
            Base.metadata.tables[table_name].create(bind=bind, checkfirst=True)

    columns = {column["name"] for column in sa.inspect(bind).get_columns("test_cases")}
    if any(name not in columns for name in ("research_hypothesis_id", "technique", "research_metadata")):
        with op.batch_alter_table("test_cases") as batch:
            if "research_hypothesis_id" not in columns:
                batch.add_column(sa.Column("research_hypothesis_id", sa.Integer(), nullable=True))
                batch.create_foreign_key(
                    "fk_test_cases_research_hypothesis", "research_hypotheses",
                    ["research_hypothesis_id"], ["id"], ondelete="SET NULL",
                )
                batch.create_index("ix_test_cases_research_hypothesis_id", ["research_hypothesis_id"])
            if "technique" not in columns:
                batch.add_column(sa.Column("technique", sa.String(length=80), nullable=True))
                batch.create_index("ix_test_cases_technique", ["technique"])
            if "research_metadata" not in columns:
                batch.add_column(sa.Column("research_metadata", sa.JSON(), nullable=True))


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("test_cases")}
    with op.batch_alter_table("test_cases") as batch:
        if "research_metadata" in columns:
            batch.drop_column("research_metadata")
        if "technique" in columns:
            batch.drop_index("ix_test_cases_technique")
            batch.drop_column("technique")
        if "research_hypothesis_id" in columns:
            batch.drop_index("ix_test_cases_research_hypothesis_id")
            batch.drop_constraint("fk_test_cases_research_hypothesis", type_="foreignkey")
            batch.drop_column("research_hypothesis_id")
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for table_name in reversed(_RESEARCH_TABLES):
        if table_name in tables:
            op.drop_table(table_name)
