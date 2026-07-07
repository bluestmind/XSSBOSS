"""Add tenant ownership and authentication boundaries.

Revision ID: 0004_tenant_isolation
Revises: 0003_test_case_execution_leases
"""
from alembic import op
import sqlalchemy as sa


revision = "0004_tenant_isolation"
down_revision = "0003_test_case_execution_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "tenants" not in inspector.get_table_names():
        op.create_table(
            "tenants",
            sa.Column("slug", sa.String(length=80), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("api_token_hash", sa.String(length=64), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("quotas", sa.JSON(), nullable=True),
            sa.Column("retention_days", sa.Integer(), nullable=False, server_default="90"),
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("slug"),
            sa.UniqueConstraint("api_token_hash"),
        )
        op.create_index("ix_tenants_id", "tenants", ["id"])
        op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)
        op.create_index("ix_tenants_api_token_hash", "tenants", ["api_token_hash"], unique=True)

    default_id = bind.execute(sa.text("SELECT id FROM tenants WHERE slug = 'default'")).scalar()
    if default_id is None:
        bind.execute(sa.text(
            "INSERT INTO tenants (id, slug, name, is_active, retention_days) "
            "VALUES (1, 'default', 'Default', true, 90)"
        ))
        default_id = 1
        if bind.dialect.name == "postgresql":
            bind.execute(sa.text(
                "SELECT setval(pg_get_serial_sequence('tenants', 'id'), "
                "GREATEST((SELECT MAX(id) FROM tenants), 1))"
            ))

    inspector = sa.inspect(bind)
    target_columns = {column["name"] for column in inspector.get_columns("targets")}
    with op.batch_alter_table("targets") as batch:
        if "tenant_id" not in target_columns:
            batch.add_column(sa.Column("tenant_id", sa.Integer(), server_default=str(default_id), nullable=False))

    inspector = sa.inspect(bind)
    index_names = {index["name"] for index in inspector.get_indexes("targets")}
    if "ix_targets_tenant_id" not in index_names:
        op.create_index("ix_targets_tenant_id", "targets", ["tenant_id"])
    foreign_keys = {fk.get("name") for fk in inspector.get_foreign_keys("targets")}
    if "fk_targets_tenant_id_tenants" not in foreign_keys:
        with op.batch_alter_table("targets") as batch:
            batch.create_foreign_key(
                "fk_targets_tenant_id_tenants", "tenants", ["tenant_id"], ["id"], ondelete="RESTRICT"
            )


def downgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.drop_constraint("fk_targets_tenant_id_tenants", type_="foreignkey")
        batch.drop_index("ix_targets_tenant_id")
        batch.drop_column("tenant_id")
    op.drop_table("tenants")
