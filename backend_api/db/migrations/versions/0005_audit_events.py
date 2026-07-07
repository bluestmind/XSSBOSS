"""Add append-only tamper-evident audit events.

Revision ID: 0005_audit_events
Revises: 0004_tenant_isolation
"""
from alembic import op
import sqlalchemy as sa


revision = "0005_audit_events"
down_revision = "0004_tenant_isolation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_events" not in inspector.get_table_names():
        op.create_table(
            "audit_events",
            sa.Column("tenant_id", sa.Integer(), nullable=True),
            sa.Column("request_id", sa.String(length=64), nullable=False),
            sa.Column("actor", sa.String(length=160), nullable=False),
            sa.Column("method", sa.String(length=16), nullable=False),
            sa.Column("path", sa.String(length=512), nullable=False),
            sa.Column("status_code", sa.Integer(), nullable=False),
            sa.Column("duration_ms", sa.Float(), nullable=False),
            sa.Column("client_ip_hash", sa.String(length=64), nullable=True),
            sa.Column("event_type", sa.String(length=80), nullable=False, server_default="api_request"),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column("previous_hash", sa.String(length=64), nullable=False, server_default=""),
            sa.Column("event_hash", sa.String(length=64), nullable=False),
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("request_id"),
            sa.UniqueConstraint("event_hash"),
        )
        for column in ("id", "tenant_id", "request_id", "event_hash"):
            op.create_index(
                f"ix_audit_events_{column}", "audit_events", [column],
                unique=column in {"request_id", "event_hash"},
            )

    if bind.dialect.name == "postgresql":
        op.execute("""
            CREATE OR REPLACE FUNCTION xssboss_reject_audit_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit_events is append-only';
            END;
            $$ LANGUAGE plpgsql;
        """)
        op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
        op.execute("""
            CREATE TRIGGER audit_events_append_only
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION xssboss_reject_audit_mutation()
        """)
    elif bind.dialect.name == "sqlite":
        op.execute("""
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events BEGIN
                SELECT RAISE(ABORT, 'audit_events is append-only');
            END
        """)
        op.execute("""
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events BEGIN
                SELECT RAISE(ABORT, 'audit_events is append-only');
            END
        """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
        op.execute("DROP FUNCTION IF EXISTS xssboss_reject_audit_mutation()")
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_delete")
    op.drop_table("audit_events")
