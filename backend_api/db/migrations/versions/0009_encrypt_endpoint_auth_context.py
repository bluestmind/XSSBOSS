"""Encrypt endpoint authentication context at rest.

Revision ID: 0009_encrypt_endpoint_auth_context
Revises: 0008_encrypt_target_auth_info
"""
from alembic import op
import sqlalchemy as sa


revision = "0009_encrypt_endpoint_auth_context"
down_revision = "0008_encrypt_target_auth_info"
branch_labels = None
depends_on = None


ALEMBIC_VERSION_NUM_LENGTH = 128


def _ensure_alembic_revision_capacity(bind) -> None:
    """Widen Alembic's default version column before stamping this revision."""
    # SQLite accepts values longer than a declared VARCHAR length. Other
    # production databases enforce Alembic's default VARCHAR(32), while this
    # revision and its descendants use longer descriptive identifiers.
    if bind.dialect.name == "sqlite":
        return

    version_column = next(
        (
            column
            for column in sa.inspect(bind).get_columns("alembic_version")
            if column["name"] == "version_num"
        ),
        None,
    )
    if version_column is None:
        raise RuntimeError("Alembic version table is missing version_num")

    existing_type = version_column["type"]
    existing_length = getattr(existing_type, "length", None)
    if existing_length is None or existing_length >= ALEMBIC_VERSION_NUM_LENGTH:
        return

    op.alter_column(
        "alembic_version",
        "version_num",
        existing_type=existing_type,
        type_=sa.String(length=ALEMBIC_VERSION_NUM_LENGTH),
        existing_nullable=bool(version_column.get("nullable", False)),
    )


def upgrade() -> None:
    bind = op.get_bind()
    _ensure_alembic_revision_capacity(bind)

    from backend_api.db.encrypted_json import encrypt_json_value

    endpoints = sa.table(
        "endpoints",
        sa.column("id", sa.Integer),
        sa.column("auth_context", sa.JSON),
    )
    rows = bind.execute(
        sa.select(endpoints.c.id, endpoints.c.auth_context).where(
            endpoints.c.auth_context.is_not(None)
        )
    ).all()
    for row in rows:
        encrypted = encrypt_json_value(row.auth_context)
        if encrypted != row.auth_context:
            bind.execute(
                endpoints.update()
                .where(endpoints.c.id == row.id)
                .values(auth_context=encrypted)
            )


def downgrade() -> None:
    from backend_api.db.encrypted_json import decrypt_json_value

    bind = op.get_bind()
    endpoints = sa.table(
        "endpoints",
        sa.column("id", sa.Integer),
        sa.column("auth_context", sa.JSON),
    )
    rows = bind.execute(
        sa.select(endpoints.c.id, endpoints.c.auth_context).where(
            endpoints.c.auth_context.is_not(None)
        )
    ).all()
    for row in rows:
        decrypted = decrypt_json_value(row.auth_context)
        if decrypted != row.auth_context:
            bind.execute(
                endpoints.update()
                .where(endpoints.c.id == row.id)
                .values(auth_context=decrypted)
            )
