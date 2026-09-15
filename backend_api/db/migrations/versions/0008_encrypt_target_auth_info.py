"""Encrypt target authentication configuration at rest.

Revision ID: 0008_encrypt_target_auth_info
Revises: 0007_research_intelligence
"""
from alembic import op
import sqlalchemy as sa


revision = "0008_encrypt_target_auth_info"
down_revision = "0007_research_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from backend_api.db.encrypted_json import encrypt_json_value

    bind = op.get_bind()
    targets = sa.table(
        "targets",
        sa.column("id", sa.Integer),
        sa.column("auth_info", sa.JSON),
    )
    rows = bind.execute(
        sa.select(targets.c.id, targets.c.auth_info).where(targets.c.auth_info.is_not(None))
    ).all()
    for row in rows:
        encrypted = encrypt_json_value(row.auth_info)
        if encrypted != row.auth_info:
            bind.execute(
                targets.update().where(targets.c.id == row.id).values(auth_info=encrypted)
            )


def downgrade() -> None:
    from backend_api.db.encrypted_json import decrypt_json_value

    bind = op.get_bind()
    targets = sa.table(
        "targets",
        sa.column("id", sa.Integer),
        sa.column("auth_info", sa.JSON),
    )
    rows = bind.execute(
        sa.select(targets.c.id, targets.c.auth_info).where(targets.c.auth_info.is_not(None))
    ).all()
    for row in rows:
        decrypted = decrypt_json_value(row.auth_info)
        if decrypted != row.auth_info:
            bind.execute(
                targets.update().where(targets.c.id == row.id).values(auth_info=decrypted)
            )
