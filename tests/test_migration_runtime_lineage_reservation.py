"""Migration checks for the controlled runtime-lineage reservation."""
from __future__ import annotations

from importlib import import_module
from io import StringIO
from types import SimpleNamespace

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


migration_0009 = import_module(
    "backend_api.db.migrations.versions.0009_encrypt_endpoint_auth_context"
)
migration_0010 = import_module(
    "backend_api.db.migrations.versions.0010_runtime_lineage_probe_reservation"
)


def test_long_revision_ids_fit_capacity_established_before_0009_stamp():
    assert len(migration_0009.revision) <= migration_0009.ALEMBIC_VERSION_NUM_LENGTH
    assert len(migration_0010.revision) <= migration_0009.ALEMBIC_VERSION_NUM_LENGTH
    assert migration_0010.down_revision == migration_0009.revision


def test_0009_widens_postgresql_alembic_version_column(monkeypatch):
    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    operations = Operations(context)
    bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
    inspector = SimpleNamespace(
        get_columns=lambda _table: [
            {"name": "version_num", "type": sa.String(32), "nullable": False}
        ]
    )
    monkeypatch.setattr(migration_0009.sa, "inspect", lambda _bind: inspector)
    monkeypatch.setattr(migration_0009.op, "alter_column", operations.alter_column)

    migration_0009._ensure_alembic_revision_capacity(bind)

    sql = output.getvalue()
    assert "ALTER TABLE alembic_version" in sql
    assert "TYPE VARCHAR(128)" in sql


def test_0009_leaves_sqlite_and_already_wide_columns_unchanged(monkeypatch):
    calls = []
    monkeypatch.setattr(
        migration_0009.op,
        "alter_column",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    sqlite_bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))
    migration_0009._ensure_alembic_revision_capacity(sqlite_bind)

    wide_bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
    inspector = SimpleNamespace(
        get_columns=lambda _table: [
            {"name": "version_num", "type": sa.String(255), "nullable": False}
        ]
    )
    monkeypatch.setattr(migration_0009.sa, "inspect", lambda _bind: inspector)
    migration_0009._ensure_alembic_revision_capacity(wide_bind)

    assert calls == []
