from sqlalchemy import create_engine, inspect, text

from app.db import ensure_schema


def test_ensure_schema_adds_missing_scope_column_to_existing_projects_table(tmp_path):
    db_path = tmp_path / "legacy.db"
    legacy_engine = create_engine(f"sqlite:///{db_path}")
    try:
        with legacy_engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE TABLE projects ("
                    "id INTEGER PRIMARY KEY, name VARCHAR NOT NULL, target VARCHAR NOT NULL, "
                    "scope_notes TEXT NOT NULL, authorized BOOLEAN NOT NULL, "
                    "authorized_at DATETIME, created_at DATETIME)"
                )
            )

        ensure_schema(bind=legacy_engine)

        inspector = inspect(legacy_engine)
        columns = {col["name"] for col in inspector.get_columns("projects")}
        assert "scope" in columns
    finally:
        legacy_engine.dispose()


def test_ensure_schema_is_a_no_op_when_scope_column_already_exists(tmp_path):
    db_path = tmp_path / "current.db"
    current_engine = create_engine(f"sqlite:///{db_path}")
    try:
        ensure_schema(bind=current_engine)
        # calling it again must not raise (column already present)
        ensure_schema(bind=current_engine)

        inspector = inspect(current_engine)
        columns = {col["name"] for col in inspector.get_columns("projects")}
        assert "scope" in columns
    finally:
        current_engine.dispose()
