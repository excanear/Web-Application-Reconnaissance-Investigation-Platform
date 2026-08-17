from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

connect_args = (
    {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def ensure_schema(bind=None) -> None:
    """Creates any missing tables, then adds any columns the current
    models define that an existing table predates (SQLite's
    ALTER TABLE ... ADD COLUMN is sufficient here - no full migration
    framework needed for a single additive column)."""
    bind = bind or engine
    Base.metadata.create_all(bind=bind)

    inspector = inspect(bind)
    if "projects" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("projects")}
    if "scope" not in columns:
        with bind.begin() as conn:
            conn.execute(text("ALTER TABLE projects ADD COLUMN scope JSON"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
