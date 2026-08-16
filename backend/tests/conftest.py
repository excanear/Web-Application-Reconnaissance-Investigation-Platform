import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_db_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"

import pytest


@pytest.fixture(scope="session", autouse=True)
def _cleanup_test_db():
    yield
    from app.db import engine

    engine.dispose()
    try:
        os.remove(_db_path)
    except OSError:
        pass
