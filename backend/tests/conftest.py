import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_db_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["CELERY_TASK_ALWAYS_EAGER"] = "true"

import pytest


@pytest.fixture(scope="session", autouse=True)
def _cleanup_test_db():
    yield
    os.remove(_db_path)
