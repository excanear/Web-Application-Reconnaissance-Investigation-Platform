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


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    # Modules that rate-limit or pace NVD requests call time.sleep for real;
    # tests exercising those loops shouldn't actually wait. Tests asserting
    # specific sleep durations patch app.ratelimit.time.sleep locally, which
    # overrides this for the duration of their own `with` block.
    monkeypatch.setattr("time.sleep", lambda seconds: None)
