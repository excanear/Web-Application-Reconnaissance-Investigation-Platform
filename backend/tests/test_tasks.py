from unittest.mock import patch

from app.tasks import run_scan_task


def test_run_scan_task_calls_orchestrator_run_scan():
    with patch("app.tasks.run_scan") as mock_run_scan:
        run_scan_task.run(42)

    mock_run_scan.assert_called_once_with(42)
