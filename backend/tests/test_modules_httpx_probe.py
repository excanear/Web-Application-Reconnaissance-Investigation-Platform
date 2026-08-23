import subprocess
import pytest
from unittest.mock import MagicMock, patch

from app.audit import AuditLog
from app.modules.httpx_probe import HttpxProbeModule
from app.tool_check import ToolResolutionError


@pytest.fixture(autouse=True)
def _resolved_httpx_binary():
    # httpx_probe now resolves the real ProjectDiscovery httpx binary
    # before invoking it (see test_tool_check.py for that logic) --
    # these tests are about parsing/scope/audit behavior, so pin
    # resolution to a fixed name and let subprocess.run itself be mocked
    # as before.
    with patch("app.modules.httpx_probe.resolve_httpx_binary", return_value="httpx"):
        yield


def test_httpx_probe_parses_json_lines_into_live_host_findings():
    fake_output = (
        '{"url": "https://a.example.com", "input": "a.example.com", '
        '"status_code": 200, "tech": ["nginx"], "title": "A"}\n'
    )
    fake_result = MagicMock(stdout=fake_output)
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result) as mock_run:
        findings = HttpxProbeModule().run(
            "example.com", {"subdomains": {"a.example.com"}}
        )

    called_input = mock_run.call_args.kwargs["input"]
    assert "a.example.com" in called_input
    assert "example.com" in called_input
    assert len(findings) == 1
    assert findings[0].type == "live_host"
    assert findings[0].value == "https://a.example.com"
    assert findings[0].data["technologies"] == ["nginx"]
    assert findings[0].data["status_code"] == 200


def test_httpx_probe_falls_back_to_target_when_no_subdomains_discovered():
    fake_result = MagicMock(stdout="")
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result) as mock_run:
        HttpxProbeModule().run("example.com", {})

    assert mock_run.call_args.kwargs["input"] == "example.com"


def test_httpx_probe_passes_configured_rate_limit_to_the_subprocess():
    fake_result = MagicMock(stdout="")
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result) as mock_run:
        HttpxProbeModule().run("example.com", {"rate_limit": 15.0})

    command = mock_run.call_args.args[0]
    assert command[command.index("-rate-limit") + 1] == "15"


def test_httpx_probe_defaults_rate_limit_when_not_configured():
    fake_result = MagicMock(stdout="")
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result) as mock_run:
        HttpxProbeModule().run("example.com", {})

    command = mock_run.call_args.args[0]
    assert command[command.index("-rate-limit") + 1] == "5"


def test_pre_filters_out_of_scope_hosts_before_invoking_httpx():
    fake_result = MagicMock(stdout="")
    scope = {"include": ["example.com"], "exclude": ["blocked.example.com"]}

    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result) as mock_run:
        findings = HttpxProbeModule().run(
            "example.com", {"subdomains": {"blocked.example.com"}, "scope": scope}
        )

    called_input = mock_run.call_args.kwargs["input"]
    assert "blocked.example.com" not in called_input
    assert "example.com" in called_input

    out_of_scope = [f for f in findings if f.type == "out_of_scope"]
    assert [f.value for f in out_of_scope] == ["blocked.example.com"]
    assert out_of_scope[0].data == {"module": "httpx_probe"}


def test_records_one_entry_per_host_from_parsed_output():
    fake_output = (
        '{"url": "https://a.example.com", "input": "a.example.com", "status_code": 200}\n'
    )
    fake_result = MagicMock(stdout=fake_output)
    audit = AuditLog()
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result):
        HttpxProbeModule().run("example.com", {"subdomains": {"a.example.com"}, "audit": audit})

    entries = {e["target"]: e["outcome"] for e in audit.entries}
    assert entries["a.example.com"] == "200"
    assert entries["example.com"] == "no_response"


def test_url_only_record_does_not_produce_a_contradictory_no_response_entry():
    # Regression test: some httpx versions/flag combinations omit "input"
    # on a line but still include "url". The host must still correlate to
    # its real response, not get a second, contradictory "no_response"
    # audit entry alongside the real one.
    fake_output = '{"url": "https://a.example.com", "status_code": 200}\n'
    fake_result = MagicMock(stdout=fake_output)
    audit = AuditLog()
    with patch("app.modules.httpx_probe.subprocess.run", return_value=fake_result):
        HttpxProbeModule().run("example.com", {"subdomains": {"a.example.com"}, "audit": audit})

    host_entries = [e for e in audit.entries if e["target"] == "a.example.com"]
    assert len(host_entries) == 1
    assert host_entries[0]["outcome"] == "200"


def test_records_not_attempted_when_httpx_binary_is_missing():
    audit = AuditLog()
    with patch(
        "app.modules.httpx_probe.subprocess.run",
        side_effect=OSError("httpx not found"),
    ):
        with pytest.raises(OSError):
            HttpxProbeModule().run(
                "example.com", {"subdomains": {"a.example.com"}, "audit": audit}
            )

    targets = {e["target"] for e in audit.entries}
    assert targets == {"example.com", "a.example.com"}
    assert all(e["outcome"].startswith("not_attempted:") for e in audit.entries)


def test_records_error_for_every_host_when_subprocess_fails():
    audit = AuditLog()
    with patch(
        "app.modules.httpx_probe.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "httpx"),
    ):
        with pytest.raises(subprocess.CalledProcessError):
            HttpxProbeModule().run(
                "example.com", {"subdomains": {"a.example.com"}, "audit": audit}
            )

    targets = {e["target"] for e in audit.entries}
    assert targets == {"example.com", "a.example.com"}
    assert all(e["outcome"].startswith("error:") for e in audit.entries)


def test_records_not_attempted_for_every_host_when_httpx_binary_cannot_be_resolved():
    # Regression test: on some machines "httpx" on PATH resolves to an
    # unrelated Python package's CLI that shadows ProjectDiscovery's
    # httpx (same command name). The module must fail clearly and
    # record it per host, without ever invoking the wrong binary.
    audit = AuditLog()
    with patch(
        "app.modules.httpx_probe.resolve_httpx_binary",
        side_effect=ToolResolutionError("wrong tool detected"),
    ):
        with patch("app.modules.httpx_probe.subprocess.run") as mock_run:
            with pytest.raises(ToolResolutionError):
                HttpxProbeModule().run(
                    "example.com", {"subdomains": {"a.example.com"}, "audit": audit}
                )

    mock_run.assert_not_called()
    targets = {e["target"] for e in audit.entries}
    assert targets == {"example.com", "a.example.com"}
    assert all(
        e["outcome"] == "not_attempted: wrong tool detected" for e in audit.entries
    )
