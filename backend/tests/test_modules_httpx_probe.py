from unittest.mock import MagicMock, patch

from app.modules.httpx_probe import HttpxProbeModule


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
