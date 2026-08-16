from unittest.mock import MagicMock, patch

from app.modules.subfinder import SubfinderModule


def test_subfinder_parses_stdout_into_subdomain_findings():
    fake_result = MagicMock(stdout="b.example.com\na.example.com\na.example.com\n")
    with patch("app.modules.subfinder.subprocess.run", return_value=fake_result) as mock_run:
        findings = SubfinderModule().run("example.com", {})

    mock_run.assert_called_once_with(
        ["subfinder", "-d", "example.com", "-silent"],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    assert [f.value for f in findings] == ["a.example.com", "b.example.com"]
    assert all(f.type == "subdomain" for f in findings)
