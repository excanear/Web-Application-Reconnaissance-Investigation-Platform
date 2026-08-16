from unittest.mock import MagicMock, patch

from app.modules import cve_correlation
from app.modules.cve_correlation import CveCorrelationModule

NVD_RESPONSE_ONE_CVE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-23017",
                "descriptions": [{"lang": "en", "value": "A vulnerability in nginx resolver."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.4, "baseSeverity": "CRITICAL"}}
                    ]
                },
            }
        }
    ]
}


def _mock_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def test_correlates_technology_with_version_into_cve_findings(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}

    with patch(
        "app.modules.cve_correlation.requests.get",
        return_value=_mock_response(NVD_RESPONSE_ONE_CVE),
    ) as mock_get:
        findings = CveCorrelationModule().run("example.com", context)

    assert mock_get.call_args.kwargs["params"] == {"keywordSearch": "nginx 1.18.0"}
    assert "headers" not in mock_get.call_args.kwargs or "apiKey" not in (
        mock_get.call_args.kwargs.get("headers") or {}
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "cve"
    assert finding.value == "CVE-2021-23017"
    assert finding.data["cvss_score"] == 9.4
    assert finding.data["severity"] == "CRITICAL"
    assert finding.data["matched_technology"] == "nginx"
    assert finding.data["matched_technology_version"] == "1.18.0"
    assert "resolver" in finding.data["description"]


def test_sends_api_key_header_when_configured(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", "test-key-123")
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}

    with patch(
        "app.modules.cve_correlation.requests.get",
        return_value=_mock_response(NVD_RESPONSE_ONE_CVE),
    ) as mock_get:
        CveCorrelationModule().run("example.com", context)

    assert mock_get.call_args.kwargs["headers"]["apiKey"] == "test-key-123"


def test_skips_technologies_without_a_known_version(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "PHP", "version": None}]}

    with patch("app.modules.cve_correlation.requests.get") as mock_get:
        findings = CveCorrelationModule().run("example.com", context)

    mock_get.assert_not_called()
    assert findings == []


def test_returns_empty_list_when_no_technologies_in_context(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)

    with patch("app.modules.cve_correlation.requests.get") as mock_get:
        findings = CveCorrelationModule().run("example.com", {})

    mock_get.assert_not_called()
    assert findings == []


def test_isolates_one_failing_technology_query_and_keeps_the_rest(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {
        "technologies": [
            {"name": "broken-tech", "version": "1.0"},
            {"name": "nginx", "version": "1.18.0"},
        ]
    }

    import requests

    def fake_get(url, params=None, **kwargs):
        if params.get("keywordSearch") == "broken-tech 1.0":
            raise requests.RequestException("nvd is down")
        return _mock_response(NVD_RESPONSE_ONE_CVE)

    with patch("app.modules.cve_correlation.requests.get", side_effect=fake_get):
        findings = CveCorrelationModule().run("example.com", context)

    assert len(findings) == 1
    assert findings[0].value == "CVE-2021-23017"


def test_sleeps_between_requests_to_respect_nvd_rate_limit(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    sleep_calls = []
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda seconds: sleep_calls.append(seconds))

    context = {
        "technologies": [
            {"name": "nginx", "version": "1.18.0"},
            {"name": "PHP", "version": "8.1"},
        ]
    }

    with patch(
        "app.modules.cve_correlation.requests.get",
        return_value=_mock_response(NVD_RESPONSE_ONE_CVE),
    ):
        CveCorrelationModule().run("example.com", context)

    assert len(sleep_calls) == 2
    assert all(s > 0 for s in sleep_calls)
