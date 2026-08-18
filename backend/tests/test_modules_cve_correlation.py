from unittest.mock import MagicMock, patch

from app.modules import cve_correlation
from app.modules.cve_correlation import CveCorrelationModule


def _nvd_response(*vulnerabilities):
    return {"vulnerabilities": [{"cve": v} for v in vulnerabilities]}


def _cve(cve_id, cpe_matches, cvss_score=9.4, severity="CRITICAL", description="A vuln."):
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": cvss_score, "baseSeverity": severity}}]},
        "configurations": [{"nodes": [{"cpeMatch": cpe_matches}]}],
    }


NGINX_RANGE_MATCH = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "0.6.18",
    "versionEndExcluding": "1.20.1",
}

NGINX_EXACT_MATCH = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:f5:nginx:1.19.0:*:*:*:*:*:*:*",
}


def _mock_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def test_correlates_technology_whose_version_falls_inside_the_cpe_range(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch(
        "app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)
    ) as mock_get:
        findings = CveCorrelationModule().run("example.com", context)

    assert mock_get.call_args.kwargs["params"] == {"keywordSearch": "nginx"}

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "cve"
    assert finding.value == "CVE-2021-23017"
    assert finding.data["cvss_score"] == 9.4
    assert finding.data["severity"] == "CRITICAL"
    assert finding.data["matched_technology"] == "nginx"
    assert finding.data["matched_technology_version"] == "1.18.0"


def test_excludes_cve_whose_range_does_not_cover_the_detected_version(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    # 1.20.1 is >= versionEndExcluding, so this CVE does not apply.
    context = {"technologies": [{"name": "nginx", "version": "1.20.1"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        findings = CveCorrelationModule().run("example.com", context)

    assert findings == []


def test_matches_cve_pinned_to_an_exact_cpe_version_with_no_range(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.19.0"}]}
    payload = _nvd_response(_cve("CVE-2099-99999", [NGINX_EXACT_MATCH]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        findings = CveCorrelationModule().run("example.com", context)

    assert len(findings) == 1
    assert findings[0].value == "CVE-2099-99999"


def test_excludes_cve_for_a_different_product_sharing_keyword_results(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}
    unrelated_match = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:openresty:openresty:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "1.19.3.2",
    }
    payload = _nvd_response(_cve("CVE-9999-00001", [unrelated_match]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        findings = CveCorrelationModule().run("example.com", context)

    assert findings == []


def test_sends_api_key_header_when_configured(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", "test-key-123")
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch(
        "app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)
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
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    import requests

    def fake_get(url, params=None, **kwargs):
        if params.get("keywordSearch") == "broken-tech":
            raise requests.RequestException("nvd is down")
        return _mock_response(payload)

    with patch("app.modules.cve_correlation.requests.get", side_effect=fake_get):
        findings = CveCorrelationModule().run("example.com", context)

    assert len(findings) == 1
    assert findings[0].value == "CVE-2021-23017"


def test_circuit_breaker_trips_after_threshold_consecutive_query_failures(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    import requests

    context = {
        "technologies": [{"name": f"tech{i}", "version": "1.0"} for i in range(5)],
        "circuit_breaker_threshold": 2,
    }

    with patch(
        "app.modules.cve_correlation.requests.get",
        side_effect=requests.RequestException("nvd is down"),
    ):
        findings = CveCorrelationModule().run("example.com", context)

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "cve_correlation"
    assert tripped[0].data["skipped_technologies"] == 3


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
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        CveCorrelationModule().run("example.com", context)

    assert len(sleep_calls) == 2
    assert all(s > 0 for s in sleep_calls)


def test_records_a_successful_nvd_query_to_the_audit_log(monkeypatch):
    from app.audit import AuditLog

    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))
    audit = AuditLog()
    context["audit"] = audit

    with patch(
        "app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)
    ):
        CveCorrelationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "cve_correlation"
    assert audit.entries[0]["target"] == "nginx"
    assert audit.entries[0]["outcome"] == "200"
    assert audit.entries[0]["url"] == cve_correlation.NVD_API_URL


def test_records_a_failed_nvd_query_to_the_audit_log(monkeypatch):
    from app.audit import AuditLog

    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0"}]}
    audit = AuditLog()
    context["audit"] = audit

    import requests as requests_lib

    with patch(
        "app.modules.cve_correlation.requests.get",
        side_effect=requests_lib.RequestException("nvd is down"),
    ):
        CveCorrelationModule().run("example.com", context)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: nvd is down"
