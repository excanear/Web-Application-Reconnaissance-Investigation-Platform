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
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

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
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

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


def test_excludes_a_different_apache_product_sharing_the_apache_vendor_field(monkeypatch):
    # Regression: "Apache" (our web-server rule, meaning Apache HTTP Server)
    # used to match any CPE whose *vendor* field was "apache" -- including
    # unrelated Apache Software Foundation products like Log4j -- because
    # matching searched the whole criteria string instead of the product
    # field specifically.
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "Apache", "version": "2.4.7", "host": "example.com"}]}
    log4j_match = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
    }
    payload = _nvd_response(_cve("CVE-2021-44228", [log4j_match]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        findings = CveCorrelationModule().run("example.com", context)

    assert findings == []


def test_still_matches_apache_http_server_itself_via_the_product_alias(monkeypatch):
    # The alias that fixes the false-positive above must not also break the
    # legitimate case: Apache HTTP Server's own CPE product is "http_server",
    # not "apache".
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

    context = {"technologies": [{"name": "Apache", "version": "2.4.7", "host": "example.com"}]}
    http_server_match = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.4.0",
        "versionEndIncluding": "2.4.39",
    }
    payload = _nvd_response(_cve("CVE-2019-10092", [http_server_match]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        findings = CveCorrelationModule().run("example.com", context)

    assert len(findings) == 1
    assert findings[0].value == "CVE-2019-10092"


def test_excludes_a_different_product_whose_cpe_slug_merely_contains_the_name(monkeypatch):
    # Regression test for a real false positive found on a live scan:
    # CVE-2019-15517 is about "Nginx Proxy Manager" (a third-party admin
    # panel), cpe:2.3:a:jc21:nginx_proxy_manager:* -- confirmed against
    # the real NVD API. The old matching used `needle in product`
    # (substring), so fingerprinted "Nginx" (the actual web server)
    # matched it too, since "nginx" is a substring of the stripped
    # product "nginxproxymanager". Product identity must be exact, not
    # "contains", or every "X Manager"/"X UI"/"X Ingress Controller"
    # product sharing a name fragment shows up as a false "suspected" CVE.
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "Nginx", "version": "1.24.0", "host": "example.com"}]}
    nginx_proxy_manager_match = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:jc21:nginx_proxy_manager:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "2.0.13",
    }
    payload = _nvd_response(_cve("CVE-2019-15517", [nginx_proxy_manager_match]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        findings = CveCorrelationModule().run("example.com", context)

    assert findings == []


def test_sends_api_key_header_when_configured(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", "test-key-123")
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

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
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

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
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

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
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

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


def test_cve_finding_includes_host_and_suspected_status(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

    context = {
        "technologies": [{"name": "nginx", "version": "1.18.0", "host": "tech.example.com"}]
    }
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        findings = CveCorrelationModule().run("example.com", context)

    assert len(findings) == 1
    assert findings[0].data["host"] == "tech.example.com"
    assert findings[0].data["status"] == "suspected"


def test_cve_finding_carries_english_description_and_none_pt_without_a_deepl_key(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)
    # cve_correlation.settings and app.translate's settings are the same
    # object (both modules do `from app.config import settings`), so
    # patching it here also governs translate_en_to_pt's behavior below.
    monkeypatch.setattr(cve_correlation.settings, "deepl_api_key", None)

    context = {
        "technologies": [{"name": "nginx", "version": "1.18.0", "host": "tech.example.com"}]
    }
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH], description="A vuln."))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        findings = CveCorrelationModule().run("example.com", context)

    assert findings[0].data["description_en"] == "A vuln."
    assert findings[0].data["description_pt"] is None


def test_cve_finding_carries_translated_description_when_deepl_is_configured(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)
    monkeypatch.setattr(cve_correlation, "fetch_epss", lambda *args, **kwargs: None)

    context = {
        "technologies": [{"name": "nginx", "version": "1.18.0", "host": "tech.example.com"}]
    }
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH], description="A vuln."))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        with patch(
            "app.modules.cve_correlation.translate_en_to_pt", return_value="Uma vulnerabilidade."
        ) as mock_translate:
            findings = CveCorrelationModule().run("example.com", context)

    assert findings[0].data["description_pt"] == "Uma vulnerabilidade."
    assert mock_translate.call_args.kwargs["module"] == "cve_correlation"
    assert mock_translate.call_args.kwargs["audit_target"] == "CVE-2021-23017"


def test_cve_finding_includes_the_epss_score_when_the_lookup_succeeds(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0", "host": "tech.example.com"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        with patch("app.modules.cve_correlation.fetch_epss", return_value=0.42):
            findings = CveCorrelationModule().run("example.com", context)

    assert findings[0].data["epss_score"] == 0.42


def test_cve_finding_has_a_none_epss_score_when_the_lookup_fails(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0", "host": "tech.example.com"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        with patch("app.modules.cve_correlation.fetch_epss", return_value=None):
            findings = CveCorrelationModule().run("example.com", context)

    assert findings[0].data["epss_score"] is None
