from unittest.mock import MagicMock, patch

from app.modules.tech_fingerprint import TechFingerprintModule


def _response(status_code=200, headers=None, text="", cookies=None):
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.text = text
    response.cookies = cookies or {}
    return response


def test_header_rule_detects_web_server_and_version():
    base = _response(headers={"Server": "nginx/1.18.0"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run("example.com", {})

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["nginx"].data["category"] == "web_server"
    assert by_name["nginx"].data["version"] == "1.18.0"
    assert by_name["nginx"].value == "example.com"


def test_cookie_rule_detects_backend_language_without_version():
    base = _response(cookies={"PHPSESSID": "abc123"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run("example.com", {})

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["PHP"].data["category"] == "backend"
    assert by_name["PHP"].data["version"] is None
    assert by_name["PHP"].data["source"] == "cookie"


def test_meta_generator_rule_detects_cms_and_version():
    base = _response(text='<meta name="generator" content="WordPress 6.4.2" />')
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run("example.com", {})

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["WordPress"].data["version"] == "6.4.2"
    assert by_name["WordPress"].data["source"] == "meta_generator"


def test_path_probe_rule_detects_version_from_known_file():
    base = _response()
    changelog = _response(status_code=200, text="== Changelog ==\n\nVersion 6.4.2\n* fixed things")

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return changelog
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run("example.com", {})

    by_name_source = {(f.data["name"], f.data["source"]): f for f in findings}
    finding = by_name_source[("WordPress", "path_probe")]
    assert finding.data["version"] == "6.4.2"


def test_html_regex_rule_detects_frontend_framework_and_version():
    base = _response(text='<html ng-version="17.0.2"><body>hi</body></html>')
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run("example.com", {})

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["Angular"].data["category"] == "frontend"
    assert by_name["Angular"].data["version"] == "17.0.2"
    assert by_name["Angular"].data["source"] == "html_regex"


def test_html_regex_rule_detects_framework_without_version():
    base = _response(text='<div id="root" data-reactroot=""></div>')
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run("example.com", {})

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["React"].data["version"] is None
    assert by_name["React"].data["confidence"] == "medium"


def test_header_rule_detects_cdn_by_header_presence_without_version():
    base = _response(headers={"Server": "cloudflare"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run("example.com", {})

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["Cloudflare"].data["category"] == "cdn_waf"


def test_unreachable_host_is_skipped_without_crashing():
    import requests

    with patch(
        "app.modules.tech_fingerprint.requests.get", side_effect=requests.RequestException("down")
    ):
        findings = TechFingerprintModule().run("example.com", {})

    assert findings == []


def test_circuit_breaker_trips_after_threshold_consecutive_failures_and_skips_remaining_hosts():
    import requests

    subdomains = {f"host{i}.example.com" for i in range(5)}

    with patch(
        "app.modules.tech_fingerprint.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        findings = TechFingerprintModule().run(
            "example.com", {"subdomains": subdomains, "circuit_breaker_threshold": 2}
        )

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "tech_fingerprint"
    # 6 hosts total (target + 5 subdomains); breaker opens on the 2nd
    # consecutive failure, so 4 hosts never get probed.
    assert tripped[0].data["skipped_hosts"] == 4


def test_rate_limiter_paces_requests_between_hosts():
    base = _response(headers={"Server": "nginx/1.18.0"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get), patch(
        "app.modules.tech_fingerprint.RateLimiter.wait"
    ) as mock_wait:
        TechFingerprintModule().run(
            "example.com", {"subdomains": {"a.example.com"}, "rate_limit": 10.0}
        )

    assert mock_wait.call_count >= 2


def test_probes_discovered_subdomains_alongside_target():
    base = _response(headers={"Server": "nginx/1.18.0"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run(
            "example.com", {"subdomains": {"a.example.com"}}
        )

    hosts = {f.value for f in findings}
    assert hosts == {"example.com", "a.example.com"}


def test_out_of_scope_hosts_are_skipped_and_recorded_without_requests():
    base = _response(headers={"Server": "nginx/1.18.0"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        assert "blocked.example.com" not in url
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    scope = {"include": ["example.com"], "exclude": ["blocked.example.com"]}

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run(
            "example.com", {"subdomains": {"blocked.example.com"}, "scope": scope}
        )

    out_of_scope = [f for f in findings if f.type == "out_of_scope"]
    assert [f.value for f in out_of_scope] == ["blocked.example.com"]
    assert out_of_scope[0].data == {"module": "tech_fingerprint"}
    assert any(f.data.get("name") == "nginx" for f in findings if f.type == "technology")


def test_records_the_main_request_to_the_audit_log():
    from app.audit import AuditLog

    base = _response(headers={"Server": "nginx/1.18.0"})
    probe_404 = _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe_404
        return base

    audit = AuditLog()
    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        TechFingerprintModule().run("example.com", {"audit": audit})

    main_entries = [e for e in audit.entries if e["url"] == "https://example.com/"]
    assert len(main_entries) == 1
    assert main_entries[0]["outcome"] == "200"
    assert main_entries[0]["target"] == "example.com"


def test_records_the_path_probe_request_to_the_audit_log_when_it_fires():
    from app.audit import AuditLog

    base = _response()
    changelog = _response(status_code=200, text="== Changelog ==\n\nVersion 6.4.2\n* fixed things")

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return changelog
        return base

    audit = AuditLog()
    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        TechFingerprintModule().run("example.com", {"audit": audit})

    probe_entries = [e for e in audit.entries if e["url"] == "https://example.com/CHANGELOG.txt"]
    assert len(probe_entries) == 1
    assert probe_entries[0]["outcome"] == "200"


def test_records_a_failed_main_request_to_the_audit_log():
    import requests as requests_lib

    from app.audit import AuditLog

    audit = AuditLog()
    with patch(
        "app.modules.tech_fingerprint.requests.get",
        side_effect=requests_lib.RequestException("down"),
    ):
        TechFingerprintModule().run("example.com", {"audit": audit})

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: down"
