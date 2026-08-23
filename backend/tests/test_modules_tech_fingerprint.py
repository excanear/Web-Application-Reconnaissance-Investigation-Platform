from unittest.mock import MagicMock, patch

import pytest

from app import wappalyzer
from app.modules.tech_fingerprint import TechFingerprintModule

# The real vendored categories.json isn't created until a later
# manual-validation step (outside this plan's tasks), so every test here
# would otherwise hit load_categories()'s FileNotFoundError -- mirroring
# how backend/tests/test_wappalyzer.py monkeypatches the same loader per
# test, this autouse fixture supplies just the category ids these tests'
# synthetic technologies dicts reference.
CATEGORIES = {
    "18": {"name": "Web servers"},
    "27": {"name": "Programming languages"},
    "12": {"name": "JavaScript frameworks"},
    "31": {"name": "CDN"},
}


@pytest.fixture(autouse=True)
def _fake_categories(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)


NGINX_TECH = {
    "nginx": {"cats": [18], "headers": {"Server": r"nginx\/?([\d.]+)?\;version:\1"}}
}
PHP_COOKIE_TECH = {"PHP": {"cats": [27], "cookies": {"PHPSESSID": ""}}}
ANGULAR_TECH = {"Angular": {"cats": [12], "html": [r'ng-version="([\d.]+)"\;version:\1']}}
REACT_TECH = {"React": {"cats": [12], "html": [r"data-reactroot|react-dom"]}}
CLOUDFLARE_TECH = {"Cloudflare": {"cats": [31], "headers": {"Server": "cloudflare"}}}


def _response(status_code=200, headers=None, text="", cookies=None):
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.text = text
    response.cookies = cookies or {}
    return response


def _fake_get(base, probe=None):
    probe = probe if probe is not None else _response(status_code=404)

    def fake_get(url, **kwargs):
        if url.endswith("/CHANGELOG.txt"):
            return probe
        return base

    return fake_get


def test_header_check_detects_technology_and_version():
    base = _response(headers={"Server": "nginx/1.18.0"})

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        findings = TechFingerprintModule().run(
            "example.com", {"wappalyzer_technologies": NGINX_TECH}
        )

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["nginx"].data["category"] == "web_servers"
    assert by_name["nginx"].data["version"] == "1.18.0"
    assert by_name["nginx"].data["source"] == "header"
    assert by_name["nginx"].value == "example.com"


def test_cookie_check_detects_technology_without_a_version():
    base = _response(cookies={"PHPSESSID": "abc123"})

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        findings = TechFingerprintModule().run(
            "example.com", {"wappalyzer_technologies": PHP_COOKIE_TECH}
        )

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["PHP"].data["version"] is None
    assert by_name["PHP"].data["source"] == "cookie"
    assert by_name["PHP"].data["confidence"] == "medium"


def test_wordpress_path_probe_still_detects_a_precise_version():
    base = _response()
    changelog = _response(status_code=200, text="== Changelog ==\n\nVersion 6.4.2\n* fixed things")

    with patch(
        "app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base, changelog)
    ):
        findings = TechFingerprintModule().run("example.com", {"wappalyzer_technologies": {}})

    by_name_source = {(f.data["name"], f.data["source"]): f for f in findings}
    finding = by_name_source[("WordPress", "path_probe")]
    assert finding.data["version"] == "6.4.2"
    assert finding.data["category"] == "cms"


BOOTSTRAP_SCRIPTSRC_TECH = {
    "Bootstrap": {"cats": [12], "scriptSrc": [r"bootstrap"]}
}


def test_scriptsrc_match_without_a_version_is_backfilled_from_the_script_content():
    # Real-world case that motivated this: self-hosted vendor scripts
    # like "assets/vendor/bootstrap/js/bootstrap.bundle.min.js" carry no
    # version in the URL, but the file itself has a "/*! Bootstrap
    # v5.3.3 ... */" banner comment.
    base = _response(
        text='<script src="/assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>'
    )
    script = _response(status_code=200, text="/*!\n * Bootstrap v5.3.3\n */\n!function(){}();")

    def fake_get(url, **kwargs):
        if url.endswith("bootstrap.bundle.min.js"):
            return script
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run(
            "example.com", {"wappalyzer_technologies": BOOTSTRAP_SCRIPTSRC_TECH}
        )

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["Bootstrap"].data["version"] == "5.3.3"
    assert by_name["Bootstrap"].data["confidence"] == "high"


def test_scriptsrc_match_stays_versionless_when_the_script_has_no_banner_version():
    base = _response(
        text='<script src="/assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>'
    )
    script = _response(status_code=200, text="!function(){/* no version banner here */}();")

    def fake_get(url, **kwargs):
        if url.endswith("bootstrap.bundle.min.js"):
            return script
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run(
            "example.com", {"wappalyzer_technologies": BOOTSTRAP_SCRIPTSRC_TECH}
        )

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["Bootstrap"].data["version"] is None
    assert by_name["Bootstrap"].data["confidence"] == "medium"


def test_scriptsrc_content_fetch_failure_leaves_the_finding_versionless_without_crashing():
    import requests

    base = _response(
        text='<script src="/assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>'
    )

    def fake_get(url, **kwargs):
        if url.endswith("bootstrap.bundle.min.js"):
            raise requests.ConnectionError("boom")
        return base

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run(
            "example.com", {"wappalyzer_technologies": BOOTSTRAP_SCRIPTSRC_TECH}
        )

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["Bootstrap"].data["version"] is None


def test_html_check_detects_frontend_framework_and_version():
    base = _response(text='<html ng-version="17.0.2"><body>hi</body></html>')

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        findings = TechFingerprintModule().run(
            "example.com", {"wappalyzer_technologies": ANGULAR_TECH}
        )

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["Angular"].data["version"] == "17.0.2"
    assert by_name["Angular"].data["source"] == "html"


def test_html_check_detects_framework_without_a_version():
    base = _response(text='<div id="root" data-reactroot=""></div>')

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        findings = TechFingerprintModule().run(
            "example.com", {"wappalyzer_technologies": REACT_TECH}
        )

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["React"].data["version"] is None
    assert by_name["React"].data["confidence"] == "medium"


def test_header_presence_check_detects_a_cdn_without_a_version():
    base = _response(headers={"Server": "cloudflare"})

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        findings = TechFingerprintModule().run(
            "example.com", {"wappalyzer_technologies": CLOUDFLARE_TECH}
        )

    by_name = {f.data["name"]: f for f in findings}
    assert by_name["Cloudflare"].data["version"] is None


def test_unreachable_host_is_skipped_without_crashing():
    import requests

    with patch(
        "app.modules.tech_fingerprint.requests.get", side_effect=requests.RequestException("down")
    ):
        findings = TechFingerprintModule().run("example.com", {"wappalyzer_technologies": {}})

    assert findings == []


def test_circuit_breaker_trips_after_threshold_consecutive_failures_and_skips_remaining_hosts():
    import requests

    subdomains = {f"host{i}.example.com" for i in range(5)}

    with patch(
        "app.modules.tech_fingerprint.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        findings = TechFingerprintModule().run(
            "example.com",
            {"subdomains": subdomains, "circuit_breaker_threshold": 2, "wappalyzer_technologies": {}},
        )

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "tech_fingerprint"
    assert tripped[0].data["skipped_hosts"] == 4


def test_rate_limiter_paces_requests_between_hosts():
    base = _response(headers={"Server": "nginx/1.18.0"})

    with patch(
        "app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)
    ), patch("app.modules.tech_fingerprint.RateLimiter.wait") as mock_wait:
        TechFingerprintModule().run(
            "example.com",
            {"subdomains": {"a.example.com"}, "rate_limit": 10.0, "wappalyzer_technologies": {}},
        )

    assert mock_wait.call_count >= 2


def test_probes_discovered_subdomains_alongside_target():
    base = _response(headers={"Server": "nginx/1.18.0"})

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        findings = TechFingerprintModule().run(
            "example.com", {"subdomains": {"a.example.com"}, "wappalyzer_technologies": NGINX_TECH}
        )

    hosts = {f.value for f in findings}
    assert hosts == {"example.com", "a.example.com"}


def test_out_of_scope_hosts_are_skipped_and_recorded_without_requests():
    base = _response(headers={"Server": "nginx/1.18.0"})

    def fake_get(url, **kwargs):
        assert "blocked.example.com" not in url
        if url.endswith("/CHANGELOG.txt"):
            return _response(status_code=404)
        return base

    scope = {"include": ["example.com"], "exclude": ["blocked.example.com"]}

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=fake_get):
        findings = TechFingerprintModule().run(
            "example.com",
            {"subdomains": {"blocked.example.com"}, "scope": scope, "wappalyzer_technologies": {}},
        )

    out_of_scope = [f for f in findings if f.type == "out_of_scope"]
    assert [f.value for f in out_of_scope] == ["blocked.example.com"]
    assert out_of_scope[0].data == {"module": "tech_fingerprint"}


def test_records_the_main_request_to_the_audit_log():
    from app.audit import AuditLog

    base = _response(headers={"Server": "nginx/1.18.0"})
    audit = AuditLog()

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        TechFingerprintModule().run(
            "example.com", {"audit": audit, "wappalyzer_technologies": {}}
        )

    main_entries = [e for e in audit.entries if e["url"] == "https://example.com/"]
    assert len(main_entries) == 1
    assert main_entries[0]["outcome"] == "200"
    assert main_entries[0]["target"] == "example.com"


def test_records_the_path_probe_request_to_the_audit_log_when_it_fires():
    from app.audit import AuditLog

    base = _response()
    changelog = _response(status_code=200, text="== Changelog ==\n\nVersion 6.4.2\n* fixed things")
    audit = AuditLog()

    with patch(
        "app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base, changelog)
    ):
        TechFingerprintModule().run(
            "example.com", {"audit": audit, "wappalyzer_technologies": {}}
        )

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
        TechFingerprintModule().run(
            "example.com", {"audit": audit, "wappalyzer_technologies": {}}
        )

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: down"


def test_max_workers_default_is_fully_sequential_and_unchanged():
    # Same scenario/assertions as the pre-existing
    # test_circuit_breaker_trips_after_threshold_consecutive_failures_and_skips_remaining_hosts,
    # run with no max_workers in context at all -- proves the default path
    # is untouched by this task's changes.
    import requests

    subdomains = {f"host{i}.example.com" for i in range(5)}

    with patch(
        "app.modules.tech_fingerprint.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        findings = TechFingerprintModule().run(
            "example.com",
            {"subdomains": subdomains, "circuit_breaker_threshold": 2, "wappalyzer_technologies": {}},
        )

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["skipped_hosts"] == 4


def test_max_workers_greater_than_one_still_detects_every_host():
    base = _response(headers={"Server": "nginx/1.18.0"})
    subdomains = {f"host{i}.example.com" for i in range(6)}

    with patch("app.modules.tech_fingerprint.requests.get", side_effect=_fake_get(base)):
        findings = TechFingerprintModule().run(
            "example.com",
            {
                "subdomains": subdomains,
                "wappalyzer_technologies": NGINX_TECH,
                "max_workers": 3,
            },
        )

    hosts_detected = {f.value for f in findings if f.data.get("name") == "nginx"}
    assert hosts_detected == subdomains | {"example.com"}


def test_max_workers_circuit_breaker_trips_deterministically_on_batch_boundary():
    # 6 hosts total (sorted: example.com, host0..host4), max_workers=3 ->
    # two batches of 3. threshold=2 failures trips inside the first
    # batch (both requests in that batch fail) -- the trip must fire
    # using the same "last host whose failure crossed the threshold, in
    # host-list order" rule as the sequential (max_workers=1) case, and
    # the second batch must never be submitted.
    import requests

    subdomains = {f"host{i}.example.com" for i in range(5)}

    with patch(
        "app.modules.tech_fingerprint.requests.get",
        side_effect=requests.RequestException("down"),
    ) as mock_get:
        findings = TechFingerprintModule().run(
            "example.com",
            {
                "subdomains": subdomains,
                "circuit_breaker_threshold": 2,
                "wappalyzer_technologies": {},
                "max_workers": 3,
            },
        )

    # sorted hosts: ["example.com", "host0.example.com", "host1.example.com",
    #                "host2.example.com", "host3.example.com", "host4.example.com"]
    # batch 1 = indices 0,1,2 -> failures at index 0 and 1 trip the breaker
    # (threshold=2) while processing batch-1 results in order; trip fires
    # on the host at index 1 (host0.example.com), matching what max_workers=1
    # would produce -- but real batching resolves all 3 hosts' main requests
    # concurrently via ThreadPoolExecutor before bookkeeping even starts,
    # since each failing _fingerprint_host call makes exactly one
    # requests.get call (path-probe requests only fire on a 200 response).
    # A purely sequential loop (old code, or max_workers=1) would stop
    # immediately after the 2nd failure and never attempt the 3rd host's
    # request at all. Asserting call_count == 3 (not 2) is what actually
    # proves batching happened.
    assert mock_get.call_count == 3
    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].value == "host0.example.com"
    assert tripped[0].data["skipped_hosts"] == 4
