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


def test_unreachable_host_is_skipped_without_crashing():
    import requests

    with patch(
        "app.modules.tech_fingerprint.requests.get", side_effect=requests.RequestException("down")
    ):
        findings = TechFingerprintModule().run("example.com", {})

    assert findings == []


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
