import re

from app import wappalyzer
from app.wappalyzer import _parse_pattern, _substitute_version, match_technologies


def _response(headers=None, cookies=None, text=""):
    class FakeResponse:
        pass

    r = FakeResponse()
    r.headers = headers or {}
    r.cookies = cookies or {}
    r.text = text
    return r


CATEGORIES = {"18": {"name": "Web servers"}, "1": {"name": "CMS"}, "12": {"name": "JavaScript frameworks"}}


def test_parses_a_bare_pattern_with_no_annotations():
    parsed = _parse_pattern("nginx")
    assert parsed.regex == "nginx"
    assert parsed.version_template is None
    assert parsed.confidence == 100


def test_parses_a_version_template_annotation():
    parsed = _parse_pattern(r"nginx\/?([\d.]+)?\;version:\1")
    assert parsed.regex == r"nginx\/?([\d.]+)?"
    assert parsed.version_template == r"\1"


def test_parses_and_discards_a_confidence_annotation():
    parsed = _parse_pattern(r"php\;confidence:50")
    assert parsed.confidence == 50
    assert parsed.regex == "php"


def test_empty_pattern_means_presence_only():
    parsed = _parse_pattern("")
    assert parsed.regex == ""


def test_substitutes_a_captured_group_into_the_version_template():
    match = re.search(r"nginx/([\d.]+)", "nginx/1.18.0")
    assert _substitute_version(r"\1", match) == "1.18.0"


def test_substitute_version_returns_none_when_the_referenced_group_is_absent():
    match = re.search(r"nginx", "nginx")
    assert _substitute_version(r"\1", match) is None


def test_matches_a_header_and_extracts_the_version(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "nginx": {"cats": [18], "headers": {"Server": r"nginx\/?([\d.]+)?\;version:\1"}}
    }
    response = _response(headers={"Server": "nginx/1.18.0"})

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["name"] == "nginx"
    assert findings[0].data["category"] == "web_servers"
    assert findings[0].data["version"] == "1.18.0"
    assert findings[0].data["confidence"] == "high"
    assert findings[0].data["source"] == "header"
    assert findings[0].value == "example.com"


def test_header_confidence_annotation_never_changes_the_high_medium_bucket(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"nginx": {"cats": [18], "headers": {"Server": r"nginx\;confidence:10"}}}
    response = _response(headers={"Server": "nginx"})

    findings = match_technologies("example.com", response, technologies=technologies)

    assert findings[0].data["version"] is None
    assert findings[0].data["confidence"] == "medium"


def test_cookie_presence_only_match_without_a_pattern(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"Laravel": {"cats": [1], "cookies": {"laravel_session": ""}}}
    response = _response(cookies={"laravel_session": "abc123"})

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["name"] == "Laravel"
    assert findings[0].data["source"] == "cookie"
    assert findings[0].data["version"] is None


def test_cookie_absent_produces_no_finding(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"Laravel": {"cats": [1], "cookies": {"laravel_session": ""}}}
    response = _response(cookies={})

    findings = match_technologies("example.com", response, technologies=technologies)

    assert findings == []


def test_matches_a_meta_tag_regardless_of_attribute_order(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"WordPress": {"cats": [1], "meta": {"generator": r"WordPress\s*([\d.]+)?\;version:\1"}}}

    name_first = _response(text='<meta name="generator" content="WordPress 6.4.2" />')
    content_first = _response(text='<meta content="WordPress 6.4.2" name="generator" />')

    for response in (name_first, content_first):
        findings = match_technologies("example.com", response, technologies=technologies)
        assert len(findings) == 1
        assert findings[0].data["version"] == "6.4.2"
        assert findings[0].data["source"] == "meta"


def test_matches_an_html_pattern_and_extracts_the_version(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"Angular": {"cats": [12], "html": [r'ng-version="([\d.]+)"\;version:\1']}}
    response = _response(text='<html ng-version="17.0.2"><body>hi</body></html>')

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["version"] == "17.0.2"
    assert findings[0].data["source"] == "html"


def test_matches_a_scriptsrc_pattern_against_extracted_script_urls(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"jQuery": {"cats": [12], "scriptSrc": [r"jquery[.-]?([\d.]+)?(?:\.min)?\.js\;version:\1"]}}
    response = _response(text='<script src="/static/jquery-3.6.0.min.js"></script>')

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["version"] == "3.6.0"
    assert findings[0].data["source"] == "scriptSrc"


def test_skips_a_definition_whose_only_check_types_are_js_dom_or_css(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "SomeSPAFramework": {"cats": [12], "js": {"someGlobal": ""}, "dom": {"div.app": {}}}
    }
    response = _response(text="<html></html>")

    findings = match_technologies("example.com", response, technologies=technologies)

    assert findings == []


def test_uses_the_first_listed_category_when_a_technology_has_several(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"WordPress": {"cats": [1, 18], "meta": {"generator": "WordPress"}}}
    response = _response(text='<meta name="generator" content="WordPress" />')

    findings = match_technologies("example.com", response, technologies=technologies)

    assert findings[0].data["category"] == "cms"


def test_a_technology_can_produce_more_than_one_finding_from_independent_checks(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "WordPress": {
            "cats": [1],
            "headers": {"X-Powered-By": r"WordPress"},
            "meta": {"generator": r"WordPress"},
        }
    }
    response = _response(
        headers={"X-Powered-By": "WordPress"},
        text='<meta name="generator" content="WordPress" />',
    )

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 2
    assert {f.data["source"] for f in findings} == {"header", "meta"}
