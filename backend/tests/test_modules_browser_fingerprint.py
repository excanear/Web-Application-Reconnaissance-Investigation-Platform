from unittest.mock import MagicMock, patch

import pytest
from playwright.sync_api import Error as PlaywrightError

from app.audit import AuditLog
from app.modules.browser_fingerprint import BrowserFingerprintModule

CATEGORIES = {"12": {"name": "JavaScript frameworks"}}


def _technologies():
    return {
        "A-Frame": {"cats": [12], "js": {"AFRAME.version": r"^(.+)$\;version:\1"}},
        "Angular": {
            "cats": [12],
            "dom": {"[ng-version]": {"attributes": {"ng-version": r"^([\d\.]+)\;version:\1"}}},
        },
        "Material UI": {"cats": [12], "css": [r"\.MuiPaper-root"]},
    }


def _fake_browser(page_factory):
    browser = MagicMock()
    browser.new_page.side_effect = page_factory
    playwright = MagicMock()
    playwright.chromium.launch.return_value = browser
    cm = MagicMock()
    cm.__enter__.return_value = playwright
    cm.__exit__.return_value = False
    return cm, browser


def _fake_page(js_result, dom_result, css_result, goto_side_effect=None):
    page = MagicMock()
    if goto_side_effect is not None:
        page.goto.side_effect = goto_side_effect
    page.evaluate.side_effect = [js_result, dom_result, css_result]
    return page


def test_returns_empty_without_launching_a_browser_when_no_technology_needs_one():
    context = {"wappalyzer_technologies": {"nginx": {"cats": [18], "headers": {"Server": "nginx"}}}}

    with patch("app.modules.browser_fingerprint.sync_playwright") as mock_sync_playwright:
        findings = BrowserFingerprintModule().run("example.com", context)

    mock_sync_playwright.assert_not_called()
    assert findings == []


def test_detects_js_dom_and_css_technologies_on_a_single_host(monkeypatch):
    monkeypatch.setattr("app.wappalyzer.load_categories", lambda: CATEGORIES)
    context = {"wappalyzer_technologies": _technologies()}
    page = _fake_page(
        js_result=["1.4.0"],
        dom_result=[{"text": "", "attributes": {"ng-version": "17.0.2"}, "properties": {}}],
        css_result=".MuiPaper-root { padding: 8px; }",
    )
    cm, browser = _fake_browser(lambda: page)

    with patch("app.modules.browser_fingerprint.sync_playwright", return_value=cm):
        findings = BrowserFingerprintModule().run("example.com", context)

    names = {f.data["name"]: f.data["version"] for f in findings if f.type == "technology"}
    assert names == {"A-Frame": "1.4.0", "Angular": "17.0.2", "Material UI": None}
    page.goto.assert_called_once_with(
        "https://example.com/", timeout=15000, wait_until="domcontentloaded"
    )
    browser.close.assert_called_once()


def test_probes_discovered_subdomains_alongside_the_target(monkeypatch):
    monkeypatch.setattr("app.wappalyzer.load_categories", lambda: CATEGORIES)
    context = {
        "wappalyzer_technologies": _technologies(),
        "subdomains": {"sub.example.com"},
    }
    pages = [
        _fake_page(js_result=[None], dom_result=[None], css_result="") for _ in range(2)
    ]
    cm, browser = _fake_browser(lambda: pages.pop(0))

    with patch("app.modules.browser_fingerprint.sync_playwright", return_value=cm):
        findings = BrowserFingerprintModule().run("example.com", context)

    assert findings == []
    assert browser.new_page.call_count == 2


def test_raises_a_helpful_error_when_chromium_is_not_installed():
    context = {"wappalyzer_technologies": _technologies()}
    playwright = MagicMock()
    playwright.chromium.launch.side_effect = PlaywrightError("Executable doesn't exist")
    cm = MagicMock()
    cm.__enter__.return_value = playwright
    cm.__exit__.return_value = False

    with patch("app.modules.browser_fingerprint.sync_playwright", return_value=cm):
        with pytest.raises(RuntimeError, match="playwright install --with-deps chromium"):
            BrowserFingerprintModule().run("example.com", context)


def test_unreachable_host_is_skipped_without_crashing(monkeypatch):
    monkeypatch.setattr("app.wappalyzer.load_categories", lambda: CATEGORIES)
    context = {"wappalyzer_technologies": _technologies()}
    audit = AuditLog()
    context["audit"] = audit
    page = MagicMock()
    page.goto.side_effect = PlaywrightError("net::ERR_NAME_NOT_RESOLVED")
    cm, browser = _fake_browser(lambda: page)

    with patch("app.modules.browser_fingerprint.sync_playwright", return_value=cm):
        findings = BrowserFingerprintModule().run("example.com", context)

    assert findings == []
    assert audit.entries[0]["outcome"].startswith("error:")


def test_out_of_scope_host_is_skipped_and_recorded_without_opening_a_page(monkeypatch):
    monkeypatch.setattr("app.wappalyzer.load_categories", lambda: CATEGORIES)
    context = {
        "wappalyzer_technologies": _technologies(),
        "scope": {"include": ["example.com"], "exclude": ["blocked.example.com"]},
        "subdomains": {"blocked.example.com"},
    }
    page = _fake_page(js_result=[None], dom_result=[None], css_result="")
    cm, browser = _fake_browser(lambda: page)

    with patch("app.modules.browser_fingerprint.sync_playwright", return_value=cm):
        findings = BrowserFingerprintModule().run("example.com", context)

    out_of_scope = [f for f in findings if f.type == "out_of_scope"]
    assert len(out_of_scope) == 1
    assert out_of_scope[0].value == "blocked.example.com"
    assert browser.new_page.call_count == 1  # only the in-scope target


def test_circuit_breaker_trips_after_threshold_consecutive_failures(monkeypatch):
    monkeypatch.setattr("app.wappalyzer.load_categories", lambda: CATEGORIES)
    context = {
        "wappalyzer_technologies": _technologies(),
        "subdomains": {f"host{i}.example.com" for i in range(5)},
        "circuit_breaker_threshold": 2,
    }
    page = MagicMock()
    page.goto.side_effect = PlaywrightError("timeout")
    cm, browser = _fake_browser(lambda: page)

    with patch("app.modules.browser_fingerprint.sync_playwright", return_value=cm):
        findings = BrowserFingerprintModule().run("example.com", context)

    tripped = [f for f in findings if f.type == "circuit_breaker_tripped"]
    assert len(tripped) == 1
    assert tripped[0].data["module"] == "browser_fingerprint"
