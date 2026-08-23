import re

from app import wappalyzer
from app.wappalyzer import (
    _parse_pattern,
    _substitute_version,
    collect_browser_probe_requirements,
    match_browser_technologies,
    match_technologies,
)


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


def test_substitute_version_returns_none_for_a_ternary_annotation():
    match = re.search(r"SomeCMS/([\d.]+)", "SomeCMS/2.0")
    assert _substitute_version(r"\1?Enterprise:Community", match) is None


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


def test_scriptsrc_match_retains_the_matched_url_for_a_later_content_probe(monkeypatch):
    # A self-hosted vendor script (e.g. "assets/vendor/bootstrap/js/
    # bootstrap.bundle.min.js") often carries no version in its URL at
    # all, so scriptSrc matches at "medium" confidence with no version --
    # but tech_fingerprint can still fetch that exact URL and look for a
    # version banner inside the file itself. That requires knowing which
    # URL matched, so it must survive on the Finding.
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"Bootstrap": {"cats": [12], "scriptSrc": [r"bootstrap"]}}
    response = _response(
        text='<script src="assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>'
    )

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["version"] is None
    assert findings[0].data["script_src"] == "assets/vendor/bootstrap/js/bootstrap.bundle.min.js"


def test_non_scriptsrc_match_has_no_script_src(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"nginx": {"cats": [22], "headers": {"Server": "nginx/([\\d.]+)\\;version:\\1"}}}
    response = _response(headers={"Server": "nginx/1.18.0"})

    findings = match_technologies("example.com", response, technologies=technologies)

    assert findings[0].data["script_src"] is None


def test_a_winning_non_scriptsrc_match_still_picks_up_script_src_from_a_shadowed_duplicate(
    monkeypatch,
):
    # Real case: Bootstrap's own Wappalyzer definition matches this page
    # via an "html" check (e.g. a CSS custom-property signature) *and*
    # via "scriptSrc" against the actual vendored bootstrap.bundle.min.js
    # -- both at version=None, so they dedupe to a single Finding. Which
    # check type happens to run first must not decide whether the
    # backfill-from-script-content pass downstream (tech_fingerprint)
    # gets a URL to work with; the script_src must survive regardless.
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "Bootstrap": {
            "cats": [12],
            "html": [r"data-bs-signature"],
            "scriptSrc": [r"bootstrap"],
        }
    }
    response = _response(
        text=(
            '<html data-bs-signature="1">'
            '<script src="assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>'
            "</html>"
        )
    )

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["source"] == "html"
    assert findings[0].data["script_src"] == "assets/vendor/bootstrap/js/bootstrap.bundle.min.js"


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


def test_independent_checks_matching_the_same_host_name_version_are_deduplicated(monkeypatch):
    # Both the header check and the meta check identify the same
    # technology at the same (host, name, version) tuple -- (example.com,
    # "WordPress", None) here, since neither pattern captures a version.
    # Reporting that tuple twice would make cve_correlation query NVD for
    # the same technology twice, so match_technologies keeps only the
    # first Finding for a given (host, name, version); whichever check
    # ran first (headers, before meta) wins.
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

    assert len(findings) == 1
    assert findings[0].data["name"] == "WordPress"
    assert findings[0].data["version"] is None
    assert findings[0].data["source"] == "header"


def test_two_patterns_matching_the_same_check_type_produce_only_one_finding(monkeypatch):
    # Two scriptSrc patterns both matching the same jQuery script tag
    # (e.g. one from a project override and one from the vendored
    # dataset) must not produce two Findings for the same (host, name,
    # version) -- that's the literal duplicate-pattern case the dedup
    # exists to eliminate.
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "jQuery": {
            "cats": [12],
            "scriptSrc": [
                r"jquery[.-]?([\d.]+)?(?:\.min)?\.js\;version:\1",
                r"jquery\.js",
            ],
        }
    }
    response = _response(text='<script src="/static/jquery-3.6.0.min.js"></script>')

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["name"] == "jQuery"
    assert findings[0].data["version"] == "3.6.0"


def test_ternary_version_annotation_is_detected_without_a_fabricated_version(monkeypatch):
    # Wappalyzer's `version:\1?Enterprise:Community` ternary syntax is not
    # evaluated by this engine -- the technology must still be detected,
    # but no garbled/fabricated version should be reported, and
    # confidence must fall to "medium" (only a real version bumps it to
    # "high").
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "SomeCMS": {
            "cats": [1],
            "headers": {"X-Powered-By": r"SomeCMS\/?([\d.]+)?\;version:\1?Enterprise:Community"},
        }
    }
    response = _response(headers={"X-Powered-By": "SomeCMS/2.0"})

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["name"] == "SomeCMS"
    assert findings[0].data["version"] is None
    assert findings[0].data["confidence"] == "medium"


def test_a_malformed_pattern_in_one_technology_does_not_abort_matching_the_rest(monkeypatch):
    # The vendored dataset is refreshed from upstream Wappalyzer, whose
    # schema permits shapes this engine doesn't fully model (e.g.
    # list-valued header patterns) and can contain regexes Python's `re`
    # rejects. A single malformed technology definition must be skipped,
    # not crash match_technologies for every other technology in the same
    # scan.
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "Broken": {"cats": [1], "headers": {"X-Broken": "(unclosed"}},
        "AlsoBroken": {"cats": [1], "headers": {"X-Also-Broken": ["not", "a", "string"]}},
        "nginx": {"cats": [18], "headers": {"Server": r"nginx\/?([\d.]+)?\;version:\1"}},
    }
    response = _response(
        headers={
            "X-Broken": "anything",
            "X-Also-Broken": "anything",
            "Server": "nginx/1.18.0",
        }
    )

    findings = match_technologies("example.com", response, technologies=technologies)

    assert len(findings) == 1
    assert findings[0].data["name"] == "nginx"
    assert findings[0].data["version"] == "1.18.0"


# --- collect_browser_probe_requirements -----------------------------------


def test_collects_and_dedupes_js_paths_across_technologies():
    technologies = {
        "A-Frame": {"cats": [12], "js": {"AFRAME.version": "", "aframeStats": ""}},
        "Other": {"cats": [12], "js": {"aframeStats": ""}},
    }

    reqs = collect_browser_probe_requirements(technologies)

    assert reqs.js_paths == ["AFRAME.version", "aframeStats"]


def test_collects_list_form_dom_selectors():
    technologies = {"A8.net": {"cats": [1], "dom": ["img[src*='.a8.net']"]}}

    reqs = collect_browser_probe_requirements(technologies)

    assert reqs.dom_selectors == ["img[src*='.a8.net']"]
    assert reqs.dom_selector_specs == {}


def test_collects_dict_form_dom_selectors_with_attributes_and_properties():
    technologies = {
        "Angular": {
            "cats": [12],
            "dom": {"[ng-version]": {"attributes": {"ng-version": r"^([\d\.]+)\;version:\1"}}},
        },
        "Amazon Associates": {
            "cats": [1],
            "dom": {
                "a[href*='amazon.com']": {"attributes": {"href": "tag="}},
                "input.qty": {"properties": {"value": ""}},
            },
        },
    }

    reqs = collect_browser_probe_requirements(technologies)

    assert set(reqs.dom_selectors) == {"[ng-version]", "a[href*='amazon.com']", "input.qty"}
    assert reqs.dom_selector_specs["[ng-version]"] == {"attributes": ["ng-version"], "properties": []}
    assert reqs.dom_selector_specs["input.qty"] == {"attributes": [], "properties": ["value"]}


def test_needs_css_is_true_only_when_a_technology_declares_a_css_check():
    assert collect_browser_probe_requirements({"A": {"cats": [1], "css": [".foo"]}}).needs_css is True
    assert collect_browser_probe_requirements({"A": {"cats": [1], "js": {"x": ""}}}).needs_css is False


# --- match_browser_technologies --------------------------------------------


def test_matches_a_js_global_and_extracts_the_version(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"A-Frame": {"cats": [12], "js": {"AFRAME.version": r"^(.+)$\;version:\1"}}}

    findings = match_browser_technologies(
        "example.com", js_values={"AFRAME.version": "1.4.0"}, dom_results={}, css_text="",
        technologies=technologies,
    )

    assert len(findings) == 1
    assert findings[0].data["name"] == "A-Frame"
    assert findings[0].data["version"] == "1.4.0"
    assert findings[0].data["source"] == "js"


def test_js_global_absent_produces_no_finding(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"A-Frame": {"cats": [12], "js": {"AFRAME.version": ""}}}

    findings = match_browser_technologies(
        "example.com", js_values={}, dom_results={}, css_text="", technologies=technologies,
    )

    assert findings == []


def test_matches_a_list_form_dom_selector_on_presence_alone(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"A8.net": {"cats": [1], "dom": ["img[src*='.a8.net']"]}}

    findings = match_browser_technologies(
        "example.com", js_values={}, dom_results={"img[src*='.a8.net']": {"text": "", "attributes": {}, "properties": {}}},
        css_text="", technologies=technologies,
    )

    assert len(findings) == 1
    assert findings[0].data["name"] == "A8.net"
    assert findings[0].data["version"] is None
    assert findings[0].data["source"] == "dom"


def test_list_form_dom_selector_absent_produces_no_finding(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"A8.net": {"cats": [1], "dom": ["img[src*='.a8.net']"]}}

    findings = match_browser_technologies(
        "example.com", js_values={}, dom_results={"img[src*='.a8.net']": None},
        css_text="", technologies=technologies,
    )

    assert findings == []


def test_matches_a_dict_form_dom_attribute_and_extracts_the_version(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "Angular": {
            "cats": [12],
            "dom": {"[ng-version]": {"attributes": {"ng-version": r"^([\d\.]+)\;version:\1"}}},
        }
    }

    findings = match_browser_technologies(
        "example.com", js_values={},
        dom_results={"[ng-version]": {"text": "", "attributes": {"ng-version": "17.0.2"}, "properties": {}}},
        css_text="", technologies=technologies,
    )

    assert len(findings) == 1
    assert findings[0].data["name"] == "Angular"
    assert findings[0].data["version"] == "17.0.2"
    assert findings[0].data["source"] == "dom"


def test_matches_a_dict_form_dom_exists_check(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"All in One SEO": {"cats": [1], "dom": {"script.aioseo-schema": {"exists": ""}}}}

    findings = match_browser_technologies(
        "example.com", js_values={},
        dom_results={"script.aioseo-schema": {"text": "", "attributes": {}, "properties": {}}},
        css_text="", technologies=technologies,
    )

    assert len(findings) == 1
    assert findings[0].data["name"] == "All in One SEO"


def test_matches_a_dict_form_dom_property(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"QtyWidget": {"cats": [1], "dom": {"input.qty": {"properties": {"value": r"^(\d+)$\;version:\1"}}}}}

    findings = match_browser_technologies(
        "example.com", js_values={},
        dom_results={"input.qty": {"text": "", "attributes": {}, "properties": {"value": "3"}}},
        css_text="", technologies=technologies,
    )

    assert len(findings) == 1
    assert findings[0].data["version"] == "3"


def test_matches_a_dict_form_dom_text(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"Banner": {"cats": [1], "dom": {".powered-by": {"text": "Powered by Ghost"}}}}

    findings = match_browser_technologies(
        "example.com", js_values={},
        dom_results={".powered-by": {"text": "Powered by Ghost", "attributes": {}, "properties": {}}},
        css_text="", technologies=technologies,
    )

    assert len(findings) == 1
    assert findings[0].data["name"] == "Banner"


def test_matches_a_css_pattern_against_the_full_stylesheet_text(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"Material UI": {"cats": [12], "css": [r"\.MuiPaper-root"]}}

    findings = match_browser_technologies(
        "example.com", js_values={}, dom_results={},
        css_text=".MuiPaper-root { padding: 8px; }", technologies=technologies,
    )

    assert len(findings) == 1
    assert findings[0].data["name"] == "Material UI"
    assert findings[0].data["source"] == "css"


def test_css_pattern_not_present_in_stylesheet_produces_no_finding(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"Material UI": {"cats": [12], "css": [r"\.MuiPaper-root"]}}

    findings = match_browser_technologies(
        "example.com", js_values={}, dom_results={}, css_text="body { color: red; }",
        technologies=technologies,
    )

    assert findings == []


def test_a_definition_with_only_http_checks_is_ignored_by_the_browser_matcher(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {"nginx": {"cats": [18], "headers": {"Server": "nginx"}}}

    findings = match_browser_technologies(
        "example.com", js_values={}, dom_results={}, css_text="", technologies=technologies,
    )

    assert findings == []


def test_js_and_dom_matches_for_the_same_technology_version_are_deduplicated(monkeypatch):
    monkeypatch.setattr(wappalyzer, "load_categories", lambda: CATEGORIES)
    technologies = {
        "Foo": {
            "cats": [12],
            "js": {"Foo.version": r"^(.+)$\;version:\1"},
            "dom": {"[foo-version]": {"attributes": {"foo-version": r"^(.+)$\;version:\1"}}},
        }
    }

    findings = match_browser_technologies(
        "example.com",
        js_values={"Foo.version": "2.0"},
        dom_results={"[foo-version]": {"text": "", "attributes": {"foo-version": "2.0"}, "properties": {}}},
        css_text="",
        technologies=technologies,
    )

    assert len(findings) == 1
    assert findings[0].data["source"] == "js"


def test_extract_version_from_script_banner_finds_a_bang_comment_version():
    # Real content captured from artssystem.com.br's self-hosted
    # bootstrap.bundle.min.js -- no version in the URL, but the file's
    # own banner comment has it.
    content = (
        "/*!\n"
        "  * Bootstrap v5.3.3 (https://getbootstrap.com/)\n"
        "  * Copyright 2011-2024 The Bootstrap Authors\n"
        "  */\n"
        '!function(t,e){"object"==typeof exports...'
    )
    assert wappalyzer.extract_version_from_script_banner("Bootstrap", content) == "5.3.3"


def test_extract_version_from_script_banner_finds_a_packaged_style_version():
    content = (
        "/*!\n"
        " * Isotope PACKAGED v3.0.6\n"
        " *\n"
        " * Licensed GPLv3 for open source use\n"
        " */\n"
    )
    assert wappalyzer.extract_version_from_script_banner("Isotope", content) == "3.0.6"


def test_extract_version_from_script_banner_finds_a_plain_name_then_version():
    content = "/**\n * Swiper 11.1.0\n * Most modern mobile touch slider\n */\n"
    assert wappalyzer.extract_version_from_script_banner("Swiper", content) == "11.1.0"


def test_extract_version_from_script_banner_returns_none_when_name_is_absent():
    content = "/*! Some Other Library v9.9.9 */\n"
    assert wappalyzer.extract_version_from_script_banner("Bootstrap", content) is None


def test_extract_version_from_script_banner_returns_none_without_a_version_number():
    content = "/*! Bootstrap - a responsive framework */\n"
    assert wappalyzer.extract_version_from_script_banner("Bootstrap", content) is None


def test_extract_version_from_script_banner_ignores_a_match_far_past_the_banner():
    # A version-shaped number deep inside minified code (e.g. part of an
    # unrelated numeric literal or an unrelated library's own banner
    # later in a bundle) must not be picked up -- only the top-of-file
    # banner, where this convention actually lives, counts.
    content = "x" * 5000 + "Bootstrap v1.2.3"
    assert wappalyzer.extract_version_from_script_banner("Bootstrap", content) is None
