import json
import os
import re
from dataclasses import dataclass

from app.modules.base import Finding

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TECHNOLOGIES_PATH = os.path.join(DATA_DIR, "technologies.json")
CATEGORIES_PATH = os.path.join(DATA_DIR, "categories.json")

# These check types can be evaluated from a single HTTP GET response
# without a real browser.
SUPPORTED_CHECK_TYPES = ("headers", "cookies", "meta", "html", "scriptSrc")

# js (global JS variables), dom (element selectors/attributes/text/props),
# and css (stylesheet text) all require actually executing the page --
# app.modules.browser_fingerprint drives a headless browser to gather the
# raw signals these checks match against; match_browser_technologies below
# stays a pure function over those signals so it's testable without one.
BROWSER_CHECK_TYPES = ("js", "dom", "css")

_technologies_cache: dict | None = None
_categories_cache: dict | None = None


@dataclass
class ParsedPattern:
    regex: str
    version_template: str | None
    confidence: int


def load_technologies(path: str | None = None) -> dict:
    """Loads (and caches, unless an explicit path is given) the vendored
    technologies.json. A missing or malformed vendored file raises --
    unlike a network call, this is a packaging/setup problem (the
    operator hasn't run `recon update-fingerprints` yet), not a
    transient condition to silently degrade from. The orchestrator's
    existing module_error handling already converts a raising module
    into a single Finding without aborting the scan."""
    global _technologies_cache
    if path is not None:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    if _technologies_cache is None:
        with open(TECHNOLOGIES_PATH, encoding="utf-8") as f:
            _technologies_cache = json.load(f)
    return _technologies_cache


def load_categories(path: str | None = None) -> dict:
    """Loads (and caches) the vendored categories.json (numeric id, as a
    string key, -> {"name": ...})."""
    global _categories_cache
    if path is not None:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    if _categories_cache is None:
        with open(CATEGORIES_PATH, encoding="utf-8") as f:
            _categories_cache = json.load(f)
    return _categories_cache


def _slugify(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def _category_name(cats: list, categories: dict) -> str:
    if not cats:
        return ""
    entry = categories.get(str(cats[0]), {})
    return _slugify(entry.get("name", ""))


def _parse_pattern(raw: str) -> ParsedPattern:
    """Wappalyzer patterns are a regex optionally followed by \\;key:value
    annotations. An empty regex segment means "match on presence alone"
    -- equivalent to this project's existing r".+" convention for
    presence-only rules."""
    parts = raw.split("\\;")
    regex = parts[0]
    version_template = None
    confidence = 100
    for part in parts[1:]:
        if part.startswith("version:"):
            version_template = part[len("version:"):]
        elif part.startswith("confidence:"):
            try:
                confidence = int(part[len("confidence:"):])
            except ValueError:
                confidence = 100
    return ParsedPattern(regex=regex, version_template=version_template, confidence=confidence)


def _substitute_version(template: str, match: re.Match) -> str | None:
    # Wappalyzer's `version:\1?Enterprise:Community` ternary syntax picks
    # between two literal strings depending on whether group 1 matched.
    # Evaluating that ternary is out of scope here -- but naively
    # substituting \1 and leaving the "?a:b" tail in place would produce a
    # garbled string like "1 (Enterprise)?Enterprise:Community" reported
    # at "high" confidence, which is worse than reporting no version at
    # all. Detect the annotation (a literal "?" in the raw template) and
    # bail out to "no version" instead of fabricating one.
    if "?" in template:
        return None

    def repl(m: re.Match) -> str:
        try:
            group = match.group(int(m.group(1)))
        except IndexError:
            return ""
        return group or ""

    result = re.sub(r"\\(\d+)", repl, template)
    return result or None


def _try_match(name: str, category: str, raw_pattern: str, value: str, host: str, source: str) -> Finding | None:
    # `raw_pattern` and `value` both originate from externally-sourced
    # data -- the vendored (but upstream-updatable) technologies.json can
    # contain a regex Python's `re` module rejects (re.error), and
    # upstream's schema permits list-valued headers/cookies/meta entries
    # where this code expects a string (TypeError/AttributeError). One
    # malformed technology definition must never abort matching for every
    # other technology, so a single bad pattern is skipped here rather
    # than left to propagate out of match_technologies.
    try:
        parsed = _parse_pattern(raw_pattern)
        version = None
        if parsed.regex:
            match = re.search(parsed.regex, value or "", re.IGNORECASE)
            if not match:
                return None
            if parsed.version_template:
                version = _substitute_version(parsed.version_template, match)
    except (re.error, TypeError, AttributeError):
        return None
    return Finding(
        type="technology",
        value=host,
        data={
            "category": category,
            "name": name,
            "version": version,
            "confidence": "high" if version else "medium",
            "source": source,
        },
    )


def _extract_meta(text: str) -> dict:
    meta: dict = {}
    for m in re.finditer(
        r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']', text, re.IGNORECASE
    ):
        meta[m.group(1).lower()] = m.group(2)
    for m in re.finditer(
        r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']([^"\']+)["\']', text, re.IGNORECASE
    ):
        meta.setdefault(m.group(2).lower(), m.group(1))
    return meta


def _extract_script_srcs(text: str) -> list:
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text, re.IGNORECASE)


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _has_supported_check(definition: dict) -> bool:
    return any(key in definition for key in SUPPORTED_CHECK_TYPES)


def _has_browser_check(definition: dict) -> bool:
    return any(key in definition for key in BROWSER_CHECK_TYPES)


@dataclass
class BrowserProbeRequirements:
    """What a headless browser needs to gather from one page so every
    js/dom/css technology definition can be matched against it -- three
    values regardless of how many thousand technologies define such a
    check, so the driving module (app.modules.browser_fingerprint) makes
    at most three page.evaluate() round trips per host."""

    js_paths: list[str]
    dom_selectors: list[str]
    dom_selector_specs: dict[str, dict]
    needs_css: bool


def collect_browser_probe_requirements(technologies: dict | None = None) -> BrowserProbeRequirements:
    if technologies is None:
        technologies = load_technologies()

    js_paths: set[str] = set()
    dom_selectors: set[str] = set()
    dom_selector_specs: dict[str, dict] = {}
    needs_css = False

    for definition in technologies.values():
        js_paths.update(definition.get("js", {}).keys())

        dom = definition.get("dom")
        if isinstance(dom, list):
            dom_selectors.update(s for s in dom if isinstance(s, str))
        elif isinstance(dom, dict):
            for selector, spec in dom.items():
                if not isinstance(spec, dict):
                    continue
                dom_selectors.add(selector)
                entry = dom_selector_specs.setdefault(
                    selector, {"attributes": set(), "properties": set()}
                )
                entry["attributes"].update(spec.get("attributes", {}).keys())
                entry["properties"].update(spec.get("properties", {}).keys())

        if "css" in definition:
            needs_css = True

    return BrowserProbeRequirements(
        js_paths=sorted(js_paths),
        dom_selectors=sorted(dom_selectors),
        dom_selector_specs={
            sel: {"attributes": sorted(spec["attributes"]), "properties": sorted(spec["properties"])}
            for sel, spec in dom_selector_specs.items()
        },
        needs_css=needs_css,
    )


def _stringify_browser_value(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return str(value)
    return str(value)


def match_browser_technologies(
    host: str,
    js_values: dict,
    dom_results: dict,
    css_text: str,
    technologies: dict | None = None,
) -> list[Finding]:
    """Matches every js/dom/css technology definition against browser
    signals already gathered for `host`. Pure function, deliberately
    unaware of Playwright/how the signals were collected -- a headless
    browser driver just needs to shape its findings as:

    - js_values: {dotted.path: <JSON-safe value or None if undefined>}
    - dom_results: {selector: None | {"text": str, "attributes": {attr:
      value}, "properties": {prop: value}} for the first matching element}
    - css_text: concatenated text of every stylesheet rule + <style> tag
      on the page
    """
    if technologies is None:
        technologies = load_technologies()
    categories = load_categories()

    findings: list[Finding] = []
    seen: set[tuple[str, str, str | None]] = set()

    def _add(finding: Finding | None) -> None:
        if finding is None:
            return
        key = (finding.value, finding.data["name"], finding.data["version"])
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    for name, definition in technologies.items():
        if not _has_browser_check(definition):
            continue
        category = _category_name(definition.get("cats", []), categories)

        for path, raw_pattern in definition.get("js", {}).items():
            value = _stringify_browser_value(js_values.get(path))
            if value is None:
                continue
            _add(_try_match(name, category, raw_pattern, value, host, "js"))

        dom = definition.get("dom")
        if isinstance(dom, list):
            for selector in dom:
                if not isinstance(selector, str) or dom_results.get(selector) is None:
                    continue
                _add(_try_match(name, category, "", "present", host, "dom"))
        elif isinstance(dom, dict):
            for selector, spec in dom.items():
                if not isinstance(spec, dict):
                    continue
                element = dom_results.get(selector)
                if element is None:
                    continue
                if "exists" in spec:
                    _add(_try_match(name, category, "", "present", host, "dom"))
                if "text" in spec:
                    text_value = _stringify_browser_value(element.get("text"))
                    if text_value is not None:
                        _add(_try_match(name, category, spec["text"], text_value, host, "dom"))
                for attr, attr_pattern in spec.get("attributes", {}).items():
                    attr_value = _stringify_browser_value(element.get("attributes", {}).get(attr))
                    if attr_value is not None:
                        _add(_try_match(name, category, attr_pattern, attr_value, host, "dom"))
                for prop, prop_pattern in spec.get("properties", {}).items():
                    prop_value = _stringify_browser_value(element.get("properties", {}).get(prop))
                    if prop_value is not None:
                        _add(_try_match(name, category, prop_pattern, prop_value, host, "dom"))

        for raw_pattern in _as_list(definition.get("css")):
            _add(_try_match(name, category, raw_pattern, css_text, host, "css"))

    return findings


def match_technologies(host: str, response, technologies: dict | None = None) -> list[Finding]:
    """Evaluates every technology definition against one fetched HTTP
    response, for the check types this tool supports without a browser
    (headers/cookies/meta/html/scriptSrc). `technologies` defaults to the
    vendored dataset via load_technologies() -- tests pass a small
    synthetic dict directly instead of depending on the real vendored
    file. Returns at most one Finding per distinct (host, name, version)
    tuple: several checks (e.g. a header match and a meta match, or two
    scriptSrc patterns) can independently identify the same technology at
    the same version, but reporting each of those as a separate Finding
    only makes cve_correlation query NVD for the same (name, version)
    pair over and over -- each a redundant network round trip plus a
    rate-limit sleep. The first check to find a given (host, name,
    version) wins; later ones matching the same tuple are dropped."""
    if technologies is None:
        technologies = load_technologies()
    categories = load_categories()
    text = response.text or ""
    meta_tags = _extract_meta(text)
    script_srcs = _extract_script_srcs(text)

    findings: list[Finding] = []
    seen: set[tuple[str, str, str | None]] = set()

    def _add(finding: Finding | None) -> None:
        if finding is None:
            return
        key = (finding.value, finding.data["name"], finding.data["version"])
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    for name, definition in technologies.items():
        if not _has_supported_check(definition):
            continue
        category = _category_name(definition.get("cats", []), categories)

        for header_name, raw_pattern in definition.get("headers", {}).items():
            value = response.headers.get(header_name)
            if value is None:
                continue
            _add(_try_match(name, category, raw_pattern, value, host, "header"))

        for cookie_name, raw_pattern in definition.get("cookies", {}).items():
            if cookie_name not in response.cookies:
                continue
            value = response.cookies.get(cookie_name) or ""
            _add(_try_match(name, category, raw_pattern, value, host, "cookie"))

        for meta_name, raw_pattern in definition.get("meta", {}).items():
            value = meta_tags.get(meta_name.lower())
            if value is None:
                continue
            _add(_try_match(name, category, raw_pattern, value, host, "meta"))

        for raw_pattern in _as_list(definition.get("html")):
            _add(_try_match(name, category, raw_pattern, text, host, "html"))

        for raw_pattern in _as_list(definition.get("scriptSrc")):
            for src in script_srcs:
                finding = _try_match(name, category, raw_pattern, src, host, "scriptSrc")
                if finding:
                    _add(finding)
                    break

    return findings
