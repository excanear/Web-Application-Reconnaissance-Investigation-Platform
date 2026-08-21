import json
import os
import re
from dataclasses import dataclass

from app.modules.base import Finding

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TECHNOLOGIES_PATH = os.path.join(DATA_DIR, "technologies.json")
CATEGORIES_PATH = os.path.join(DATA_DIR, "categories.json")

# Only these check types can be evaluated from a single HTTP GET response
# without a real browser -- js (global JS variables), dom (element
# selectors), and css (computed styles) all require actually executing
# the page, which this tool deliberately never does.
SUPPORTED_CHECK_TYPES = ("headers", "cookies", "meta", "html", "scriptSrc")

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
    def repl(m: re.Match) -> str:
        try:
            group = match.group(int(m.group(1)))
        except IndexError:
            return ""
        return group or ""

    result = re.sub(r"\\(\d+)", repl, template)
    return result or None


def _try_match(name: str, category: str, raw_pattern: str, value: str, host: str, source: str) -> Finding | None:
    parsed = _parse_pattern(raw_pattern)
    version = None
    if parsed.regex:
        match = re.search(parsed.regex, value or "", re.IGNORECASE)
        if not match:
            return None
        if parsed.version_template:
            version = _substitute_version(parsed.version_template, match)
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


def match_technologies(host: str, response, technologies: dict | None = None) -> list[Finding]:
    """Evaluates every technology definition against one fetched HTTP
    response, for the check types this tool supports without a browser
    (headers/cookies/meta/html/scriptSrc). `technologies` defaults to the
    vendored dataset via load_technologies() -- tests pass a small
    synthetic dict directly instead of depending on the real vendored
    file. Returns one Finding per (technology, matching check): the same
    technology can appear more than once if multiple independent checks
    match."""
    if technologies is None:
        technologies = load_technologies()
    categories = load_categories()
    text = response.text or ""
    meta_tags = _extract_meta(text)
    script_srcs = _extract_script_srcs(text)

    findings: list[Finding] = []
    for name, definition in technologies.items():
        if not _has_supported_check(definition):
            continue
        category = _category_name(definition.get("cats", []), categories)

        for header_name, raw_pattern in definition.get("headers", {}).items():
            value = response.headers.get(header_name)
            if value is None:
                continue
            finding = _try_match(name, category, raw_pattern, value, host, "header")
            if finding:
                findings.append(finding)

        for cookie_name, raw_pattern in definition.get("cookies", {}).items():
            if cookie_name not in response.cookies:
                continue
            value = response.cookies.get(cookie_name) or ""
            finding = _try_match(name, category, raw_pattern, value, host, "cookie")
            if finding:
                findings.append(finding)

        for meta_name, raw_pattern in definition.get("meta", {}).items():
            value = meta_tags.get(meta_name.lower())
            if value is None:
                continue
            finding = _try_match(name, category, raw_pattern, value, host, "meta")
            if finding:
                findings.append(finding)

        for raw_pattern in _as_list(definition.get("html")):
            finding = _try_match(name, category, raw_pattern, text, host, "html")
            if finding:
                findings.append(finding)

        for raw_pattern in _as_list(definition.get("scriptSrc")):
            for src in script_srcs:
                finding = _try_match(name, category, raw_pattern, src, host, "scriptSrc")
                if finding:
                    findings.append(finding)
                    break

    return findings
