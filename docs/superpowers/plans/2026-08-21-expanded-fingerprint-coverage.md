# Fase G: Expanded Fingerprint Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `tech_fingerprint`'s 29 hand-written rules with a new engine driven by a vendored copy of the Wappalyzer fingerprint dataset (`enthec/webappanalyzer`), covering only the check types evaluable from a single HTTP GET (headers/cookies/meta/html/scriptSrc) — no headless browser, no change to `Finding` shape.

**Architecture:** A new `backend/app/wappalyzer.py` parses Wappalyzer's pattern-with-annotation syntax and matches technology definitions against one fetched HTTP response. A new `backend/app/fingerprint_update.py` + `recon update-fingerprints` CLI command fetches and vendors the dataset on demand. `tech_fingerprint.py` calls the new engine for the bulk of detection and keeps a narrowed, project-specific `PATH_PROBE_RULES` list (just WordPress's `/CHANGELOG.txt` version probe) alongside it.

**Tech Stack:** Python, `requests`, pytest + `unittest.mock`. No new dependency.

**Spec:** `docs/superpowers/specs/2026-08-21-expanded-fingerprint-coverage-design.md`

## Global Constraints

- No headless browser, no new network-facing dependency beyond the existing `requests` usage. Wappalyzer definitions whose only check types are `js`/`dom`/`css` are skipped entirely — never partially evaluated.
- `Finding.data` shape for `type="technology"` is unchanged: `category`/`name`/`version`/`confidence`/`source`.
- `implies` relationships are never propagated — every Finding requires a direct match against a real signal.
- Wappalyzer's numeric `confidence:N` annotation is parsed but never used to pick the `"high"`/`"medium"` bucket (that stays keyed only on whether a version was extracted) and never surfaces as a new field.
- `recon update-fingerprints` never partially overwrites the vendored data files — a network failure partway through leaves the existing files untouched and reports a clear error.
- `_CPE_PRODUCT_ALIASES` in `cve_correlation.py` is not touched or expanded in this phase.

---

## File Structure

- **Create** `backend/app/fingerprint_update.py` — `fetch_latest_dataset()`, `update_vendored_data()`.
- **Create** `backend/tests/test_fingerprint_update.py`
- **Create** `backend/app/wappalyzer.py` — `load_technologies()`, `load_categories()`, `match_technologies()`.
- **Create** `backend/tests/test_wappalyzer.py`
- **Modify** `backend/app/modules/tech_fingerprint.py` — call `wappalyzer.match_technologies`, narrow `FINGERPRINT_RULES` down to a small `PATH_PROBE_RULES` list.
- **Modify** `backend/tests/test_modules_tech_fingerprint.py` — full rewrite to drive the new engine via synthetic, context-injected technology definitions.
- **Modify** `backend/app/cli.py` — new `update-fingerprints` command.
- **Modify** `backend/app/i18n.py` — 2 new string keys.
- **Modify** `README.md`, `README.pt-BR.md` — document the new command, data attribution, and known gaps.
- **Create** (not by hand — produced by running the new command for real, see Manual Validation) `backend/app/data/technologies.json`, `backend/app/data/categories.json`.

---

### Task 1: Dataset fetch/update mechanism

**Files:**
- Create: `backend/app/fingerprint_update.py`
- Test: `backend/tests/test_fingerprint_update.py`

**Interfaces:**
- Produces: `fetch_latest_dataset() -> tuple[dict, dict]` (technologies, categories); `update_vendored_data() -> tuple[int, int]` (technology count, category count); module-level `DATA_DIR`, `TECHNOLOGIES_PATH`, `CATEGORIES_PATH`, `SHARD_LETTERS` constants.

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_fingerprint_update.py
from unittest.mock import MagicMock, patch

import pytest
import requests

from app import fingerprint_update


def _mock_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def test_fetch_latest_dataset_merges_all_shards_and_categories():
    def fake_get(url, **kwargs):
        if url.endswith("/categories.json"):
            return _mock_response({"1": {"name": "CMS"}})
        letter = url.rsplit("/", 1)[-1].removesuffix(".json")
        return _mock_response({f"Tech{letter}": {"cats": [1]}})

    with patch("app.fingerprint_update.requests.get", side_effect=fake_get):
        technologies, categories = fingerprint_update.fetch_latest_dataset()

    assert len(technologies) == len(fingerprint_update.SHARD_LETTERS)
    assert "Techa" in technologies
    assert categories == {"1": {"name": "CMS"}}


def test_fetch_latest_dataset_raises_on_network_failure():
    with patch(
        "app.fingerprint_update.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        with pytest.raises(requests.RequestException):
            fingerprint_update.fetch_latest_dataset()


def test_update_vendored_data_writes_both_files(tmp_path, monkeypatch):
    monkeypatch.setattr(fingerprint_update, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(fingerprint_update, "TECHNOLOGIES_PATH", str(tmp_path / "technologies.json"))
    monkeypatch.setattr(fingerprint_update, "CATEGORIES_PATH", str(tmp_path / "categories.json"))

    def fake_get(url, **kwargs):
        if url.endswith("/categories.json"):
            return _mock_response({"1": {"name": "CMS"}})
        return _mock_response({"nginx": {"cats": [1]}})

    with patch("app.fingerprint_update.requests.get", side_effect=fake_get):
        tech_count, cat_count = fingerprint_update.update_vendored_data()

    assert tech_count == 1
    assert cat_count == 1
    assert (tmp_path / "technologies.json").exists()
    assert (tmp_path / "categories.json").exists()


def test_update_vendored_data_leaves_existing_files_untouched_on_failure(tmp_path, monkeypatch):
    tech_path = tmp_path / "technologies.json"
    tech_path.write_text('{"existing": {}}')
    monkeypatch.setattr(fingerprint_update, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(fingerprint_update, "TECHNOLOGIES_PATH", str(tech_path))
    monkeypatch.setattr(fingerprint_update, "CATEGORIES_PATH", str(tmp_path / "categories.json"))

    with patch(
        "app.fingerprint_update.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        with pytest.raises(requests.RequestException):
            fingerprint_update.update_vendored_data()

    assert tech_path.read_text() == '{"existing": {}}'
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_fingerprint_update.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.fingerprint_update'`

- [ ] **Step 3: Write `fingerprint_update.py`**

```python
# backend/app/fingerprint_update.py
import json
import os

import requests

# enthec/webappanalyzer is the community-maintained fork of Wappalyzer's
# open dataset (the original project's data went closed/commercial). It
# shards technologies.json by first letter for its own tooling; we fetch
# every shard and merge into one dict so runtime only ever does one
# json.load() of one committed file -- no sharding logic in the hot path.
RAW_BASE_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"
SHARD_LETTERS = "abcdefghijklmnopqrstuvwxyz_"
REQUEST_TIMEOUT = 30

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TECHNOLOGIES_PATH = os.path.join(DATA_DIR, "technologies.json")
CATEGORIES_PATH = os.path.join(DATA_DIR, "categories.json")


def fetch_latest_dataset() -> tuple[dict, dict]:
    """Fetches every technologies/{letter}.json shard plus categories.json
    from the enthec/webappanalyzer GitHub repo and merges the shards into
    one technologies dict. Raises requests.RequestException on any
    network failure -- the caller must leave the existing vendored files
    untouched on failure, never a partial overwrite."""
    technologies: dict = {}
    for letter in SHARD_LETTERS:
        response = requests.get(
            f"{RAW_BASE_URL}/technologies/{letter}.json", timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        technologies.update(response.json())

    categories_response = requests.get(f"{RAW_BASE_URL}/categories.json", timeout=REQUEST_TIMEOUT)
    categories_response.raise_for_status()
    categories = categories_response.json()

    return technologies, categories


def update_vendored_data() -> tuple[int, int]:
    """Fetches the latest dataset and overwrites the vendored JSON files.
    Both fetches (via fetch_latest_dataset) must succeed before anything
    on disk is touched -- a network failure partway through raises and
    leaves the existing vendored files exactly as they were."""
    technologies, categories = fetch_latest_dataset()

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(TECHNOLOGIES_PATH, "w", encoding="utf-8") as f:
        json.dump(technologies, f)
    with open(CATEGORIES_PATH, "w", encoding="utf-8") as f:
        json.dump(categories, f)

    return len(technologies), len(categories)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_fingerprint_update.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/fingerprint_update.py backend/tests/test_fingerprint_update.py
git commit -m "feat(fingerprint): add Wappalyzer dataset fetch/vendor mechanism"
```

---

### Task 2: Wappalyzer matching engine

**Files:**
- Create: `backend/app/wappalyzer.py`
- Test: `backend/tests/test_wappalyzer.py`

**Interfaces:**
- Produces: `load_technologies(path: str | None = None) -> dict`, `load_categories(path: str | None = None) -> dict`, `match_technologies(host: str, response, technologies: dict | None = None) -> list[Finding]`.
- Note on the design spec's signature: the spec listed `match_technologies(host, response, audit)`, but `match_technologies` never makes a network call itself (the caller in `tech_fingerprint.py` already fetched `response` and already audits that fetch) — an `audit` parameter here would be dead weight. This plan drops it; every other interface matches the spec exactly.

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_wappalyzer.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_wappalyzer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.wappalyzer'`

- [ ] **Step 3: Write `wappalyzer.py`**

```python
# backend/app/wappalyzer.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_wappalyzer.py -v`
Expected: PASS (15 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/wappalyzer.py backend/tests/test_wappalyzer.py
git commit -m "feat(fingerprint): add Wappalyzer-format matching engine"
```

---

### Task 3: `tech_fingerprint` integration

**Files:**
- Modify: `backend/app/modules/tech_fingerprint.py`
- Modify: `backend/tests/test_modules_tech_fingerprint.py` (full rewrite — nearly every existing test targets the old 29-rule engine's specific categories/sources, which this task deliberately changes)

**Interfaces:**
- Consumes: `wappalyzer.match_technologies(host, response, technologies=None) -> list[Finding]`, `wappalyzer.load_technologies() -> dict` (Task 2)
- Produces: `context["wappalyzer_technologies"]` — optional context override so tests (and, if ever needed, callers) can inject a synthetic technologies dict instead of loading the real vendored file. `TechFingerprintModule` keeps its existing public behavior (scope check, rate limiting, circuit breaker, audit) unchanged.

- [ ] **Step 1: Write the failing tests**

Replace the entire contents of `backend/tests/test_modules_tech_fingerprint.py`:

```python
from unittest.mock import MagicMock, patch

from app.modules.tech_fingerprint import TechFingerprintModule

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
            "example.com", {"subdomains": {"a.example.com"}, "wappalyzer_technologies": {}}
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_modules_tech_fingerprint.py -v`
Expected: FAIL — every test either errors (`context["wappalyzer_technologies"]` unused, old `FINGERPRINT_RULES` still drives detection) or asserts on categories/sources the old engine doesn't produce (e.g. `"web_servers"` vs. today's `"web_server"`).

- [ ] **Step 3: Rewrite `tech_fingerprint.py`**

Replace the entire file:

```python
# backend/app/modules/tech_fingerprint.py
import re

import requests

from app import wappalyzer
from app.audit import AuditLog
from app.modules.base import Finding, ReconModule, register_module
from app.ratelimit import CircuitBreaker, RateLimiter
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
REQUEST_TIMEOUT = 10

# Project-specific extension, not a native Wappalyzer check type: an
# active path probe for cases needing more precise version detection
# than a passive header/cookie/meta/html/scriptSrc check can offer.
PATH_PROBE_RULES = [
    {
        "category": "cms",
        "name": "WordPress",
        "path": "/CHANGELOG.txt",
        "pattern": r"Version\s+([\d.]+)",
    },
]


@register_module
class TechFingerprintModule(ReconModule):
    name = "tech_fingerprint"
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = sorted(context.get("subdomains", set()) | {target})
        scope = context.get("scope")
        audit = context.get("audit")
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        technologies = context.get("wappalyzer_technologies")
        if technologies is None:
            technologies = wappalyzer.load_technologies()

        findings: list[Finding] = []
        for index, host in enumerate(hosts):
            if scope is not None and not is_in_scope(host, None, scope):
                findings.append(
                    Finding(type="out_of_scope", value=host, data={"module": self.name})
                )
                continue

            limiter.wait()
            host_findings, reached_host = self._fingerprint_host(host, limiter, audit, technologies)
            findings.extend(host_findings)

            if reached_host:
                breaker.record_success()
                continue

            if breaker.record_failure():
                findings.append(
                    Finding(
                        type="circuit_breaker_tripped",
                        value=host,
                        data={"module": self.name, "skipped_hosts": len(hosts) - index - 1},
                    )
                )
                break
        return findings

    def _fingerprint_host(
        self, host: str, limiter: RateLimiter, audit: AuditLog | None, technologies: dict
    ) -> tuple[list[Finding], bool]:
        url = f"https://{host}/"
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"error: {exc}", url=url)
            return [], False

        if audit is not None:
            audit.record(module=self.name, target=host, outcome=str(response.status_code), url=url)

        findings = wappalyzer.match_technologies(host, response, technologies=technologies)
        for rule in PATH_PROBE_RULES:
            finding = self._apply_path_probe_rule(host, rule, limiter, audit)
            if finding is not None:
                findings.append(finding)
        return findings, True

    def _apply_path_probe_rule(
        self, host: str, rule: dict, limiter: RateLimiter, audit: AuditLog | None
    ) -> Finding | None:
        limiter.wait()
        probe_url = f"https://{host}{rule['path']}"
        try:
            probe = requests.get(probe_url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"error: {exc}", url=probe_url)
            return None
        if audit is not None:
            audit.record(module=self.name, target=host, outcome=str(probe.status_code), url=probe_url)
        if probe.status_code != 200:
            return None
        match = re.search(rule["pattern"], probe.text, re.IGNORECASE)
        if not match:
            return None
        version = match.group(1) if match.groups() else None
        return Finding(
            type="technology",
            value=host,
            data={
                "category": rule["category"],
                "name": rule["name"],
                "version": version,
                "confidence": "high" if version else "medium",
                "source": "path_probe",
            },
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_modules_tech_fingerprint.py -v`
Expected: PASS (13 tests)

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests). No other module reads `tech_fingerprint.FINGERPRINT_RULES` or the old `source` string values (`"header"`/`"cookie"`/`"meta_generator"`/`"html_regex"`) directly — `report_data.py`'s technologies table only reads `category`/`name`/`version`/`confidence`/`host`, never `source` — so this is a safe, self-contained rewrite.

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/tech_fingerprint.py backend/tests/test_modules_tech_fingerprint.py
git commit -m "feat(fingerprint): drive tech_fingerprint from the Wappalyzer engine, keep WordPress path probe"
```

---

### Task 4: CLI command — `update-fingerprints`

**Files:**
- Modify: `backend/app/cli.py`
- Modify: `backend/app/i18n.py`
- Test: `backend/tests/test_cli.py`

**Interfaces:**
- Consumes: `fingerprint_update.update_vendored_data() -> tuple[int, int]` (Task 1)
- Produces: `recon update-fingerprints` CLI command.

- [ ] **Step 1: Add the new i18n keys**

Add to `STRINGS["en"]` in `backend/app/i18n.py`:

```python
        "fingerprint_update_failed": "could not update the fingerprint dataset: {error}",
        "fingerprint_update_saved": "Fingerprint dataset updated: {tech_count} technologies, {cat_count} categories.",
```

Add to `STRINGS["pt"]`:

```python
        "fingerprint_update_failed": "nao foi possivel atualizar o dataset de fingerprint: {error}",
        "fingerprint_update_saved": "Dataset de fingerprint atualizado: {tech_count} tecnologias, {cat_count} categorias.",
```

- [ ] **Step 2: Write the failing tests**

Append to `backend/tests/test_cli.py`:

```python
def test_update_fingerprints_command_reports_success(monkeypatch):
    from app import fingerprint_update

    monkeypatch.setattr(fingerprint_update, "update_vendored_data", lambda: (3000, 50))

    result = runner.invoke(app, ["update-fingerprints"])

    assert result.exit_code == 0
    assert "3000" in result.output
    assert "50" in result.output


def test_update_fingerprints_command_reports_a_network_failure(monkeypatch):
    import requests as requests_lib

    from app import fingerprint_update

    def raise_error():
        raise requests_lib.RequestException("down")

    monkeypatch.setattr(fingerprint_update, "update_vendored_data", raise_error)

    result = runner.invoke(app, ["update-fingerprints"])

    assert result.exit_code == 1
    assert "down" in result.output
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_cli.py -v -k update_fingerprints`
Expected: FAIL — `update-fingerprints` isn't a registered command yet (Typer usage error).

- [ ] **Step 4: Update `cli.py`**

Add the import near the top, alongside the existing `app` imports:

```python
import requests

from app import fingerprint_update, i18n, models, report_csv, report_data, report_pdf
```

(This replaces the existing `from app import i18n, models, report_csv, report_data, report_pdf` line — only the module list changes, adding `fingerprint_update`; `requests` is a new top-level import since `cli.py` didn't need it directly before.)

Add the new command (near the other `@app.command()` definitions, e.g. right after `history()`):

```python
@app.command(name="update-fingerprints")
def update_fingerprints() -> None:
    try:
        tech_count, cat_count = fingerprint_update.update_vendored_data()
    except requests.RequestException as exc:
        console.print(
            f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('fingerprint_update_failed', error=str(exc))}"
        )
        raise typer.Exit(code=1)
    console.print(i18n.t("fingerprint_update_saved", tech_count=tech_count, cat_count=cat_count))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_cli.py -v -k update_fingerprints`
Expected: PASS (2 tests)

- [ ] **Step 6: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests)

- [ ] **Step 7: Commit**

```bash
git add backend/app/cli.py backend/app/i18n.py backend/tests/test_cli.py
git commit -m "feat(cli): add recon update-fingerprints command"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md`
- Modify: `README.pt-BR.md`

- [ ] **Step 1: Document the new command and dataset in `README.md`**

Find the module reference table (the one documenting `run_order`/active status for each module, e.g. near the row for `httpx_probe`) and update the `tech_fingerprint` row's description to mention the new engine, then add a new subsection near the other tool-prerequisite sections (`### Install nuclei`, etc.):

```markdown
### Update the technology fingerprint dataset

`tech_fingerprint` detects technologies using a vendored copy of the
[Wappalyzer](https://github.com/enthec/webappanalyzer) fingerprint
dataset (thousands of technologies, community-maintained fork of the
original Wappalyzer project) plus a small set of project-specific
active path probes (currently just WordPress's `/CHANGELOG.txt`, for
version precision beyond what a passive check offers).

The vendored dataset (`backend/app/data/technologies.json`,
`backend/app/data/categories.json`) ships in this repo but goes stale
over time. Refresh it with:

```
recon update-fingerprints
```

This is a local maintenance operation — no target is touched, no
`--authorized`/`--confirm-active` needed, the same posture as `nuclei
-update-templates`. A network failure leaves the existing vendored
files untouched.

**Known limitations:**
- Only technologies detectable from a single HTTP response
  (headers/cookies/meta tags/HTML body/`<script src>` URLs) are
  supported. Wappalyzer entries that only offer `js` (global JavaScript
  variable), `dom` (element selector), or `css` (computed style) checks
  require a real rendered page and are skipped entirely — this tool
  never runs a browser. This means some runtime-only signals (part of
  the Next.js App Router detection gap, for instance) still aren't
  covered.
- Newly-detected technologies whose display name doesn't match their
  CPE product name in the NVD (used by `cve_correlation`) won't
  correlate a CVE finding yet — this is a known, non-breaking gap, not
  a bug.

Wappalyzer's fingerprint data is licensed CC BY-SA 4.0 by its
contributors; the vendored copy in this repo is a direct, unmodified
mirror.
```

- [ ] **Step 2: Mirror the addition in `README.pt-BR.md`**

Find the equivalent section in `README.pt-BR.md` and add the Portuguese translation of the same content at the equivalent location, e.g.:

```markdown
### Atualizando o dataset de fingerprint de tecnologias

O `tech_fingerprint` detecta tecnologias usando uma cópia vendorizada do
dataset do [Wappalyzer](https://github.com/enthec/webappanalyzer)
(milhares de tecnologias, fork mantido pela comunidade do projeto
Wappalyzer original) mais um pequeno conjunto de sondas ativas próprias
do projeto (hoje só o `/CHANGELOG.txt` do WordPress, pra precisão de
versão além do que uma checagem passiva oferece).

O dataset vendorizado (`backend/app/data/technologies.json`,
`backend/app/data/categories.json`) vem junto com o repositório mas
fica desatualizado com o tempo. Atualize com:

```
recon update-fingerprints
```

É uma operação de manutenção local — não toca em nenhum alvo, não
precisa de `--authorized`/`--confirm-active`, mesma postura do `nuclei
-update-templates`. Uma falha de rede deixa os arquivos vendorizados
existentes intocados.

**Limitações conhecidas:**
- Só tecnologias detectáveis a partir de uma única resposta HTTP
  (headers/cookies/meta tags/corpo HTML/URLs de `<script src>`) são
  suportadas. Entradas do Wappalyzer que só oferecem checagens `js`
  (variável JavaScript global), `dom` (seletor de elemento) ou `css`
  (estilo computado) exigem uma página realmente renderizada e são
  ignoradas por completo — esta ferramenta nunca roda um navegador.
  Isso significa que alguns sinais que só existem em runtime (parte do
  gap de detecção do Next.js App Router, por exemplo) continuam sem
  cobertura.
- Tecnologias recém-detectadas cujo nome de exibição não bate com o
  nome de produto no CPE da NVD (usado pelo `cve_correlation`) ainda
  não correlacionam CVE — gap conhecido e não-quebrante, não é bug.

Os dados do Wappalyzer têm licença CC BY-SA 4.0 dos seus
contribuidores; a cópia vendorizada neste repositório é um espelho
direto, sem modificações.
```

- [ ] **Step 3: Commit**

```bash
git add README.md README.pt-BR.md
git commit -m "docs(readme): document update-fingerprints, dataset attribution, and known gaps"
```

---

## Manual validation (required before considering Fase G done)

Per the project's established testing bar (mocked unit tests are not
sufficient sign-off for a phase that swaps in a real external dataset):

1. Run `python -m app.cli update-fingerprints` for real (requires
   network access) and confirm it reports a plausible technology count
   (thousands, not a handful) and category count.
2. Commit the resulting `backend/app/data/technologies.json` and
   `backend/app/data/categories.json` — this is the first time these
   files exist in the repo; do this as its own commit, separate from
   the code tasks above, since it's a generated data artifact, not
   hand-written code:
   ```bash
   git add backend/app/data/technologies.json backend/app/data/categories.json
   git commit -m "chore(fingerprint): vendor the initial Wappalyzer dataset"
   ```
3. Re-run `tech_fingerprint` against a real target already used in this
   project's manual testing (e.g. re-scan `artssystem.com.br`, used in
   Fase F's manual validation) and compare the detected-technology list
   against the pre-Fase-G baseline (`nginx`, `Bootstrap`, `PHP`,
   `Laravel`, `jQuery` per Fase F's validation notes). Confirm coverage
   genuinely increased (new technologies detected that the 29-rule
   engine never covered), not just that the old ones still work.
4. Spot-check that the WordPress path probe still fires correctly if
   the manual-validation target (or another available one) runs
   WordPress with a reachable `/CHANGELOG.txt`.
5. Run the full test suite once more after vendoring the real data
   files, to confirm nothing in the automated suite accidentally
   depends on the real file being absent or present in a specific state
   (it shouldn't, since every automated test injects
   `wappalyzer_technologies` explicitly).
