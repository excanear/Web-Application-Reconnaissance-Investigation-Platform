# Design — Fase G: Expanded Fingerprint Coverage

**Date:** 2026-08-21
**Status:** Approved for planning
**Roadmap reference:** `docs/superpowers/specs/2026-08-17-professional-pentest-roadmap.md`, Fase G section

## Problem

Today `tech_fingerprint`'s detection is a hand-written list of 29 rules
covering a handful of web servers, CDNs, backend frameworks, CMSes, and
frontend libraries. Every new technology requires someone to notice the
gap and write a regex by hand — a process that doesn't scale, and has
already left known gaps (Vercel, Next.js App Router) unaddressed. Fase G
replaces the hand-curated rule list with a vendored copy of the
Wappalyzer fingerprint dataset (thousands of technologies, maintained by
a community), matched by a new, more general engine — without changing
the tool's HTTP-only, no-browser-automation posture.

## Goals

- Detection coverage expands from 29 hand-written rules to the full
  Wappalyzer dataset, filtered down to check types this tool can
  actually evaluate from a single HTTP GET response.
- The dataset is vendored in-repo (`backend/app/data/technologies.json`)
  and refreshed on demand via a new `recon update-fingerprints` command
  that pulls the latest data from the community-maintained
  `enthec/webappanalyzer` GitHub repository — the tool works offline by
  default; refreshing is an explicit, operator-triggered action, the
  same posture as `nuclei -update-templates`.
- `tech_fingerprint`'s existing `path_probe` mechanism (not a native
  Wappalyzer check type) is preserved as a project-specific extension
  for cases needing precise version detection beyond what a passive
  check can offer (e.g. WordPress's `/CHANGELOG.txt`).
- No new runtime dependency beyond what parsing/fetching a JSON file and
  an HTTP GET already require — no headless browser, no new
  network-facing dependency beyond the existing `requests` usage.
- `Finding` shape for `type="technology"` is unchanged
  (`category`/`name`/`version`/`confidence`/`source`) — Fase F's report
  pipeline and existing CVE correlation keep working without
  modification.

## Non-goals

- No headless-browser integration (Playwright, Selenium, or similar).
  Wappalyzer's `js` (global JS variable checks), `dom` (DOM element
  selectors), and `css` (computed style checks) check types require a
  real rendered page and are explicitly out of scope — entries whose
  *only* check types are `js`/`dom`/`css` are skipped entirely (never
  evaluated, never partially attempted). This is a deliberate,
  documented limitation, not an oversight — this tool stays a plain
  HTTP client.
- No propagation of Wappalyzer's `implies` relationships (e.g. finding
  "WordPress" does NOT automatically also emit a "PHP" Finding). Every
  Finding this phase produces still requires a direct, real signal match
  — consistent with the project's established evidentiary posture (the
  same principle behind Fase E's `suspected`/`confirmed` CVE status:
  never assert something wasn't actually checked).
- No new numeric confidence field. Wappalyzer's dataset carries a 0-100
  confidence annotation per pattern; this phase does not surface it.
  The existing convention (`"high"` when a version was extracted,
  `"medium"` otherwise) is preserved unchanged, since nothing downstream
  (report/CLI/CVE correlation) currently consumes a numeric confidence
  value, and inventing one now would be speculative.
- No expansion of the CVE-correlation name-to-CPE-product alias table
  (`_CPE_PRODUCT_ALIASES` in `cve_correlation.py`, currently just
  `{"apache": "httpserver"}`). Newly-detected technologies whose display
  name doesn't match their CPE product name simply won't correlate a
  CVE yet — a silent, non-breaking gap, accepted for this phase and left
  for incremental follow-up as real scans surface specific cases worth
  curating.
- No fully-automatic vendored-data update as part of a scan (e.g. no
  auto-fetch-on-first-run). `recon update-fingerprints` is always an
  explicit, separate command the operator runs.

## Architecture

### Vendored dataset: `backend/app/data/technologies.json`

A single JSON file, structurally equivalent to Wappalyzer's own
`technologies.json` (map of technology name → definition dict), but
**pre-merged from the upstream repo's per-letter shards** (the
`enthec/webappanalyzer` repo splits technologies into
`technologies/{a..z,_}.json` files for its own tooling reasons) so the
runtime only ever does one `json.load()` — no per-request network
access to any dataset, no sharding logic in the hot path.

Definition dict per technology (all keys optional, only the ones
Wappalyzer's format defines are relevant here):
```json
{
  "cats": [1, 18],
  "headers": {"Server": "nginx\\/?([\\d.]+)?\\;version:\\1"},
  "cookies": {"laravel_session": ""},
  "meta": {"generator": "WordPress\\s*([\\d.]+)?\\;version:\\1"},
  "html": ["ng-version=\"([\\d.]+)\"\\;version:\\1"],
  "scriptSrc": ["jquery[.-]?([\\d.]+)?(?:\\.min)?\\.js\\;version:\\1"],
  "js": {"...": "..."},
  "dom": {"...": "..."},
  "implies": ["PHP"]
}
```

`cats` are numeric IDs resolved via the upstream `categories.json`
(also vendored, `backend/app/data/categories.json`) into human names
(e.g. `18 → "Web servers"`), normalized to a `snake_case` slug (`"web
servers"` → `"web_servers"`) for the `Finding.data["category"]` value —
matching the style of today's hand-written categories
(`web_server`/`cdn_waf`/`backend`/`cms`/`frontend`). Only the *first*
listed category is used per technology, matching today's one-category-
per-Finding shape.

### Matching engine: `backend/app/wappalyzer.py`

```python
def load_technologies(path: str | None = None) -> dict:
    """Loads and caches the vendored technologies.json (+ categories.json
    for category-name resolution). Raises if the vendored file is
    missing or malformed -- unlike a network call, a missing local data
    file is a packaging/setup problem, not a transient condition to
    silently degrade from."""


def match_technologies(host: str, response, audit: AuditLog | None) -> list[Finding]:
    """Evaluates every technology definition against one fetched HTTP
    response (headers, cookies already on `response`; response.text for
    meta/html/scriptSrc), for the check types this tool supports.
    Entries whose only check types are js/dom/css are skipped without
    evaluation. Returns one Finding per technology per matching check --
    the same technology can appear more than once if multiple check
    types independently match (e.g. both a header and an html pattern),
    matching today's one-Finding-per-matched-rule convention."""
```

**Pattern parsing.** Wappalyzer patterns are a regex optionally followed
by `\;key:value` annotations:

```python
def _parse_pattern(raw: str) -> ParsedPattern:
    """Splits on '\\;', treats the first segment as the regex (empty
    string means "match on presence alone", equivalent to today's r".+"
    convention), and the remaining segments as annotations. Recognizes
    version:TEMPLATE (TEMPLATE may reference \\1, \\2, ... capture
    groups, substituted after a successful match) and confidence:N
    (0-100; parsed but discarded -- never used to pick the "high"/
    "medium" bucket and never surfaced as a new field, see Non-goals)."""
```

**Check-type extraction, one function per type:**
- `headers`/`cookies`: same extraction as today's engine (`response.headers`/`response.cookies`), generalized to iterate every header/cookie name Wappalyzer's definition specifies rather than one hardcoded name per hand-written rule.
- `meta`: a new general `<meta>` extractor building `{name: content}` for every `<meta name="..." content="...">` tag in `response.text` (today's engine only ever looked for `name="generator"`), so a definition can request any meta name (`author`, `framework`, `generator`, etc.).
- `html`: same as today's `html_regex` — direct regex against `response.text`.
- `scriptSrc`: new — extracts every `<script src="...">` URL from `response.text` via a simple regex, and matches the definition's pattern(s) against each extracted URL string (never fetches the script's contents — matching the URL is enough signal and avoids extra requests).

### `tech_fingerprint.py` changes

`TechFingerprintModule._fingerprint_host` calls
`wappalyzer.match_technologies(host, response, audit)` for the bulk of
detection, then still runs the existing small `PATH_PROBE_RULES` list
(today's `path_probe`-type entries, e.g. WordPress's `/CHANGELOG.txt`)
as a project-specific supplement — unchanged in mechanism from today's
`_apply_rule`'s `path_probe` branch, just narrowed to only the rules
that aren't better expressed as a Wappalyzer entry. The module's
existing scope-check, rate-limiting, and circuit-breaker logic around
the per-host loop is untouched.

### New CLI command: `update-fingerprints`

```
recon update-fingerprints
```

Fetches the latest per-letter shards from
`https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{a..z,_}.json`
(and `categories.json` from the repo root), merges the shards into one
dict, and overwrites `backend/app/data/technologies.json` (and
`categories.json`). No `--authorized`/`--confirm-active`/scope check —
this touches no target, only the tool's own local dataset, the same
category of operation as `nuclei -update-templates`. A network failure
leaves the existing vendored file untouched and reports a clear CLI
error; it never partially overwrites the dataset.

## Testing

- `wappalyzer.py`: TDD against small, hand-written synthetic technology
  definitions (not the real vendored dataset, which is large and
  evolves independently) — pattern-with-annotation parsing, each check
  type (headers/cookies/meta/html/scriptSrc) individually, presence-only
  patterns, version-template substitution, confirming a parsed
  `confidence:N` annotation is discarded (never changes the
  "high"/"medium" bucket, which stays keyed only on whether a version
  was extracted), and the js/dom/css-only skip rule.
- `tech_fingerprint.py`: existing tests continue to validate
  `PATH_PROBE_RULES` handling; new tests confirm the module calls
  `wappalyzer.match_technologies` and correctly merges its Findings with
  the path-probe Findings.
- `update-fingerprints` command: TDD with mocked HTTP responses for the
  shard-fetch-and-merge logic; a network failure test confirming the
  existing vendored file is left untouched.
- Manual validation (same bar as Fases E/F): re-run `tech_fingerprint`
  against a real target already used in this project's manual testing
  (`artssystem.com.br`, scanned in Fase F's manual validation) with the
  new engine and confirm detected-technology coverage genuinely
  increased versus the 29-rule baseline, not just in synthetic tests.

## Open items resolved during brainstorming (for reference)

- No headless browser: only headers/cookies/meta/html/scriptSrc are
  evaluated; js/dom/css-only entries are skipped entirely.
- Dataset source: vendored copy of `enthec/webappanalyzer`'s
  `technologies.json` (merged from its per-letter shards), refreshed via
  an explicit `recon update-fingerprints` command — not fetched
  per-scan, not left un-vendored.
- `path_probe` (project-specific, not native to Wappalyzer) is kept as a
  small supplementary rule list alongside the new engine.
- `implies` relationships are ignored — every Finding still requires a
  direct match, consistent with the project's evidentiary posture.
- Wappalyzer's numeric confidence is used only to pick between the
  existing `"high"`/`"medium"` strings — no new report field.
- The CVE-correlation CPE alias table is not expanded in this phase;
  newly-detected technologies whose name doesn't match their CPE
  product name won't correlate a CVE yet, a documented, non-breaking
  gap.
