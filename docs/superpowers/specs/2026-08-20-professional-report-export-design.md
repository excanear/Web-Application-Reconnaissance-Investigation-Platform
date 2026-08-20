# Design — Fase F: Professional Report + Export

**Date:** 2026-08-20
**Status:** Approved for planning
**Roadmap reference:** `docs/superpowers/specs/2026-08-17-professional-pentest-roadmap.md`, Fase F section

## Problem

Today `recon report <scan_id>` only prints two Rich tables (technologies,
CVEs) to the terminal. There is no way to hand a finished scan to a client
or import it into a tracking tool — no priority signal beyond CVSS, no
exportable artifact, no executive-level summary. Fase F turns the existing
terminal report into a three-format report engine (`table`/`csv`/`pdf`)
built on a shared, richer data model that adds EPSS-based prioritization
and remediation guidance.

## Goals

- `recon report <scan_id> --format table|csv|pdf` (`table` stays the
  default, behaviorally identical to today's output).
- Every CVE finding gets an `epss_score`, fetched and persisted at scan
  time (same posture as NVD/DeepL), used only as a tie-breaker under the
  existing CVSS-descending sort — CVSS remains the primary priority
  signal.
- CSV export: one row per CVE, machine-readable, no truncation.
- PDF export: executive summary (counts only, no generated prose) +
  technologies table + prioritized CVE table with remediation guidance,
  in English or Portuguese per `--lang`, self-contained file (default
  path `report_<scan_id>.pdf` in the current directory, or `--output/-o`
  to choose the path).
- Remediation text: the real `remediation` field from the matched nuclei
  template when a CVE is `confirmed`; a generic templated fallback
  (`"Upgrade {technology} to a patched version."` / PT equivalent) when
  `suspected`.
- No behavior change to `table` output beyond what's needed to share its
  data assembly with `csv`/`pdf` (i.e. it should look identical to today,
  verified by the existing `table`-format tests continuing to pass
  unmodified).

## Non-goals

- No raw HTTP request/response capture. "Evidence" in the CVE table
  continues to mean the existing `confirmation_note_{lang}` (from Fase E)
  plus the audit trail's URL/outcome — nothing new is captured from the
  target. A future phase could add this; it is out of scope here and
  would require touching every active module's request path.
- No generated narrative text in the executive summary — counts and
  tables only. Explicitly deferred per brainstorming: a template-filled
  paragraph is a plausible future addition, not part of this phase.
- No new report *sections* beyond executive summary, technologies, CVEs
  — e.g. no separate audit-trail appendix in the PDF (the `recon audit`
  command already covers that, in a different format, and stays
  separate).
- No change to `recon audit`'s existing `table`/`csv` formats or command.

## Architecture

### New module: EPSS lookup — `backend/app/epss.py`

```python
def fetch_epss(cve_id: str, audit: AuditLog | None = None) -> float | None:
    ...
```

Wraps the FIRST.org EPSS API (`https://api.first.org/data/v1/epss?cveId=<id>`),
free, no API key. Same never-raise contract as `translate_en_to_pt`
(`backend/app/translate.py`): a network failure, a CVE absent from EPSS's
dataset, or a malformed response all return `None`, never propagate an
exception. Every real HTTP call gets an `AuditLog.record(...)` entry
(`module="cve_correlation"`, `target=cve_id`, `url=EPSS_API_URL`,
`outcome=...`), same precedent as the existing NVD/DeepL calls made on the
target's behalf from inside `cve_correlation`.

### `cve_correlation.py` changes

`_finding_from_cve` calls `fetch_epss(cve_id, audit)` alongside the
existing `translate_en_to_pt` call, storing the result as
`data["epss_score"]` (a `float` in `[0, 1]`, or `None`). This is
best-effort: a missing or failed EPSS lookup never blocks the CVE finding
itself from being created, exactly like a missing translation today.

### `nuclei_validation.py` changes

When a template match confirms a CVE, the module already parses the raw
JSONL match line into a dict (`json.loads(line)`, existing code). Verified
against a real confirmed match captured during Fase E's manual
validation: the parsed dict's `info` block already includes a
`remediation` key with the template's real upgrade guidance — no new
nuclei flag is needed, the field is already present in today's
`-jsonl` output. Extract `match.get("info", {}).get("remediation")` when
present, add it to the `cve_validation` Finding's `data` as
`"remediation_en"` (nuclei templates are English-only; no translation
attempt for this field). Many templates omit it — when absent, this key
is simply not set on the Finding, and the report layer's fallback
(below) covers it.

### New module: `backend/app/report_data.py`

Pure, DB-reading, network-free. The single source of truth all three
render formats consume — extracted from today's `_print_report` in
`cli.py` without changing its output.

```python
@dataclass
class CveRow:
    cve_id: str
    severity: str
    cvss_score: float | None
    epss_score: float | None
    status: str  # "suspected" | "confirmed"
    technology: str
    host: str
    description: str   # already resolved for the active language, with
                        # the Fase E fallback/marker logic applied
    evidence: str       # confirmation note, or "-"
    remediation: str    # nuclei's own text, or the generic fallback

@dataclass
class ReportData:
    scan_id: int
    status: str
    technologies: list[dict]
    cves: list[CveRow]   # pre-sorted: CVSS desc, EPSS desc as tie-break
    summary: dict         # total_cves, confirmed_count, suspected_count,
                           # counts_by_severity: dict[str, int]

def build_report_data(scan_id: int, lang: str) -> ReportData:
    ...
```

Sort key: `sorted(cves, key=lambda c: (-(c.cvss_score or 0), -(c.epss_score or 0)))`.
`epss_score is None` sorts as if `0` — never crashes, never promoted above
a CVE with a real score.

Remediation resolution (in `build_report_data`, not in the module layer,
so it's testable independent of nuclei):
```python
remediation = (
    finding.data.get("remediation_en")
    if finding.data.get("status") == "confirmed"
    else None
) or i18n.t("remediation_generic", lang=lang, technology=matched_technology)
```

### New file: `backend/app/report_csv.py`

```python
def render_csv(data: ReportData) -> str:
    ...
```

Header row: `CVE, Severity, CVSS, EPSS, Status, Technology, Host,
Description, Evidence, Remediation`. One row per `CveRow`, full text, no
truncation (CSV is for machines/spreadsheets, not a terminal width).
Written to stdout by the CLI, matching `recon audit --format csv`'s
existing precedent exactly (`csv.writer(sys.stdout, lineterminator="\n")`).

### New file: `backend/app/report_pdf.py`

```python
def render_pdf(data: ReportData, path: str, lang: str) -> None:
    ...
```

Built with `reportlab` (pure Python, no native dependency — chosen over
`weasyprint` specifically to avoid a GTK/Pango install requirement on
Windows, where this project is developed). Three sections, each a
`reportlab.platypus` table/paragraph flowable:

1. **Executive summary** — a small counts table: total CVEs, confirmed
   vs. suspected, counts by severity. No generated prose.
2. **Technologies** — same columns as today's terminal table (category,
   name, version, confidence, host).
3. **CVEs** — same columns as the CSV, rendered as wrapped `Paragraph`
   flowables inside table cells (not truncated like the terminal, since a
   PDF page has room) so nothing is silently cut off the way the
   terminal's `_truncate()` requires.

Section titles and column headers reuse existing/new `i18n.t()` keys, so
the PDF is fully bilingual via the same mechanism as the terminal report.

### `cli.py` changes

- `report` command gains `--format table|csv|pdf` (default `table`) and
  `--output/-o` (only meaningful with `--format pdf`; silently ignored —
  not an error — for `table`/`csv`, since those formats have no natural
  file target and warning about an ignored flag would be surprising
  noise for a flag that simply doesn't apply).
- `table` format calls `build_report_data` then renders with (mostly) the
  same Rich-table code already in `_print_report`, refactored to consume
  `ReportData`/`CveRow` instead of raw `Finding` rows.
- `csv` format calls `build_report_data` then `render_csv`, prints result
  to stdout.
- `pdf` format calls `build_report_data` then `render_pdf`; if
  `--output` is omitted, path defaults to `report_<scan_id>.pdf` in the
  current working directory. On success, prints the resolved path to the
  console (the PDF itself is binary, nothing else goes to stdout). A
  write failure (bad path, no permission) is caught and reported as a
  clear CLI error with a non-zero exit code, not a raw traceback.

## Testing

- `epss.py`: TDD mirroring `translate.py`'s existing test suite exactly
  (missing network response, malformed JSON, request exception — all
  return `None`; a successful call is audited).
- `cve_correlation.py`: extend existing tests to assert `epss_score` is
  present on new findings and that a failed/missing EPSS lookup doesn't
  block the finding.
- `nuclei_validation.py`: extend the "confirms a CVE" test to assert
  `remediation_en` is captured when the template's JSON includes it, and
  absent (not a crash) when it doesn't.
- `report_data.py`: pure unit tests building `Finding` rows in memory
  (existing project pattern) — sort order (CVSS desc, EPSS tie-break,
  `None` handling), remediation fallback logic, summary counts.
- `report_csv.py`: parse the generated CSV with `csv.reader` and assert
  on real cell values, not string-contains checks.
- `report_pdf.py`: add `pypdf` (lightweight, MIT-licensed) as a
  **test-only** dependency to extract text back out of the generated PDF
  and assert expected CVE IDs/scores/section titles appear — a PDF test
  that only checks "no exception was raised" would not actually verify
  the report's content.
- Regression: `cli.py`'s existing `table`-format tests must pass
  unmodified after the `_print_report` → `report_data.py` extraction —
  this is the signal that the refactor didn't change today's behavior.
- Manual validation (same bar as Fase E): generate a real PDF against an
  existing scan (e.g. the Fase E validation scan against the
  self-hosted local target) and visually confirm it opens correctly and
  the data matches the terminal report.

## Open items resolved during brainstorming (for reference)

- Evidence stays request/response-free: reuses Fase E's
  `confirmation_note`/audit trail, no new capture added to the active
  modules.
- EPSS source: FIRST.org's free public API, same integration posture as
  NVD/DeepL.
- PDF library: `reportlab` (pure Python), not `weasyprint`, to avoid a
  native GTK/Pango dependency on Windows.
- CSV scope: CVEs only, one row each — not a raw Finding dump, not a
  combined technologies+CVEs file.
- Executive summary: statistics only, no generated narrative text.
- Priority formula: CVSS descending is still primary; EPSS is a
  tie-breaker only, not a composite score and not a "confirmed always
  first" override.
- EPSS fetch timing: at scan time inside `cve_correlation`, persisted —
  not fetched live when a report is generated, matching the NVD/DeepL
  precedent so `report`/export commands never touch the network.
- Remediation source: nuclei template's own `remediation` field when a
  CVE is `confirmed`; a generic fallback string otherwise — never a
  fabricated specific version number.
- PDF output path: defaults to `report_<scan_id>.pdf`, overridable via
  `--output/-o`, never a hard requirement to pass the flag.
