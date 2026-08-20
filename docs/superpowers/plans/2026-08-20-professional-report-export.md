# Fase F: Professional Report + Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `recon report <scan_id>` into a three-format report engine (`table`/`csv`/`pdf`) built on one shared, richer data model that adds EPSS-based CVE prioritization (CVSS primary, EPSS tie-break) and remediation guidance, without changing today's `table` output.

**Architecture:** A new `backend/app/epss.py` fetches and (via `cve_correlation`) persists each CVE's EPSS score at scan time, same posture as NVD/DeepL. A new `backend/app/report_data.py` becomes the single source of truth for report content (`build_report_data(scan_id, lang) -> ReportData`), extracted from today's `_print_report` without changing its behavior. Two new renderers (`report_csv.py`, `report_pdf.py`, the latter via `reportlab`) consume the same `ReportData`; `cli.py`'s `report` command dispatches to one of the three based on `--format`.

**Tech Stack:** Python, SQLAlchemy, Typer/Rich CLI, `requests`, `reportlab` (PDF generation, pure Python), `pypdf` (test-only, PDF text extraction), pytest + `unittest.mock`.

**Spec:** `docs/superpowers/specs/2026-08-20-professional-report-export-design.md`

## Global Constraints

- `fetch_epss` never raises: a network failure, a CVE absent from EPSS's dataset, or a malformed score all return `None` and never block a CVE finding from being created.
- Every real network call (including EPSS) gets an `AuditLog.record(...)` entry, per the existing audit-trail contract in `app/modules/base.py`.
- The `table` format's rendered output must stay behaviorally identical to today's — verified by the existing `report`/`table`-format tests in `test_cli.py` passing unmodified after the `report_data.py` extraction.
- `reportlab` is pure Python; Fase F introduces no new external binary dependency (unlike `nuclei`/`subfinder`/`httpx`, which are optional external tools).
- CSV column names are fixed, lowercase, English (`cve`, `severity`, `cvss`, ...) — not localized, matching `recon audit --format csv`'s existing convention exactly. Only `table` and `pdf` headers are localized via `i18n.t()`.
- Remediation text is either the real `remediation` field from a confirmed CVE's matched nuclei template, or the generic fallback string — never a fabricated specific version number.
- CVSS stays the primary CVE sort key; EPSS is a tie-breaker only, never combined into a composite score.

---

## File Structure

- **Create** `backend/app/epss.py` — `fetch_epss()`, FIRST.org EPSS API wrapper.
- **Create** `backend/tests/test_epss.py`
- **Modify** `backend/app/modules/cve_correlation.py` — call `fetch_epss`, store `epss_score`.
- **Modify** `backend/tests/test_modules_cve_correlation.py`
- **Modify** `backend/app/modules/nuclei_validation.py` — extract `remediation_en` from a confirmed match.
- **Modify** `backend/tests/test_modules_nuclei_validation.py`
- **Modify** `backend/app/i18n.py` — new report/CSV/PDF string keys.
- **Create** `backend/app/report_data.py` — `ReportData`, `CveRow`, `build_report_data()`, `describe_with_marker()`.
- **Create** `backend/tests/test_report_data.py`
- **Create** `backend/app/report_csv.py` — `render_csv()`.
- **Create** `backend/tests/test_report_csv.py`
- **Create** `backend/app/report_pdf.py` — `render_pdf()`.
- **Create** `backend/tests/test_report_pdf.py`
- **Modify** `backend/requirements.txt` — add `reportlab`, `pypdf` (test-only).
- **Modify** `backend/app/cli.py` — `report` command gains `--format`/`--output`; `_print_report` becomes `_render_table` consuming `ReportData`.
- **Modify** `backend/tests/test_cli.py` — new `--format csv`/`--format pdf` tests; existing `table`-format tests must pass unmodified.
- **Modify** `README.md`, `README.pt-BR.md` — document the new `--format`/`--output` flags, EPSS, and remediation guidance.

---

### Task 1: EPSS lookup helper

**Files:**
- Create: `backend/app/epss.py`
- Test: `backend/tests/test_epss.py`

**Interfaces:**
- Produces: `fetch_epss(cve_id: str, audit: AuditLog | None = None) -> float | None`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_epss.py
from unittest.mock import MagicMock, patch

import requests

from app import epss
from app.audit import AuditLog


def _mock_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def test_returns_the_epss_score_when_the_api_call_succeeds():
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.94432940", "percentile": "0.99947"}]}

    with patch("app.epss.requests.get", return_value=_mock_response(payload)) as mock_get:
        result = epss.fetch_epss("CVE-2021-44228")

    assert result == 0.94432940
    assert mock_get.call_args.kwargs["params"] == {"cveId": "CVE-2021-44228"}


def test_returns_none_when_the_cve_is_absent_from_epss_data():
    payload = {"data": []}

    with patch("app.epss.requests.get", return_value=_mock_response(payload)):
        result = epss.fetch_epss("CVE-0000-00000")

    assert result is None


def test_returns_none_and_never_raises_when_the_api_call_fails():
    with patch("app.epss.requests.get", side_effect=requests.RequestException("epss is down")):
        result = epss.fetch_epss("CVE-2021-44228")

    assert result is None


def test_returns_none_for_a_malformed_score_without_raising():
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "not-a-number"}]}

    with patch("app.epss.requests.get", return_value=_mock_response(payload)):
        result = epss.fetch_epss("CVE-2021-44228")

    assert result is None


def test_returns_none_for_an_empty_cve_id_without_calling_the_api():
    with patch("app.epss.requests.get") as mock_get:
        result = epss.fetch_epss("")

    mock_get.assert_not_called()
    assert result is None


def test_records_a_successful_call_to_the_audit_log():
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.94432940"}]}
    audit = AuditLog()

    with patch("app.epss.requests.get", return_value=_mock_response(payload)):
        epss.fetch_epss("CVE-2021-44228", audit=audit)

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "cve_correlation"
    assert audit.entries[0]["target"] == "CVE-2021-44228"
    assert audit.entries[0]["outcome"] == "200"
    assert audit.entries[0]["url"] == epss.EPSS_API_URL


def test_records_a_failed_call_to_the_audit_log():
    audit = AuditLog()

    with patch("app.epss.requests.get", side_effect=requests.RequestException("epss is down")):
        epss.fetch_epss("CVE-2021-44228", audit=audit)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: epss is down"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_epss.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.epss'`

- [ ] **Step 3: Write `epss.py`**

```python
# backend/app/epss.py
import requests

from app.audit import AuditLog

EPSS_API_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 15


def fetch_epss(cve_id: str, audit: AuditLog | None = None) -> float | None:
    """Fetches a CVE's EPSS score (probability of exploitation, 0-1) from
    the FIRST.org public API -- free, no API key. Never raises: an empty
    CVE ID, any request failure, a CVE absent from EPSS's dataset, or a
    malformed score all return None -- a missing EPSS score must never
    fail a scan."""
    if not cve_id:
        return None

    try:
        response = requests.get(
            EPSS_API_URL,
            params={"cveId": cve_id},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        if audit is not None:
            audit.record(module="cve_correlation", target=cve_id, outcome=f"error: {exc}", url=EPSS_API_URL)
        return None

    if audit is not None:
        audit.record(module="cve_correlation", target=cve_id, outcome=str(response.status_code), url=EPSS_API_URL)

    data = payload.get("data", [])
    if not data:
        return None
    try:
        return float(data[0].get("epss"))
    except (TypeError, ValueError):
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_epss.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/epss.py backend/tests/test_epss.py
git commit -m "feat(epss): add FIRST.org EPSS score lookup helper"
```

---

### Task 2: `cve_correlation` — persist EPSS score

**Files:**
- Modify: `backend/app/modules/cve_correlation.py`
- Test: `backend/tests/test_modules_cve_correlation.py`

**Interfaces:**
- Consumes: `fetch_epss(cve_id: str, audit: AuditLog | None = None) -> float | None` (Task 1)
- Produces: every `cve` Finding's `data` now includes `"epss_score": float | None`

- [ ] **Step 1: Write the failing tests**

Append to `backend/tests/test_modules_cve_correlation.py`:

```python
def test_cve_finding_includes_the_epss_score_when_the_lookup_succeeds(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0", "host": "tech.example.com"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        with patch("app.modules.cve_correlation.fetch_epss", return_value=0.42):
            findings = CveCorrelationModule().run("example.com", context)

    assert findings[0].data["epss_score"] == 0.42


def test_cve_finding_has_a_none_epss_score_when_the_lookup_fails(monkeypatch):
    monkeypatch.setattr(cve_correlation.settings, "nvd_api_key", None)
    monkeypatch.setattr(cve_correlation.time, "sleep", lambda *_: None)

    context = {"technologies": [{"name": "nginx", "version": "1.18.0", "host": "tech.example.com"}]}
    payload = _nvd_response(_cve("CVE-2021-23017", [NGINX_RANGE_MATCH]))

    with patch("app.modules.cve_correlation.requests.get", return_value=_mock_response(payload)):
        with patch("app.modules.cve_correlation.fetch_epss", return_value=None):
            findings = CveCorrelationModule().run("example.com", context)

    assert findings[0].data["epss_score"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_modules_cve_correlation.py -v -k epss`
Expected: FAIL — `AttributeError` / `ModuleNotFoundError: No module named 'app.modules.cve_correlation.fetch_epss'` (nothing imports `fetch_epss` yet) and `KeyError: 'epss_score'`

- [ ] **Step 3: Update `cve_correlation.py`**

Add the import near the top, alongside the existing `translate_en_to_pt` import:

```python
from app.epss import fetch_epss
```

In `_finding_from_cve`, add the EPSS lookup right after the existing `description_pt` block and include it in the returned `Finding.data`:

```python
    def _finding_from_cve(
        self, cve: dict, tech_name: str, tech_version: str, host: str, audit: AuditLog | None
    ) -> Finding:
        description_en = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        description_pt = (
            translate_en_to_pt(
                description_en,
                audit=audit,
                module=self.name,
                audit_target=cve.get("id", ""),
            )
            if description_en
            else None
        )
        epss_score = fetch_epss(cve.get("id", ""), audit=audit)

        cvss_score = None
        severity = None
        metrics = cve.get("metrics", {})
        for key in CVSS_METRIC_KEYS:
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                break

        return Finding(
            type="cve",
            value=cve.get("id", ""),
            data={
                "cvss_score": cvss_score,
                "severity": severity,
                "epss_score": epss_score,
                "description_en": description_en,
                "description_pt": description_pt,
                "matched_technology": tech_name,
                "matched_technology_version": tech_version,
                "host": host,
                "status": "suspected",
            },
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_modules_cve_correlation.py -v`
Expected: PASS (all tests, including the pre-existing ones — the pre-existing tests don't patch `fetch_epss`, so it runs for real against the live EPSS API during those test runs; if that's undesirable, patch `app.modules.cve_correlation.fetch_epss` to return `None` in a `monkeypatch` at the top of any pre-existing test that fails due to a real network call. Prefer this over a global `autouse` fixture — keep each test's mocking explicit.)

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/cve_correlation.py backend/tests/test_modules_cve_correlation.py
git commit -m "feat(cve-correlation): persist each CVE finding's EPSS score"
```

---

### Task 3: `nuclei_validation` — capture nuclei's own remediation text

**Files:**
- Modify: `backend/app/modules/nuclei_validation.py`
- Test: `backend/tests/test_modules_nuclei_validation.py`

**Interfaces:**
- Produces: a confirmed `cve_validation` Finding's `data` includes `"remediation_en": str` when the matched nuclei template's JSON carries an `info.remediation` field; the key is absent (not `None`) when the template doesn't carry one.

- [ ] **Step 1: Write the failing tests**

Append to `backend/tests/test_modules_nuclei_validation.py`:

```python
def test_confirmed_finding_includes_remediation_when_the_template_provides_it():
    match_line = (
        '{"template-id": "CVE-2021-23017", "matched-at": "https://tech.example.com/", '
        '"info": {"remediation": "Upgrade to version 2.0 or later.\\n"}}\n'
    )
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout=match_line),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert findings[0].data["remediation_en"] == "Upgrade to version 2.0 or later."


def test_confirmed_finding_omits_remediation_when_the_template_has_none():
    match_line = '{"template-id": "CVE-2021-23017", "matched-at": "https://tech.example.com/"}\n'
    context = {"cve_findings": [{"cve_id": "CVE-2021-23017", "host": "tech.example.com"}]}

    with patch(
        "app.modules.nuclei_validation.subprocess.run",
        return_value=_fake_result(stdout=match_line),
    ):
        findings = NucleiValidationModule().run("example.com", context)

    assert "remediation_en" not in findings[0].data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_modules_nuclei_validation.py -v -k remediation`
Expected: FAIL — `KeyError: 'remediation_en'` for the first test (second test already passes trivially since the key was never set, but run both to confirm the first fails)

- [ ] **Step 3: Update `nuclei_validation.py`**

Replace the final `return (...)` block inside `_validate`:

```python
        data = {
            "host": host,
            "status": "confirmed",
            "nuclei_template_id": template_id,
            "matched_at": matched_at,
            "confirmation_note_en": i18n.t(
                "cve_confirmed_note", lang="en", template_id=template_id, matched_at=matched_at
            ),
            "confirmation_note_pt": i18n.t(
                "cve_confirmed_note", lang="pt", template_id=template_id, matched_at=matched_at
            ),
        }
        remediation = match.get("info", {}).get("remediation")
        if remediation:
            data["remediation_en"] = remediation.strip()

        return Finding(type="cve_validation", value=cve_id, data=data), True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_modules_nuclei_validation.py -v`
Expected: PASS (all tests, including the pre-existing ones)

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add backend/app/modules/nuclei_validation.py backend/tests/test_modules_nuclei_validation.py
git commit -m "feat(nuclei): capture the confirmed template's own remediation text"
```

---

### Task 4: `report_data.py` — shared report data model

**Files:**
- Modify: `backend/app/i18n.py`
- Create: `backend/app/report_data.py`
- Test: `backend/tests/test_report_data.py`

**Interfaces:**
- Consumes: `Finding` rows via SQLAlchemy (`app.models`, `app.db.SessionLocal`); `i18n.t(key, lang=None, **kwargs)` (existing)
- Produces:
  - `CveRow` dataclass: `cve_id: str, severity: str, cvss_score: float | None, epss_score: float | None, status: str, technology: str, host: str, description: str, description_translated: bool, evidence: str, remediation: str`
  - `ReportData` dataclass: `scan_id: int, status: str, technologies: list[dict], cves: list[CveRow], other: list[dict], summary: dict`
  - `build_report_data(scan_id: int, lang: str) -> ReportData | None` (`None` when the scan doesn't exist)
  - `describe_with_marker(row: CveRow, lang: str) -> str`

- [ ] **Step 1: Add new i18n keys**

Add these keys inside `STRINGS["en"]` in `backend/app/i18n.py` (anywhere in the dict):

```python
        "cve_col_epss": "EPSS",
        "cve_col_remediation": "Remediation",
        "remediation_generic": "Upgrade {technology} to a patched version.",
        "report_pdf_title": "Recon Report - Scan #{scan_id}",
        "report_exec_summary_title": "Executive Summary",
        "report_summary_total_cves": "Total CVEs",
        "report_summary_by_severity": "By severity",
        "invalid_report_format": "--format must be 'table', 'csv', or 'pdf'.",
        "report_pdf_saved": "PDF report saved to {path}",
        "report_pdf_write_failed": "could not write the PDF report: {error}",
```

Add the matching keys inside `STRINGS["pt"]`:

```python
        "cve_col_epss": "EPSS",
        "cve_col_remediation": "Remediacao",
        "remediation_generic": "Atualize {technology} para uma versao corrigida.",
        "report_pdf_title": "Relatorio de Recon - Scan #{scan_id}",
        "report_exec_summary_title": "Resumo Executivo",
        "report_summary_total_cves": "Total de CVEs",
        "report_summary_by_severity": "Por severidade",
        "invalid_report_format": "--format deve ser 'table', 'csv' ou 'pdf'.",
        "report_pdf_saved": "Relatorio PDF salvo em {path}",
        "report_pdf_write_failed": "nao foi possivel escrever o relatorio PDF: {error}",
```

- [ ] **Step 2: Write the failing tests**

```python
# backend/tests/test_report_data.py
from app.db import SessionLocal
from app import models
from app.report_data import CveRow, build_report_data, describe_with_marker


def _make_scan(cve_data_list, technologies=None, other=None):
    db = SessionLocal()
    try:
        project = models.Project(
            name="Report Data Co", target="example.com", scope_notes="ok", authorized=True
        )
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        for entry in cve_data_list:
            db.add(
                models.Finding(
                    scan_id=scan_row.id, module="cve_correlation", type="cve",
                    value=entry["value"], data=entry["data"],
                )
            )
        for tech in technologies or []:
            db.add(
                models.Finding(
                    scan_id=scan_row.id, module="tech_fingerprint", type="technology",
                    value=tech["value"], data=tech["data"],
                )
            )
        for item in other or []:
            db.add(
                models.Finding(
                    scan_id=scan_row.id, module=item.get("module", "orchestrator"),
                    type=item["type"], value=item["value"], data=item.get("data", {}),
                )
            )
        db.commit()
        return scan_row.id
    finally:
        db.close()


def test_returns_none_for_a_missing_scan():
    assert build_report_data(999999, "en") is None


def test_sorts_cves_by_cvss_descending_with_epss_as_tiebreak():
    scan_id = _make_scan(
        [
            {"value": "CVE-LOW-CVSS", "data": {"cvss_score": 5.0, "severity": "MEDIUM", "epss_score": 0.9, "status": "suspected", "description_en": "d", "host": "example.com"}},
            {"value": "CVE-HIGH-CVSS", "data": {"cvss_score": 9.0, "severity": "CRITICAL", "epss_score": 0.1, "status": "suspected", "description_en": "d", "host": "example.com"}},
            {"value": "CVE-TIE-HIGH-EPSS", "data": {"cvss_score": 9.0, "severity": "CRITICAL", "epss_score": 0.5, "status": "suspected", "description_en": "d", "host": "example.com"}},
        ]
    )

    data = build_report_data(scan_id, "en")

    assert [row.cve_id for row in data.cves] == ["CVE-TIE-HIGH-EPSS", "CVE-HIGH-CVSS", "CVE-LOW-CVSS"]


def test_treats_a_missing_epss_score_as_zero_for_the_tiebreak():
    scan_id = _make_scan(
        [
            {"value": "CVE-NO-EPSS", "data": {"cvss_score": 9.0, "severity": "CRITICAL", "epss_score": None, "status": "suspected", "description_en": "d", "host": "example.com"}},
            {"value": "CVE-WITH-EPSS", "data": {"cvss_score": 9.0, "severity": "CRITICAL", "epss_score": 0.01, "status": "suspected", "description_en": "d", "host": "example.com"}},
        ]
    )

    data = build_report_data(scan_id, "en")

    assert [row.cve_id for row in data.cves] == ["CVE-WITH-EPSS", "CVE-NO-EPSS"]


def test_uses_the_generic_remediation_fallback_for_a_suspected_cve():
    scan_id = _make_scan(
        [{"value": "CVE-SUSPECTED", "data": {
            "cvss_score": 5.0, "severity": "MEDIUM", "status": "suspected", "description_en": "d",
            "matched_technology": "nginx", "matched_technology_version": "1.18.0", "host": "example.com",
        }}]
    )

    data = build_report_data(scan_id, "en")

    assert data.cves[0].remediation == "Upgrade nginx 1.18.0 to a patched version."


def test_uses_the_nuclei_remediation_text_for_a_confirmed_cve():
    scan_id = _make_scan(
        [{"value": "CVE-CONFIRMED", "data": {
            "cvss_score": 9.0, "severity": "CRITICAL", "status": "confirmed", "remediation_en": "Upgrade to 2.0.",
            "description_en": "d", "matched_technology": "nginx", "matched_technology_version": "1.18.0", "host": "example.com",
        }}]
    )

    data = build_report_data(scan_id, "en")

    assert data.cves[0].remediation == "Upgrade to 2.0."


def test_falls_back_to_the_legacy_description_field_and_suspected_status():
    scan_id = _make_scan(
        [{"value": "CVE-LEGACY", "data": {
            "cvss_score": 9.4, "severity": "CRITICAL", "description": "Legacy description.",
            "matched_technology": "nginx", "matched_technology_version": "1.18.0",
        }}]
    )

    data = build_report_data(scan_id, "en")

    assert data.cves[0].status == "suspected"
    assert data.cves[0].description == "Legacy description."


def test_summary_counts_confirmed_suspected_and_by_severity():
    scan_id = _make_scan(
        [
            {"value": "CVE-A", "data": {"cvss_score": 9.0, "severity": "CRITICAL", "status": "confirmed", "description_en": "d", "host": "example.com"}},
            {"value": "CVE-B", "data": {"cvss_score": 5.0, "severity": "MEDIUM", "status": "suspected", "description_en": "d", "host": "example.com"}},
            {"value": "CVE-C", "data": {"cvss_score": 5.0, "severity": "MEDIUM", "status": "suspected", "description_en": "d", "host": "example.com"}},
        ]
    )

    data = build_report_data(scan_id, "en")

    assert data.summary["total_cves"] == 3
    assert data.summary["confirmed_count"] == 1
    assert data.summary["suspected_count"] == 2
    assert data.summary["counts_by_severity"] == {"CRITICAL": 1, "MEDIUM": 2}


def test_includes_technologies_and_other_findings():
    scan_id = _make_scan(
        [],
        technologies=[{"value": "example.com", "data": {"category": "web_server", "name": "nginx", "version": "1.18.0", "confidence": "high"}}],
        other=[{"type": "module_error", "value": "subfinder", "data": {"error": "not installed"}}],
    )

    data = build_report_data(scan_id, "en")

    assert data.technologies == [{"category": "web_server", "name": "nginx", "version": "1.18.0", "confidence": "high", "host": "example.com"}]
    assert data.other == [{"type": "module_error", "value": "subfinder", "module": "orchestrator"}]


def test_describe_with_marker_appends_the_marker_only_when_untranslated_and_portuguese():
    translated_row = CveRow(
        cve_id="CVE-1", severity="LOW", cvss_score=1.0, epss_score=None, status="suspected",
        technology="x", host="example.com", description="Traduzido.", description_translated=True,
        evidence="-", remediation="-",
    )
    untranslated_row = CveRow(
        cve_id="CVE-2", severity="LOW", cvss_score=1.0, epss_score=None, status="suspected",
        technology="x", host="example.com", description="Original.", description_translated=False,
        evidence="-", remediation="-",
    )

    assert describe_with_marker(translated_row, "pt") == "Traduzido."
    assert describe_with_marker(untranslated_row, "pt") == "Original. (traducao indisponivel)"
    assert describe_with_marker(untranslated_row, "en") == "Original."
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_report_data.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.report_data'`

- [ ] **Step 4: Write `report_data.py`**

```python
# backend/app/report_data.py
from dataclasses import dataclass, field

from app import i18n, models
from app.db import SessionLocal


@dataclass
class CveRow:
    cve_id: str
    severity: str
    cvss_score: float | None
    epss_score: float | None
    status: str
    technology: str
    host: str
    description: str
    description_translated: bool
    evidence: str
    remediation: str


@dataclass
class ReportData:
    scan_id: int
    status: str
    technologies: list[dict] = field(default_factory=list)
    cves: list[CveRow] = field(default_factory=list)
    other: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


def describe_with_marker(row: CveRow, lang: str) -> str:
    """Full CVE description text for `lang`, with the translation-unavailable
    marker appended -- untruncated -- when Portuguese is requested but no
    real translation exists. A caller with a fixed display width (the
    terminal table) must truncate `row.description` first, leaving room
    for this marker, rather than truncating this function's return value."""
    if lang == "pt" and not row.description_translated:
        return f"{row.description} {i18n.t('translation_unavailable', lang=lang)}".strip()
    return row.description


def _resolve_description(data: dict, lang: str) -> tuple[str, bool]:
    description_en = data.get("description_en", data.get("description", ""))
    description_pt = data.get("description_pt")
    if lang == "pt" and description_pt:
        return description_pt, True
    return description_en, False


def _resolve_remediation(data: dict, technology: str, lang: str) -> str:
    remediation_en = data.get("remediation_en") if data.get("status") == "confirmed" else None
    if remediation_en:
        return remediation_en
    return i18n.t("remediation_generic", lang=lang, technology=technology)


def _cve_row(finding, lang: str) -> CveRow:
    data = finding.data
    technology = f"{data.get('matched_technology', '')} {data.get('matched_technology_version', '')}".strip()
    description, translated = _resolve_description(data, lang)
    evidence = data.get(f"confirmation_note_{lang}") or data.get("confirmation_note_en", "") or "-"
    return CveRow(
        cve_id=finding.value,
        severity=str(data.get("severity") or ""),
        cvss_score=data.get("cvss_score"),
        epss_score=data.get("epss_score"),
        status=data.get("status", "suspected"),
        technology=technology,
        host=data.get("host", ""),
        description=description,
        description_translated=translated,
        evidence=evidence,
        remediation=_resolve_remediation(data, technology, lang),
    )


def build_report_data(scan_id: int, lang: str) -> ReportData | None:
    db = SessionLocal()
    try:
        scan_row = db.get(models.Scan, scan_id)
        if scan_row is None:
            return None
        findings = list(scan_row.findings)
        status = scan_row.status
    finally:
        db.close()

    technologies = [
        {
            "category": f.data.get("category", ""),
            "name": f.data.get("name", ""),
            "version": f.data.get("version") or "-",
            "confidence": f.data.get("confidence", ""),
            "host": f.value,
        }
        for f in findings
        if f.type == "technology"
    ]

    cve_rows = [_cve_row(f, lang) for f in findings if f.type == "cve"]
    cve_rows.sort(key=lambda row: (-(row.cvss_score or 0), -(row.epss_score or 0)))

    other = [
        {"type": f.type, "value": f.value, "module": f.module}
        for f in findings
        if f.type not in ("technology", "cve")
    ]

    confirmed_count = sum(1 for row in cve_rows if row.status == "confirmed")
    counts_by_severity: dict[str, int] = {}
    for row in cve_rows:
        if row.severity:
            counts_by_severity[row.severity] = counts_by_severity.get(row.severity, 0) + 1

    summary = {
        "total_cves": len(cve_rows),
        "confirmed_count": confirmed_count,
        "suspected_count": len(cve_rows) - confirmed_count,
        "counts_by_severity": counts_by_severity,
    }

    return ReportData(
        scan_id=scan_id, status=status, technologies=technologies,
        cves=cve_rows, other=other, summary=summary,
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_report_data.py -v`
Expected: PASS (10 tests)

- [ ] **Step 6: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests)

- [ ] **Step 7: Commit**

```bash
git add backend/app/i18n.py backend/app/report_data.py backend/tests/test_report_data.py
git commit -m "feat(report): add shared ReportData model with EPSS tie-break and remediation resolution"
```

---

### Task 5: CSV renderer

**Files:**
- Create: `backend/app/report_csv.py`
- Test: `backend/tests/test_report_csv.py`

**Interfaces:**
- Consumes: `ReportData`, `CveRow`, `describe_with_marker(row, lang)` (Task 4)
- Produces: `render_csv(data: ReportData, lang: str) -> str`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_report_csv.py
import csv
import io

from app.report_csv import render_csv
from app.report_data import CveRow, ReportData


def _row(**overrides):
    defaults = dict(
        cve_id="CVE-2021-23017", severity="CRITICAL", cvss_score=9.4, epss_score=0.42,
        status="confirmed", technology="nginx 1.18.0", host="example.com",
        description="A vuln.", description_translated=True,
        evidence="Confirmed via nuclei template CVE-2021-23017.",
        remediation="Upgrade to nginx 1.20.1 or later.",
    )
    defaults.update(overrides)
    return CveRow(**defaults)


def test_writes_a_header_row_and_one_row_per_cve():
    data = ReportData(scan_id=1, status="complete", cves=[_row()])

    output = render_csv(data, lang="en")
    rows = list(csv.reader(io.StringIO(output)))

    assert rows[0] == [
        "cve", "severity", "cvss", "epss", "status", "technology", "host",
        "description", "evidence", "remediation",
    ]
    assert rows[1] == [
        "CVE-2021-23017", "CRITICAL", "9.4", "0.42", "confirmed", "nginx 1.18.0", "example.com",
        "A vuln.", "Confirmed via nuclei template CVE-2021-23017.", "Upgrade to nginx 1.20.1 or later.",
    ]


def test_appends_the_translation_unavailable_marker_untruncated_in_portuguese():
    long_description = "x" * 500
    data = ReportData(
        scan_id=1, status="complete",
        cves=[_row(description=long_description, description_translated=False)],
    )

    output = render_csv(data, lang="pt")
    rows = list(csv.reader(io.StringIO(output)))

    assert rows[1][7] == f"{long_description} (traducao indisponivel)"


def test_writes_an_empty_cell_for_a_missing_cvss_or_epss_score():
    data = ReportData(scan_id=1, status="complete", cves=[_row(cvss_score=None, epss_score=None)])

    output = render_csv(data, lang="en")
    rows = list(csv.reader(io.StringIO(output)))

    assert rows[1][2] == ""
    assert rows[1][3] == ""


def test_writes_only_the_header_row_when_there_are_no_cves():
    data = ReportData(scan_id=1, status="complete", cves=[])

    output = render_csv(data, lang="en")
    rows = list(csv.reader(io.StringIO(output)))

    assert len(rows) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_report_csv.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.report_csv'`

- [ ] **Step 3: Write `report_csv.py`**

```python
# backend/app/report_csv.py
import csv
import io

from app.report_data import ReportData, describe_with_marker


def render_csv(data: ReportData, lang: str) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        ["cve", "severity", "cvss", "epss", "status", "technology", "host", "description", "evidence", "remediation"]
    )
    for row in data.cves:
        writer.writerow(
            [
                row.cve_id,
                row.severity,
                row.cvss_score if row.cvss_score is not None else "",
                row.epss_score if row.epss_score is not None else "",
                row.status,
                row.technology,
                row.host,
                describe_with_marker(row, lang),
                row.evidence,
                row.remediation,
            ]
        )
    return buffer.getvalue()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_report_csv.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add backend/app/report_csv.py backend/tests/test_report_csv.py
git commit -m "feat(report): add CSV export renderer"
```

---

### Task 6: PDF renderer

**Files:**
- Modify: `backend/requirements.txt`
- Create: `backend/app/report_pdf.py`
- Test: `backend/tests/test_report_pdf.py`

**Interfaces:**
- Consumes: `ReportData`, `CveRow`, `describe_with_marker(row, lang)` (Task 4); `i18n.t(key, lang=None, **kwargs)` (existing)
- Produces: `render_pdf(data: ReportData, path: str, lang: str) -> None`

- [ ] **Step 1: Add the new dependencies**

Run, from `backend/`:
```bash
pip install reportlab pypdf
pip show reportlab | grep Version
pip show pypdf | grep Version
```

Append two lines to `backend/requirements.txt` using the versions printed above, e.g.:
```
reportlab==4.2.5
pypdf==5.1.0  # test-only: extracts text from generated PDFs to verify report_pdf.py's output
```
(Use whatever versions `pip show` actually printed — do not guess if they differ from this example.)

- [ ] **Step 2: Write the failing tests**

```python
# backend/tests/test_report_pdf.py
import os

from pypdf import PdfReader

from app.report_data import CveRow, ReportData
from app.report_pdf import render_pdf


def _row(**overrides):
    defaults = dict(
        cve_id="CVE-2021-23017", severity="CRITICAL", cvss_score=9.4, epss_score=0.42,
        status="confirmed", technology="nginx 1.18.0", host="example.com",
        description="A vuln.", description_translated=True,
        evidence="Confirmed via nuclei template CVE-2021-23017.",
        remediation="Upgrade to nginx 1.20.1 or later.",
    )
    defaults.update(overrides)
    return CveRow(**defaults)


def _extract_text(path: str) -> str:
    reader = PdfReader(path)
    return "\n".join(page.extract_text() for page in reader.pages)


def test_renders_a_pdf_containing_the_cve_id_and_remediation(tmp_path):
    path = str(tmp_path / "report.pdf")
    data = ReportData(
        scan_id=42, status="complete",
        technologies=[{"category": "web_server", "name": "nginx", "version": "1.18.0", "confidence": "high", "host": "example.com"}],
        cves=[_row()],
        summary={"total_cves": 1, "confirmed_count": 1, "suspected_count": 0, "counts_by_severity": {"CRITICAL": 1}},
    )

    render_pdf(data, path, lang="en")

    assert os.path.exists(path)
    text = _extract_text(path)
    assert "CVE-2021-23017" in text
    assert "nginx" in text
    assert "Upgrade to nginx 1.20.1 or later." in text


def test_renders_in_portuguese_when_requested(tmp_path):
    path = str(tmp_path / "report.pdf")
    data = ReportData(
        scan_id=42, status="complete", cves=[_row()],
        summary={"total_cves": 1, "confirmed_count": 1, "suspected_count": 0, "counts_by_severity": {}},
    )

    render_pdf(data, path, lang="pt")

    text = _extract_text(path)
    assert "Confirmada" in text


def test_renders_without_a_technologies_or_cves_section_when_both_are_empty(tmp_path):
    path = str(tmp_path / "report.pdf")
    data = ReportData(
        scan_id=1, status="complete",
        summary={"total_cves": 0, "confirmed_count": 0, "suspected_count": 0, "counts_by_severity": {}},
    )

    render_pdf(data, path, lang="en")

    assert os.path.exists(path)
    text = _extract_text(path)
    assert "Executive Summary" in text
    assert "Technologies" not in text
    assert "CVEs" not in text
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_report_pdf.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.report_pdf'`

- [ ] **Step 4: Write `report_pdf.py`**

```python
# backend/app/report_pdf.py
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app import i18n
from app.report_data import ReportData, describe_with_marker

_HEADER_STYLE = TableStyle(
    [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2A2A2A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]
)


def render_pdf(data: ReportData, path: str, lang: str) -> None:
    styles = getSampleStyleSheet()
    cell_style = styles["BodyText"]
    cell_style.fontSize = 8

    doc = SimpleDocTemplate(path, pagesize=A4)
    elements = [
        Paragraph(i18n.t("report_pdf_title", lang=lang, scan_id=data.scan_id), styles["Title"]),
        Spacer(1, 12),
    ]

    elements.append(Paragraph(i18n.t("report_exec_summary_title", lang=lang), styles["Heading2"]))
    severity_lines = ", ".join(
        f"{severity}: {count}" for severity, count in sorted(data.summary.get("counts_by_severity", {}).items())
    )
    summary_table = Table(
        [
            [i18n.t("report_summary_total_cves", lang=lang), str(data.summary.get("total_cves", 0))],
            [i18n.t("status_confirmed", lang=lang), str(data.summary.get("confirmed_count", 0))],
            [i18n.t("status_suspected", lang=lang), str(data.summary.get("suspected_count", 0))],
            [i18n.t("report_summary_by_severity", lang=lang), severity_lines or "-"],
        ]
    )
    summary_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 9)]))
    elements.append(summary_table)
    elements.append(Spacer(1, 16))

    if data.technologies:
        elements.append(Paragraph(i18n.t("technologies_title", lang=lang), styles["Heading2"]))
        tech_rows = [
            [
                i18n.t("tech_col_category", lang=lang),
                i18n.t("tech_col_name", lang=lang),
                i18n.t("tech_col_version", lang=lang),
                i18n.t("tech_col_confidence", lang=lang),
                i18n.t("tech_col_host", lang=lang),
            ]
        ]
        for tech in data.technologies:
            tech_rows.append(
                [
                    str(tech.get("category", "")),
                    str(tech.get("name", "")),
                    str(tech.get("version") or "-"),
                    str(tech.get("confidence", "")),
                    str(tech.get("host", "")),
                ]
            )
        tech_table = Table(tech_rows, repeatRows=1)
        tech_table.setStyle(_HEADER_STYLE)
        elements.append(tech_table)
        elements.append(Spacer(1, 16))

    if data.cves:
        elements.append(Paragraph(i18n.t("cves_title", lang=lang), styles["Heading2"]))
        cve_rows = [
            [
                i18n.t("cve_col_id", lang=lang),
                i18n.t("cve_col_severity", lang=lang),
                i18n.t("cve_col_cvss", lang=lang),
                i18n.t("cve_col_epss", lang=lang),
                i18n.t("cve_col_status", lang=lang),
                i18n.t("cve_col_technology", lang=lang),
                i18n.t("cve_col_description", lang=lang),
                i18n.t("cve_col_evidence", lang=lang),
                i18n.t("cve_col_remediation", lang=lang),
            ]
        ]
        for row in data.cves:
            status_label = i18n.t(
                "status_confirmed" if row.status == "confirmed" else "status_suspected", lang=lang
            )
            cve_rows.append(
                [
                    row.cve_id,
                    row.severity,
                    f"{row.cvss_score:.1f}" if row.cvss_score is not None else "-",
                    f"{row.epss_score:.3f}" if row.epss_score is not None else "-",
                    status_label,
                    row.technology,
                    Paragraph(describe_with_marker(row, lang), cell_style),
                    Paragraph(row.evidence, cell_style),
                    Paragraph(row.remediation, cell_style),
                ]
            )
        cve_table = Table(
            cve_rows, repeatRows=1,
            colWidths=[2.2 * cm, 1.6 * cm, 1.3 * cm, 1.3 * cm, 1.8 * cm, 2.8 * cm, 5 * cm, 4 * cm, 4 * cm],
        )
        cve_table.setStyle(_HEADER_STYLE)
        elements.append(cve_table)

    doc.build(elements)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_report_pdf.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests)

- [ ] **Step 7: Commit**

```bash
git add backend/requirements.txt backend/app/report_pdf.py backend/tests/test_report_pdf.py
git commit -m "feat(report): add PDF export renderer via reportlab"
```

---

### Task 7: `cli.py` — wire `--format`/`--output`, refactor table rendering

**Files:**
- Modify: `backend/app/cli.py`
- Test: `backend/tests/test_cli.py`

**Interfaces:**
- Consumes: `build_report_data(scan_id, lang) -> ReportData | None`, `ReportData`, `CveRow`, `describe_with_marker(row, lang)` (Task 4); `render_csv(data, lang) -> str` (Task 5); `render_pdf(data, path, lang) -> None` (Task 6)
- Produces: `report` command gains `--format table|csv|pdf` (default `table`) and `--output/-o` (pdf only)

- [ ] **Step 1: Write the failing tests**

Append to `backend/tests/test_cli.py`:

```python
def test_report_rejects_an_invalid_format():
    result = runner.invoke(app, ["report", "1", "--format", "xml"])

    assert result.exit_code == 1
    assert "table" in result.output.lower()


def test_report_csv_format_writes_a_header_and_one_row_per_cve():
    db = SessionLocal()
    try:
        project = models.Project(name="CSV Co", target="csv.example.com", scope_notes="ok", authorized=True)
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        db.add(
            models.Finding(
                scan_id=scan_row.id, module="cve_correlation", type="cve", value="CVE-2021-23017",
                data={
                    "cvss_score": 9.4, "severity": "CRITICAL", "epss_score": 0.5,
                    "description_en": "A vuln.", "description_pt": None,
                    "matched_technology": "nginx", "matched_technology_version": "1.18.0",
                    "host": "csv.example.com", "status": "suspected",
                },
            )
        )
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["report", str(scan_id), "--format", "csv"])

    assert result.exit_code == 0
    rows = list(csv.reader(io.StringIO(result.output)))
    assert rows[0][0] == "cve"
    assert rows[1][0] == "CVE-2021-23017"


def test_report_pdf_format_writes_a_file_and_reports_its_path(tmp_path):
    db = SessionLocal()
    try:
        project = models.Project(name="PDF Co", target="pdf.example.com", scope_notes="ok", authorized=True)
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    output_path = str(tmp_path / "custom_report.pdf")
    result = runner.invoke(app, ["report", str(scan_id), "--format", "pdf", "--output", output_path])

    assert result.exit_code == 0
    assert output_path in result.output
    assert os.path.exists(output_path)


def test_report_pdf_format_defaults_to_report_scan_id_pdf_in_the_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = SessionLocal()
    try:
        project = models.Project(name="Default PDF Co", target="defaultpdf.example.com", scope_notes="ok", authorized=True)
        db.add(project)
        db.commit()
        scan_row = models.Scan(project_id=project.id, status="complete")
        db.add(scan_row)
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    result = runner.invoke(app, ["report", str(scan_id), "--format", "pdf"])

    assert result.exit_code == 0
    assert os.path.exists(tmp_path / f"report_{scan_id}.pdf")
```

Add `import io`, `import os` to the top of `backend/tests/test_cli.py` alongside the existing `import csv`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_cli.py -v -k "report_rejects or report_csv_format or report_pdf_format"`
Expected: FAIL — `--format`/`--output` aren't recognized options on `report` yet (Typer usage error), or `AttributeError` for missing renderer wiring.

- [ ] **Step 3: Update `cli.py`**

Update the import line near the top:

```python
from app import i18n, models, report_csv, report_data, report_pdf
```

Replace the `report` command:

```python
@app.command()
def report(
    scan_id: int = typer.Argument(..., help="ID of a previously run scan"),
    format: str = typer.Option("table", "--format", help="Output format: table (default), csv, or pdf"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path (pdf format only)"),
) -> None:
    if format not in ("table", "csv", "pdf"):
        console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('invalid_report_format')}")
        raise typer.Exit(code=1)

    lang = i18n.current_lang()
    data = report_data.build_report_data(scan_id, lang)
    if data is None:
        console.print(f"[red]{i18n.t('scan_not_found', scan_id=scan_id)}[/red]")
        raise typer.Exit(code=1)

    if format == "table":
        _render_table(data, lang)
    elif format == "csv":
        sys.stdout.write(report_csv.render_csv(data, lang))
    else:
        path = output or f"report_{scan_id}.pdf"
        try:
            report_pdf.render_pdf(data, path, lang)
        except OSError as exc:
            console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('report_pdf_write_failed', error=str(exc))}")
            raise typer.Exit(code=1)
        console.print(i18n.t("report_pdf_saved", path=path))
```

Replace the entire `_print_report` function (from `def _print_report(scan_id: int) -> None:` to its closing `console.print(table)` under the "other" section) with:

```python
def _render_table(data, lang: str) -> None:
    console.print(f"\n[bold]Scan #{data.scan_id}[/bold] - {i18n.t('status_label', status=data.status)}")

    if data.technologies:
        table = Table(title=i18n.t("technologies_title"))
        for key in ("tech_col_category", "tech_col_name", "tech_col_version", "tech_col_confidence", "tech_col_host"):
            table.add_column(i18n.t(key))
        for tech in data.technologies:
            table.add_row(
                str(tech.get("category", "")),
                str(tech.get("name", "")),
                str(tech.get("version") or "-"),
                str(tech.get("confidence", "")),
                str(tech.get("host", "")),
            )
        console.print(table)

    if data.cves:
        table = Table(title=i18n.t("cves_title"))
        for key in (
            "cve_col_id", "cve_col_severity", "cve_col_cvss", "cve_col_technology",
            "cve_col_status", "cve_col_description", "cve_col_evidence",
        ):
            table.add_column(i18n.t(key))
        for row in data.cves:
            style = SEVERITY_STYLE.get(row.severity)
            severity_cell = f"[{style}]{row.severity}[/{style}]" if style else row.severity
            status_key = "status_confirmed" if row.status == "confirmed" else "status_suspected"

            if lang == "pt" and not row.description_translated:
                suffix = f" {i18n.t('translation_unavailable')}"
                budget = max(0, DESCRIPTION_MAX_LENGTH - len(suffix) - 3)
                description_cell = f"{_truncate(row.description, budget)}{suffix}"
            else:
                description_cell = row.description

            table.add_row(
                row.cve_id,
                severity_cell,
                str(row.cvss_score or "-"),
                row.technology,
                i18n.t(status_key),
                _truncate(description_cell),
                _truncate(row.evidence),
            )
        console.print(table)

    if data.other:
        table = Table(title=i18n.t("other_findings_title"))
        for key in ("other_col_type", "other_col_value", "other_col_module"):
            table.add_column(i18n.t(key))
        for item in data.other:
            table.add_row(item["type"], item["value"], item["module"])
        console.print(table)
```

Update `scan()`'s final line (currently `_print_report(scan_id)`) to:

```python
    lang = i18n.current_lang()
    data = report_data.build_report_data(scan_id, lang)
    _render_table(data, lang)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_cli.py -v`
Expected: PASS (all tests, including every pre-existing `table`-format test — `test_report_prints_technology_and_cve_sections`, `test_report_truncates_long_cve_descriptions`, `test_report_shows_confirmed_status_and_evidence_for_a_validated_cve`, `test_report_falls_back_to_suspected_status_for_legacy_findings_without_a_status_field`, `test_report_marks_a_missing_portuguese_translation_instead_of_showing_nothing`, `test_report_shows_the_missing_translation_marker_even_for_a_long_description` — all unmodified, all still green)

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: PASS (all tests — this is the last code task, so this is the full green suite for Fase F)

- [ ] **Step 6: Commit**

```bash
git add backend/app/cli.py backend/tests/test_cli.py
git commit -m "feat(cli): wire report --format csv|pdf and --output, refactor table rendering onto ReportData"
```

---

### Task 8: Documentation

**Files:**
- Modify: `README.md`
- Modify: `README.pt-BR.md`

- [ ] **Step 1: Document `recon report`'s new flags in `README.md`**

Find the section documenting the `recon report` command (search for `recon report <scan_id>` or the module reference table's surrounding prose) and add, immediately after the existing description of the terminal report:

```markdown
### Exporting a report

`recon report <scan_id>` defaults to the terminal table shown above.
Two additional formats are available:

- `recon report <scan_id> --format csv` — one row per CVE finding
  (`cve, severity, cvss, epss, status, technology, host, description,
  evidence, remediation`), written to stdout. Column names are fixed and
  in English regardless of `--lang`, matching `recon audit --format csv`'s
  convention — CSV is for machines/spreadsheets, not the CLI's display
  language.
- `recon report <scan_id> --format pdf [--output PATH]` — a
  self-contained PDF (executive summary, detected technologies, and
  CVEs prioritized by CVSS with EPSS as a tie-breaker), localized per
  `--lang`. Without `--output`/`-o`, the file is written as
  `report_<scan_id>.pdf` in the current directory. Generating a PDF
  needs no external tool install — `reportlab` is a pure-Python
  dependency already pinned in `requirements.txt`, unlike `nuclei`/
  `subfinder`/`httpx`.

Every CVE's EPSS score (probability of exploitation, from FIRST.org's
free public API) is fetched and stored once, at scan time, the same way
NVD/DeepL data already is — `report`/export commands never touch the
network. CVSS remains the primary priority signal; EPSS only
tie-breaks CVEs that already share the same CVSS score.

Remediation guidance comes from the confirming `nuclei` template's own
`remediation` text when a CVE's status is `confirmed`; otherwise a
generic "upgrade to a patched version" message names the affected
technology without guessing a specific fixed version number.
```

- [ ] **Step 2: Mirror the addition in `README.pt-BR.md`**

Find the equivalent section in `README.pt-BR.md` and add the Portuguese translation of the same content at the equivalent location, e.g.:

```markdown
### Exportando um relatorio

`recon report <scan_id>` usa por padrao a tabela do terminal mostrada
acima. Dois formatos adicionais estao disponiveis:

- `recon report <scan_id> --format csv` — uma linha por CVE encontrado
  (`cve, severity, cvss, epss, status, technology, host, description,
  evidence, remediation`), escrito no stdout. Os nomes das colunas sao
  fixos e em ingles independente do `--lang`, seguindo a mesma
  convencao de `recon audit --format csv` — CSV e pra maquina/planilha,
  nao pro idioma de exibicao da CLI.
- `recon report <scan_id> --format pdf [--output CAMINHO]` — um PDF
  autocontido (resumo executivo, tecnologias detectadas e CVEs
  priorizados por CVSS com EPSS como desempate), no idioma de
  `--lang`. Sem `--output`/`-o`, o arquivo e salvo como
  `report_<scan_id>.pdf` no diretorio atual. Gerar um PDF nao exige
  instalar nenhuma ferramenta externa -- `reportlab` e uma dependencia
  Python pura, ja fixada em `requirements.txt`, diferente de
  `nuclei`/`subfinder`/`httpx`.

O score EPSS de cada CVE (probabilidade de exploracao, vindo da API
publica gratuita do FIRST.org) e buscado e salvo uma unica vez, durante
o scan, do mesmo jeito que os dados de NVD/DeepL ja funcionam --
`report`/exportacao nunca tocam a rede. O CVSS continua sendo o sinal
principal de prioridade; o EPSS so desempata CVEs que ja compartilham o
mesmo CVSS.

A recomendacao de remediacao vem do proprio texto `remediation` do
template `nuclei` que confirmou o CVE, quando o status e `confirmed`;
caso contrario, uma mensagem generica de "atualize para uma versao
corrigida" nomeia a tecnologia afetada sem chutar um numero de versao
especifico.
```

- [ ] **Step 3: Commit**

```bash
git add README.md README.pt-BR.md
git commit -m "docs(readme): document report --format csv|pdf, EPSS, and remediation guidance"
```

---

## Manual validation (required before considering Fase F done)

Per the project's established testing bar (mocked unit tests are not
sufficient sign-off for a phase that touches real external data):

1. Run `recon report <scan_id> --format csv` against a real scan with at
   least one CVE finding (e.g. the Fase E validation scans already in
   `dev.db`) and confirm the CSV opens correctly in a spreadsheet
   application, with real CVSS/EPSS/remediation values.
2. Run `recon report <scan_id> --format pdf` against the same scan,
   open the generated PDF, and visually confirm the executive summary
   counts match the terminal report, the CVE table is legible and
   correctly prioritized (CVSS descending), and remediation text reads
   sensibly for both a `confirmed` and a `suspected` CVE.
3. Repeat step 2 with `--lang pt` and confirm the PDF is fully in
   Portuguese (titles, column headers, status labels).
4. Confirm `recon report <scan_id>` with no `--format` flag still shows
   exactly the same terminal table as before this phase (visual diff
   against a pre-Fase-F scan already validated in this project).
