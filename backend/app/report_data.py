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
