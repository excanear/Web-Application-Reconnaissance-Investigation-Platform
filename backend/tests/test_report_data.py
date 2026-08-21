# backend/tests/test_report_data.py
from app.db import Base, SessionLocal, engine
from app import models
from app.report_data import CveRow, build_report_data, describe_with_marker


def _make_scan(cve_data_list, technologies=None, other=None):
    Base.metadata.create_all(bind=engine)
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
    Base.metadata.create_all(bind=engine)
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
