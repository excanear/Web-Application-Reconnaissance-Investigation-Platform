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


def test_renders_a_pdf_when_cve_text_contains_html_like_markup(tmp_path):
    path = str(tmp_path / "report.pdf")
    data = ReportData(
        scan_id=42, status="complete",
        cves=[
            _row(
                description="Reflected XSS via <script>alert(1)</script>",
                evidence="Payload: <img src=x onerror=alert(1)>",
                remediation="Sanitize input.<br>Escape output.",
            )
        ],
        summary={"total_cves": 1, "confirmed_count": 1, "suspected_count": 0, "counts_by_severity": {"CRITICAL": 1}},
    )

    # Must not raise ValueError: paraparser: syntax error (reportlab treats
    # Paragraph content as mini-HTML; unescaped markup in CVE text used to crash).
    render_pdf(data, path, lang="en")

    assert os.path.exists(path)
    text = _extract_text(path)
    # The CVE ID column now wraps (finding #3), so it may be broken across
    # lines by Paragraph -- just confirm the markup-laden text made it in
    # (escaped, not interpreted) and rendering succeeded.
    assert "Reflected XSS" in text
    assert "onerror" in text


def test_renders_a_pdf_with_a_very_long_description_without_layout_error(tmp_path):
    path = str(tmp_path / "report.pdf")
    long_description = "A" * 2000
    data = ReportData(
        scan_id=42, status="complete",
        cves=[_row(description=long_description)],
        summary={"total_cves": 1, "confirmed_count": 1, "suspected_count": 0, "counts_by_severity": {"CRITICAL": 1}},
    )

    # Must not raise reportlab.platypus.doctemplate.LayoutError when a wrapped
    # cell's content is too tall to fit on a single page.
    render_pdf(data, path, lang="en")

    assert os.path.exists(path)


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
    # The Executive Summary always shows a "Total CVEs" line item (even when
    # zero), which contains "CVEs" as a substring -- so we check for the CVE
    # *section heading* specifically (it renders on its own line), not the
    # bare substring "CVEs".
    assert "\nCVEs\n" not in text
