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
