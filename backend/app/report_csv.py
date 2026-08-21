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
