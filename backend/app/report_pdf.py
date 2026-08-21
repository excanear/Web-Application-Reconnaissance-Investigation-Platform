# backend/app/report_pdf.py
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
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

    doc = SimpleDocTemplate(path, pagesize=landscape(A4))
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
                    Paragraph(escape(row.cve_id), cell_style),
                    Paragraph(escape(row.severity), cell_style),
                    f"{row.cvss_score:.1f}" if row.cvss_score is not None else "-",
                    f"{row.epss_score:.3f}" if row.epss_score is not None else "-",
                    Paragraph(escape(status_label), cell_style),
                    Paragraph(escape(row.technology), cell_style),
                    Paragraph(escape(describe_with_marker(row, lang)), cell_style),
                    Paragraph(escape(row.evidence), cell_style),
                    Paragraph(escape(row.remediation), cell_style),
                ]
            )
        cve_table = Table(
            cve_rows, repeatRows=1,
            colWidths=[2.2 * cm, 1.6 * cm, 1.3 * cm, 1.3 * cm, 1.8 * cm, 2.8 * cm, 4 * cm, 4 * cm, 5 * cm],
            splitInRow=1,
        )
        cve_table.setStyle(_HEADER_STYLE)
        elements.append(cve_table)

    doc.build(elements)
