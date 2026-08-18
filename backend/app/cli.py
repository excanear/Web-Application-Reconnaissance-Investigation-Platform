import csv
import ipaddress
import re
import sys

import typer
from rich.console import Console
from rich.table import Table

from app import i18n, models
from app.db import SessionLocal, ensure_schema
from app.modules.base import MODULE_REGISTRY
from app.orchestrator import run_scan
from app.scope import is_in_scope
from app.timeutil import utc_now

# NVD descriptions can contain characters legacy Windows consoles (cp1252)
# can't encode; replace instead of crashing the whole report.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

app = typer.Typer(help="Recon & Investigation CLI")
console = Console()

ensure_schema()

DESCRIPTION_MAX_LENGTH = 200
SCOPE_WINDOW_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$")


def _truncate(text: str, max_length: int = DESCRIPTION_MAX_LENGTH) -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length].rstrip() + "..."

SEVERITY_STYLE = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


@app.callback()
def main(
    lang: str = typer.Option(
        i18n.DEFAULT_LANG, "--lang", help="Output language: en (default) or pt"
    ),
) -> None:
    i18n.set_lang(lang)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain/target to scan"),
    scope: str = typer.Option(..., "--scope", help="Description of the authorized scope"),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirm you are authorized to test this target"
    ),
    confirm_active: bool = typer.Option(
        False, "--confirm-active", help="Confirm active/intrusive modules may run"
    ),
    name: str = typer.Option(None, "--name", help="Project name (defaults to target)"),
    max_requests_per_second: float = typer.Option(
        5.0, "--max-requests-per-second", help="Cap request pace against the target/subdomains"
    ),
    circuit_breaker_threshold: int = typer.Option(
        5,
        "--circuit-breaker-threshold",
        help="Consecutive failures against a target before a module stops probing it",
    ),
    scope_include: list[str] = typer.Option(
        None, "--scope-include", help="Domain pattern or CIDR explicitly in scope (repeatable)"
    ),
    scope_exclude: list[str] = typer.Option(
        None, "--scope-exclude", help="Domain pattern or CIDR explicitly excluded (repeatable)"
    ),
    scope_window: str = typer.Option(
        None, "--scope-window", help="Allowed UTC time window, e.g. 09:00-18:00"
    ),
) -> None:
    if not authorized:
        console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('authorized_required')}")
        raise typer.Exit(code=1)

    if not scope.strip():
        console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('scope_empty')}")
        raise typer.Exit(code=1)

    has_active_modules = any(cls.is_active for cls in MODULE_REGISTRY.values())
    if has_active_modules and not confirm_active:
        console.print(
            f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('active_modules_confirm_required')}"
        )
        raise typer.Exit(code=1)

    include = list(scope_include) if scope_include else [target, f"*.{target}"]
    exclude = list(scope_exclude) if scope_exclude else []

    allowed_window = None
    if scope_window:
        match = SCOPE_WINDOW_RE.match(scope_window.strip())
        if not match:
            console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('scope_window_invalid')}")
            raise typer.Exit(code=1)
        start_str, end_str = scope_window.strip().split("-", 1)
        allowed_window = {"start": start_str.strip(), "end": end_str.strip()}

    scope_dict = {"include": include, "exclude": exclude}
    if allowed_window is not None:
        scope_dict["allowed_window"] = allowed_window

    try:
        target_ip = str(ipaddress.ip_address(target))
    except ValueError:
        target_ip = None

    if not is_in_scope(target, target_ip, scope_dict):
        console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('target_excluded_from_scope')}")
        raise typer.Exit(code=1)

    db = SessionLocal()
    try:
        project = models.Project(
            name=name or target,
            target=target,
            scope_notes=scope,
            scope=scope_dict,
            authorized=True,
            authorized_at=utc_now(),
        )
        db.add(project)
        db.commit()

        scan_row = models.Scan(project_id=project.id, status="pending")
        db.add(scan_row)
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    def on_progress(module_name: str) -> None:
        console.print(f"[cyan]{i18n.t('running_module')}[/cyan] {module_name}...")

    run_scan(
        scan_id,
        progress_callback=on_progress,
        rate_limit=max_requests_per_second,
        circuit_breaker_threshold=circuit_breaker_threshold,
    )

    _print_report(scan_id)


@app.command()
def history() -> None:
    db = SessionLocal()
    try:
        scans = db.query(models.Scan).order_by(models.Scan.id.desc()).all()
        table = Table(title=i18n.t("history_title"))
        table.add_column(i18n.t("history_col_id"))
        table.add_column(i18n.t("history_col_project"))
        table.add_column(i18n.t("history_col_target"))
        table.add_column(i18n.t("history_col_status"))
        table.add_column(i18n.t("history_col_started_at"))
        for scan_row in scans:
            table.add_row(
                str(scan_row.id),
                scan_row.project.name,
                scan_row.project.target,
                scan_row.status,
                str(scan_row.started_at or ""),
            )
        console.print(table)
    finally:
        db.close()


@app.command()
def report(scan_id: int = typer.Argument(..., help="ID of a previously run scan")) -> None:
    _print_report(scan_id)


@app.command()
def audit(
    scan_id: int = typer.Argument(..., help="ID of a previously run scan"),
    format: str = typer.Option("table", "--format", help="Output format: table (default) or csv"),
) -> None:
    if format not in ("table", "csv"):
        console.print(f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('invalid_audit_format')}")
        raise typer.Exit(code=1)

    db = SessionLocal()
    try:
        scan_row = db.get(models.Scan, scan_id)
        if scan_row is None:
            console.print(f"[red]{i18n.t('scan_not_found', scan_id=scan_id)}[/red]")
            raise typer.Exit(code=1)
        entries = list(scan_row.audit_entries)
    finally:
        db.close()

    if format == "csv":
        writer = csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(["module", "target", "url", "outcome", "requested_at"])
        for entry in entries:
            writer.writerow(
                [entry.module, entry.target, entry.url or "", entry.outcome, entry.requested_at]
            )
        return

    table = Table(title=i18n.t("audit_title"))
    for key in (
        "audit_col_module",
        "audit_col_target",
        "audit_col_url",
        "audit_col_outcome",
        "audit_col_requested_at",
    ):
        table.add_column(i18n.t(key))
    for entry in entries:
        table.add_row(
            entry.module, entry.target, entry.url or "-", entry.outcome, str(entry.requested_at)
        )
    console.print(table)


def _print_report(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan_row = db.get(models.Scan, scan_id)
        if scan_row is None:
            console.print(f"[red]{i18n.t('scan_not_found', scan_id=scan_id)}[/red]")
            raise typer.Exit(code=1)
        findings = list(scan_row.findings)
        status = scan_row.status
    finally:
        db.close()

    console.print(f"\n[bold]Scan #{scan_id}[/bold] - {i18n.t('status_label', status=status)}")

    technologies = [f for f in findings if f.type == "technology"]
    cves = sorted(
        [f for f in findings if f.type == "cve"],
        key=lambda f: -(f.data.get("cvss_score") or 0),
    )
    other = [f for f in findings if f.type not in ("technology", "cve")]

    if technologies:
        table = Table(title=i18n.t("technologies_title"))
        for key in ("tech_col_category", "tech_col_name", "tech_col_version", "tech_col_confidence", "tech_col_host"):
            table.add_column(i18n.t(key))
        for f in technologies:
            table.add_row(
                str(f.data.get("category", "")),
                str(f.data.get("name", "")),
                str(f.data.get("version") or "-"),
                str(f.data.get("confidence", "")),
                f.value,
            )
        console.print(table)

    if cves:
        table = Table(title=i18n.t("cves_title"))
        for key in ("cve_col_id", "cve_col_severity", "cve_col_cvss", "cve_col_technology", "cve_col_description"):
            table.add_column(i18n.t(key))
        for f in cves:
            severity = str(f.data.get("severity") or "")
            style = SEVERITY_STYLE.get(severity)
            severity_cell = f"[{style}]{severity}[/{style}]" if style else severity
            table.add_row(
                f.value,
                severity_cell,
                str(f.data.get("cvss_score") or "-"),
                f"{f.data.get('matched_technology', '')} {f.data.get('matched_technology_version', '')}".strip(),
                _truncate(str(f.data.get("description", ""))),
            )
        console.print(table)

    if other:
        table = Table(title=i18n.t("other_findings_title"))
        for key in ("other_col_type", "other_col_value", "other_col_module"):
            table.add_column(i18n.t(key))
        for f in other:
            table.add_row(f.type, f.value, f.module)
        console.print(table)


if __name__ == "__main__":
    app()
