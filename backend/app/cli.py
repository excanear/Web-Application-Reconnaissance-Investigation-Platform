import typer
from rich.console import Console
from rich.table import Table

from app import models
from app.db import Base, SessionLocal, engine
from app.modules.base import MODULE_REGISTRY
from app.orchestrator import run_scan
from app.timeutil import utc_now

app = typer.Typer(help="Recon & Investigation CLI")
console = Console()

Base.metadata.create_all(bind=engine)

SEVERITY_STYLE = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


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
) -> None:
    if not authorized:
        console.print("[red]Erro:[/red] --authorized e obrigatorio para criar um projeto.")
        raise typer.Exit(code=1)

    if not scope.strip():
        console.print("[red]Erro:[/red] --scope nao pode ser vazio.")
        raise typer.Exit(code=1)

    has_active_modules = any(cls.is_active for cls in MODULE_REGISTRY.values())
    if has_active_modules and not confirm_active:
        console.print(
            "[red]Erro:[/red] este scan inclui modulos ativos que sondam o alvo diretamente. "
            "Use --confirm-active para prosseguir."
        )
        raise typer.Exit(code=1)

    db = SessionLocal()
    try:
        project = models.Project(
            name=name or target,
            target=target,
            scope_notes=scope,
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
        console.print(f"[cyan]Rodando[/cyan] {module_name}...")

    run_scan(scan_id, progress_callback=on_progress)

    _print_report(scan_id)


@app.command()
def history() -> None:
    db = SessionLocal()
    try:
        scans = db.query(models.Scan).order_by(models.Scan.id.desc()).all()
        table = Table(title="Historico de scans")
        table.add_column("ID")
        table.add_column("Projeto")
        table.add_column("Alvo")
        table.add_column("Status")
        table.add_column("Iniciado em")
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


def _print_report(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan_row = db.get(models.Scan, scan_id)
        if scan_row is None:
            console.print(f"[red]Scan {scan_id} nao encontrado.[/red]")
            raise typer.Exit(code=1)
        findings = list(scan_row.findings)
        status = scan_row.status
    finally:
        db.close()

    console.print(f"\n[bold]Scan #{scan_id}[/bold] - status: {status}")

    technologies = [f for f in findings if f.type == "technology"]
    cves = sorted(
        [f for f in findings if f.type == "cve"],
        key=lambda f: -(f.data.get("cvss_score") or 0),
    )
    other = [f for f in findings if f.type not in ("technology", "cve")]

    if technologies:
        table = Table(title="Tecnologias")
        for column in ("Categoria", "Nome", "Versao", "Confianca", "Host"):
            table.add_column(column)
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
        table = Table(title="CVEs")
        for column in ("CVE", "Severidade", "CVSS", "Tecnologia", "Descricao"):
            table.add_column(column)
        for f in cves:
            severity = str(f.data.get("severity") or "")
            style = SEVERITY_STYLE.get(severity)
            severity_cell = f"[{style}]{severity}[/{style}]" if style else severity
            table.add_row(
                f.value,
                severity_cell,
                str(f.data.get("cvss_score") or "-"),
                f"{f.data.get('matched_technology', '')} {f.data.get('matched_technology_version', '')}".strip(),
                str(f.data.get("description", "")),
            )
        console.print(table)

    if other:
        table = Table(title="Outros achados")
        for column in ("Tipo", "Valor", "Modulo"):
            table.add_column(column)
        for f in other:
            table.add_row(f.type, f.value, f.module)
        console.print(table)


if __name__ == "__main__":
    app()
