import csv
import ipaddress
import re
import shlex
import sys
from collections.abc import Iterable, Iterator

import requests
import typer
from rich.console import Console
from rich.table import Table
from typer.main import get_command

from app import fingerprint_update, i18n, models, report_csv, report_data, report_pdf
from app.db import SessionLocal, ensure_schema
from app.modules.base import MODULE_REGISTRY
from app.orchestrator import run_scan
from app.scope import is_in_scope
from app.timeutil import utc_now
from app.tool_check import preflight_report

# NVD descriptions can contain characters legacy Windows consoles (cp1252)
# can't encode; replace instead of crashing the whole report.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

app = typer.Typer(
    help=(
        "webscan - plataforma de reconhecimento e investigacao de aplicacoes web.\n\n"
        "Descobre subdominios, identifica tecnologias em uso e correlaciona/valida "
        "CVEs conhecidas contra um alvo autorizado, com escopo controlado, "
        "rate limiting, circuit breaker e trilha de auditoria completa.\n\n"
        "Fluxo tipico de uso:\n\n"
        "  1. webscan doctor                              (confere as ferramentas externas instaladas)\n"
        "  2. webscan scan <alvo> --authorized --scope \"...\"   (executa o scan)\n"
        "  3. webscan history                             (lista os scans ja executados)\n"
        "  4. webscan report <id>                         (ve o relatorio de um scan)\n"
        "  5. webscan audit <id>                           (ve a trilha de auditoria de um scan)\n\n"
        "Rode `webscan` sem nenhum comando para entrar no shell interativo, ou "
        "`webscan <comando> --help` para ver os detalhes e exemplos de cada comando."
    ),
)
# When stdout isn't a real terminal (piped, redirected, or captured by
# tests), Rich falls back to an 80-column default that's too narrow for
# the CVE table's seven columns and ellipsis-truncates cell content
# (including IDs and status text) instead of wrapping it. Pin a wider
# width for that non-tty case only; a real terminal keeps Rich's normal
# auto-detection and sizing/word-wrap to the user's actual width.
console = Console(width=160) if not sys.stdout.isatty() else Console()

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
        i18n.DEFAULT_LANG, "--lang", help="Idioma da saida: en (padrao em ingles) ou pt (portugues)"
    ),
) -> None:
    i18n.set_lang(lang)


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="Dominio ou IP alvo do scan (ex: exemplo.com.br)"
    ),
    scope: str = typer.Option(
        ...,
        "--scope",
        help="Texto livre descrevendo a autorizacao/escopo (ex: 'pentest autorizado pelo dono do dominio'). Fica gravado no projeto para auditoria.",
    ),
    authorized: bool = typer.Option(
        False,
        "--authorized",
        help="Obrigatorio: confirma que voce tem autorizacao para testar este alvo. Sem essa flag o scan e recusado.",
    ),
    confirm_active: bool = typer.Option(
        False,
        "--confirm-active",
        help="Obrigatorio quando ha modulos ativos registrados (ex: nuclei_validation, msf_validation, nmap_validation, tls_validation): confirma que voce autoriza trafego ativo/intrusivo contra o alvo, alem da coleta passiva.",
    ),
    name: str = typer.Option(
        None, "--name", help="Nome do projeto no banco de dados (padrao: o proprio alvo)"
    ),
    max_requests_per_second: float = typer.Option(
        5.0,
        "--max-requests-per-second",
        help="Limite de requisicoes por segundo contra o alvo e seus subdominios (padrao: 5.0)",
    ),
    circuit_breaker_threshold: int = typer.Option(
        5,
        "--circuit-breaker-threshold",
        help="Numero de falhas consecutivas contra um host antes de um modulo parar de sondar aquele host (protege contra ficar martelando um host fora do ar)",
    ),
    max_workers: int = typer.Option(
        1,
        "--max-workers",
        min=1,
        help="Quantos hosts processar em paralelo dentro de tech_fingerprint/cloud_range (padrao: 1, totalmente sequencial). Aumente para acelerar scans com muitos subdominios.",
    ),
    max_subdomains: int = typer.Option(
        1000,
        "--max-subdomains",
        min=1,
        help="Teto de candidatos a subdominio aceitos somando todos os modulos de descoberta (crt.sh + subfinder + permutacao). Protege o resto do scan quando uma fonte passiva devolve ruido demais (padrao: 1000).",
    ),
    scope_include: list[str] = typer.Option(
        None,
        "--scope-include",
        help="Padrao de dominio ou CIDR explicitamente dentro do escopo (pode repetir a flag varias vezes). Sem isso, o padrao e '<alvo>' e '*.<alvo>'.",
    ),
    scope_exclude: list[str] = typer.Option(
        None,
        "--scope-exclude",
        help="Padrao de dominio ou CIDR explicitamente fora do escopo, mesmo que bata com --scope-include (pode repetir a flag varias vezes)",
    ),
    scope_window: str = typer.Option(
        None,
        "--scope-window",
        help="Janela de horario (UTC) em que o scan pode rodar, formato HH:MM-HH:MM (ex: 09:00-18:00). Fora da janela, os modulos sao pulados.",
    ),
) -> None:
    """Executa um scan de reconhecimento completo contra um alvo autorizado.

    Descobre subdominios (crt.sh, subfinder, permutacao de wordlist),
    identifica hosts vivos e tecnologias em uso (HTTP + fingerprint via
    navegador), correlaciona CVEs conhecidas para as tecnologias
    encontradas e tenta confirma-las ativamente com os validadores
    instalados (nuclei, Metasploit, nmap, testssl.sh). Ao final, imprime
    o relatorio na tela (mesmo formato do comando `report`).

    Exemplos:

      webscan scan exemplo.com.br --authorized --scope "pentest autorizado pelo dono do dominio"

      webscan scan exemplo.com.br --authorized --confirm-active --scope "autorizado" \\
          --scope-include "exemplo.com.br" --scope-include "*.exemplo.com.br" \\
          --scope-exclude "admin.exemplo.com.br" --max-requests-per-second 2

    Use `webscan doctor` antes, para confirmar que as ferramentas
    externas necessarias estao instaladas -- uma ferramenta ausente ou
    nao reconhecida corretamente reduz silenciosamente os resultados
    (menos hosts vivos -> menos tecnologias -> menos CVEs correlacionadas)."""
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
        max_workers=max_workers,
        max_subdomains=max_subdomains,
    )

    lang = i18n.current_lang()
    data = report_data.build_report_data(scan_id, lang)
    _render_table(data, lang)


@app.command()
def history() -> None:
    """Lista todos os scans ja executados (mais recente primeiro), com
    ID, projeto, alvo, status e horario de inicio. Use o ID mostrado
    aqui com `webscan report <id>` ou `webscan audit <id>`.

    Exemplo:  webscan history"""
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


@app.command(name="update-fingerprints")
def update_fingerprints() -> None:
    """Baixa a versao mais recente do dataset de fingerprint (assinaturas
    de tecnologias, ~7.500+ tecnologias, baseado no Wappalyzer) e
    substitui o dataset local usado por tech_fingerprint/browser_fingerprint.

    Rode isso periodicamente para detectar tecnologias novas ou versoes
    mais recentes de assinaturas ja conhecidas. Nao afeta scans ja
    executados, so os proximos.

    Exemplo:  webscan update-fingerprints"""
    try:
        tech_count, cat_count = fingerprint_update.update_vendored_data()
    except requests.RequestException as exc:
        console.print(
            f"[red]{i18n.t('error_prefix')}[/red] {i18n.t('fingerprint_update_failed', error=str(exc))}"
        )
        raise typer.Exit(code=1)
    console.print(i18n.t("fingerprint_update_saved", tech_count=tech_count, cat_count=cat_count))


@app.command()
def doctor() -> None:
    """Verifica se cada ferramenta externa que um scan pode usar
    (subfinder, httpx, nuclei, msfconsole, nmap, testssl.sh) esta
    instalada e corretamente identificada nesta maquina, e imprime uma
    tabela de status (OK / PROBLEMA + detalhe).

    Rode isso antes de um scan, e sempre que os resultados parecerem
    menores do que deveriam -- uma ferramenta ausente ou com o nome
    colidindo com outro programa (ex: "httpx" apontando para o pacote
    Python de mesmo nome, e nao para o httpx do ProjectDiscovery) faz o
    modulo correspondente falhar silenciosamente (module_error), e tudo
    que depende dele encolhe junto (menos hosts vivos -> menos
    tecnologias -> menos CVEs correlacionadas), sem nenhum erro obvio
    no relatorio final.

    Sai com codigo 1 se alguma ferramenta estiver com problema (util em
    scripts de instalacao/CI).

    Exemplo:  webscan doctor"""
    table = Table(title=i18n.t("doctor_title"))
    table.add_column(i18n.t("doctor_col_tool"))
    table.add_column(i18n.t("doctor_col_status"))
    table.add_column(i18n.t("doctor_col_detail"))

    all_ok = True
    for tool in preflight_report():
        if tool["ok"]:
            status = f"[green]{i18n.t('doctor_status_ok')}[/green]"
            detail = tool.get("path", "")
        else:
            all_ok = False
            status = f"[red]{i18n.t('doctor_status_problem')}[/red]"
            detail = tool.get("detail", "")
        table.add_row(tool["name"], status, detail)

    console.print(table)
    if not all_ok:
        raise typer.Exit(code=1)


@app.command()
def report(
    scan_id: int = typer.Argument(..., help="ID de um scan ja executado (veja 'webscan history')"),
    format: str = typer.Option(
        "table",
        "--format",
        help="Formato de saida: table (tabela na tela, padrao), csv, ou pdf",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Caminho do arquivo de saida (so vale para --format pdf; padrao: report_<id>.pdf)",
    ),
) -> None:
    """Mostra o relatorio de um scan ja executado: tecnologias
    detectadas, CVEs correlacionadas (com status confirmado/suspeito e
    evidencia de qual validador confirmou) e outros achados.

    Exemplos:

      webscan report 20

      webscan report 20 --format csv > relatorio.csv

      webscan report 20 --format pdf --output relatorio.pdf

      webscan --lang pt report 20   (forca a saida em portugues)"""
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


@app.command()
def audit(
    scan_id: int = typer.Argument(..., help="ID de um scan ja executado (veja 'webscan history')"),
    format: str = typer.Option(
        "table", "--format", help="Formato de saida: table (tabela na tela, padrao) ou csv"
    ),
) -> None:
    """Mostra a trilha de auditoria completa de um scan: toda requisicao
    que cada modulo tentou (ou nao tentou, se a ferramenta faltava) --
    modulo, alvo, URL, resultado e horario.

    Use para investigar por que um scan trouxe menos resultados do que
    o esperado: procure por entradas 'not_attempted:' (ferramenta nao
    encontrada) ou 'error:' (a ferramenta rodou mas falhou), que nao
    aparecem no relatorio normal (`webscan report`).

    Exemplos:

      webscan audit 20

      webscan audit 20 --format csv > auditoria.csv"""
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


def _prompt_lines() -> Iterator[str]:
    """Yield lines typed at an interactive `webscan> ` prompt until EOF
    (Ctrl+D/Ctrl+Z). A Ctrl+C on an empty prompt cancels that line and
    reprompts instead of killing the whole shell."""
    while True:
        try:
            yield input("webscan> ")
        except EOFError:
            print()
            return
        except KeyboardInterrupt:
            print()
            continue


def _run_repl_loop(lines: Iterable[str]) -> None:
    cli = get_command(app)
    console.print(i18n.t("repl_welcome"))
    console.print(i18n.t("repl_commands_hint"))
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line in ("exit", "quit"):
            break
        if line in ("help", "?"):
            line = "--help"

        try:
            args = shlex.split(line)
        except ValueError as exc:
            console.print(f"[red]{i18n.t('error_prefix')}[/red] {exc}")
            continue

        # standalone_mode=False stops Click from calling sys.exit()/os._exit()
        # on every command, which would otherwise tear down this loop after
        # the first command (successful or not).
        try:
            cli.main(args=args, prog_name="webscan", standalone_mode=False)
        except typer.Exit:
            pass
        except KeyboardInterrupt:
            print()
        except Exception as exc:
            # Click's UsageError/ClickException (unknown command, bad
            # option, etc.) know how to format themselves via .show();
            # typer vendors its own Click fork so we can't import its
            # exception classes directly, only detect the interface.
            if hasattr(exc, "show") and callable(exc.show):
                exc.show()
            else:
                console.print(f"[red]{i18n.t('error_prefix')}[/red] {exc}")


def run_repl() -> None:
    _run_repl_loop(_prompt_lines())


def main() -> None:
    if len(sys.argv) == 1:
        run_repl()
    else:
        app()


if __name__ == "__main__":
    main()
