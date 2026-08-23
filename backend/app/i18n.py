"""User-facing string translations for the CLI.

English is the default/primary language; Portuguese is a selectable
secondary option (`--lang pt`). Add a new key to both dicts in STRINGS to
add a new user-facing string; add a new top-level key to STRINGS to add a
new language.
"""

STRINGS = {
    "en": {
        "error_prefix": "Error:",
        "authorized_required": "--authorized is required to create a project.",
        "scope_empty": "--scope cannot be empty.",
        "active_modules_confirm_required": (
            "this scan includes active modules that probe the target directly. "
            "Use --confirm-active to proceed."
        ),
        "target_excluded_from_scope": (
            "the target itself falls outside the declared scope "
            "(--scope-include/--scope-exclude) - refusing to create a "
            "project with nothing left to test."
        ),
        "scope_window_invalid": (
            "--scope-window must be in the form HH:MM-HH:MM (e.g. 09:00-18:00)."
        ),
        "running_module": "Running",
        "scan_not_found": "Scan {scan_id} not found.",
        "status_label": "status: {status}",
        "history_title": "Scan history",
        "history_col_id": "ID",
        "history_col_project": "Project",
        "history_col_target": "Target",
        "history_col_status": "Status",
        "history_col_started_at": "Started at",
        "technologies_title": "Technologies",
        "tech_col_category": "Category",
        "tech_col_name": "Name",
        "tech_col_version": "Version",
        "tech_col_confidence": "Confidence",
        "tech_col_host": "Host",
        "cves_title": "CVEs",
        "cve_col_id": "CVE",
        "cve_col_severity": "Severity",
        "cve_col_cvss": "CVSS",
        "cve_col_technology": "Technology",
        "cve_col_description": "Description",
        "other_findings_title": "Other findings",
        "other_col_type": "Type",
        "other_col_value": "Value",
        "other_col_module": "Module",
        "audit_title": "Audit trail",
        "audit_col_module": "Module",
        "audit_col_target": "Target",
        "audit_col_url": "URL",
        "audit_col_outcome": "Outcome",
        "audit_col_requested_at": "Requested at",
        "invalid_audit_format": "--format must be 'table' or 'csv'.",
        "cve_col_status": "Status",
        "cve_col_evidence": "Evidence",
        "status_suspected": "Suspected",
        "status_confirmed": "Confirmed",
        "translation_unavailable": "(translation unavailable)",
        "cve_confirmed_note": "Confirmed via nuclei template {template_id}: matched at {matched_at}.",
        "cve_confirmed_note_msf": "Confirmed via Metasploit module {module}: check reported the target as vulnerable.",
        "cve_confirmed_note_nmap": "Confirmed via nmap script {script}: reported VULNERABLE.",
        "cve_confirmed_note_tls": "Confirmed via testssl.sh check {check}: reported VULNERABLE.",
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
        "fingerprint_update_failed": "could not update the fingerprint dataset: {error}",
        "fingerprint_update_saved": "Fingerprint dataset updated: {tech_count} technologies, {cat_count} categories.",
        "repl_welcome": (
            "webscan interactive shell. Type a command (e.g. 'history'), "
            "'help' for options, or 'exit' to quit."
        ),
    },
    "pt": {
        "error_prefix": "Erro:",
        "authorized_required": "--authorized e obrigatorio para criar um projeto.",
        "scope_empty": "--scope nao pode ser vazio.",
        "active_modules_confirm_required": (
            "este scan inclui modulos ativos que sondam o alvo diretamente. "
            "Use --confirm-active para prosseguir."
        ),
        "target_excluded_from_scope": (
            "o proprio alvo cai fora do escopo declarado "
            "(--scope-include/--scope-exclude) - recusando criar um "
            "projeto sem nada pra testar."
        ),
        "scope_window_invalid": (
            "--scope-window deve estar no formato HH:MM-HH:MM (ex: 09:00-18:00)."
        ),
        "running_module": "Rodando",
        "scan_not_found": "Scan {scan_id} nao encontrado.",
        "status_label": "status: {status}",
        "history_title": "Historico de scans",
        "history_col_id": "ID",
        "history_col_project": "Projeto",
        "history_col_target": "Alvo",
        "history_col_status": "Status",
        "history_col_started_at": "Iniciado em",
        "technologies_title": "Tecnologias",
        "tech_col_category": "Categoria",
        "tech_col_name": "Nome",
        "tech_col_version": "Versao",
        "tech_col_confidence": "Confianca",
        "tech_col_host": "Host",
        "cves_title": "CVEs",
        "cve_col_id": "CVE",
        "cve_col_severity": "Severidade",
        "cve_col_cvss": "CVSS",
        "cve_col_technology": "Tecnologia",
        "cve_col_description": "Descricao",
        "other_findings_title": "Outros achados",
        "other_col_type": "Tipo",
        "other_col_value": "Valor",
        "other_col_module": "Modulo",
        "audit_title": "Trilha de auditoria",
        "audit_col_module": "Modulo",
        "audit_col_target": "Alvo",
        "audit_col_url": "URL",
        "audit_col_outcome": "Resultado",
        "audit_col_requested_at": "Requisitado em",
        "invalid_audit_format": "--format deve ser 'table' ou 'csv'.",
        "cve_col_status": "Status",
        "cve_col_evidence": "Evidencia",
        "status_suspected": "Suspeita",
        "status_confirmed": "Confirmada",
        "translation_unavailable": "(traducao indisponivel)",
        "cve_confirmed_note": "Confirmado via template nuclei {template_id}: correspondencia em {matched_at}.",
        "cve_confirmed_note_msf": "Confirmado via modulo Metasploit {module}: o check reportou o alvo como vulneravel.",
        "cve_confirmed_note_nmap": "Confirmado via script nmap {script}: reportado como VULNERABLE.",
        "cve_confirmed_note_tls": "Confirmado via checagem testssl.sh {check}: reportado como VULNERABLE.",
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
        "fingerprint_update_failed": "nao foi possivel atualizar o dataset de fingerprint: {error}",
        "fingerprint_update_saved": "Dataset de fingerprint atualizado: {tech_count} tecnologias, {cat_count} categorias.",
        "repl_welcome": (
            "Shell interativo do webscan. Digite um comando (ex: 'history'), "
            "'help' para ver as opcoes, ou 'exit' para sair."
        ),
    },
}

DEFAULT_LANG = "en"

_current_lang = DEFAULT_LANG


def set_lang(lang: str) -> None:
    """Set the active language for subsequent t() calls. Any string is
    accepted here; unknown languages simply fall back to English at
    lookup time in t()."""
    global _current_lang
    _current_lang = lang


def current_lang() -> str:
    return _current_lang


def t(key: str, lang: str | None = None, **kwargs) -> str:
    """Look up `key` in `lang` if given, else the active language,
    falling back to English if that language or the key isn't translated."""
    strings = STRINGS.get(lang or _current_lang, STRINGS[DEFAULT_LANG])
    template = strings.get(key, STRINGS[DEFAULT_LANG].get(key, key))
    return template.format(**kwargs) if kwargs else template
