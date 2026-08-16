# CLI-Only Pivot — Design

## Contexto e objetivo

Segundo pivô de arquitetura: a ferramenta deixa de ser um web app
(FastAPI + Celery + Redis + React) e passa a ser um processo CLI único,
síncrono. Motivo do usuário: "controle máximo" e "mais fácil de usar" —
sem servidor pra subir, sem múltiplos serviços pra coordenar.

## O que sai

- `frontend/` inteiro (React/Vite/Vitest)
- `backend/app/main.py` (app FastAPI), `app/routers/`, `app/schemas.py`
- `backend/app/celery_app.py`, `app/tasks.py`
- `backend/docker-compose.yml` (Postgres/Redis não são mais necessários —
  SQLite local é suficiente pra um processo CLI de usuário único)
- Dependências `fastapi`, `uvicorn[standard]`, `celery`, `redis` do
  `requirements.txt`

## O que fica sem mudança

- `app/db.py`, `app/models.py` — `Project`/`Scan`/`Finding` continuam
  sendo o histórico persistido em SQLite
- `app/modules/*` — todos os módulos de recon (interface `ReconModule`,
  registro `MODULE_REGISTRY`) inalterados
- `app/orchestrator.py` — `run_scan(scan_id)` ganha um parâmetro opcional
  `progress_callback` (default no-op) pra emitir progresso ao vivo; lógica
  de execução dos módulos inalterada
- `app/config.py`, `app/timeutil.py`

## Novo: `app/cli.py`

Framework: `typer` (ergonomia, `--help` automático) + `rich` (tabelas
coloridas no terminal). Comandos:

```
recon scan <target> --scope "..." --authorized --confirm-active [--name NOME]
```
- Cria `Project` (nome default = target, se `--name` omitido) +
  `Scan`.
- `--authorized` obrigatório (mesma trava que a API tinha via
  `ProjectCreate.must_be_authorized`).
- `--confirm-active` obrigatório sempre que `MODULE_REGISTRY` tiver algum
  módulo com `is_active=True` (mesma trava que a API tinha em
  `POST /scans`).
- Roda `run_scan(scan_id, progress_callback=...)` síncrono no mesmo
  processo, imprimindo "Rodando <módulo>..." conforme cada um executa.
- Ao final, imprime relatório formatado: tabela de Tecnologias, tabela de
  CVEs (ordenada por CVSS decrescente, severidade colorida), tabela de
  Outros achados — mesmo agrupamento que existia no `ScanReport.tsx`.

```
recon history
```
Lista `Project`/`Scan` já executados (id, alvo, status, data).

```
recon report <scan_id>
```
Reimprime o relatório formatado de um scan já existente, sem rodar de
novo.

## Testes

- `app/cli.py` testado via `typer.testing.CliRunner`, mockando
  `run_scan`/DB onde fizer sentido — mesmo padrão TDD do resto do
  projeto.
- `orchestrator.py`: teste novo garantindo que `progress_callback` é
  chamado com o nome de cada módulo, na ordem certa (`run_order`).

## Fora de escopo deste pivô

- Servir a mesma lógica via HTTP no futuro fica possível (o
  orquestrador/modelos não mudam), mas não é construído agora.
- Rate limiting e log de auditoria (backlog já registrado antes) não
  entram neste pivô — ficam para depois.
