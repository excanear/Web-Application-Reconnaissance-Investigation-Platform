<div align="center">

# Web Application Reconnaissance &amp; Investigation Platform

**Aponte um domínio. Receba tecnologia exata, versão exata e CVE real.**

Uma CLI de reconhecimento ofensivo que mapeia a superfície de ataque de um
alvo autorizado — descoberta de subdomínio, fingerprint ativo de
tecnologia, e correlação de vulnerabilidades contra o NVD real — tudo num
único processo síncrono, sem servidor, sem fila, sem infraestrutura pra
manter no ar.

[![Python](https://img.shields.io/badge/python-3.13%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![CLI](https://img.shields.io/badge/interface-CLI-000000?style=flat-square)](#como-usar)
[![Autorização obrigatória](https://img.shields.io/badge/uso-somente%20autorizado-red?style=flat-square)](#autorização-e-uso-responsável)
[![Testes](https://img.shields.io/badge/testes-52%20passing-brightgreen?style=flat-square)](#testes)

</div>

---

## Sumário

- [O que ela faz](#o-que-ela-faz)
- [Tutorial: do zero ao primeiro scan](#tutorial-do-zero-ao-primeiro-scan)
- [Problemas comuns](#problemas-comuns)
- [Referência de comandos](#referência-de-comandos)
- [Autorização e uso responsável](#autorização-e-uso-responsável)
- [Como funciona por dentro](#como-funciona-por-dentro)
- [Catálogo de módulos](#catálogo-de-módulos)
- [Fingerprint de tecnologia](#fingerprint-de-tecnologia)
- [Correlação de CVE](#correlação-de-cve)
- [Configuração](#configuração)
- [Dados e persistência](#dados-e-persistência)
- [Testes](#testes)
- [Limitações conhecidas](#limitações-conhecidas)
- [Roteiro](#roteiro)

---

## O que ela faz

Você entrega um domínio. A ferramenta:

1. **Descobre** subdomínios (certificate transparency, enumeração passiva,
   permutação de wordlist).
2. **Sonda ativamente** o alvo e cada subdomínio contra um motor de
   fingerprint com dezenas de regras — servidor web, CDN/WAF, linguagem e
   framework de backend, CMS, framework de frontend — extraindo a
   **versão exata** sempre que ela vaza em headers, cookies, tags
   `generator`, ou arquivos de changelog/manifest expostos.
3. **Correlaciona** cada tecnologia com versão conhecida contra a API real
   do NVD, filtrando por range de CPE — não é busca de texto solta, é
   verificação estrutural de que aquela versão específica realmente cai
   dentro do intervalo vulnerável daquele CVE.
4. **Imprime um relatório** no terminal, agrupado por Tecnologias, CVEs
   (ordenados por CVSS decrescente, severidade colorida) e demais achados
   — e guarda tudo num SQLite local pra você revisitar depois.

Sem frontend, sem API HTTP, sem Celery, sem Redis, sem Docker. Um comando,
um processo, um relatório.

---

## Tutorial: do zero ao primeiro scan

Este tutorial assume que você **nunca rodou a ferramenta antes**. Siga na
ordem — cada passo tem um jeito de conferir que deu certo antes de ir pro
próximo. Se algo não bater com o que está descrito, pule direto pra
[Problemas comuns](#problemas-comuns).

Escolha sua aba: [Windows (PowerShell)](#passo-0-abrir-o-terminal-certo)
é a mais detalhada porque é onde a maioria dos travamentos acontece;
macOS/Linux vem em seguida em cada passo.

### Passo 0 — Abrir o terminal certo

**Windows:** abra o **PowerShell** (não o "Prompt de Comando"/`cmd`). Menu
Iniciar → digite `PowerShell` → Enter.

**macOS/Linux:** abra o Terminal normalmente.

### Passo 1 — Confirmar que o Python está instalado (versão 3.13 ou mais nova)

```powershell
python --version
```

Resultado esperado: algo como `Python 3.13.12`. Se aparecer
**`'python' não é reconhecido como um comando interno ou externo`**,
tente:

```powershell
py --version
```

Se nenhum dos dois funcionar, você não tem Python instalado — baixe em
[python.org/downloads](https://www.python.org/downloads/) (marque a
caixinha **"Add Python to PATH"** durante a instalação — esse é o passo
que mais gente esquece) e repita este passo.

> A partir daqui, este tutorial usa `python`. Se na sua máquina só o `py`
> funcionou, troque `python` por `py` em todos os comandos abaixo.

### Passo 2 — Baixar o código

```powershell
git clone https://github.com/excanear/Web-Application-Reconnaissance-Investigation-Platform.git
```

Se você não tem `git` instalado, baixe o ZIP direto pelo botão verde
**"Code" → "Download ZIP"** na página do repositório no GitHub, e
extraia a pasta.

### Passo 3 — Entrar na pasta certa

Isto é o passo onde **quase todo mundo trava**: os comandos da ferramenta
só funcionam de dentro da pasta `backend/`, não da raiz do projeto.

```powershell
cd Web-Application-Reconnaissance-Investigation-Platform\backend
```

**Confira que você está no lugar certo antes de continuar:**

```powershell
dir
```

Você precisa ver `app`, `tests`, `requirements.txt` na listagem. Se não
aparecer, você está na pasta errada — ajuste o `cd`.

*(macOS/Linux: mesma ideia, só troca `dir` por `ls` e o `\` por `/` no
caminho.)*

### Passo 4 — Criar um ambiente virtual e instalar as dependências

Um ambiente virtual (`venv`) isola os pacotes desta ferramenta do resto
do seu sistema — evita conflito de versões e, no Linux/macOS mais
recentes, é **obrigatório** (o Python do sistema recusa instalar pacotes
direto, veja [`externally-managed-environment`](#error-externally-managed-environment)
em Problemas comuns se pular este passo e der erro).

```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# macOS/Linux
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Como saber se o ambiente virtual está ativo:** o início da linha do
terminal passa a mostrar `(venv)` antes do resto do prompt. Enquanto
`(venv)` estiver ali, `python` e `pip` apontam pro ambiente isolado — é
assim que deve ficar toda vez que for usar a ferramenta (se fechar o
terminal, repita só o passo de ativar: `.\venv\Scripts\Activate.ps1` ou
`source venv/bin/activate`, não precisa recriar o venv).

Isso baixa e instala: `sqlalchemy`, `typer`, `rich`, `requests`,
`python-whois`, `python-dotenv`, `pytest`. Leva menos de um minuto.

**Como saber se deu certo:** a última linha do terminal deve ser algo como
`Successfully installed ...` listando os pacotes.

### Passo 5 — Rodar o primeiro scan

Agora sim — o comando principal da ferramenta. Vamos usar `example.com`,
que é o domínio de exemplo reservado do IANA e seguro pra qualquer pessoa
testar:

```powershell
python -m app.cli scan example.com --scope "meu primeiro teste" --authorized --confirm-active
```

**O que esperar na tela**, em ordem:

```text
Rodando crtsh...
Rodando subfinder...
Rodando subdomain_permutation...
Rodando cloud_range...
Rodando httpx_probe...
Rodando tech_fingerprint...
Rodando whois...
Rodando cve_correlation...
```

Isso leva entre 10 e 40 segundos (a ferramenta está de fato fazendo
requisições de rede — não travou, é o `cve_correlation` respeitando o
limite de velocidade da API do NVD). No final aparece o relatório em
tabelas.

**Se você chegou até aqui e viu o relatório final — funcionou.** Parabéns,
a ferramenta está instalada e operante.

### Passo 6 — Rodar contra o seu próprio alvo

Troque `example.com` pelo domínio que você tem autorização de testar, e
`"meu primeiro teste"` por uma descrição real do escopo:

```powershell
python -m app.cli scan seudominio.com.br --scope "pentest autorizado - contrato XYZ" --authorized --confirm-active
```

Depois, veja tudo que você já rodou:

```powershell
python -m app.cli history
```

E reimprima o relatório de um scan específico (troque `1` pelo número que
aparece na coluna `ID` do `history`):

```powershell
python -m app.cli report 1
```

---

## Problemas comuns

### `ModuleNotFoundError: No module named 'app'`

Você rodou o comando de fora da pasta `backend/`. Volte ao
[Passo 3](#passo-3--entrar-na-pasta-certa): rode `cd backend` (ajuste o
caminho conforme onde você está) e confirme com `dir`/`ls` que aparecem
`app`, `tests`, `requirements.txt` antes de tentar de novo.

### `'python' não é reconhecido como um comando`

Duas causas possíveis:
1. Python não está instalado — instale em
   [python.org/downloads](https://www.python.org/downloads/) marcando
   **"Add Python to PATH"**.
2. Python está instalado mas só responde a `py` — troque `python` por
   `py` em todos os comandos.

### PowerShell recusa rodar um script `.ps1`

Se você tentar rodar `.\scripts\install.ps1` (script opcional dos módulos
`subfinder`/`httpx`, veja [Referência de comandos](#instalar-subfinder-e-httpx-opcional))
e aparecer:

```text
não pode ser carregado porque a execução de scripts foi desabilitada neste sistema
```

Rode isto uma única vez (permite scripts baixados só pro seu usuário, não
muda nada pro resto do sistema):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Confirme com `S`/`Y` quando perguntado, e tente rodar o script de novo.

### Erro dizendo que falta `--authorized` ou `--confirm-active`

**Isso não é bug — é a trava de segurança da ferramenta funcionando.**
Ela se recusa a criar um scan sem essas duas confirmações explícitas
(veja [Autorização e uso responsável](#autorização-e-uso-responsável)).
Adicione as duas flags no final do comando:

```powershell
python -m app.cli scan example.com --scope "teste" --authorized --confirm-active
```

### O comando parece travado, não imprime nada por um tempo

Normal nos primeiros 10-40 segundos — a ferramenta está mesmo fazendo
requisições de rede reais (DNS, HTTP, consultas ao NVD). Se passar de
uns 2 minutos sem nenhuma linha nova, aí sim pode ser um alvo com muitos
subdomínios ou uma rede lenta; aguarde mais um pouco antes de interromper
com `Ctrl+C`.

### `error: externally-managed-environment`

```text
error: externally-managed-environment

× This environment is externally managed
╰─> To install Python packages system-wide, try apt install
    python3-xyz, where xyz is the package you are trying to
    install...
```

Isso acontece quando você tenta `pip install` **fora** de um ambiente
virtual, num Python instalado pelo gerenciador de pacotes do sistema
(comum em Ubuntu/Debian recentes e em Python instalado via Homebrew no
macOS). O Python se recusa a instalar pacotes direto no sistema pra não
quebrar outras ferramentas que dependem dele.

**A correção é o [Passo 4](#passo-4--criar-um-ambiente-virtual-e-instalar-as-dependências):**
crie e ative um ambiente virtual antes de rodar `pip install`:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Confirme que `(venv)` apareceu no início da linha do terminal antes de
instalar — é isso que indica que o ambiente virtual está ativo e que o
`pip install` vai parar de reclamar.

> Existe um jeito de forçar a instalação sem ambiente virtual
> (`pip install --break-system-packages -r requirements.txt`), mas ele
> tem esse nome por um motivo — pode quebrar outras ferramentas Python
> do seu sistema. Use o ambiente virtual; leva 10 segundos a mais e evita
> esse risco.

### Erro de permissão ao instalar dependências

Se `pip install` falhar por permissão mesmo dentro do ambiente virtual
ativado (raro, mas acontece se o próprio `venv` foi criado numa pasta sem
permissão de escrita), apague a pasta `venv` e recrie num local onde seu
usuário tenha permissão total — por exemplo, dentro da sua pasta pessoal
(`Documentos`, `home`), não em pastas de sistema.

### `'pip' não é reconhecido como um comando`

Com o ambiente virtual ativado (passo 4), isso não deveria acontecer. Se
acontecer mesmo assim, troque `pip install` por
`python -m pip install` (ou `python3 -m pip install` no macOS/Linux).

### Acham `module_error` pra `subfinder` ou `httpx_probe` no relatório

Esperado se você não instalou as ferramentas externas em Go — são
opcionais. O resto do scan continua funcionando normalmente (`crtsh`,
`whois`, `tech_fingerprint`, `cve_correlation` são Python puro, não
dependem delas). Se quiser instalar mesmo assim, veja
[Referência de comandos](#instalar-subfinder-e-httpx-opcional).

### `sqlite3.OperationalError: database is locked` ou erro ao apagar `dev.db`

Outro processo da ferramenta ainda está rodando (ou travou) e segurando o
arquivo `dev.db`. Feche qualquer terminal onde a ferramenta esteja
rodando e tente de novo. No Windows, se persistir, reinicie o terminal.

### Nada do que está aqui resolveu

Abra uma [issue no repositório](https://github.com/excanear/Web-Application-Reconnaissance-Investigation-Platform/issues)
colando: o comando exato que você rodou, a mensagem de erro completa, e
o resultado de `python --version`.

---

## Referência de comandos

### Instalar `subfinder` e `httpx` (opcional)

Ferramentas externas em Go, usadas pelos módulos de mesmo nome. Exigem o
[Go](https://go.dev/dl/) instalado. Sem elas, esses dois módulos
específicos registram `module_error` e o resto do scan continua normal —
não é obrigatório instalar pra usar a ferramenta.

```powershell
# Windows (de dentro de backend/)
.\scripts\install.ps1
```

```bash
# Linux/macOS (de dentro de backend/)
./scripts/install.sh
```

### Configurar a chave de API do NVD (opcional, recomendado)

Sem chave, o limite de consulta ao NVD é de 5 requisições a cada 30
segundos. Com chave gratuita, sobe pra 50/30s — scans com muitas
tecnologias ficam bem mais rápidos.

```powershell
copy .env.example .env
```

Abra o `.env` num editor de texto e preencha `NVD_API_KEY=` com uma chave
gratuita obtida em
[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).
O `.env` nunca é enviado ao git (já está no `.gitignore`).

### Rodar um scan

```bash
python -m app.cli scan <alvo> --scope "<descrição do escopo autorizado>" --authorized --confirm-active
```

| Flag | Obrigatório | O que faz |
|---|---|---|
| `<alvo>` (argumento posicional) | sim | Domínio a mapear |
| `--scope` | sim | Descrição textual do escopo autorizado — fica salva no registro do projeto |
| `--authorized` | sim | Confirmação explícita de que você tem autorização para testar o alvo |
| `--confirm-active` | sim (há módulos ativos registrados) | Confirmação de que módulos que sondam o alvo diretamente podem rodar |
| `--name` | não | Nome do projeto (padrão: o próprio alvo) |

Omitir qualquer flag obrigatória interrompe a execução **antes** de
qualquer requisição ao alvo, com uma mensagem de erro explicando o que
falta.

### Ver o histórico

```bash
python -m app.cli history
```

Lista todos os scans já executados (id, projeto, alvo, status, data).

### Reimprimir um relatório

```bash
python -m app.cli report <scan_id>
```

Reimprime o relatório formatado de um scan já concluído, sem rodar nada
de novo — útil pra revisitar um resultado sem gastar requisições novas
contra o alvo ou o NVD.

<details>
<summary><strong>Ver <code>--help</code> completo</strong></summary>

```text
$ python -m app.cli --help

Usage: python -m app.cli [OPTIONS] COMMAND [ARGS]...

 Recon & Investigation CLI

+- Commands ------------------------------------------------------------------+
| scan       Cria um projeto e roda um scan completo                         |
| history    Lista scans já executados                                       |
| report     Reimprime o relatório de um scan existente                      |
+-----------------------------------------------------------------------------+
```

</details>

---

## Autorização e uso responsável

> [!IMPORTANT]
> Esta é uma ferramenta ofensiva. Ela envia requisições reais contra o
> alvo que você informar — descoberta de subdomínio, sondagem HTTP direta,
> resolução DNS. **Use apenas contra sistemas que você possui ou tem
> autorização explícita e documentada para testar** (pentest contratado,
> bug bounty com escopo definido, seus próprios sistemas, ou domínios de
> teste públicos como `example.com`).

A ferramenta impõe duas travas técnicas, não apenas uma recomendação:

1. **`--authorized`** — obrigatório em todo `scan`. Sem essa flag, nenhum
   projeto é criado e nenhuma requisição sai da sua máquina.
2. **`--confirm-active`** — obrigatório sempre que houver um módulo
   marcado como ativo no registro (`httpx_probe` e `tech_fingerprint`
   hoje — eles enviam requisições HTTP reais direto pro alvo, ao
   contrário de módulos passivos como `crtsh` ou `whois`, que consultam
   serviços de terceiros).

Cada projeto guarda seu `scope_notes` — a descrição de escopo que você
forneceu — junto com o resultado, então o histórico do scan carrega o
registro da autorização declarada.

## Como funciona por dentro

```
recon scan → cria Project + Scan (SQLite)
           → orchestrator.run_scan(scan_id)
                → itera MODULE_REGISTRY ordenado por run_order
                     10  descoberta     (crtsh, subfinder, subdomain_permutation)
                     50  análise        (cloud_range, httpx_probe, tech_fingerprint, whois)
                     90  correlação     (cve_correlation)
                → cada módulo recebe (target, context) e devolve Finding[]
                → context["subdomains"] e context["technologies"] acumulam
                  conforme os módulos rodam, alimentando os módulos seguintes
                → toda Finding é persistida, isolada por módulo — um módulo
                  quebrado vira um Finding tipo module_error, o scan continua
           → CLI imprime o relatório agrupado
```

O núcleo é um **registro de plugins**: cada módulo é uma classe Python
decorada com `@register_module`, com um atributo `run_order` (controla
quando roda) e `is_active` (controla se exige `--confirm-active`).
Adicionar um módulo novo não exige tocar no orquestrador — só criar o
arquivo e importar em `app/modules/__init__.py`.

## Catálogo de módulos

| Módulo | `run_order` | Ativo? | O que faz |
|---|---|---|---|
| `crtsh` | 10 | não | Consulta os logs públicos de certificate transparency (crt.sh) por subdomínios que apareceram em certificados SSL emitidos |
| `subfinder` | 10 | não | Agrega subdomínios de múltiplas fontes passivas via a ferramenta externa `subfinder` |
| `subdomain_permutation` | 10 | não | Gera candidatos combinando um wordlist de nomes comuns de ambiente (dev, staging, admin, api, vpn...) com os subdomínios já descobertos |
| `cloud_range` | 50 | não | Resolve cada host por DNS e verifica se o IP cai num range conhecido de AWS/GCP/Azure |
| `httpx_probe` | 50 | **sim** | Visita cada host candidato via HTTP de verdade, confirma quais estão vivos, faz fingerprint básico via `httpx -tech-detect` |
| `tech_fingerprint` | 50 | **sim** | Motor de 29 regras de fingerprint ativo — ver seção dedicada abaixo |
| `whois` | 50 | não | Consulta os dados reais de registro do domínio |
| `cve_correlation` | 90 | não | Correlaciona cada tecnologia com versão conhecida contra a API real do NVD |

"Ativo" = envia requisições diretamente contra o alvo/subdomínios, além
de consultar serviços de terceiros. Módulos ativos exigem
`--confirm-active`.

## Fingerprint de tecnologia

`tech_fingerprint` roda 29 regras contra 5 categorias, cada uma
combinando um tipo de sinal (`header`, `cookie`, `meta_generator`,
`html_regex`, `path_probe`) com um regex que extrai a versão quando ela
está disponível:

| Categoria | Tecnologias detectadas |
|---|---|
| Servidor web | nginx, Apache, Microsoft-IIS, Tomcat |
| CDN / WAF | Cloudflare, Akamai, Varnish, AWS CloudFront, Fastly |
| Backend | PHP, Java, ASP.NET, Express, Werkzeug/Flask, Ruby on Rails, Laravel, Django |
| CMS | WordPress, Drupal, Joomla, Shopify |
| Frontend | Angular, React, Vue.js, Next.js, jQuery, Bootstrap |

O motor é uma tabela de dados (`FINGERPRINT_RULES` em
`app/modules/tech_fingerprint.py`) — adicionar uma tecnologia nova é
adicionar uma entrada na tabela, sem tocar no código do motor.

Fingerprint de banco de dados fica deliberadamente limitado a sinais
indiretos (cookies, headers, mensagens de erro já expostas) — detecção
direta via técnicas de injeção é teste de vulnerabilidade, não recon, e
está fora do escopo desta ferramenta.

## Correlação de CVE

`cve_correlation` não faz busca de frase exata contra o NVD — essa
abordagem foi tentada, testada ao vivo, e descartada por retornar quase
zero resultados reais (a maioria das descrições de CVE não cita a versão
como texto literal). A abordagem real:

1. Busca por palavra-chave só do **nome** da tecnologia (`keywordSearch=nginx`).
2. Para cada CVE retornado, lê a lista de `configurations` que o NVD
   anexa — os ranges de CPE (`versionStartIncluding`,
   `versionEndExcluding`, etc.) que definem quais versões são realmente
   afetadas.
3. Só reporta o CVE se a versão detectada cair de fato dentro do range
   (ou bater exatamente com uma versão fixada no CPE, quando não há
   range).

Validado ao vivo: `nginx 1.18.0` retorna corretamente **46 CVEs reais**
contra a API de produção do NVD.

## Configuração

Variáveis de ambiente lidas de `backend/.env` (nunca commitado —
`.gitignore` já cobre isso):

| Variável | Obrigatória | Padrão | Descrição |
|---|---|---|---|
| `DATABASE_URL` | não | `sqlite:///./dev.db` | String de conexão SQLAlchemy. SQLite local por padrão — funciona sem nenhum banco externo |
| `NVD_API_KEY` | não | (nenhuma) | Eleva o limite de requisição ao NVD de 5/30s pra 50/30s. Gratuita em nvd.nist.gov |

## Dados e persistência

Três tabelas em SQLite (`app/models.py`):

```
Project(id, name, target, scope_notes, authorized, authorized_at, created_at)
Scan(id, project_id, status, started_at, finished_at)
Finding(id, scan_id, module, type, value, data:JSON, created_at)
```

`Finding.type` hoje inclui: `subdomain`, `whois`, `live_host`,
`technology`, `cve`, `cloud_asset`, `module_error`. `Finding.data` guarda
o payload específico de cada tipo (categoria/versão/confiança pra
tecnologia; CVSS/severidade/descrição pra CVE, etc).

## Testes

```bash
cd backend
pytest -v
```

52 testes, cobrindo cada módulo isoladamente (mockando chamadas
externas), o orquestrador (isolamento de falha por módulo, ordenação por
`run_order`, propagação de contexto), e a CLI (`typer.testing.CliRunner`,
mockando o orquestrador pra não depender de rede).

## Limitações conhecidas

- **Sem rate limiting** — nenhum módulo limita volume de requisição
  contra o alvo. Fica na sua responsabilidade não rodar contra algo com
  centenas de subdomínios sem supervisão.
- **Sem log de auditoria** — requisições feitas ao alvo não ficam
  registradas além dos próprios `Finding`s persistidos.
- **`subfinder`/`httpx` exigem instalação manual** de ferramentas Go
  externas — sem elas, esses dois módulos específicos ficam limitados
  (viram `module_error`, o resto do scan continua normal).
- **Sem cache de CVE** — toda consulta ao NVD é uma chamada de rede nova,
  mesmo repetindo o mesmo alvo/tecnologia entre scans.
- **`subdomain_permutation` gera candidatos não confirmados** — eles
  aparecem como achado `subdomain` mesmo sem confirmação de que
  respondem de verdade, a menos que `httpx_probe` esteja instalado pra
  filtrar quem está realmente vivo.
- **Fingerprint de CDN/frontend cobre um conjunto fixo** — plataformas
  fora da tabela (ex: Vercel) ou variações modernas de um framework (ex:
  Next.js App Router, que não expõe mais o marcador que a regra atual
  procura) não são detectadas ainda.

## Roteiro

- Rate limiting configurável por módulo/alvo
- Log de auditoria de toda requisição enviada ao alvo
- Cache de resultado de CVE entre scans
- Fingerprint por hash de favicon
- Cobertura de mais plataformas de hospedagem/CDN (Vercel, Netlify, Render)
  e do Next.js App Router
- Grafo de correlação de ativos (domínio → subdomínio → IP → tecnologia → CVE)
- Catálogo de recon ativo de rede (port scan, inspeção TLS profunda)
