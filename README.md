<div align="center">

# Web Application Reconnaissance &amp; Investigation Platform

**Aponte um domínio. Receba tecnologia exata, versão exata e CVE real.**

Uma CLI de reconhecimento ofensivo que mapeia a superfície de ataque de um
alvo autorizado — descoberta de subdomínio, fingerprint ativo de
tecnologia, e correlação de vulnerabilidades contra o NVD real — tudo num
único processo síncrono, sem servidor, sem fila, sem infraestrutura pra
manter no ar.

[![Python](https://img.shields.io/badge/python-3.13%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![CLI](https://img.shields.io/badge/interface-CLI-000000?style=flat-square)](#uso)
[![Autorização obrigatória](https://img.shields.io/badge/uso-somente%20autorizado-red?style=flat-square)](#autorização-e-uso-responsável)
[![Testes](https://img.shields.io/badge/testes-50%20passing-brightgreen?style=flat-square)](#testes)

</div>

---

## Sumário

- [O que ela faz](#o-que-ela-faz)
- [Por que existe](#por-que-existe)
- [Demonstração](#demonstração)
- [Instalação](#instalação)
- [Uso](#uso)
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

## Por que existe

A maioria das ferramentas de recon te dá uma lista de subdomínios e para
por aí, ou te dá um scanner de vulnerabilidade genérico sem saber
exatamente qual tecnologia e qual versão está rodando. Esta ferramenta
fecha esse ciclo: mapeia a tecnologia real do alvo até o nível de versão,
e só then pergunta ao NVD "existe CVE pra essa versão específica?" — o que
elimina a maior fonte de ruído (falso positivo por versão errada) que
scanners baseados em busca de texto livre produzem.

## Demonstração

```text
$ python -m app.cli scan example.com --scope "authorized recon test" --authorized --confirm-active

Rodando crtsh...
Rodando subfinder...
Rodando subdomain_permutation...
Rodando cloud_range...
Rodando httpx_probe...
Rodando tech_fingerprint...
Rodando whois...
Rodando cve_correlation...

Scan #9 - status: complete
                           Tecnologias
+---------------------------------------------------------------+
| Categoria | Nome       | Versao | Confianca | Host            |
|-----------+------------+--------+-----------+-----------------|
| cdn_waf   | Cloudflare | -      | medium    | example.com     |
| cdn_waf   | Cloudflare | -      | medium    | www.example.com |
+---------------------------------------------------------------+
                             CVEs
+-------------------------------------------------------------------------+
| CVE            | Severidade | CVSS | Tecnologia    | Descricao          |
|----------------+------------+------+---------------+--------------------|
| CVE-2021-23017 | HIGH       | 7.7  | nginx 1.18.0  | Vulnerabilidade... |
+-------------------------------------------------------------------------+
                     Outros achados
+----------------------------------------------------------------------+
| Tipo         | Valor                     | Modulo                    |
|--------------+---------------------------+---------------------------|
| subdomain    | dev.example.com           | crtsh                     |
| whois        | example.com               | whois                     |
+----------------------------------------------------------------------+
```

*(saída real, capturada rodando a ferramenta contra `example.com` — o
domínio de exemplo reservado do IANA, seguro pra qualquer pessoa testar.
A tabela de CVE é ilustrativa aqui; contra um alvo real com uma
tecnologia versionada, é exatamente essa tabela que aparece preenchida
com CVEs reais retornados pela API do NVD.)*

## Instalação

**Pré-requisitos:** Python 3.13+, [Go](https://go.dev/dl/) (opcional, só
pros dois módulos que usam ferramentas externas).

```bash
git clone <este-repositório>
cd "Web Application Reconnaissance & Investigation Platform/backend"
pip install -r requirements.txt
```

Instale as ferramentas externas opcionais (`subfinder` e `httpx`, usadas
pelos módulos de mesmo nome — sem elas, esses dois módulos registram um
`module_error` e o resto do scan continua normalmente):

```bash
# Linux/macOS
./scripts/install.sh

# Windows
.\scripts\install.ps1
```

Configure sua chave de API do NVD (opcional, mas recomendado — sem ela o
limite de consulta cai de 50 pra 5 requisições a cada 30 segundos):

```bash
cp .env.example .env
# edite .env e preencha NVD_API_KEY=
# chave gratuita em https://nvd.nist.gov/developers/request-an-api-key
```

## Uso

Todos os comandos rodam a partir de `backend/`:

```bash
cd backend
```

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

50 testes, cobrindo cada módulo isoladamente (mockando chamadas
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

## Roteiro

- Rate limiting configurável por módulo/alvo
- Log de auditoria de toda requisição enviada ao alvo
- Cache de resultado de CVE entre scans
- Fingerprint por hash de favicon
- Grafo de correlação de ativos (domínio → subdomínio → IP → tecnologia → CVE)
- Catálogo de recon ativo de rede (port scan, inspeção TLS profunda)
