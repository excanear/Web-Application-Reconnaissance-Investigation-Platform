# Web Application Reconnaissance & Investigation Platform — Design

## Contexto e objetivo

Ferramenta ofensiva de segurança para pentest autorizado (freelance/CTF): recebe um
domínio/URL/alvo e produz o mapeamento mais completo e correlacionado possível da
superfície de ataque daquele sistema — recon passivo (OSINT), recon ativo de rede,
mapeamento web/app, e detecção de possíveis CVEs — priorizado por risco real.

**Nota de escopo honesta**: nenhuma ferramenta mapeia "100%" de um sistema — sempre
existem ativos desconhecidos, zero-days sem CVE público, e proteções (WAF/rate-limit)
que limitam visibilidade sem violar termos de uso. O objetivo é cobertura máxima
realista, extensível e continuamente atualizável, no nível de ferramentas
profissionais (reNgine, Bishop Fox, etc.), não uma garantia de completude absoluta.

Uso: pessoal, contra alvos com autorização explícita do usuário (pentest, bug
bounty, CTF).

## Interface

Web app local (dashboard), rodando em `localhost`. Backend FastAPI expõe API REST +
SSE para progresso ao vivo. Frontend React + Vite consome a API.

## Arquitetura

- **Orquestrador de plugins**: cada módulo de recon é uma classe Python com
  interface padrão `run(target, config) -> List[Finding]`, carregada
  dinamicamente por um registry. Adicionar um módulo novo não exige tocar no core.
- **Fila de tarefas distribuída**: Celery + Redis. Permite scans concorrentes,
  retry automático, agendamento de re-scans periódicos, e cancelamento.
- **Banco**: PostgreSQL. Suporta concorrência real e consultas relacionais de
  correlação (grafo de ativos).
- **Grafo de ativos**: camada de correlação sobre o relacional — domínio →
  subdomínio → IP → ASN → cloud bucket → tecnologia → CVE — representada via
  tabela de arestas (`asset_relations`) e materializada em memória com
  `networkx` para consultas de caminho (ex.: "que caminho leva de um
  subdomínio esquecido até um serviço com CVE crítico").
- A maioria dos módulos orquestra ferramentas externas consagradas via
  subprocess (subfinder, amass, httpx, dnsx, katana, nmap, nuclei, gowitness,
  ffuf) e normaliza a saída de cada uma para um schema comum (`Finding`).

## Módulos (catálogo completo)

### A. OSINT / Passivo
- Subdomínios: subfinder, amass (passivo), crt.sh, permutação (dnsgen) +
  resolução em massa
- ASN/IP ranges da organização; matching contra ranges públicos de
  AWS/GCP/Azure
- WHOIS (atual + histórico), reverse WHOIS (mesma organização em outros
  domínios)
- Certificate Transparency contínuo (novos certs = novos subdomínios)
- Vazamento de código: menções ao domínio em repositórios públicos
  (GitHub/GitLab), chaves de API expostas
- Metadados de documentos públicos do domínio (PDF/DOCX)
- OSINT de funcionários/emails ligados à organização (apenas contexto,
  não usado para exploração)

### B. Rede ativa
- Port scan (nmap: top-1000 rápido, full range sob demanda)
- Detecção de serviço/versão (`-sV`), OS fingerprint (`-O`)
- TLS/SSL deep inspection: versões suportadas, ciphers fracos, certificados
  expirados/self-signed
- Detecção de WAF/CDN (para contexto do relatório, não para evasão)
- Screenshot de todos os serviços web encontrados (gowitness)

### C. Web/App mapping
- Crawling recursivo (katana) com renderização JS (headless) para SPAs
- Extração de endpoints/parâmetros de arquivos JS
- Descoberta de API: spec Swagger/OpenAPI, introspecção GraphQL, endpoints
  REST inferidos
- Fuzzing de diretórios/arquivos (ffuf, wordlist por tecnologia detectada)
- Fingerprint de tecnologia (CMS, framework, versão)
- Detecção de subdomain takeover (CNAME órfão)
- Storage exposto: buckets S3/GCS/Azure Blob públicos ligados ao domínio

### D. Vulnerabilidades / CVEs
- `nuclei` com templates comunitários + customizados por tecnologia detectada
- Correlação CVE: tech+versão detectada → mirror local do NVD (sincronizado
  periodicamente) → CVEs aplicáveis (via CPE matching)
- Priorização por CVSS + EPSS (probabilidade real de exploração)
- Misconfigurações comuns: headers de segurança ausentes, CORS mal
  configurado, debug mode exposto, cookies sem flags
- Diffing entre scans: o que mudou desde o último scan

## Modelo de dados

```
Project(id, name, target, scope_notes, authorized:bool, authorized_at, created_at)
Scan(id, project_id, modules_selected[], status, started_at, finished_at)
Asset(id, type[domain|subdomain|ip|port|service|tech|bucket|endpoint], value, first_seen, last_seen)
AssetRelation(from_asset_id, to_asset_id, relation_type)
Finding(id, asset_id, scan_id, module, type, data:JSON, cvss?, epss?, severity)
CVE(cve_id, description, cvss, epss, affected_tech_cpe)
```

O relatório final é uma consulta ao grafo — todos os ativos, suas relações, e os
achados/CVEs anexados a cada um — renderizado como grafo interativo + tabela
priorizada por risco no dashboard, exportável em JSON/HTML/PDF/SARIF.

## Autorização e controles de segurança

- Toda criação de Projeto exige `scope_notes` preenchido + confirmação explícita
  de autorização antes de habilitar qualquer Scan. Fica registrado no relatório.
- Módulos ativos/intrusivos (fuzzing, port scan completo, nuclei) exigem uma
  segunda confirmação explícita.
- Rate limiting configurável por módulo/alvo — nunca gera carga suficiente para
  afetar disponibilidade do alvo.
- Log de auditoria: todo request feito a um alvo é registrado com timestamp.

## Setup

Script `install.ps1`/`install.sh` verifica Go instalado e instala via
`go install` os binários necessários (subfinder, dnsx, httpx, katana, nuclei,
gowitness, ffuf); nmap requer instalação manual do sistema. Backend faz
healthcheck no startup e avisa no dashboard quais ferramentas faltam.

## Testes

- Unit: parsers/normalizadores de cada módulo (mock de saída real das
  ferramentas)
- Integração: orquestrador rodando módulos contra alvo de teste local/próprio
- API: endpoints do FastAPI (criação de projeto, disparo de scan, consulta de
  relatório)

## Roadmap de implementação

1. **Fase 1 — Core**: plugin engine, grafo de ativos, Postgres, Celery/Redis,
   módulos A (OSINT), dashboard com grafo básico e relatório
2. **Fase 2**: módulos B (rede ativa) + C (web/app mapping)
3. **Fase 3**: módulos D (correlação de CVE + mirror NVD + EPSS) + priorização
   de risco no dashboard
4. **Fase 4**: monitoramento contínuo (re-scans agendados + diffing) + módulos
   avançados (busca de leaks, cloud storage, subdomain takeover)

A spec de implementação detalhada (writing-plans) começa pela Fase 1.
