<div align="center">

# Web Application Reconnaissance &amp; Investigation Platform

English | **[Leia isto em Português](README.pt-BR.md)**

**Point it at a domain. Get back the exact technology, exact version, and real CVEs.**

An offensive reconnaissance CLI that maps the attack surface of an
authorized target — subdomain discovery, active technology fingerprinting,
and vulnerability correlation against the real NVD — all in a single
synchronous process, no server, no queue, no infrastructure to keep
running.

[![Python](https://img.shields.io/badge/python-3.13%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![CLI](https://img.shields.io/badge/interface-CLI-000000?style=flat-square)](#command-reference)
[![Authorization required](https://img.shields.io/badge/use-authorized%20only-red?style=flat-square)](#authorization-and-responsible-use)
[![Tests](https://img.shields.io/badge/tests-136%20passing-brightgreen?style=flat-square)](#tests)

</div>

---

## Table of contents

- [What it does](#what-it-does)
- [Tutorial: from zero to your first scan](#tutorial-from-zero-to-your-first-scan)
- [Common problems](#common-problems)
- [Command reference](#command-reference)
- [Authorization and responsible use](#authorization-and-responsible-use)
- [How it works internally](#how-it-works-internally)
- [Module catalog](#module-catalog)
- [Technology fingerprinting](#technology-fingerprinting)
- [CVE correlation](#cve-correlation)
- [Configuration](#configuration)
- [Data and persistence](#data-and-persistence)
- [Audit trail](#audit-trail)
- [Tests](#tests)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)

---

## What it does

You give it a domain. The tool:

1. **Discovers** subdomains (certificate transparency, passive enumeration,
   wordlist permutation).
2. **Actively probes** the target and every subdomain against a
   fingerprinting engine with dozens of rules — web server, CDN/WAF,
   backend language and framework, CMS, frontend framework — extracting
   the **exact version** whenever it leaks through headers, cookies,
   `generator` tags, or exposed changelog/manifest files.
3. **Correlates** each technology with a known version against the real
   NVD API, filtering by CPE range — not loose text search, but structural
   verification that the specific version actually falls inside that
   CVE's vulnerable range.
4. **Prints a report** to the terminal, grouped by Technologies, CVEs
   (sorted by descending CVSS, severity color-coded), and other
   findings — and stores everything in a local SQLite database so you can
   revisit it later.

No frontend, no HTTP API, no Celery, no Redis, no Docker. One command,
one process, one report.

---

## Tutorial: from zero to your first scan

This tutorial assumes you've **never run the tool before**. Follow it in
order — each step has a way to confirm it worked before moving to the
next. If something doesn't match what's described, skip straight to
[Common problems](#common-problems).

Pick your platform: [Windows (PowerShell)](#step-0--open-the-right-terminal)
is the most detailed since it's where most people get stuck; macOS/Linux
follows in each step.

### Step 0 — Open the right terminal

**Windows:** open **PowerShell** (not "Command Prompt"/`cmd`). Start menu
→ type `PowerShell` → Enter.

**macOS/Linux:** open your regular Terminal.

### Step 1 — Confirm Python is installed (version 3.13 or newer)

```powershell
python --version
```

Expected result: something like `Python 3.13.12`. If you see
**`'python' is not recognized as an internal or external command`**,
try:

```powershell
py --version
```

If neither works, you don't have Python installed — download it from
[python.org/downloads](https://www.python.org/downloads/) (check the
**"Add Python to PATH"** box during install — this is the step most
people forget) and repeat this step.

> From here on, this tutorial uses `python`. If only `py` worked on your
> machine, swap `python` for `py` in every command below.

### Step 2 — Download the code

```powershell
git clone https://github.com/excanear/Web-Application-Reconnaissance-Investigation-Platform.git
```

If you don't have `git` installed, download the ZIP directly via the
green **"Code" → "Download ZIP"** button on the repository's GitHub page,
and extract the folder.

### Step 3 — Enter the right folder

This is the step where **almost everyone gets stuck**: the tool's
commands only work from inside the `backend/` folder, not from the
project root.

```powershell
cd Web-Application-Reconnaissance-Investigation-Platform\backend
```

**Check you're in the right place before continuing:**

```powershell
dir
```

You need to see `app`, `tests`, `requirements.txt` in the listing. If you
don't, you're in the wrong folder — adjust the `cd`.

*(macOS/Linux: same idea, just swap `dir` for `ls` and `\` for `/` in the
path.)*

### Step 4 — Create a virtual environment and install dependencies

A virtual environment (`venv`) isolates this tool's packages from the
rest of your system — it avoids version conflicts and, on recent
Linux/macOS, it's **required** (the system Python refuses to install
packages directly, see
[`externally-managed-environment`](#error-externally-managed-environment)
in Common problems if you skip this step and hit that error).

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

**How to tell the virtual environment is active:** the start of your
terminal line now shows `(venv)` before the rest of the prompt. While
`(venv)` is there, `python` and `pip` point at the isolated environment —
that's how it should look every time you use the tool (if you close the
terminal, just repeat the activation step:
`.\venv\Scripts\Activate.ps1` or `source venv/bin/activate` — no need to
recreate the venv).

This downloads and installs: `sqlalchemy`, `typer`, `rich`, `requests`,
`python-whois`, `python-dotenv`, `pytest`. Takes under a minute.

**How to tell it worked:** the last line in the terminal should look like
`Successfully installed ...` listing the packages.

### Step 5 — Run your first scan

Now for the tool's main command. We'll use `example.com`, IANA's reserved
example domain, safe for anyone to test against:

```powershell
python -m app.cli scan example.com --scope "my first test" --authorized --confirm-active
```

**What to expect on screen**, in order:

```text
Running crtsh...
Running subfinder...
Running subdomain_permutation...
Running cloud_range...
Running httpx_probe...
Running tech_fingerprint...
Running whois...
Running cve_correlation...
```

This takes 10 to 40 seconds (the tool is genuinely making network
requests — it hasn't frozen, that's `cve_correlation` respecting the NVD
API's rate limit). At the end the report appears in tables.

**If you got this far and saw the final report — it worked.**
Congratulations, the tool is installed and operating.

### Step 6 — Run against your own target

Swap `example.com` for the domain you're authorized to test, and
`"my first test"` for a real scope description:

```powershell
python -m app.cli scan yourdomain.com --scope "authorized pentest - contract XYZ" --authorized --confirm-active
```

Then, see everything you've already run:

```powershell
python -m app.cli history
```

And reprint the report for a specific scan (swap `1` for the number in
the `ID` column from `history`):

```powershell
python -m app.cli report 1
```

---

## Common problems

### `ModuleNotFoundError: No module named 'app'`

You ran the command from outside the `backend/` folder. Go back to
[Step 3](#step-3--enter-the-right-folder): run `cd backend` (adjust the
path to where you are) and confirm with `dir`/`ls` that `app`, `tests`,
`requirements.txt` show up before trying again.

### `'python' is not recognized as a command`

Two possible causes:
1. Python isn't installed — install it from
   [python.org/downloads](https://www.python.org/downloads/), checking
   **"Add Python to PATH"**.
2. Python is installed but only responds to `py` — swap `python` for
   `py` in every command.

### PowerShell refuses to run a `.ps1` script

If you try to run `.\scripts\install.ps1` (the optional script for the
`subfinder`/`httpx` modules, see
[Command reference](#install-subfinder-and-httpx-optional)) and see:

```text
cannot be loaded because running scripts is disabled on this system
```

Run this once (allows scripts downloaded just for your user, doesn't
change anything else on the system):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Confirm with `Y` when prompted, and try running the script again.

### Error saying `--authorized` or `--confirm-active` is missing

**This isn't a bug — it's the tool's safety gate working as intended.**
It refuses to create a scan without these two explicit confirmations
(see [Authorization and responsible use](#authorization-and-responsible-use)).
Add both flags at the end of the command:

```powershell
python -m app.cli scan example.com --scope "test" --authorized --confirm-active
```

### The command looks frozen, prints nothing for a while

Normal for the first 10-40 seconds — the tool really is making live
network requests (DNS, HTTP, NVD queries). If it goes past about 2
minutes with no new line, it might be a target with many subdomains or a
slow network; wait a bit longer before interrupting with `Ctrl+C`.

### `error: externally-managed-environment`

```text
error: externally-managed-environment

× This environment is externally managed
╰─> To install Python packages system-wide, try apt install
    python3-xyz, where xyz is the package you are trying to
    install...
```

This happens when you try `pip install` **outside** of a virtual
environment, on a Python installed by the system's package manager
(common on recent Ubuntu/Debian and on Python installed via Homebrew on
macOS). Python refuses to install packages directly on the system so it
doesn't break other tools that depend on it.

**The fix is [Step 4](#step-4--create-a-virtual-environment-and-install-dependencies):**
create and activate a virtual environment before running `pip install`:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Confirm `(venv)` appeared at the start of the terminal line before
installing — that's what indicates the virtual environment is active and
`pip install` will stop complaining.

> There's a way to force the install without a virtual environment
> (`pip install --break-system-packages -r requirements.txt`), but it's
> named that way for a reason — it can break other Python tools on your
> system. Use the virtual environment; it takes 10 extra seconds and
> avoids that risk.

### Permission error installing dependencies

If `pip install` fails on permissions even inside an activated virtual
environment (rare, but happens if the `venv` itself was created in a
folder without write permission), delete the `venv` folder and recreate
it somewhere your user has full permission — for example, inside your
home folder (`Documents`, `home`), not in system folders.

### `'pip' is not recognized as a command`

With the virtual environment activated (step 4), this shouldn't happen.
If it does anyway, swap `pip install` for `python -m pip install` (or
`python3 -m pip install` on macOS/Linux).

### `module_error` for `subfinder` or `httpx_probe` in the report

Expected if you haven't installed the external Go tools — they're
optional. The rest of the scan keeps working normally (`crtsh`, `whois`,
`tech_fingerprint`, `cve_correlation` are pure Python, they don't depend
on them). If you want to install them anyway, see
[Command reference](#install-subfinder-and-httpx-optional).

### `sqlite3.OperationalError: database is locked` or an error deleting `dev.db`

Another instance of the tool is still running (or hung) and holding the
`dev.db` file. Close any terminal where the tool is running and try
again. On Windows, if it persists, restart the terminal.

### Nothing here fixed it

Open an [issue on the repository](https://github.com/excanear/Web-Application-Reconnaissance-Investigation-Platform/issues)
with: the exact command you ran, the full error message, and the output
of `python --version`.

---

## Command reference

### Install `subfinder` and `httpx` (optional)

External Go tools, used by the modules of the same name. Require
[Go](https://go.dev/dl/) installed. Without them, those two specific
modules record `module_error` and the rest of the scan continues
normally — installing them isn't required to use the tool.

```powershell
# Windows (from inside backend/)
.\scripts\install.ps1
```

```bash
# Linux/macOS (from inside backend/)
./scripts/install.sh
```

### Install `nuclei` (optional, needed for CVE validation)

`nuclei_validation` actively confirms a subset of `suspected` CVE findings
by running community-maintained `nuclei` templates matched by CVE ID
against the target. Without `nuclei` installed, this module logs a single
`module_error` finding and every CVE finding stays `suspected` — the rest
of the scan is unaffected.

1. Install `nuclei`: https://github.com/projectdiscovery/nuclei#install-nuclei
2. Update its template library (required — the tool never vendors
   templates itself): `nuclei -update-templates`
3. Re-run `nuclei -update-templates` periodically to pick up templates for
   newly disclosed CVEs.

Every `nuclei` invocation excludes `dos`, `fuzz`, and `intrusive`-tagged
templates unconditionally — this is a hard-coded safety boundary, not a
setting.

### Set up an NVD API key (optional, recommended)

Without a key, the NVD query limit is 5 requests every 30 seconds. With a
free key, it goes up to 50/30s — scans with many technologies get much
faster.

```powershell
copy .env.example .env
```

Open `.env` in a text editor and fill in `NVD_API_KEY=` with a free key
obtained at
[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).
`.env` is never committed to git (already covered by `.gitignore`).

### Output language

By default the CLI prints everything in English. For Portuguese output,
use `--lang pt` **before** the command name:

```bash
python -m app.cli --lang pt scan <target> --scope "<authorized scope description>" --authorized --confirm-active
```

### Run a scan

```bash
python -m app.cli scan <target> --scope "<authorized scope description>" --authorized --confirm-active
```

| Flag | Required | What it does |
|---|---|---|
| `<target>` (positional argument) | yes | Domain to map |
| `--scope` | yes | Text description of the authorized scope — saved to the project record |
| `--authorized` | yes | Explicit confirmation that you're authorized to test the target |
| `--confirm-active` | yes (if active modules are registered) | Confirmation that modules probing the target directly may run |
| `--name` | no | Project name (defaults to the target itself) |
| `--max-requests-per-second` | no | Caps request pace against the target/subdomains (default `5.0`) |
| `--circuit-breaker-threshold` | no | Consecutive failures against a target before a module stops probing it (default `5`) |
| `--scope-include` | no | Domain pattern or CIDR explicitly in scope (repeatable, defaults to `<target>` and `*.<target>`) |
| `--scope-exclude` | no | Domain pattern or CIDR explicitly excluded from scope (repeatable) |
| `--scope-window` | no | Allowed UTC time window, e.g. `09:00-18:00` (default: always allowed) |

Omitting any required flag stops execution **before** any request hits
the target, with an error message explaining what's missing.

`tech_fingerprint` and `cloud_range` pace each host and stop probing a
target that fails repeatedly, recording a `circuit_breaker_tripped`
finding instead of continuing blindly. `httpx_probe` passes the same
rate through to `httpx`'s own `-rate-limit` flag. `cve_correlation`
respects the general limit on top of its existing NVD-specific pacing.
`crtsh` and `whois` make exactly one request per scan, so neither
applies to them.

Modules that probe a host check the declared scope first — an
out-of-scope host a module would otherwise touch is skipped and
recorded as an `out_of_scope` finding instead. If narrowing scope with `--scope-include`
would exclude the target itself, `scan` refuses to create the project
at all.

### View history

```bash
python -m app.cli history
```

Lists every scan run so far (id, project, target, status, date).

### Reprint a report

```bash
python -m app.cli report <scan_id>
```

Reprints the formatted report for a scan that already completed, without
running anything again — useful for revisiting a result without spending
new requests against the target or the NVD.

### Exporting a report

`recon report <scan_id>` defaults to the terminal table shown above.
Two additional formats are available:

- `recon report <scan_id> --format csv` — one row per CVE finding
  (`cve, severity, cvss, epss, status, technology, host, description,
  evidence, remediation`), written to stdout. Column names are fixed and
  in English regardless of `--lang`, matching `recon audit --format csv`'s
  convention — CSV is for machines/spreadsheets, not the CLI's display
  language.
- `recon report <scan_id> --format pdf [--output PATH]` — a
  self-contained PDF (executive summary, detected technologies, and
  CVEs prioritized by CVSS with EPSS as a tie-breaker), localized per
  `--lang`. Without `--output`/`-o`, the file is written as
  `report_<scan_id>.pdf` in the current directory. Generating a PDF
  needs no external tool install — `reportlab` is a pure-Python
  dependency already pinned in `requirements.txt`, unlike `nuclei`/
  `subfinder`/`httpx`.

Every CVE's EPSS score (probability of exploitation, from FIRST.org's
free public API) is fetched and stored once, at scan time, the same way
NVD/DeepL data already is — `report`/export commands never touch the
network. CVSS remains the primary priority signal; EPSS only
tie-breaks CVEs that already share the same CVSS score.

Remediation guidance comes from the confirming `nuclei` template's own
`remediation` text when a CVE's status is `confirmed`; otherwise a
generic "upgrade to a patched version" message names the affected
technology without guessing a specific fixed version number.

### View the audit trail

```bash
python -m app.cli audit <scan_id> --format table
python -m app.cli audit <scan_id> --format csv > audit.csv
```

Lists every recorded `AuditEntry` for a scan — module, target, URL,
outcome, timestamp. `table` (default) matches `report`'s Rich styling;
`csv` writes to stdout via the stdlib `csv` module (no `--output` flag).
See [Audit trail](#audit-trail) for what gets recorded and why.

<details>
<summary><strong>See full <code>--help</code></strong></summary>

```text
$ python -m app.cli --help

Usage: python -m app.cli [OPTIONS] COMMAND [ARGS]...

 Recon & Investigation CLI

+- Options -------------------------------------------------------------------+
| --lang                      <str>  Output language: en (default) or pt      |
|                                    [default: en]                            |
+-----------------------------------------------------------------------------+
+- Commands ------------------------------------------------------------------+
| scan                                                                        |
| history                                                                     |
| report                                                                      |
| audit                                                                       |
+-----------------------------------------------------------------------------+
```

</details>

---

## Authorization and responsible use

> [!IMPORTANT]
> This is an offensive tool. It sends real requests against whatever
> target you give it — subdomain discovery, direct HTTP probing, DNS
> resolution. **Only use it against systems you own or have explicit,
> documented authorization to test** (a contracted pentest, a bug bounty
> with defined scope, your own systems, or public test domains like
> `example.com`).

The tool enforces two technical gates, not just a recommendation:

1. **`--authorized`** — required on every `scan`. Without this flag, no
   project is created and no request leaves your machine.
2. **`--confirm-active`** — required whenever a module is marked active
   in the registry (`httpx_probe` and `tech_fingerprint` today — they
   send real HTTP requests directly at the target, unlike passive modules
   like `crtsh` or `whois`, which query third-party services).

Every project stores its `scope_notes` — the scope description you
provided — alongside the results, so the scan history carries the record
of declared authorization.

## How it works internally

```
recon scan → creates Project + Scan (SQLite)
           → orchestrator.run_scan(scan_id)
                → iterates MODULE_REGISTRY ordered by run_order
                     10  discovery      (crtsh, subfinder, subdomain_permutation)
                     50  analysis       (cloud_range, httpx_probe, tech_fingerprint, whois)
                     90  correlation    (cve_correlation)
                → each module receives (target, context) and returns Finding[]
                → context["subdomains"] and context["technologies"] accumulate
                  as modules run, feeding later modules
                → every Finding is persisted, isolated per module — a broken
                  module becomes a module_error Finding, the scan continues
           → CLI prints the grouped report
```

The core is a **plugin registry**: each module is a Python class decorated
with `@register_module`, with a `run_order` attribute (controls when it
runs) and `is_active` (controls whether it requires `--confirm-active`).
Adding a new module doesn't require touching the orchestrator — just
create the file and import it in `app/modules/__init__.py`.

## Module catalog

| Module | `run_order` | Active? | What it does |
|---|---|---|---|
| `crtsh` | 10 | no | Queries public certificate transparency logs (crt.sh) for subdomains that appeared in issued SSL certificates |
| `subfinder` | 10 | no | Aggregates subdomains from multiple passive sources via the external `subfinder` tool |
| `subdomain_permutation` | 10 | no | Generates candidates by combining a wordlist of common environment names (dev, staging, admin, api, vpn...) with subdomains already discovered |
| `cloud_range` | 50 | no | Resolves each host via DNS and checks whether the IP falls inside a known AWS/GCP/Azure range |
| `httpx_probe` | 50 | **yes** | Visits each candidate host via real HTTP, confirms which are alive, does basic fingerprinting via `httpx -tech-detect` |
| `tech_fingerprint` | 50 | **yes** | 29-rule active fingerprinting engine — see the dedicated section below |
| `whois` | 50 | no | Queries the domain's real registration data |
| `cve_correlation` | 90 | no | Correlates each technology with a known version against the real NVD API |
| `nuclei_validation` | 95 | **yes** | Runs `nuclei` templates matched by CVE ID against `suspected` CVE findings to confirm exploitability, excluding `dos`/`fuzz`/`intrusive`-tagged templates |

"Active" = sends requests directly against the target/subdomains, beyond
just querying third-party services. Active modules require
`--confirm-active`.

## Technology fingerprinting

`tech_fingerprint` runs 29 rules across 5 categories, each combining a
signal type (`header`, `cookie`, `meta_generator`, `html_regex`,
`path_probe`) with a regex that extracts the version when it's available:

| Category | Technologies detected |
|---|---|
| Web server | nginx, Apache, Microsoft-IIS, Tomcat |
| CDN / WAF | Cloudflare, Akamai, Varnish, AWS CloudFront, Fastly |
| Backend | PHP, Java, ASP.NET, Express, Werkzeug/Flask, Ruby on Rails, Laravel, Django |
| CMS | WordPress, Drupal, Joomla, Shopify |
| Frontend | Angular, React, Vue.js, Next.js, jQuery, Bootstrap |

The engine is a data table (`FINGERPRINT_RULES` in
`app/modules/tech_fingerprint.py`) — adding a new technology means adding
a table entry, without touching the engine's code.

Database fingerprinting is deliberately limited to indirect signals
(cookies, headers, error messages already exposed) — direct detection via
injection techniques is vulnerability testing, not recon, and is out of
scope for this tool.

## CVE correlation

`cve_correlation` doesn't do exact-phrase search against the NVD — that
approach was tried, tested live, and dropped because it returned nearly
zero real results (most CVE descriptions don't cite the version as
literal text). The real approach:

1. Keyword search on just the technology's **name**
   (`keywordSearch=nginx`).
2. For each CVE returned, reads the `configurations` list the NVD
   attaches — the CPE ranges (`versionStartIncluding`,
   `versionEndExcluding`, etc.) that define which versions are actually
   affected.
3. Only reports the CVE if the detected version actually falls inside the
   range (or matches exactly a version pinned in the CPE, when there's no
   range).

Validated live: `nginx 1.18.0` correctly returns **46 real CVEs** against
the NVD's production API.

The report's **Status** column for each CVE shows either `suspected` or
`confirmed`. `suspected` means the version falls inside the CVE's CPE range
according to the NVD — that's the result of structural correlation alone.
`confirmed` means `nuclei_validation` ran a community-maintained template
for that CVE against the target and the template reported a positive result,
confirming the vulnerability can be actually reproduced via a safe check
(no exploitation, just detection). The **Evidence** column for confirmed
CVEs shows which `nuclei` template ID matched and at which timestamp.

## Configuration

Environment variables read from `backend/.env` (never committed —
already covered by `.gitignore`):

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | no | `sqlite:///./dev.db` | SQLAlchemy connection string. Local SQLite by default — works without any external database |
| `NVD_API_KEY` | no | (none) | Raises the NVD request limit from 5/30s to 50/30s. Free at nvd.nist.gov |
| `DEEPL_API_KEY` | no | (none) | Enables Portuguese translation of NVD's CVE descriptions. Free tier at deepl.com. Without it, CVE descriptions stay English-only and the report marks the Portuguese cell as unavailable when `--lang pt` is used. |

## Data and persistence

Four SQLite tables (`app/models.py`):

```
Project(id, name, target, scope_notes, authorized, authorized_at, created_at)
Scan(id, project_id, status, started_at, finished_at)
Finding(id, scan_id, module, type, value, data:JSON, created_at)
AuditEntry(id, scan_id, module, target, url, outcome, requested_at)
```

`Finding.type` currently includes: `subdomain`, `whois`, `live_host`,
`technology`, `cve`, `cloud_asset`, `module_error`,
`circuit_breaker_tripped`, `out_of_scope`, `scope_window_closed`.
`Finding.data` holds the type-specific payload (category/version/
confidence for technology; CVSS/severity/description for CVE, etc).

## Audit trail

Every real network request the tool makes — against the target/
subdomains and against third-party services like the NVD — is recorded
as an `AuditEntry`: module, target, URL (when applicable), outcome, and
timestamp. This is separate from the findings report; it exists to
prove what the tool actually touched, independent of what turned into
a finding. `subfinder` and `httpx_probe` shell out to external Go
binaries and can't see the individual requests those binaries make
internally, so they get one entry per invocation/per-host respectively
— an accepted approximation, not literal per-socket-request fidelity.

```bash
python -m app.cli audit <scan_id> --format table
python -m app.cli audit <scan_id> --format csv > audit.csv
```

## Tests

```bash
cd backend
pytest -v
```

136 tests, covering each module in isolation (mocking external calls), the
orchestrator (per-module failure isolation, `run_order` ordering, context
propagation), rate limiting/circuit breaker behavior in isolation, and
the CLI (`typer.testing.CliRunner`, mocking the orchestrator so it
doesn't depend on the network).

## Known limitations

- **`subfinder`/`httpx` require manual installation** of external Go
  tools — without them, those two specific modules are limited (they
  become `module_error`, the rest of the scan continues normally).
- **No CVE cache** — every NVD query is a fresh network call, even
  repeating the same target/technology across scans.
- **`subdomain_permutation` generates unconfirmed candidates** — they
  show up as a `subdomain` finding even without confirmation that they
  actually respond, unless `httpx_probe` is installed to filter for
  what's actually alive.
- **CDN/frontend fingerprinting covers a fixed set** — platforms outside
  the table (e.g. Vercel) or modern variations of a framework (e.g.
  Next.js App Router, which no longer exposes the marker the current rule
  looks for) aren't detected yet.

## Roadmap

- CVE result caching between scans
- Favicon-hash fingerprinting
- Coverage for more hosting/CDN platforms (Vercel, Netlify, Render) and
  Next.js App Router
- Asset correlation graph (domain → subdomain → IP → technology → CVE)
- Active network recon catalog (port scan, deep TLS inspection)
