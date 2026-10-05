# SOC Cyber AI Agent

A local security assessment dashboard that runs installed scanners, combines
their findings, optionally asks an AI endpoint to explain results, and exports
HTML or PDF reports. The application is Python-based and runs on Linux and
Windows.

## Linux development setup

Python 3.11 or later is required. On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git nmap nikto perl
```

Create a virtual environment and install the project:

```bash
git clone <your-repository-url> soc-cyber-ai-agent
cd soc-cyber-ai-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cp .env.example .env
python -m soc_cyber_agent.launch_ui
```

Open <http://localhost:8501>. Start the UI later with
`python -m soc_cyber_agent.launch_ui` from the project directory.
After installation, `soc-cyber-ui` is an equivalent command.

Gobuster requires Go 1.24 or later. Install it using the official Go
instructions, then install Gobuster and add Go's bin directory to `PATH`:

```bash
go install github.com/OJ/gobuster/v3@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

The assessment form needs a local wordlist path, for example
`/usr/share/wordlists/dirb/common.txt` when that file is installed.

## Windows development setup

Use Python 3.11 or later in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
Copy-Item .env.example .env
python -m soc_cyber_agent.launch_ui
```

Install scanner programs separately and make sure their commands are on
`PATH`. The launcher uses the active Python interpreter and does not modify
Windows or Linux home-directory variables.

## Local configuration and secrets

Copy `.env.example` to `.env` and edit values as needed. The app loads `.env`
without overriding environment variables already set by your shell. Never
commit `.env` or `.streamlit/secrets.toml`; they are ignored by Git.

Supported optional settings:

| Variable | Purpose |
| --- | --- |
| `SOC_AI_BASE_URL` | HTTPS base URL for an OpenAI-compatible online AI service |
| `SOC_AI_MODEL` | Cloud model name used for analysis |
| `SOC_AI_API_KEY` | Optional initial API key; configure and save it in Settings |
| `SOC_AGENT_DATA_DIR` | Location for the local SQLite database, raw reports, and report inbox |
| `NIKTO_SCRIPT` | Path to `nikto.pl` if Nikto is used from a source checkout |

The dashboard shows queued, running, and completed scanners for every active
assessment and refreshes live progress automatically. Scans run in background
workers, so you can start another assessment or inspect saved results while a
long-running tool is still working. Assessment history and scanner evidence are stored under `data/` by default.
Set `SOC_AGENT_DATA_DIR` to move those files outside the source checkout.
For an OS move, stop the dashboard first, then copy the entire `data/` folder
to the Linux project. Database scanner-output references are normalized to
paths relative to this data folder, so moving it as a unit keeps those
references useful. A Windows report that was already deleted or left outside
`data/raw/` cannot be recovered by copying the database alone.

## Scanners

- **Nmap:** host/port discovery and optional service-version detection.
- **Burp Suite:** starts a web scan through Burp Suite's built-in REST API,
  collects its issues, and adds them to the same assessment, AI analysis, and
  report export flow. Requires a running Burp instance with its REST API enabled
  and an API key. Automated active audits depend on your Burp edition/license.
- **Nikto:** web-server checks; requires Perl and Nikto.
- **Gobuster:** path discovery; requires Gobuster and a local wordlist.
- **OpenVAS (Greenbone):** import completed XML reports manually or save them
  into the watched report inbox. The inbox agent does not launch scans or
  connect to scanner APIs.

On Linux, Nmap is available in common distribution packages, and Nikto's
upstream project documents Perl/source installation. Gobuster documents
installation through Go. See the [Nmap installation guide](https://nmap.org/book/install.html),
[Nikto project](https://github.com/sullo/nikto), and
[Gobuster project](https://github.com/OJ/gobuster).

Greenbone Community Edition is a multi-service deployment. Its upstream
container guide is the recommended starting point for a separate Linux host;
it documents Docker/Compose setup and feed storage requirements.
[Greenbone Community Containers guide](https://greenbone.github.io/docs/latest/22.4/container/).
The current project consumes exported XML reports rather than controlling a
Greenbone server over GMP.

## Security tool catalog

The dashboard catalog includes web/API scanning, code and dependency analysis,
cloud and infrastructure checks, network and host monitoring, and enrichment
and case-management tools. It checks local command availability where possible
and links each product to its documentation. Nmap, Burp, Nikto, Gobuster, OWASP
ZAP, Nuclei, ffuf, and sqlmap have direct scan adapters; OpenVAS/Greenbone
reports can be imported. Nuclei and ffuf use conservative request limits.
ZAP Quick Start and sqlmap send active probes and require explicit authorization. Other
catalog entries are discovery/planning entries until their scanner-specific
input, execution, and result-normalization adapters are configured. The UI
shows that distinction explicitly instead of treating an installed binary as
an active scanner integration.

## Burp Suite connection

In Burp Suite, open **Settings → Suite → REST API**, enable the service, and
create a dedicated API key. Keep it bound to `127.0.0.1` when Burp and this
dashboard run on the same Kali VM. In the dashboard's **Settings** page, save
the service root (normally `http://127.0.0.1:1337`) and API key once. The key is
kept in the ignored local `data/app-settings.json` file with restrictive POSIX
permissions. New assessments reuse the saved connection. Select **Burp**, enter
an absolute target URL such as `https://authorized.example/`. The app asks Burp to use its configured default scan behavior,
waits for completion, stores the raw API result under `data/raw/`, and normalizes
issues into the assessment. The REST API reference is available from Burp at
`[service URL]/[API key]`; API routes can vary by Burp version.

Set Burp's default scan behavior in Burp itself before launching scans. Active
audits send test traffic to discovered inputs and may affect the target; use
them only with explicit authorization. Named scan configurations can vary by
Burp installation, so the integration does not assume a built-in name. If
Burp's API is not available in your edition/setup, the existing XML import
workflow remains.

## Burp / OpenVAS report workflow

In the dashboard, select **Import reports**:

- Upload a Burp Suite XML issues report or OpenVAS/Greenbone GMP XML report in
  **Manual import**. This is also the fallback for Burp editions or setups
  without REST scan access.
- Or start the local **Automatic collection** agent and place reports in
  `data/inbox/` as `burp-*.xml`, `openvas-*.xml`, or `gvm-*.xml`.

The agent imports completed reports into assessment history, archives the
original under `data/raw/`, and moves the inbox copy under
`data/inbox/processed/`. It does not initiate scans.

## AI analysis

The AI step is explicit and separate from scanning. It uses an online HTTPS
OpenAI-compatible endpoint; local Ollama endpoints are not supported. Configure
the base URL, API key, and model in **Settings**, where the app can list models
advertised by the service. One analysis correlates findings from all scanners
and returns an overall risk summary, prioritized observations, and an ordered
remediation plan. The UI requires a separate privacy confirmation for each
assessment before sending normalized findings, evidence, and scanner coverage.
AI output is advisory; validate it against scanner evidence. API credentials are
stored in the local ignored `data/app-settings.json` file.

Assessment history keeps each scan run as its own record. Re-running an
assessment creates the next numbered run in that target's history; deleting a
completed record also removes its associated raw scanner files.

## Reports and data

Each assessment includes scanner status, severity totals, searchable findings,
AI analysis, and PDF/HTML download actions. Local history uses SQLite. The
`.gitignore` excludes the virtual environment, `.env`, Streamlit secrets,
generated package files, and `data/` so machine-specific results stay local.

Only scan systems you own or are explicitly authorized to assess.
