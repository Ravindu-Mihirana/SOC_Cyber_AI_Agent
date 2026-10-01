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
| `SOC_AI_BASE_URL` | AI endpoint URL, such as local Ollama or an OpenAI-compatible service |
| `SOC_AI_MODEL` | Model name used in the AI panel |
| `SOC_AI_API_KEY` | Optional API key for a remote AI endpoint |
| `SOC_AGENT_DATA_DIR` | Location for the local SQLite database, raw reports, and report inbox |
| `NIKTO_SCRIPT` | Path to `nikto.pl` if Nikto is used from a source checkout |

Assessment history and scanner evidence are stored under `data/` by default.
Set `SOC_AGENT_DATA_DIR` to move those files outside the source checkout.
For an OS move, stop the dashboard first, then copy the entire `data/` folder
to the Linux project. Database scanner-output references are normalized to
paths relative to this data folder, so moving it as a unit keeps those
references useful. A Windows report that was already deleted or left outside
`data/raw/` cannot be recovered by copying the database alone.

## Scanners

- **Nmap:** host/port discovery and optional service-version detection.
- **Nikto:** web-server checks; requires Perl and Nikto.
- **Gobuster:** path discovery; requires Gobuster and a local wordlist.
- **Burp Suite / OpenVAS (Greenbone):** import completed XML reports manually
  or save them into the watched report inbox. The inbox agent does not launch
  scans or connect to scanner APIs.

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

## Burp / OpenVAS report workflow

In the dashboard, select **Import reports**:

- Upload a Burp Suite XML issues report or OpenVAS/Greenbone GMP XML report in
  **Manual import**.
- Or start the local **Automatic collection** agent and place reports in
  `data/inbox/` as `burp-*.xml`, `openvas-*.xml`, or `gvm-*.xml`.

The agent imports completed reports into assessment history, archives the
original under `data/raw/`, and moves the inbox copy under
`data/inbox/processed/`. It does not initiate scans.

## AI analysis

The AI step is explicit and separate from scanning. It supports local Ollama
and OpenAI-compatible endpoints. The UI requires a privacy confirmation before
sending normalized findings and evidence to the configured endpoint. AI output
is advisory; validate it against scanner evidence.

## Reports and data

Each assessment includes scanner status, severity totals, searchable findings,
AI analysis, and PDF/HTML download actions. Local history uses SQLite. The
`.gitignore` excludes the virtual environment, `.env`, Streamlit secrets,
generated package files, and `data/` so machine-specific results stay local.

Only scan systems you own or are explicitly authorized to assess.
