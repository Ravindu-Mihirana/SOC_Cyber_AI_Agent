"""Streamlit dashboard for scans, AI review, history, and report downloads."""

import os
from datetime import datetime
from typing import Any
from uuid import uuid4

import streamlit as st

from soc_cyber_agent.app_settings import load_app_settings, save_burp_settings
from soc_cyber_agent.ai_analyzer import AIAnalysisError, analyze_findings
from soc_cyber_agent.reports import render_html, render_pdf
from soc_cyber_agent.report_importers import ReportImportError, parse_burp_xml, parse_openvas_xml
from soc_cyber_agent.report_agent import agent_status, start_report_agent, stop_report_agent
from soc_cyber_agent.scanner_runner import SCANNERS, ScannerError, run_scan, scanner_availability
from soc_cyber_agent.storage import data_dir, get_assessment, list_assessments, new_assessment, save_assessment


def _format_created(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return value


def _make_assessment(targets: dict[str, str], scanners: list[str], scan_type: str, ports: str, wordlist: str,
                     burp_api_url: str, burp_api_key: str, burp_profile: str) -> str:
    label = " · ".join(f"{name}: {target}" for name, target in targets.items() if target)
    assessment = new_assessment(label, scanners)
    save_assessment(assessment)
    progress = st.progress(0, text="Preparing assessment")
    status_box = st.status("Assessment in progress", expanded=True)
    for index, scanner in enumerate(scanners, start=1):
        target = targets["nmap"] if scanner == "nmap" else targets["web"]
        status_box.write(f"Running {scanner.title()} against {target}…")
        try:
            findings, raw_path = run_scan(
                scanner, target, scan_type=scan_type, ports=ports, wordlist=wordlist,
                burp_api_url=burp_api_url, burp_api_key=burp_api_key, burp_profile=burp_profile,
                on_progress=status_box.write if scanner == "burp" else None,
            )
            assessment["findings"].extend(findings)
            assessment["scanner_results"][scanner] = {
                "status": "complete", "target": target, "count": len(findings), "raw_path": raw_path,
            }
            status_box.write(f"{scanner.title()} completed: {len(findings)} findings")
        except (ScannerError, OSError, ValueError) as exc:
            assessment["scanner_results"][scanner] = {
                "status": "failed", "target": target, "error": str(exc),
            }
            status_box.write(f"{scanner.title()} could not complete: {exc}")
        save_assessment(assessment)
        progress.progress(index / len(scanners), text=f"Finished {scanner.title()}")
    completed = any(item.get("status") == "complete" for item in assessment["scanner_results"].values())
    assessment["status"] = "complete" if completed else "failed"
    save_assessment(assessment)
    status_box.update(label="Assessment finished" if completed else "Assessment failed", state="complete" if completed else "error")
    return assessment["id"]


def _findings_table(findings: list[dict[str, Any]]) -> None:
    if not findings:
        st.info("No findings were returned by this scan.")
        return
    sources = sorted({str(item.get("source_tool", "unknown")) for item in findings})
    severities = sorted({str(item.get("severity", "unknown")) for item in findings})
    search, col_source, col_severity = st.columns([1.4, 1, 1])
    query = search.text_input("Search findings", placeholder="Title, host, CVE, evidence…", key="finding_search")
    selected_sources = col_source.multiselect("Scanner", sources, default=sources, key="finding_sources")
    selected_severity = col_severity.multiselect("Severity", severities, default=severities, key="finding_severity")
    query = query.strip().casefold()
    filtered = [item for item in findings if item.get("source_tool") in selected_sources and item.get("severity", "unknown") in selected_severity and (not query or query in " ".join(str(item.get(field, "")) for field in ("title", "host", "target", "description", "evidence", "cve_ids")).casefold())]
    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
    st.dataframe([
        {
            "Severity": str(item.get("severity", "unknown")).upper(),
            "Scanner": item.get("source_tool", ""),
            "Asset": f"{item.get('host', '')}{':' + str(item.get('port')) if item.get('port') else ''}",
            "Finding": item.get("title", ""),
            "Confidence": item.get("service_confidence", ""),
        }
        for item in filtered
    ], hide_index=True, use_container_width=True)
    for index, item in enumerate(filtered):
        title = str(item.get("title", "Finding"))
        with st.expander(f"{str(item.get('severity', 'unknown')).upper()} · {title}", expanded=False):
            st.write(item.get("description", ""))
            if item.get("service_name"):
                service_line = str(item["service_name"])
                if item.get("service_product") or item.get("service_version"):
                    service_line += f" — {item.get('service_product', '')} {item.get('service_version', '')}".strip()
                method = item.get("service_detection_method")
                confidence = item.get("service_confidence")
                if method:
                    service_line += f" · {method} detection"
                if confidence is not None:
                    service_line += f" · confidence {confidence}/10"
                st.caption(service_line)
            if item.get("cve_ids"):
                st.write("CVE IDs:", ", ".join(item["cve_ids"]))
            st.code(str(item.get("evidence", "No additional evidence")), language=None)
            st.caption(f"Raw scanner output: {item.get('raw_ref', '')}")


def _render_ai(assessment: dict[str, Any]) -> None:
    findings = assessment.get("findings", [])
    scanner_names = sorted({str(item.get("source_tool", "unknown")) for item in findings})
    if not scanner_names:
        st.info("Run a scanner successfully before requesting AI analysis.")
        return
    st.subheader("AI analysis")
    st.caption("Analysis is advisory. Review the supporting scanner evidence before acting on recommendations.")
    with st.expander("AI connection and privacy", expanded=False):
        provider = st.selectbox("Provider", ["Ollama (local)", "OpenAI-compatible endpoint"], key="ai_provider")
        default_base = os.environ.get("SOC_AI_BASE_URL", "http://127.0.0.1:11434") if provider == "Ollama (local)" else os.environ.get("SOC_AI_BASE_URL", "https://api.openai.com")
        base_url = st.text_input("Base URL", value=default_base, key=f"ai_url_{provider}")
        default_model = os.environ.get("SOC_AI_MODEL", "llama3.1:8b") if provider == "Ollama (local)" else os.environ.get("SOC_AI_MODEL", "gpt-4o-mini")
        model = st.text_input("Model", value=default_model, key=f"ai_model_{provider}")
        api_key = ""
        if provider != "Ollama (local)":
            api_key = st.text_input(
                "API key (used for this session only)",
                value=os.environ.get("SOC_AI_API_KEY", ""), type="password", key="ai_api_key",
            )
        allow_send = st.checkbox("I reviewed the privacy choice and allow sending normalized finding details to this endpoint.", key="ai_allow_send")
        if provider != "Ollama (local)":
            st.warning("The selected remote service will receive finding titles, descriptions, and evidence. Avoid sending confidential assessment data unless approved.")
        else:
            st.caption("Ollama is local when pointed at localhost; cloud models/endpoints may transmit data externally.")
    if st.button("Analyze each scanner's results", type="primary", disabled=not allow_send, key="analyze_all"):
        analyses = assessment.setdefault("analyses", {})
        with st.spinner("Analyzing normalized findings…"):
            for scanner in scanner_names:
                scanner_findings = [item for item in findings if item.get("source_tool") == scanner]
                result = assessment.get("scanner_results", {}).get(scanner, {})
                try:
                    analyses[scanner] = analyze_findings(
                        scanner, str(result.get("target", assessment.get("target", ""))), scanner_findings,
                        provider=provider, base_url=base_url, model=model, api_key=api_key,
                    )
                except AIAnalysisError as exc:
                    analyses[scanner] = f"Analysis unavailable: {exc}"
                save_assessment(assessment)
        st.rerun()
    analyses = assessment.get("analyses", {})
    if analyses:
        for scanner, analysis in analyses.items():
            with st.expander(f"{scanner.title()} analysis", expanded=True):
                st.markdown(str(analysis))


def _render_report_downloads(assessment: dict[str, Any]) -> None:
    st.subheader("Export assessment")
    html_bytes = render_html(assessment)
    pdf_bytes = render_pdf(assessment)
    safe_id = assessment["id"][:8]
    left, right = st.columns(2)
    left.download_button("Download HTML report", data=html_bytes,
                         file_name=f"security-assessment-{safe_id}.html", mime="text/html", use_container_width=True)
    right.download_button("Download PDF report", data=pdf_bytes,
                          file_name=f"security-assessment-{safe_id}.pdf", mime="application/pdf", use_container_width=True)


def _render_assessment(assessment: dict[str, Any]) -> None:
    scanners = assessment.get("scanner_results", {})
    completed = sum(result.get("status") == "complete" for result in scanners.values())
    failed = sum(result.get("status") == "failed" for result in scanners.values())
    findings = assessment.get("findings", [])
    critical = sum(item.get("severity") == "critical" for item in findings)
    high = sum(item.get("severity") == "high" for item in findings)
    st.markdown(f"## Assessment <span class='id-chip'>{assessment['id'][:8]}</span>", unsafe_allow_html=True)
    st.caption(f"{_format_created(assessment.get('created_at', ''))}  ·  {assessment.get('target', '')}")
    overview, finding_tab, ai_tab, export_tab = st.tabs(["Overview", f"Findings · {len(findings)}", "AI analysis", "Export"])
    with overview:
        metric1, metric2, metric3, metric4 = st.columns(4)
        metric1.metric("Total findings", len(findings), help="Combined observations from the selected scanners")
        metric2.metric("Scanners completed", completed)
        metric3.metric("Scanners failed", failed)
        metric4.metric("High / critical", f"{high} / {critical}")
        st.markdown("#### Scanner activity")
        if scanners:
            for name, result in scanners.items():
                label = "Complete" if result.get("status") == "complete" else "Failed"
                with st.container(border=True):
                    left, middle, right = st.columns([1, 2, 2])
                    left.markdown(f"**{name.title()}**")
                    if result.get("status") == "complete":
                        middle.success(f"{label} · {result.get('count', 0)} findings")
                    else:
                        middle.error(f"{label} · {result.get('error', 'Unknown error')}")
                    right.caption(result.get("target", ""))
                    if result.get("raw_path"):
                        st.caption(f"Raw evidence: {result['raw_path']}")
        else:
            st.info("No scanner results recorded yet.")
        if findings:
            st.markdown("#### Priority snapshot")
            priority_cols = st.columns(4)
            for col, level in zip(priority_cols, ("critical", "high", "medium", "low")):
                count = sum(item.get("severity") == level for item in findings)
                col.metric(level.title(), count)
    with finding_tab:
        _findings_table(findings)
    with ai_tab:
        _render_ai(assessment)
    with export_tab:
        st.markdown("### Share this assessment")
        st.write("Download a self-contained report with findings, evidence, scanner status, and any AI analysis.")
        _render_report_downloads(assessment)


def _new_assessment_page() -> None:
    st.markdown("<div class='eyebrow'>ASSESSMENT WORKSPACE</div>", unsafe_allow_html=True)
    st.title("Start an assessment")
    st.write("Choose tools, set the target, and review what will run before you start.")
    availability = scanner_availability()
    burp_settings = load_app_settings()
    with st.container(border=True):
        st.markdown("#### Scanner readiness")
        cols = st.columns(len(SCANNERS))
        for col, name in zip(cols, SCANNERS):
            ready, detail = availability[name]
            if name == "burp":
                ready = bool(burp_settings["burp_api_url"] and burp_settings["burp_api_key"])
                detail = burp_settings["burp_api_url"] if ready else "Configure the REST API in Settings"
            with col:
                with st.container(border=True):
                    if ready:
                        st.success(f"{name.title()} · Ready")
                    else:
                        st.warning(f"{name.title()} · Setup needed")
                    st.caption(detail)
    with st.form("new_assessment_form"):
        st.markdown("#### 1 · Choose scanners")
        scanner_cols = st.columns(len(SCANNERS))
        selected = []
        descriptions = {
            "nmap": "Hosts, ports, and service versions",
            "burp": "Web crawl and vulnerability audit through Burp Suite",
            "nikto": "Web server checks",
            "gobuster": "Discover web paths from a wordlist",
        }
        for index, (col, name) in enumerate(zip(scanner_cols, SCANNERS)):
            ready, _ = availability[name]
            if name == "burp":
                ready = bool(burp_settings["burp_api_url"] and burp_settings["burp_api_key"])
            with col:
                with st.container(border=True):
                    chosen = st.checkbox(name.title(), value=(name == "nmap"), key=f"scan_select_{name}")
                    st.caption(descriptions[name])
                    st.caption("Ready" if ready else "Configure in Settings" if name == "burp" else "Tool not detected")
            if chosen:
                selected.append(name)
        scanners = selected
        st.markdown("#### 2 · Set target and scan options")
        col_nmap, col_web = st.columns(2)
        nmap_target = col_nmap.text_input("Nmap hostname or IP", placeholder="192.0.2.10")
        web_target = col_web.text_input("Web target URL (Burp / Nikto / Gobuster)", placeholder="https://authorized.example")
        burp_api_url = burp_settings["burp_api_url"]
        burp_api_key = burp_settings["burp_api_key"]
        burp_profile = ""
        if "burp" in scanners:
            with st.expander("Burp Suite connection and scan profile", expanded=True):
                if burp_api_key:
                    st.success(f"Using saved Burp connection · {burp_api_url}")
                else:
                    st.warning("Burp connection is not configured. Add its service URL and API key on the Settings page.")
                st.caption("The scan uses Burp's default configuration. Named configurations differ between Burp installations; set the default scan behavior in Burp itself.")
        scan_type = st.selectbox("Nmap profile", ["quick", "version"], help="Quick scans common ports; version attempts service detection on the top 100 ports.")
        ports = st.text_input("Optional Nmap ports", placeholder="e.g. 80,443 or 1-1000")
        wordlist = st.text_input("Gobuster wordlist path", placeholder="/path/to/wordlist.txt")
        approved = st.checkbox("I own these targets or have explicit permission to scan them.")
        submitted = st.form_submit_button("Start authorized assessment", type="primary", use_container_width=True)
    if submitted:
        if not scanners:
            st.error("Choose at least one scanner.")
            return
        if not approved:
            st.error("Confirm authorization before starting any scan.")
            return
        targets: dict[str, str] = {}
        if "nmap" in scanners:
            if not nmap_target.strip():
                st.error("Enter a hostname or IP address for Nmap.")
                return
            targets["nmap"] = nmap_target.strip()
        if any(name in scanners for name in ("burp", "nikto", "gobuster")):
            if not web_target.strip():
                st.error("Enter an http(s) URL for the web scanners.")
                return
            targets["web"] = web_target.strip()
        if "burp" in scanners and not burp_api_key.strip():
            st.error("Configure Burp's REST API URL and key on the Settings page before starting a Burp scan.")
            return
        if "gobuster" in scanners and not wordlist.strip():
            st.error("Enter an existing local wordlist path for Gobuster.")
            return
        missing = [name for name in scanners if name != "burp" and not availability[name][0]]
        if missing:
            st.warning(f"Unavailable scanners will be recorded as failed: {', '.join(missing)}")
        assessment_id = _make_assessment(
            targets, scanners, scan_type, ports.strip(), wordlist.strip(),
            burp_api_url.strip(), burp_api_key.strip(), burp_profile,
        )
        st.session_state["current_assessment_id"] = assessment_id
        st.rerun()
    current_id = st.session_state.get("current_assessment_id")
    if current_id:
        assessment = get_assessment(current_id)
        if assessment:
            st.divider()
            _render_assessment(assessment)


def _settings_page() -> None:
    st.markdown("<div class='eyebrow'>CONNECTIONS</div>", unsafe_allow_html=True)
    st.title("Settings")
    st.write("Save the Burp Suite REST API connection once. New assessments will reuse it automatically.")
    settings = load_app_settings()
    with st.container(border=True):
        st.subheader("Burp Suite REST API")
        st.caption("On the Kali VM, keep Burp's API bound to localhost when Burp and this dashboard run on the same machine. Enter the service root only; the app adds your key and API route.")
        with st.form("burp_connection_settings"):
            api_url = st.text_input("Service URL", value=settings["burp_api_url"], placeholder="http://127.0.0.1:1337")
            api_key = st.text_input("API key", value=settings["burp_api_key"], type="password", help="Saved locally in data/app-settings.json and excluded from Git with the rest of data/.")
            submitted = st.form_submit_button("Save Burp connection", type="primary")
        if submitted:
            try:
                save_burp_settings(api_url.strip(), api_key)
                settings = load_app_settings()
                st.success("Burp connection saved. New assessments will use these settings.")
            except (OSError, ValueError) as exc:
                st.error(f"Could not save Burp settings: {exc}")
        if settings["burp_api_key"] and st.button("Forget saved API key", key="forget_burp_api_key"):
            try:
                save_burp_settings(settings["burp_api_url"], "")
                st.success("Saved API key removed.")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not remove saved API key: {exc}")


def _history_page() -> None:
    st.title("Assessment history")
    assessments = list_assessments()
    if not assessments:
        st.info("No assessments saved yet. Start one from the New assessment page.")
        return
    labels = {item["id"]: f"{_format_created(item['created_at'])} · {item['target']} · {item['status']}" for item in assessments}
    ids = list(labels)
    default_id = st.session_state.get("current_assessment_id", ids[0])
    index = ids.index(default_id) if default_id in ids else 0
    selected_id = st.selectbox("Saved assessments", ids, index=index, format_func=lambda value: labels[value])
    assessment = get_assessment(selected_id)
    if assessment:
        st.session_state["current_assessment_id"] = selected_id
        _render_assessment(assessment)


def _import_reports_page() -> None:
    st.markdown("<div class='eyebrow'>COLLECT FINDINGS</div>", unsafe_allow_html=True)
    st.title("Scanner reports")
    st.write("Automatically collect XML exports with the agent, or import reports manually.")
    agent_tab, manual_tab = st.tabs(["Automatic collection", "Manual import"])
    with agent_tab:
        _report_agent_controls()
        with st.container(border=True):
            st.markdown("#### Connect scanner exports")
            st.write("Save completed reports into the inbox below. The agent creates an assessment and preserves the raw evidence.")
            st.code("data/inbox/burp-latest.xml\ndata/inbox/openvas-weekly.xml", language="text")
            st.caption("No scan is launched by this agent.")
    with manual_tab:
        with st.container(border=True):
            st.markdown("#### Upload completed reports")
            st.caption("Burp: export an XML issues report. OpenVAS / Greenbone: download a completed task report as XML.")
            left, right = st.columns(2)
            burp_upload = left.file_uploader("Burp Suite XML", type=["xml"], key="burp_import")
            gvm_upload = right.file_uploader("OpenVAS / Greenbone XML", type=["xml"], key="openvas_import")
            if st.button("Import selected reports", type="primary", disabled=not (burp_upload or gvm_upload)):
                raw_dir = data_dir() / "raw"
                raw_dir.mkdir(parents=True, exist_ok=True)
                scanners: list[str] = []
                targets: list[str] = []
                imports: list[tuple[str, Any, str]] = []
                try:
                    for scanner, uploaded, parser in (("burp", burp_upload, parse_burp_xml), ("openvas", gvm_upload, parse_openvas_xml)):
                        if uploaded is None:
                            continue
                        raw_id = str(uuid4())
                        content = uploaded.getvalue()
                        findings = parser(content, raw_ref=raw_id)
                        raw_path = raw_dir / f"{raw_id}-{scanner}.xml"
                        raw_path.write_bytes(content)
                        imports.append((scanner, findings, raw_path.relative_to(data_dir()).as_posix()))
                        scanners.append(scanner)
                        targets.extend(sorted({str(item.target) for item in findings}))
                except (ReportImportError, OSError) as exc:
                    st.error(f"Report import failed: {exc}")
                    return
                assessment = new_assessment("Imported reports: " + (", ".join(dict.fromkeys(targets)) or "unknown target"), scanners)
                assessment["status"] = "complete"
                for scanner, findings, raw_path in imports:
                    assessment["findings"].extend(item.to_dict() for item in findings)
                    assessment["scanner_results"][scanner] = {
                        "status": "complete", "target": ", ".join(sorted({str(item.target) for item in findings})),
                        "count": len(findings), "raw_path": raw_path, "mode": "imported report",
                    }
                save_assessment(assessment)
                st.session_state["current_assessment_id"] = assessment["id"]
                st.success(f"Imported {len(assessment['findings'])} findings from {len(imports)} report(s).")
    current_id = st.session_state.get("current_assessment_id")
    assessment = get_assessment(current_id) if current_id else None
    if assessment:
        st.divider()
        _render_assessment(assessment)


@st.fragment(run_every=3)
def _report_agent_controls() -> None:
    st.subheader("Automatic report agent")
    status = agent_status()
    st.caption("The local agent watches this folder and imports completed XML reports into assessment history:")
    st.code(status["inbox"], language=None)
    left, right = st.columns(2)
    if status["running"]:
        left.success("Agent is watching for reports")
        if right.button("Stop report agent", key="stop_report_agent"):
            stop_report_agent()
            st.rerun()
    else:
        left.info("Agent is stopped")
        if right.button("Start report agent", type="primary", key="start_report_agent"):
            start_report_agent()
            st.rerun()
    st.caption("Save files as `burp-*.xml` or `openvas-*.xml` / `gvm-*.xml`. Imported files move to `inbox/processed`; originals are also preserved in `data/raw`.")
    st.caption(f"Reports auto-imported this run: {status['processed']}")
    if status["last_file"]:
        st.caption(f"Most recent: {status['last_file']} · assessment `{status['last_assessment_id'][:8]}`")
    if status["last_error"]:
        st.error(f"Agent needs attention: {status['last_error']}")
    new_id = status["last_assessment_id"]
    if new_id and new_id != st.session_state.get("agent_last_seen_assessment"):
        st.session_state["agent_last_seen_assessment"] = new_id
        st.session_state["current_assessment_id"] = new_id
        st.rerun(scope="app")


def main() -> None:
    st.set_page_config(page_title="SOC Cyber AI Agent", page_icon="🛡️", layout="wide")
    st.markdown("""
        <style>
        .stApp {background:radial-gradient(ellipse at 85% 0%,rgba(22,92,119,.16),transparent 35%),#0b1220}
        .block-container {padding-top:2.4rem;padding-bottom:4rem;max-width:1360px}
        [data-testid="stSidebar"] {background:linear-gradient(180deg,#101b2b,#0d1624);border-right:1px solid #203047}
        [data-testid="stSidebar"] [data-testid="stRadio"] label {padding:.6rem .75rem;border-radius:.6rem}
        [data-testid="stMetric"] {background:linear-gradient(145deg,#162336,#111c2c);padding:16px 18px;border-radius:14px;border:1px solid #24354c}
        [data-testid="stMetricLabel"] p {color:#a9bbd1;font-size:.82rem}
        [data-testid="stMetricValue"] {color:#eff6ff;font-weight:700}
        [data-testid="stVerticalBlockBorderWrapper"] {background:rgba(18,31,48,.72);border-color:#263950;border-radius:14px}
        [data-testid="stForm"] {background:rgba(16,27,42,.68);border:1px solid #263950;border-radius:16px;padding:1.2rem 1.35rem}
        .stButton>button,.stDownloadButton>button,[data-testid="stFormSubmitButton"] button {border-radius:10px;border:1px solid #2c4964;min-height:2.65rem;transition:all .15s ease}
        .stButton>button:hover,.stDownloadButton>button:hover {border-color:#42c8c2;color:#7ce2dc;transform:translateY(-1px)}
        [data-testid="stTabs"] button {font-weight:600}
        .eyebrow {color:#55d2c9;font-size:.72rem;font-weight:750;letter-spacing:.16em;margin-bottom:.4rem}
        .id-chip {font:600 .75rem ui-monospace,monospace;color:#a9bfd8;background:#17273a;border:1px solid #30445c;border-radius:999px;padding:.35rem .65rem;vertical-align:middle}
        h1 {letter-spacing:-.035em} h2,h3 {letter-spacing:-.02em}
        [data-testid="stCaptionContainer"] {color:#b0bfd0}
        @media(max-width:800px){.block-container{padding-left:1rem;padding-right:1rem}.stApp{background:#0b1220}}
        </style>
    """, unsafe_allow_html=True)
    with st.sidebar:
        st.title("🛡️ SOC Cyber")
        st.caption("SECURITY OPERATIONS WORKSPACE")
        st.markdown("---")
        page = st.radio("Workspace", ["New assessment", "Import reports", "Assessment history", "Settings"], label_visibility="collapsed")
        st.divider()
        st.caption("Scans start only after you confirm authorization and submit.")
        st.markdown("---")
        st.caption(f"{len(list_assessments())} saved assessments")
    if page == "New assessment":
        _new_assessment_page()
    elif page == "Import reports":
        _import_reports_page()
    elif page == "Settings":
        _settings_page()
    else:
        _history_page()


if __name__ == "__main__":
    main()
