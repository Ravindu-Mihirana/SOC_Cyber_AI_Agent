"""Streamlit dashboard for scans, AI review, history, and report downloads."""

import threading
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

import streamlit as st

from soc_cyber_agent.app_settings import load_app_settings, save_ai_settings, save_burp_settings
from soc_cyber_agent.ai_analyzer import AIAnalysisError, analyze_assessment, list_models
from soc_cyber_agent.reports import render_html, render_pdf
from soc_cyber_agent.report_importers import ReportImportError, parse_burp_xml, parse_openvas_xml
from soc_cyber_agent.report_agent import agent_status, start_report_agent, stop_report_agent
from soc_cyber_agent.scanner_runner import SCANNERS, ScannerError, run_scan, scanner_availability
from soc_cyber_agent.tool_catalog import TOOL_CATEGORIES, catalog_tool_status
from soc_cyber_agent.storage import (
    data_dir, delete_assessment, get_assessment, list_assessment_scans,
    list_assessments, new_assessment, next_scan_number, recover_interrupted_assessments, save_assessment,
)

recover_interrupted_assessments()


def _format_created(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return value


def _navigate_to(page: str) -> None:
    st.session_state["workspace_page"] = page


def _open_assessment(assessment_id: str) -> None:
    st.session_state["current_assessment_id"] = assessment_id
    st.session_state["workspace_page"] = "Assessment history"


def _delete_assessment_and_evidence(assessment_id: str) -> tuple[bool, str]:
    assessment = get_assessment(assessment_id)
    if not assessment:
        return False, "Assessment was not found."
    if assessment.get("status") == "running":
        return False, "Wait for the active scan to finish before deleting its history."
    removed = delete_assessment(assessment_id)
    if not removed:
        return False, "Assessment was not found."
    raw_dir = data_dir() / "raw"
    if raw_dir.is_symlink():
        return True, "Assessment deleted. Raw files were retained because the configured raw directory is a symbolic link."
    raw_root = raw_dir.resolve()
    errors = []
    for result in removed.get("scanner_results", {}).values():
        raw_path = result.get("raw_path")
        if not raw_path:
            continue
        parts = PurePosixPath(str(raw_path).replace("\\", "/")).parts
        if not parts or parts[0].casefold() != "raw":
            continue
        candidate = (data_dir() / Path(*parts)).resolve()
        if candidate.parent != raw_root or not candidate.is_file():
            continue
        try:
            candidate.unlink()
        except OSError as exc:
            errors.append(str(exc))
    return True, "Assessment deleted." + (f" Some raw files could not be removed: {'; '.join(errors)}" if errors else "")


def _rerun_from_history(assessment_id: str) -> None:
    if not st.session_state.get(f"rerun_authorized_{assessment_id}"):
        return
    source = get_assessment(assessment_id)
    if not source:
        st.session_state["history_rerun_message"] = ("error", "Assessment was not found.")
        return
    try:
        new_id = _start_rescan(source)
        new_scan = get_assessment(new_id)
        st.session_state["current_assessment_id"] = new_id
        st.session_state["history_selected_scan"] = new_id
        st.session_state["history_rerun_message"] = (
            "success", f"Started scan run #{new_scan['scan_number']}. It is saved as a separate record in this target's history."
        )
    except (KeyError, ValueError, OSError) as exc:
        st.session_state["history_rerun_message"] = ("error", f"Could not rerun this assessment: {exc}")


def _confirm_delete_from_history(assessment_id: str) -> None:
    if not st.session_state.get(f"confirm_delete_{assessment_id}"):
        return
    deleted, message = _delete_assessment_and_evidence(assessment_id)
    st.session_state.pop("pending_delete_assessment", None)
    if st.session_state.get("current_assessment_id") == assessment_id:
        st.session_state.pop("current_assessment_id", None)
    remaining = list_assessments()
    if remaining:
        st.session_state["history_selected_scan"] = remaining[0]["id"]
    else:
        st.session_state.pop("history_selected_scan", None)
    st.session_state["history_delete_message"] = ("success" if deleted else "error", message)


def _make_assessment(targets: dict[str, str], scanners: list[str], scan_type: str, ports: str, wordlist: str,
                     burp_api_url: str, burp_api_key: str, burp_profile: str, *,
                     group_id: str | None = None, scan_number: int = 1,
                     scan_config: dict[str, Any] | None = None) -> str:
    label = " · ".join(f"{name}: {target}" for name, target in targets.items() if target)
    assessment = new_assessment(label, scanners, group_id=group_id, scan_number=scan_number, scan_config=scan_config)
    assessment["scanner_results"] = {
        scanner: {"status": "queued", "target": targets["nmap"] if scanner == "nmap" else targets["web"]}
        for scanner in scanners
    }
    save_assessment(assessment)
    worker = threading.Thread(
        target=_run_assessment_worker,
        args=(assessment["id"], targets, scanners, scan_type, ports, wordlist, burp_api_url, burp_api_key, burp_profile),
        name=f"scan-{assessment['id'][:8]}", daemon=True,
    )
    worker.start()
    return assessment["id"]


def _start_rescan(source: dict[str, Any]) -> str:
    scanners = list(source.get("scanners", []))
    source_results = source.get("scanner_results", {})
    targets: dict[str, str] = {}
    for scanner in scanners:
        target = str(source_results.get(scanner, {}).get("target", "")).strip()
        if target:
            targets["nmap" if scanner == "nmap" else "web"] = target
    if not scanners or any(("nmap" if scanner == "nmap" else "web") not in targets for scanner in scanners):
        raise ValueError("This assessment does not have enough saved target details to repeat its scans.")
    if any(source_results.get(scanner, {}).get("mode") == "imported report" for scanner in scanners):
        raise ValueError("Imported reports do not contain scan configuration to rerun. Start a new scan instead.")
    settings = load_app_settings()
    config = source.get("scan_config", {})
    return _make_assessment(
        targets, scanners, str(config.get("scan_type", "quick")), str(config.get("ports", "")),
        str(config.get("wordlist", "")), settings["burp_api_url"], settings["burp_api_key"],
        str(config.get("burp_profile", "Crawl and Audit - Lightweight")),
        group_id=str(source.get("group_id", source["id"])),
        scan_number=next_scan_number(str(source.get("group_id", source["id"]))),
        scan_config=config,
    )


def _run_assessment_worker(assessment_id: str, targets: dict[str, str], scanners: list[str], scan_type: str,
                           ports: str, wordlist: str, burp_api_url: str, burp_api_key: str, burp_profile: str) -> None:
    """Run scanner work off the Streamlit request and persist each state change."""
    for scanner in scanners:
        assessment = get_assessment(assessment_id)
        if not assessment:
            return
        target = targets["nmap"] if scanner == "nmap" else targets["web"]
        assessment["scanner_results"][scanner] = {"status": "running", "target": target, "detail": f"Starting {scanner.title()}"}
        save_assessment(assessment)

        def report_progress(message: str, scanner_name: str = scanner) -> None:
            latest = get_assessment(assessment_id)
            if not latest:
                return
            result = latest["scanner_results"].get(scanner_name, {})
            result["detail"] = message
            import re
            match = re.search(r"(\d{1,3})%", message)
            if match:
                result["progress"] = min(100, int(match.group(1)))
            latest["scanner_results"][scanner_name] = result
            save_assessment(latest)

        try:
            findings, raw_path = run_scan(
                scanner, target, scan_type=scan_type, ports=ports, wordlist=wordlist,
                burp_api_url=burp_api_url, burp_api_key=burp_api_key, burp_profile=burp_profile,
                on_progress=report_progress if scanner == "burp" else None,
            )
            assessment = get_assessment(assessment_id)
            if not assessment:
                return
            assessment["findings"].extend(findings)
            assessment["scanner_results"][scanner] = {
                "status": "complete", "target": target, "count": len(findings), "raw_path": raw_path, "progress": 100,
            }
        except Exception as exc:
            assessment = get_assessment(assessment_id)
            if not assessment:
                return
            assessment["scanner_results"][scanner] = {"status": "failed", "target": target, "error": str(exc), "progress": 100}
        assessment["status"] = "running"
        save_assessment(assessment)
    assessment = get_assessment(assessment_id)
    if assessment:
        completed = any(item.get("status") == "complete" for item in assessment["scanner_results"].values())
        assessment["status"] = "complete" if completed else "failed"
        save_assessment(assessment)


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
    if not findings:
        st.info("Run a scanner successfully before requesting AI analysis.")
        return
    st.subheader("Unified AI assessment")
    settings = load_app_settings()
    st.caption(f"Cloud model: **{settings['ai_model']}** · {settings['ai_base_url']}")
    st.caption("One analysis correlates every scanner’s findings and returns a prioritized remediation plan. Recommendations are advisory.")
    if not settings["ai_api_key"]:
        st.warning("Add the cloud provider API key in Settings before running an analysis.")
    st.warning("The configured online AI service receives normalized findings, scanner evidence, and coverage. Send them only when approved for this data.")
    allow_send = st.checkbox(
        "I reviewed the privacy choice and allow sending these assessment results to the configured cloud AI endpoint.",
        key=f"ai_allow_send_{assessment['id']}",
    )
    if st.button("Analyze all tool results", type="primary", disabled=not allow_send or not settings["ai_api_key"], key=f"analyze_all_{assessment['id']}"):
        analyses = assessment.setdefault("analyses", {})
        with st.spinner("Analyzing normalized findings…"):
            try:
                analyses["unified"] = analyze_assessment(
                    str(assessment.get("target", "")), findings, assessment.get("scanner_results", {}),
                    base_url=settings["ai_base_url"], model=settings["ai_model"], api_key=settings["ai_api_key"],
                )
            except AIAnalysisError as exc:
                analyses["unified"] = f"Analysis unavailable: {exc}"
            save_assessment(assessment)
        st.rerun()
    analyses = assessment.get("analyses", {})
    if analyses.get("unified"):
        st.markdown(str(analyses["unified"]))
    elif analyses:
        st.info("Existing per-scanner analyses are available in this assessment’s saved history.")


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
                with st.container(border=True):
                    left, middle, right = st.columns([1, 2, 2])
                    left.markdown(f"**{name.title()}**")
                    if result.get("status") == "complete":
                        middle.success(f"Complete · {result.get('count', 0)} findings")
                    elif result.get("status") == "failed":
                        middle.error(f"Failed · {result.get('error', 'Unknown error')}")
                    elif result.get("status") == "running":
                        middle.info(f"Running · {result.get('progress')}%" if result.get("progress") is not None else "Running")
                    else:
                        middle.caption("Queued")
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


@st.fragment(run_every=3)
def _dashboard_page() -> None:
    assessments = list_assessments()
    active = [item for item in assessments if item.get("status") == "running"]
    all_findings = sum(len(item.get("findings", [])) for item in assessments)
    st.markdown("<div class='eyebrow'>SECURITY OPERATIONS</div>", unsafe_allow_html=True)
    title, action = st.columns([4, 1])
    title.title("Security dashboard")
    if action.button("＋ New scan", type="primary", use_container_width=True, key="dashboard_new_scan",
                     on_click=_navigate_to, args=("New scan",)):
        st.rerun(scope="app")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Running scans", len(active))
    m2.metric("Saved assessments", len(assessments))
    m3.metric("Recorded findings", all_findings)
    m4.metric("Available tools", f"{sum(ready for ready, _ in scanner_availability().values())}/{len(SCANNERS)}")

    st.markdown("### Live scan progress")
    if not active:
        st.info("No scans are running. Start a new authorized scan to see per-tool progress here.")
    for assessment in active:
        results = assessment.get("scanner_results", {})
        done = sum(result.get("status") in {"complete", "failed"} for result in results.values())
        with st.container(border=True):
            header, view = st.columns([4, 1])
            header.markdown(f"**{assessment.get('target', 'Assessment')}** · `{assessment['id'][:8]}`")
            if view.button("Open", key=f"open_active_{assessment['id']}",
                           on_click=_open_assessment, args=(assessment["id"],)):
                st.rerun(scope="app")
            overall = done / max(1, len(results))
            st.progress(overall, text=f"{done} of {len(results)} tools finished")
            for scanner, result in results.items():
                status = result.get("status", "queued")
                cols = st.columns([1.1, 2.2, 2.7, 1])
                cols[0].markdown(f"**{scanner.title()}**")
                if status == "complete":
                    cols[1].success(f"Complete · {result.get('count', 0)} findings")
                elif status == "failed":
                    cols[1].error("Failed")
                elif status == "running":
                    cols[1].info("Running")
                else:
                    cols[1].caption("Queued")
                cols[2].caption(result.get("detail") or result.get("error") or result.get("target", ""))
                if status == "running" and result.get("progress") is not None:
                    cols[3].caption(f"{result['progress']}%")
                elif status == "running":
                    cols[3].caption("In progress")

    st.markdown("### Operations")
    tools_col, models_col = st.columns([1, 1])
    with tools_col:
        with st.container(border=True):
            st.markdown("#### Available tools")
            availability = scanner_availability()
            burp = load_app_settings()
            for name in SCANNERS:
                ready, detail = availability[name]
                if name == "burp":
                    ready = bool(burp["burp_api_url"] and burp["burp_api_key"])
                    detail = burp["burp_api_url"] if ready else "Configure REST API in Settings"
                badge = "Ready" if ready else "Setup needed"
                st.markdown(f"**{name.title()}** · {badge}")
                st.caption(detail)
    with models_col:
        with st.container(border=True):
            st.markdown("#### Online AI model")
            ai_settings = load_app_settings()
            st.markdown(f"**{ai_settings['ai_model']}**")
            st.caption(ai_settings["ai_base_url"])
            st.caption("API key configured" if ai_settings["ai_api_key"] else "API key not configured")
            if st.button("Configure cloud AI", key="dashboard_ai_settings",
                         on_click=_navigate_to, args=("Settings",)):
                st.rerun(scope="app")

    catalog_count = sum(len(category["tools"]) for category in TOOL_CATEGORIES)
    st.markdown("### Security tool catalog")
    st.caption(
        f"{len(TOOL_CATEGORIES)} categories · {catalog_count} tools. The catalog shows whether each item is "
        "directly integrated, import-only, installed but awaiting an adapter, or needs an API/agent connection."
    )
    tool_query = st.text_input("Filter tools", placeholder="Search by name, category, or capability…", key="dashboard_tool_filter").strip().casefold()
    catalog_availability = scanner_availability()
    catalog_settings = load_app_settings()
    for category in TOOL_CATEGORIES:
        visible_tools = [
            tool for tool in category["tools"]
            if not tool_query or tool_query in category["name"].casefold()
            or tool_query in tool["name"].casefold() or tool_query in tool["summary"].casefold()
        ]
        if not visible_tools:
            continue
        with st.expander(f"{category['name']} · {len(visible_tools)} tools", expanded=bool(tool_query)):
            for tool in visible_tools:
                state, detail = catalog_tool_status(tool, catalog_availability, catalog_settings)
                name_cell, summary_cell, status_cell = st.columns([1.2, 2.4, 2])
                name_cell.markdown(f"**[{tool['name']}]({tool['url']})**" if tool.get("url") else f"**{tool['name']}**")
                summary_cell.caption(tool["summary"])
                status_cell.caption(f"{state} · {detail}")

    st.markdown("### Recent assessments")
    for assessment in assessments[:5]:
        left, middle, right = st.columns([3, 1, 1])
        left.write(f"Run #{assessment.get('scan_number', 1)} · {_format_created(assessment.get('created_at', ''))} · {assessment.get('target', '')}")
        middle.caption(assessment.get("status", "unknown").title())
        if right.button("View", key=f"dashboard_history_{assessment['id']}",
                        on_click=_open_assessment, args=(assessment["id"],)):
            st.rerun(scope="app")
    if not assessments:
        st.caption("Your assessments will appear here after a scan or report import.")


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
        burp_profile = "Crawl and Audit - Lightweight"
        if "burp" in scanners:
            with st.expander("Burp Suite connection and scan profile", expanded=True):
                if burp_api_key:
                    st.success(f"Using saved Burp connection · {burp_api_url}")
                else:
                    st.warning("Burp connection is not configured. Add its service URL and API key on the Settings page.")
                burp_modes = {
                    "Lightweight": "Crawl and Audit - Lightweight",
                    "Fast": "Crawl and Audit - Fast",
                    "Balanced": "Crawl and Audit - Balanced",
                    "Deep": "Crawl and Audit - Deep",
                    "Custom": "",
                }
                burp_mode = st.selectbox(
                    "Burp Crawl & Audit configuration",
                    options=list(burp_modes),
                    index=0,
                    help="Choose how much time Burp spends crawling the site and auditing for vulnerabilities.",
                    key="burp_scan_mode",
                )
                if burp_mode == "Custom":
                    burp_profile = st.text_input(
                        "Saved custom configuration name",
                        placeholder="Enter the exact configuration name from Burp",
                        help="Import or save your custom configuration in Burp, then enter its exact name here.",
                        key="burp_custom_profile",
                    ).strip()
                    st.caption("Custom configurations must already exist in Burp's configuration library.")
                else:
                    burp_profile = burp_modes[burp_mode]
                    st.caption(f"Burp will run Crawl and Audit using: {burp_profile}")
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
            scan_config={"scan_type": scan_type, "ports": ports.strip(), "wordlist": wordlist.strip(), "burp_profile": burp_profile},
        )
        st.session_state["current_assessment_id"] = assessment_id
        st.rerun()
    current_id = st.session_state.get("current_assessment_id")
    if current_id:
        assessment = get_assessment(current_id)
        if assessment:
            st.button("View live progress on Dashboard", on_click=_navigate_to, args=("Dashboard",), key="assessment_dashboard_link")
            st.divider()
            _render_assessment(assessment)


def _settings_page() -> None:
    st.markdown("<div class='eyebrow'>CONNECTIONS</div>", unsafe_allow_html=True)
    st.title("Settings")
    st.write("Configure the cloud AI endpoint and scanner connections used by future assessments.")
    settings = load_app_settings()
    with st.container(border=True):
        st.subheader("Online AI analysis")
        st.caption("Use an HTTPS endpoint that implements the OpenAI chat completions and model-list APIs. The API key is saved locally in the ignored data/app-settings.json file.")
        ai_base_url = st.text_input("Cloud AI base URL", value=settings["ai_base_url"], key="settings_ai_base_url",
                                    placeholder="https://api.openai.com")
        ai_api_key = st.text_input("API key", value=settings["ai_api_key"], type="password", key="settings_ai_api_key")
        model_cache_key = f"settings_available_models_{ai_base_url}"
        models = st.session_state.get(model_cache_key, [])
        if st.button("Load available cloud models", key="settings_load_ai_models"):
            models = list_models(base_url=ai_base_url, api_key=ai_api_key)
            st.session_state[model_cache_key] = models
            if models:
                st.success(f"Found {len(models)} model(s). Choose one below.")
            else:
                st.warning("No models were returned. Check the HTTPS endpoint and API key; you can still enter the exact model name.")
            st.rerun()
        if models:
            st.caption("Models advertised by this provider (copy the exact chat-capable model ID into the field below):")
            st.code("\n".join(models), language=None)
        ai_model = st.text_input("Model name", value=settings["ai_model"], key="settings_ai_model_text",
                                 help="This value is sent unchanged to the chat completions API.")
        if st.button("Save cloud AI settings", type="primary", key="save_ai_settings"):
            try:
                save_ai_settings(ai_base_url.strip(), ai_model, ai_api_key)
                st.success("Cloud AI settings saved. The API key is stored locally and reused for analysis.")
            except (OSError, ValueError) as exc:
                st.error(f"Could not save cloud AI settings: {exc}")

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

    if settings["ai_api_key"] and st.button("Forget cloud AI API key", key="forget_ai_api_key"):
        try:
            save_ai_settings(settings["ai_base_url"], settings["ai_model"], "")
            st.success("Cloud AI API key removed from local settings.")
            st.rerun()
        except (OSError, ValueError) as exc:
            st.error(f"Could not remove cloud AI API key: {exc}")


def _history_page() -> None:
    st.title("Assessment history")
    message = st.session_state.pop("history_rerun_message", None)
    if message:
        (st.success if message[0] == "success" else st.error)(message[1])
    message = st.session_state.pop("history_delete_message", None)
    if message:
        (st.success if message[0] == "success" else st.error)(message[1])
    assessments = list_assessments()
    if not assessments:
        st.info("No assessments saved yet. Start one from the New scan page.")
        return
    labels = {
        item["id"]: f"#{item.get('scan_number', 1)} · {_format_created(item['created_at'])} · {item['target']} · {item['status']}"
        for item in assessments
    }
    ids = list(labels)
    default_id = st.session_state.get("current_assessment_id", ids[0])
    index = ids.index(default_id) if default_id in ids else 0
    selected_id = st.selectbox("Saved scans", ids, index=index, format_func=lambda value: labels[value], key="history_selected_scan")
    assessment = get_assessment(selected_id)
    if assessment:
        st.session_state["current_assessment_id"] = selected_id
        lineage = list_assessment_scans(assessment.get("group_id", assessment["id"]))
        st.markdown(f"#### Target scan history · {len(lineage)} run(s)")
        for scan in lineage:
            st.caption(f"Run #{scan.get('scan_number', 1)} · {_format_created(scan['created_at'])} · {scan['status'].title()} · {len(scan.get('findings', []))} findings · `{scan['id'][:8]}`")

        action_cols = st.columns(3)
        imported = any(item.get("mode") == "imported report" for item in assessment.get("scanner_results", {}).values())
        can_rerun = assessment.get("status") != "running" and not imported and bool(assessment.get("scanners"))
        rerun_authorized = st.checkbox(
            "I confirm this target is still authorized for another scan.",
            key=f"rerun_authorized_{assessment['id']}", disabled=not can_rerun,
        )
        action_cols[0].button(
            "Re-run scan", type="primary", disabled=not (can_rerun and rerun_authorized),
            key=f"rerun_scan_{assessment['id']}", on_click=_rerun_from_history, args=(assessment["id"],),
        )
        if action_cols[2].button("Delete scan", disabled=assessment.get("status") == "running", key=f"request_delete_{assessment['id']}"):
            st.session_state["pending_delete_assessment"] = assessment["id"]
            st.rerun()
        if st.session_state.get("pending_delete_assessment") == assessment["id"]:
            st.warning("Delete this scan record and its saved raw scanner files? This cannot be undone.")
            confirm_col, cancel_col = st.columns(2)
            confirm_delete = st.checkbox("Confirm permanent deletion", key=f"confirm_delete_{assessment['id']}")
            confirm_col.button(
                "Permanently delete scan", disabled=not confirm_delete,
                key=f"confirm_delete_button_{assessment['id']}",
                on_click=_confirm_delete_from_history, args=(assessment["id"],),
            )
            if cancel_col.button("Cancel", key=f"cancel_delete_{assessment['id']}"):
                st.session_state.pop("pending_delete_assessment", None)
                st.rerun()
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
        st.title("🛡️ Cyber AI Agent")
        st.caption("SECURITY OPERATIONS WORKSPACE")
        st.markdown("---")
        page = st.radio("Workspace", ["Dashboard", "New scan", "Import reports", "Assessment history", "Settings"], key="workspace_page", index=0, label_visibility="collapsed")
        st.divider()
        st.caption("Scans start only after you confirm authorization and submit.")
        st.markdown("---")
        st.caption(f"{len(list_assessments())} saved assessments")
    if page == "Dashboard":
        _dashboard_page()
    elif page == "New scan":
        _new_assessment_page()
    elif page == "Import reports":
        _import_reports_page()
    elif page == "Settings":
        _settings_page()
    else:
        _history_page()


if __name__ == "__main__":
    main()
