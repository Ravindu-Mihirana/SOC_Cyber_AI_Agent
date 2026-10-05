"""Export an assessment as a polished standalone HTML or PDF report."""

import html
import io
from typing import Any


SEVERITIES = ("critical", "high", "medium", "low", "info")


def _summary(assessment: dict[str, Any]) -> str:
    results = assessment.get("scanner_results", {})
    completed = sum(result.get("status") == "complete" for result in results.values())
    failed = sum(result.get("status") == "failed" for result in results.values())
    return f"{completed} scanner(s) completed · {failed} failed · {len(assessment.get('findings', []))} normalized findings"


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {level: sum(str(item.get("severity", "info")).lower() == level for item in findings) for level in SEVERITIES}


def render_html(assessment: dict[str, Any]) -> bytes:
    findings = assessment.get("findings", [])
    analyses = assessment.get("analyses", {})
    counts = _counts(findings)
    target = html.escape(str(assessment.get("target", "Unknown target")))
    created = html.escape(str(assessment.get("created_at", "")))
    status = html.escape(str(assessment.get("status", "unknown")).title())
    scan_number = assessment.get("scan_number", 1)
    chips = "".join(f'<div class="metric {level}"><b>{count}</b><span>{level.title()}</span></div>' for level, count in counts.items())
    scanner_rows = "".join(
        f'<tr><td>{html.escape(name.title())}</td><td><span class="pill {html.escape(str(result.get("status", "unknown")))}">{html.escape(str(result.get("status", "unknown")).title())}</span></td><td>{int(result.get("count", 0))}</td><td>{html.escape(str(result.get("error", result.get("target", ""))))}</td></tr>'
        for name, result in assessment.get("scanner_results", {}).items()
    ) or '<tr><td colspan="4" class="empty">No scanner activity recorded.</td></tr>'
    finding_cards = []
    for item in sorted(findings, key=lambda row: SEVERITIES.index(str(row.get("severity", "info")).lower()) if str(row.get("severity", "info")).lower() in SEVERITIES else len(SEVERITIES)):
        severity = str(item.get("severity", "unknown")).lower()
        asset = str(item.get("host", "")) + (f":{item['port']}" if item.get("port") else "")
        evidence = item.get("evidence")
        finding_cards.append(f'''<article class="finding"><div class="finding-top"><span class="pill {html.escape(severity)}">{html.escape(severity.upper())}</span><span class="muted">{html.escape(str(item.get("source_tool", "Unknown scanner")))}</span></div>
<h3>{html.escape(str(item.get("title", "Untitled finding")))}</h3><p>{html.escape(str(item.get("description", "No description provided.")))}</p>
<div class="asset"><b>Asset</b> {html.escape(asset or "Not specified")}</div>{f'<details><summary>Evidence</summary><pre>{html.escape(str(evidence))}</pre></details>' if evidence else ''}</article>''')
    analysis_sections = "".join(f'<section class="analysis"><h3>{html.escape(str(name).title())}</h3><pre>{html.escape(str(content))}</pre></section>' for name, content in analyses.items())
    body = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security assessment — {target}</title>
<style>
:root{{--ink:#142033;--muted:#64748b;--line:#dce4ee;--paper:#fff;--bg:#f2f5f9;--blue:#1d4ed8}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,Segoe UI,sans-serif}}main{{max-width:1100px;margin:32px auto;padding:0 24px 40px}}.hero{{background:linear-gradient(120deg,#101c32,#19365e);color:white;border-radius:16px;padding:32px}}.eyebrow{{text-transform:uppercase;letter-spacing:.14em;font-size:11px;color:#b8cae4}}h1{{font-size:30px;line-height:1.2;margin:8px 0}}.meta{{color:#cad6e6;display:flex;gap:16px;flex-wrap:wrap}}.summary{{margin:20px 0 0;padding:12px 16px;border:1px solid #ffffff35;border-radius:9px;background:#ffffff0d}}section,.panel{{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:18px}}h2{{margin:0 0 14px;font-size:19px}}.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}}.metric{{padding:14px;border-radius:9px;background:#f7f9fc;border-top:3px solid #94a3b8}}.metric b{{display:block;font-size:24px}}.metric span{{color:var(--muted)}}.critical{{border-color:#dc2626;color:#b91c1c}}.high{{border-color:#ea580c;color:#c2410c}}.medium{{border-color:#d97706;color:#a16207}}.low{{border-color:#2563eb;color:#1d4ed8}}.info{{border-color:#64748b;color:#475569}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}}th{{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}}.pill{{display:inline-block;border-radius:99px;padding:3px 9px;background:#edf2f8;color:#334155;font-size:11px;font-weight:700}}.pill.complete{{background:#dcfce7;color:#166534}}.pill.failed{{background:#fee2e2;color:#991b1b}}.pill.running{{background:#dbeafe;color:#1e40af}}.finding{{padding:16px 0;border-bottom:1px solid var(--line);break-inside:avoid}}.finding:last-child{{border:0}}.finding-top{{display:flex;justify-content:space-between}}h3{{margin:8px 0 4px}}p{{margin:6px 0 12px}}.muted{{color:var(--muted)}}.asset{{font-size:12px;color:#475569}}details{{margin-top:10px}}summary{{cursor:pointer;color:var(--blue)}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f8fb;border:1px solid var(--line);padding:12px;border-radius:8px;font:12px/1.5 ui-monospace,Consolas,monospace;color:#334155}}.notice{{color:var(--muted);font-size:12px}}.empty{{color:var(--muted)}}@media(max-width:680px){{main{{padding:0 12px 24px;margin:12px auto}}.hero{{padding:22px}}.metrics{{grid-template-columns:repeat(2,1fr)}}table{{font-size:12px}}}}@media print{{body{{background:#fff}}main{{max-width:none;margin:0;padding:0}}.hero{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}section,.panel{{break-inside:avoid;box-shadow:none}}details>pre{{display:block}}}}
</style></head><body><main><header class="hero"><div class="eyebrow">Security assessment · Run #{scan_number}</div><h1>{target}</h1><div class="meta"><span>{created}</span><span>Status: {status}</span><span>ID: {html.escape(str(assessment.get('id', ''))[:8])}</span></div><div class="summary">{html.escape(_summary(assessment))}</div></header>
<section><h2>Risk overview</h2><div class="metrics">{chips}</div></section>
<section><h2>Scanner coverage</h2><table><thead><tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Target / note</th></tr></thead><tbody>{scanner_rows}</tbody></table></section>
<section><h2>Findings</h2>{''.join(finding_cards) or '<p class="empty">No findings recorded for this assessment.</p>'}</section>
{f'<section><h2>AI analysis</h2>{analysis_sections}</section>' if analysis_sections else ''}
<p class="notice">Scanner output is evidence for analyst review. AI-generated recommendations are advisory and must be validated before remediation.</p></main></body></html>'''
    return body.encode("utf-8")


def render_pdf(assessment: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    output = io.BytesIO()
    navy = colors.HexColor("#142744")
    muted = colors.HexColor("#64748b")
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=17 * mm, leftMargin=17 * mm,
                            topMargin=18 * mm, bottomMargin=17 * mm, title="Security assessment",
                            author="SOC Cyber AI Agent")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportMeta", parent=styles["BodyText"], fontSize=9, leading=13, textColor=muted))
    styles.add(ParagraphStyle(name="ReportSection", parent=styles["Heading2"], fontSize=15, leading=19, textColor=navy, spaceBefore=8 * mm, spaceAfter=3 * mm, keepWithNext=True))
    styles.add(ParagraphStyle(name="ReportCell", parent=styles["BodyText"], fontSize=8, leading=11, alignment=TA_LEFT, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="ReportEvidence", parent=styles["BodyText"], fontSize=7, leading=9, textColor=muted, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="ReportFinding", parent=styles["Heading3"], fontSize=10, leading=13, textColor=navy, spaceAfter=2, keepWithNext=True))
    story = [Paragraph("SECURITY ASSESSMENT", styles["Title"]),
             Paragraph(escape(str(assessment.get("target", "Unknown target"))), styles["Heading2"]),
             Paragraph(f"Run #{assessment.get('scan_number', 1)} · {escape(str(assessment.get('status', 'unknown')).title())} · {escape(str(assessment.get('created_at', '')))}", styles["ReportMeta"]),
             Paragraph(escape(_summary(assessment)), styles["ReportMeta"]), Spacer(1, 4 * mm)]

    story.append(Paragraph("Risk overview", styles["ReportSection"]))
    counts = _counts(assessment.get("findings", []))
    count_cells = [[Paragraph(f"<b>{count}</b><br/>{level.title()}", styles["ReportCell"]) for level, count in counts.items()]]
    metrics = Table(count_cells, colWidths=[(A4[0] - 34 * mm) / 5] * 5)
    metrics.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f4f9")), ("BOX", (0, 0), (-1, -1), .4, colors.HexColor("#dce4ee")), ("INNERGRID", (0, 0), (-1, -1), .4, colors.white), ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    story.append(metrics)

    story.append(Paragraph("Scanner coverage", styles["ReportSection"]))
    scan_rows = [["Scanner", "Status", "Findings", "Target / note"]]
    for name, result in assessment.get("scanner_results", {}).items():
        note = str(result.get("error", result.get("target", "")))
        scan_rows.append([
            Paragraph(escape(str(name).title()), styles["ReportCell"]),
            Paragraph(escape(str(result.get("status", "unknown")).title()), styles["ReportCell"]),
            str(result.get("count", 0)),
            Paragraph(escape(note), styles["ReportCell"]),
        ])
    coverage = Table(scan_rows, colWidths=[29 * mm, 24 * mm, 20 * mm, 119 * mm], repeatRows=1, hAlign="LEFT")
    coverage.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#dce4ee")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(coverage)

    story.append(Paragraph("Findings", styles["ReportSection"]))
    findings = assessment.get("findings", [])
    if not findings:
        story.append(Paragraph("No findings recorded for this assessment.", styles["ReportCell"]))
    for index, item in enumerate(findings, 1):
        severity = escape(str(item.get("severity", "unknown")).upper())
        title = escape(str(item.get("title", "Untitled finding")))
        asset = str(item.get("host", "")) + (f":{item['port']}" if item.get("port") else "")
        details = [Paragraph(f"{index}. [{severity}] {title}", styles["ReportFinding"]),
                   Paragraph(f"<b>Scanner:</b> {escape(str(item.get('source_tool', 'Unknown')))} &nbsp; <b>Asset:</b> {escape(asset or 'Not specified')}", styles["ReportCell"]),
                   Paragraph(escape(str(item.get("description", "No description provided."))), styles["ReportCell"])]
        if item.get("evidence"):
            details.append(Paragraph(f"<b>Evidence:</b> {escape(str(item['evidence']))}", styles["ReportEvidence"]))
        story.append(KeepTogether(details))
        story.append(Spacer(1, 2 * mm))

    for scanner, content in assessment.get("analyses", {}).items():
        story.append(Paragraph(f"{escape(str(scanner).title())} analysis", styles["ReportSection"]))
        for line in str(content).splitlines():
            story.append(Paragraph(escape(line) if line.strip() else "&nbsp;", styles["ReportCell"]))
    story.extend([Spacer(1, 5 * mm), Paragraph("AI-generated analysis and recommendations are advisory. Validate findings using scanner evidence and analyst review before remediation.", styles["ReportMeta"])])

    def footer(canvas: Any, doc_template: Any) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#dce4ee"))
        canvas.line(17 * mm, 13 * mm, A4[0] - 17 * mm, 13 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(muted)
        canvas.drawString(17 * mm, 8 * mm, "SOC Cyber AI Agent · Confidential assessment")
        canvas.drawRightString(A4[0] - 17 * mm, 8 * mm, f"Page {doc_template.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
