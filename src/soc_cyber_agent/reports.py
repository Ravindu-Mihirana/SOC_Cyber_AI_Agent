"""Export an assessment as standalone HTML or PDF bytes."""

import html
import io
from datetime import datetime
from typing import Any


def _summary(assessment: dict[str, Any]) -> str:
    successful = [name for name, result in assessment.get("scanner_results", {}).items() if result.get("status") == "complete"]
    failed = [name for name, result in assessment.get("scanner_results", {}).items() if result.get("status") == "failed"]
    return f"Scanners completed: {', '.join(successful) or 'none'}. Scanners failed: {', '.join(failed) or 'none'}. Total normalized findings: {len(assessment.get('findings', []))}."


def render_html(assessment: dict[str, Any]) -> bytes:
    findings = assessment.get("findings", [])
    analyses = assessment.get("analyses", {})
    cards = []
    for finding in findings:
        evidence = html.escape(str(finding.get("evidence", "")))
        cards.append(f"""<tr>
          <td>{html.escape(str(finding.get('severity', 'unknown')).upper())}</td>
          <td>{html.escape(str(finding.get('source_tool', '')))}</td>
          <td>{html.escape(str(finding.get('host', '')))}{':' + str(finding.get('port')) if finding.get('port') else ''}</td>
          <td>{html.escape(str(finding.get('title', '')))}<small>{html.escape(str(finding.get('description', '')))}</small><code>{evidence}</code></td>
        </tr>""")
    analysis_html = "".join(
        f"<section><h3>{html.escape(scanner.title())} analysis</h3><pre>{html.escape(str(content))}</pre></section>"
        for scanner, content in analyses.items()
    )
    date = html.escape(str(assessment.get("created_at", "")))
    body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security assessment — {html.escape(str(assessment.get('target', '')))}</title>
<style>
body{{font:15px/1.55 system-ui,Segoe UI,sans-serif;color:#182230;background:#f4f7fb;margin:0;padding:36px}}main{{max-width:1100px;margin:auto;background:white;padding:34px;border-radius:16px;box-shadow:0 8px 32px #1c355210}}h1{{margin-bottom:4px}}.muted,small{{color:#617083}}.summary{{padding:18px;background:#edf5ff;border-left:4px solid #2563eb;border-radius:8px}}table{{width:100%;border-collapse:collapse;margin-top:18px}}th,td{{text-align:left;vertical-align:top;padding:12px;border-bottom:1px solid #e5eaf0}}th{{background:#f7f9fc}}small{{display:block;margin-top:5px}}code{{display:block;white-space:pre-wrap;color:#44536a;margin-top:7px}}pre{{white-space:pre-wrap;background:#f7f9fc;padding:16px;border-radius:8px}}@media print{{body{{background:#fff;padding:0}}main{{box-shadow:none;max-width:none}}}}
</style></head><body><main><h1>Security assessment</h1><div class="muted">{date} · {html.escape(str(assessment.get('target', '')))}</div>
<p class="summary">{html.escape(_summary(assessment))}</p>{analysis_html}<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Scanner</th><th>Asset</th><th>Observation</th></tr></thead><tbody>{''.join(cards) or '<tr><td colspan="4">No findings recorded.</td></tr>'}</tbody></table>
<p class="muted">Scanner output is evidence for analyst review. AI-generated analysis is advisory and should be validated.</p></main></body></html>"""
    return body.encode("utf-8")


def render_pdf(assessment: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=landscape(A4), rightMargin=14 * mm, leftMargin=14 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm, title="Security assessment")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7.5, leading=10, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="Evidence", parent=styles["BodyText"], fontSize=7, leading=9, textColor=colors.HexColor("#56657a")))
    story = [Paragraph("Security assessment", styles["Title"]), Spacer(1, 3 * mm)]
    story.append(Paragraph(f"<b>Target:</b> {escape(str(assessment.get('target', '')))}", styles["BodyText"]))
    story.append(Paragraph(f"<b>Created:</b> {escape(str(assessment.get('created_at', '')))}", styles["BodyText"]))
    story.append(Paragraph(escape(_summary(assessment)), styles["BodyText"]))
    story.append(Spacer(1, 5 * mm))
    for scanner, content in assessment.get("analyses", {}).items():
        story.append(Paragraph(f"{escape(scanner.title())} analysis", styles["Heading2"]))
        for line in str(content).splitlines():
            safe_line = escape(line) if line.strip() else "&nbsp;"
            story.append(Paragraph(safe_line, styles["SmallCell"]))
        story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Findings", styles["Heading2"]))
    rows: list[list[Any]] = [[Paragraph("Severity", styles["SmallCell"]), Paragraph("Scanner", styles["SmallCell"]),
                              Paragraph("Asset", styles["SmallCell"]), Paragraph("Finding / evidence", styles["SmallCell"])]]
    for finding in assessment.get("findings", []):
        asset = str(finding.get("host", ""))
        if finding.get("port"):
            asset += f":{finding['port']}/{finding.get('protocol', '')}"
        detail = f"<b>{escape(str(finding.get('title', '')))}</b><br/>{escape(str(finding.get('description', '')))}<br/><font color='#56657a'>{escape(str(finding.get('evidence', '')))}</font>"
        rows.append([Paragraph(escape(str(finding.get("severity", "unknown")).upper()), styles["SmallCell"]),
                     Paragraph(escape(str(finding.get("source_tool", ""))), styles["SmallCell"]),
                     Paragraph(escape(asset), styles["SmallCell"]), Paragraph(detail, styles["SmallCell"])])
    table = Table(rows, colWidths=[24 * mm, 27 * mm, 42 * mm, 170 * mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf0f8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17263c")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d8e0ea")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([table, Spacer(1, 4 * mm), Paragraph("AI analysis is advisory. Validate findings using scanner evidence and analyst review.", styles["SmallCell"])])
    doc.build(story)
    return output.getvalue()
