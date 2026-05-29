import tempfile
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

_DARK   = colors.HexColor("#0f172a")
_CYAN   = colors.HexColor("#0891b2")
_LIGHT  = colors.HexColor("#f1f5f9")
_GREY   = colors.HexColor("#e2e8f0")
_GREEN  = colors.HexColor("#065f46")

_SEV_COLOR = {
    "critical": colors.HexColor("#7f1d1d"),
    "high":     colors.HexColor("#9a3412"),
    "medium":   colors.HexColor("#92400e"),
    "low":      colors.HexColor("#1e3a8a"),
}


def generate_pdf(scan: dict, findings: list) -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp.close()

    doc    = SimpleDocTemplate(tmp.name, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # ── Cover ───────────────────────────────────────────────────────
    title_s = ParagraphStyle("t", parent=styles["Title"],
                              textColor=_DARK, fontSize=22, spaceAfter=4)
    sub_s   = ParagraphStyle("s", parent=styles["Normal"],
                              textColor=_CYAN, fontSize=11, spaceAfter=2)
    story.append(Paragraph("Team Cyber — Security Assessment Report", title_s))
    story.append(Paragraph("Autonomous Multi-Agent Vulnerability Analysis", sub_s))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_CYAN))
    story.append(Spacer(1, 0.5*cm))

    created = scan.get("created_at", datetime.utcnow())
    if isinstance(created, str):
        created = datetime.fromisoformat(created)

    meta = [
        ["Project",    scan.get("project_name", "Unknown")],
        ["Scan ID",    str(scan.get("_id", ""))],
        ["Date",       created.strftime("%Y-%m-%d %H:%M UTC")],
        ["Source",     f"{scan.get('source_type','').upper()} — {scan.get('source_value','')}"],
        ["Tech Stack", ", ".join(scan.get("tech_stack", [])) or "—"],
        ["Status",     scan.get("status", "").upper()],
    ]
    _add_table(story, meta, [4.5*cm, 12*cm])
    story.append(Spacer(1, 0.8*cm))

    # ── Executive Summary ───────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    story.append(Spacer(1, 0.3*cm))

    c = scan.get("findings_count", {})
    comp = scan.get("compliance_results", {})
    summary = [
        ["Severity",              "Count"],
        ["Critical",              str(c.get("critical", 0))],
        ["High",                  str(c.get("high",     0))],
        ["Medium",                str(c.get("medium",   0))],
        ["Low",                   str(c.get("low",      0))],
        ["Total Findings",        str(sum(c.values()))],
        ["OWASP Compliance Score", f"{comp.get('score', 'N/A')}%"],
    ]
    tbl = Table(summary, colWidths=[9*cm, 7.5*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("GRID",          (0, 0), (-1, -1), 0.4, _GREY),
        ("ROWBACKGROUNDS",(1, 1), (-1, -2), [colors.white, colors.HexColor("#f8fafc")]),
        ("FONTNAME",      (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND",    (0, -1), (-1, -1), colors.HexColor("#ecfdf5")),
        ("TEXTCOLOR",     (0, -1), (-1, -1), _GREEN),
    ]))
    story.append(tbl)
    story.append(PageBreak())

    # ── OWASP Top 10 ───────────────────────────────────────────────
    if comp.get("categories"):
        _add_compliance_table(
            story, styles,
            "OWASP Top 10 2021",
            comp["categories"],
            f"Score: {comp.get('score','?')}% — "
            f"{comp.get('passed',0)} passed / {comp.get('failed',0)} failed",
            col_widths=[2.5*cm, 11*cm, 3*cm],
        )
        story.append(PageBreak())

    # ── CWE Top 25 ─────────────────────────────────────────────────
    cwe_data = comp.get("cwe_top25", {})
    if cwe_data.get("categories"):
        _add_compliance_table(
            story, styles,
            "CWE Top 25 Most Dangerous Weaknesses (2023)",
            cwe_data["categories"],
            f"Score: {cwe_data.get('score','?')}% — "
            f"{cwe_data.get('passed',0)} passed / {cwe_data.get('failed',0)} failed",
            col_widths=[2.5*cm, 11*cm, 3*cm],
        )
        story.append(PageBreak())

    # ── PCI-DSS v4.0 ───────────────────────────────────────────────
    pci_data = comp.get("pci_dss", {})
    if pci_data.get("categories"):
        _add_compliance_table(
            story, styles,
            "PCI-DSS v4.0 (Key Requirements)",
            pci_data["categories"],
            f"Score: {pci_data.get('score','?')}% — "
            f"{pci_data.get('passed',0)} passed / {pci_data.get('failed',0)} failed",
            col_widths=[2.5*cm, 10*cm, 4*cm],
        )
        story.append(PageBreak())

    # ── NIST SP 800-53 Rev 5 ───────────────────────────────────────
    nist_data = comp.get("nist_800_53", {})
    if nist_data.get("categories"):
        _add_compliance_table(
            story, styles,
            "NIST SP 800-53 Rev 5 (Control Families)",
            nist_data["categories"],
            f"Score: {nist_data.get('score','?')}% — "
            f"{nist_data.get('passed',0)} passed / {nist_data.get('failed',0)} failed",
            col_widths=[2*cm, 11.5*cm, 3*cm],
        )
        story.append(PageBreak())

    # ── Detailed Findings ───────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", styles["Heading1"]))
    story.append(Spacer(1, 0.4*cm))

    h2_s   = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=11, textColor=_DARK)
    body_s = ParagraphStyle("b",  parent=styles["Normal"],   fontSize=9,  leading=13)

    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "low").lower()
        sc    = _SEV_COLOR.get(sev, colors.grey)
        conf  = f.get("confidence", 0)

        story.append(Paragraph(
            f'{i}. {f.get("vulnerability","Unknown")} '
            f'<font color="#{sc.hexval()[2:]}"><b>[{sev.upper()}]</b></font>',
            h2_s,
        ))

        detail = [
            ["Confidence", f"{conf*100:.0f}%"],
            ["Location",   f'{f.get("location","—")}{f":"+str(f["line"]) if f.get("line") else ""}'],
            ["Tool",       f.get("tool", "—")],
            ["CVE",        f.get("cve", "—")],
            ["OWASP",      f.get("owasp", "—")],
            ["Verified",   "Yes" if f.get("verified") else "Pending"],
        ]
        _add_table(story, detail, [4.5*cm, 12*cm])
        story.append(Spacer(1, 0.2*cm))

        for label, key in [("Root Cause","root_cause"),("Impact","impact"),("Recommended Fix","fix")]:
            if f.get(key):
                story.append(Paragraph(f"<b>{label}:</b> {f[key]}", body_s))

        if f.get("code_snippet"):
            story.append(Paragraph("<b>Code Snippet:</b>", body_s))
            story.append(Paragraph(
                f'<font face="Courier" size="8">{f["code_snippet"][:500]}</font>', body_s,
            ))

        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=0.4, color=_GREY))
        story.append(Spacer(1, 0.5*cm))

    doc.build(story)
    return tmp.name


def _add_table(story, rows, col_widths):
    tbl = Table(rows, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), _LIGHT),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("GRID",         (0, 0), (-1, -1), 0.3, _GREY),
        ("TEXTCOLOR",    (0, 0), (-1, -1), _DARK),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)


def _add_compliance_table(story, styles, title: str, categories: dict,
                          subtitle: str, col_widths):
    """Render any compliance framework (OWASP / CWE / PCI-DSS / NIST) as a table."""
    _PASS_COLOR = colors.HexColor("#065f46")
    _FAIL_COLOR = colors.HexColor("#7f1d1d")

    story.append(Paragraph(title, styles["Heading1"]))
    story.append(Paragraph(subtitle, ParagraphStyle(
        "sub", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor("#64748b"), spaceAfter=6,
    )))
    story.append(Spacer(1, 0.2*cm))

    rows = [["ID / Req", "Name", "Status"]]
    row_styles = [
        ("BACKGROUND",    (0, 0), (-1, 0), _DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("GRID",          (0, 0), (-1, -1), 0.3, _GREY),
        ("ROWBACKGROUNDS",(1, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]

    for i, (cat_id, info) in enumerate(categories.items(), start=1):
        passing     = info.get("status", "pass") == "pass"
        status_text = "✓ PASS" if passing else "✗ FAIL"
        findings    = info.get("findings", [])
        name_text   = info.get("name", "")
        if not passing and findings:
            name_text += f"\n  → {', '.join(findings[:3])}" \
                         + (f" +{len(findings)-3} more" if len(findings) > 3 else "")

        rows.append([cat_id, name_text, status_text])
        color = _PASS_COLOR if passing else _FAIL_COLOR
        row_styles.append(("TEXTCOLOR", (2, i), (2, i), color))
        row_styles.append(("FONTNAME",  (2, i), (2, i), "Helvetica-Bold"))

    tbl = Table(rows, colWidths=col_widths)
    tbl.setStyle(TableStyle(row_styles))
    story.append(tbl)
