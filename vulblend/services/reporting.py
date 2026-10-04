"""Professional export helpers for the Reports module."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..config import REPORT_DIR
from ..db import insert, new_id, now_iso


def report_payload(application: dict, scan: dict, findings: list[dict], experiments: list[dict] | None = None) -> dict:
    return {"project": "VulnBlend", "data_notice": "Results are derived from stored analysis or explicitly labelled demo data.", "application": dict(application), "scan": dict(scan), "findings": [dict(row) for row in findings], "experiments": [dict(row) for row in (experiments or [])], "generated_at": now_iso()}


def generate_json(payload: dict, application_id: str | None = None, scan_id: str | None = None) -> tuple[str, bytes]:
    filename = f"vulnblend_{now_iso().replace(':', '').replace('+00:00', 'Z')}.json"
    content = json.dumps(payload, indent=2, default=str).encode()
    path = REPORT_DIR / filename
    path.write_bytes(content)
    insert("reports", {"id": new_id("rep_"), "application_id": application_id, "scan_id": scan_id, "report_type": "JSON", "file_name": filename, "file_path": str(path), "created_at": now_iso()})
    return filename, content


def generate_csv(findings: list[dict], application_id: str | None = None, scan_id: str | None = None) -> tuple[str, bytes]:
    filename = f"vulnblend_findings_{now_iso().replace(':', '').replace('+00:00', 'Z')}.csv"
    output = io.StringIO()
    fields = ["id", "title", "finding_type", "severity", "verification_status", "correlation_status", "endpoint", "parameter", "file_path", "line_number", "confidence", "status", "data_origin"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader(); writer.writerows(findings)
    content = output.getvalue().encode()
    path = REPORT_DIR / filename; path.write_bytes(content)
    insert("reports", {"id": new_id("rep_"), "application_id": application_id, "scan_id": scan_id, "report_type": "CSV", "file_name": filename, "file_path": str(path), "created_at": now_iso()})
    return filename, content


def generate_pdf(payload: dict, application_id: str | None = None, scan_id: str | None = None) -> tuple[str, bytes]:
    filename = f"vulnblend_assessment_{now_iso().replace(':', '').replace('+00:00', 'Z')}.pdf"
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet(); story = [Paragraph("VulnBlend Security Assessment", styles["Title"]), Paragraph("Controlled laboratory report — evidence is minimized and demo rows are labelled.", styles["Normal"]), Spacer(1, 12)]
    app = payload.get("application", {})
    story.append(Paragraph(f"Application: {app.get('name', 'Unknown')} · Environment: {app.get('environment', 'unknown')}", styles["Heading2"]))
    story.append(Paragraph(f"Generated: {payload.get('generated_at')} · Findings: {len(payload.get('findings', []))}", styles["Normal"]))
    data = [["Type", "Severity", "Verification", "Risk", "Endpoint"]]
    for finding in payload.get("findings", []):
        data.append([finding.get("finding_type"), finding.get("severity"), finding.get("verification_status"), str(finding.get("score", "—")), finding.get("endpoint", "—")])
    table = Table(data, colWidths=[90, 70, 90, 45, 160]); table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#172554")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .25, colors.HexColor("#CBD5E1")), ("FONTSIZE", (0,0), (-1,-1), 8), ("VALIGN", (0,0), (-1,-1), "TOP")]))
    story.extend([Spacer(1, 12), table])
    doc.build(story)
    content = buffer.getvalue(); path = REPORT_DIR / filename; path.write_bytes(content)
    insert("reports", {"id": new_id("rep_"), "application_id": application_id, "scan_id": scan_id, "report_type": "PDF", "file_name": filename, "file_path": str(path), "created_at": now_iso()})
    return filename, content
