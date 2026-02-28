"""
PDF Compliance Report Generator
================================

Generates professional PDF compliance reports with:
  - Executive summary + overall risk score
  - Per-framework compliance breakdown (CIS, SOC 2, PCI-DSS)
  - Findings table with severity and remediation status
  - Recommendations

Usage:
    from report_generator import generate_report
    pdf_bytes = generate_report(events, stats)
"""

import os
import sys
from datetime import datetime, timezone
from fpdf import FPDF

# Add shared modules to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda", "shared"))
try:
    from compliance import get_compliance_summary, get_compliance_for_event, COMPLIANCE_MAP
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda", "shared"))
    from compliance import get_compliance_summary, get_compliance_for_event, COMPLIANCE_MAP


class CSPMReport(FPDF):
    """Custom PDF with CSPM branding."""

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "Serverless CSPM - Compliance Report", align="R")
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}", align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(27, 27, 58)
        self.cell(0, 10, title)
        self.ln(8)
        self.set_draw_color(0, 120, 212)
        self.set_line_width(0.5)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(6)

    def subsection_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(50, 50, 50)
        self.cell(0, 8, title)
        self.ln(6)

    def body_text(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(60, 60, 60)
        self.multi_cell(0, 5, text)
        self.ln(3)

    def risk_score_badge(self, score):
        """Draw a large risk score circle."""
        x, y = 85, self.get_y() + 5
        radius = 18

        if score >= 80:
            r, g, b = 16, 124, 16  # green
        elif score >= 60:
            r, g, b = 255, 170, 68  # amber
        else:
            r, g, b = 209, 52, 56  # red

        self.set_fill_color(r, g, b)
        self.set_draw_color(r, g, b)
        self.ellipse(x - radius, y - radius, radius * 2, radius * 2, style="F")

        self.set_font("Helvetica", "B", 20)
        self.set_text_color(255, 255, 255)
        self.set_xy(x - radius, y - 8)
        self.cell(radius * 2, 12, f"{score}%", align="C")

        self.set_font("Helvetica", "", 8)
        self.set_xy(x - radius, y + 4)
        self.cell(radius * 2, 6, "COMPLIANCE", align="C")

        self.set_y(y + radius + 8)


def generate_report(events: list, stats: dict) -> bytes:
    """
    Generate a PDF compliance report.

    Args:
        events: List of CSPM event dicts from DynamoDB
        stats: Stats dict from the API

    Returns:
        PDF file contents as bytes
    """
    pdf = CSPMReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)

    # --- Cover Page ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(27, 27, 58)
    pdf.ln(30)
    pdf.cell(0, 15, "Cloud Security Posture", align="C")
    pdf.ln(12)
    pdf.cell(0, 15, "Management Report", align="C")
    pdf.ln(20)

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, f"Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}", align="C")
    pdf.ln(6)
    pdf.cell(0, 8, f"Total Events Analyzed: {len(events)}", align="C")
    pdf.ln(20)

    # Risk score
    compliance = get_compliance_summary(events)
    pdf.risk_score_badge(compliance["overall_score"])

    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, "Automated Security Posture Assessment", align="C")
    pdf.ln(4)
    pdf.cell(0, 6, "Powered by Serverless CSPM", align="C")

    # --- Executive Summary ---
    pdf.add_page()
    pdf.section_title("1. Executive Summary")

    total = stats.get("total_events", len(events))
    remediated = stats.get("remediated", 0)
    failed = stats.get("failed", 0)
    flagged = stats.get("flagged", 0)
    compliance_rate = stats.get("compliance_rate", compliance["overall_score"])

    pdf.body_text(
        f"This report summarizes the security posture of the monitored AWS environment. "
        f"A total of {total} security events were analyzed across "
        f"{stats.get('unique_buckets', 'multiple')} resources in "
        f"{len(stats.get('active_regions', []))} AWS regions.\n\n"
        f"Key findings:\n"
        f"  - {remediated} vulnerabilities were automatically remediated\n"
        f"  - {failed} remediation attempts failed\n"
        f"  - {flagged} IAM policy violations were flagged for review\n"
        f"  - Overall compliance rate: {compliance_rate}%"
    )

    # --- KPI Table ---
    pdf.subsection_title("Key Metrics")
    pdf.set_font("Helvetica", "", 10)

    col_w = 47.5
    pdf.set_fill_color(240, 240, 240)
    pdf.set_text_color(50, 50, 50)

    metrics = [
        ("Total Events", str(total)),
        ("Remediated", str(remediated)),
        ("Failed", str(failed)),
        ("Compliance", f"{compliance_rate}%"),
    ]

    for label, value in metrics:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(col_w, 8, label, border=1, fill=True, align="C")
    pdf.ln()
    for label, value in metrics:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(col_w, 8, value, border=1, align="C")
    pdf.ln(12)

    # --- Compliance Framework Breakdown ---
    pdf.section_title("2. Compliance Framework Analysis")

    for fw_name, fw_stats in compliance["frameworks"].items():
        pdf.subsection_title(f"{fw_name}")

        # Score bar
        score = fw_stats["score"]
        bar_w = 120
        bar_h = 6
        x = pdf.get_x()
        y = pdf.get_y()

        # Background bar
        pdf.set_fill_color(230, 230, 230)
        pdf.rect(x, y, bar_w, bar_h, style="F")

        # Filled bar
        if score >= 80:
            pdf.set_fill_color(16, 124, 16)
        elif score >= 60:
            pdf.set_fill_color(255, 170, 68)
        else:
            pdf.set_fill_color(209, 52, 56)

        pdf.rect(x, y, bar_w * score / 100, bar_h, style="F")

        pdf.set_xy(x + bar_w + 5, y - 1)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(30, 8, f"{score}%  ({fw_stats['passed']}/{fw_stats['total']} controls)")
        pdf.ln(12)

    # --- Detailed Findings ---
    pdf.add_page()
    pdf.section_title("3. Detailed Findings")

    # Table header
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(27, 27, 58)
    pdf.set_text_color(255, 255, 255)

    col_widths = [35, 40, 30, 25, 25, 35]
    headers = ["Timestamp", "Resource", "Type", "Severity", "Status", "Region"]

    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 7, header, border=1, fill=True, align="C")
    pdf.ln()

    # Table rows
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(50, 50, 50)
    fill = False

    for event in events[:50]:  # Limit to 50 rows
        if pdf.get_y() > 260:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(27, 27, 58)
            pdf.set_text_color(255, 255, 255)
            for i, header in enumerate(headers):
                pdf.cell(col_widths[i], 7, header, border=1, fill=True, align="C")
            pdf.ln()
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(50, 50, 50)
            fill = False

        if fill:
            pdf.set_fill_color(248, 248, 248)
        else:
            pdf.set_fill_color(255, 255, 255)

        ts = event.get("timestamp", "")[:16]
        resource = event.get("bucket_name", "")[:20]
        vtype = event.get("vulnerability_type", "")[:15]
        severity = event.get("severity", "")
        status = event.get("status", "")[:15]
        region = event.get("region", "")

        row_data = [ts, resource, vtype, severity, status, region]
        for i, val in enumerate(row_data):
            pdf.cell(col_widths[i], 6, val, border=1, fill=True, align="C")
        pdf.ln()
        fill = not fill

    # --- Compliance Control Details ---
    pdf.add_page()
    pdf.section_title("4. Compliance Control Mapping")

    for vuln_type, mapping in COMPLIANCE_MAP.items():
        pdf.subsection_title(vuln_type)
        pdf.body_text(mapping["description"])

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(240, 240, 240)
        ctrl_widths = [30, 20, 100, 20]
        ctrl_headers = ["Framework", "Control", "Title", "Severity"]
        for i, h in enumerate(ctrl_headers):
            pdf.cell(ctrl_widths[i], 6, h, border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(50, 50, 50)
        for ctrl in mapping["controls"]:
            pdf.cell(ctrl_widths[0], 5, ctrl["framework"], border=1, align="C")
            pdf.cell(ctrl_widths[1], 5, ctrl["control_id"], border=1, align="C")
            pdf.cell(ctrl_widths[2], 5, ctrl["title"][:55], border=1)
            pdf.cell(ctrl_widths[3], 5, ctrl["severity"], border=1, align="C")
            pdf.ln()

        pdf.ln(6)

    # --- Recommendations ---
    pdf.add_page()
    pdf.section_title("5. Recommendations")

    recommendations = [
        ("Enable S3 Block Public Access at account level",
         "Use AWS Organizations SCP to enforce public access blocks across all accounts."),
        ("Enforce default encryption on all S3 buckets",
         "Use AWS Config rules to automatically detect and remediate unencrypted buckets."),
        ("Implement least-privilege IAM policies",
         "Replace wildcard (*) permissions with specific resource ARNs and actions."),
        ("Enable CloudTrail in all regions",
         "Ensure complete audit trail for compliance reporting and incident response."),
        ("Schedule regular CSPM scans",
         "Run IAM audit and S3 checks on a daily schedule via EventBridge."),
    ]

    for i, (title, desc) in enumerate(recommendations, 1):
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(27, 27, 58)
        pdf.cell(0, 7, f"{i}. {title}")
        pdf.ln(6)
        pdf.body_text(desc)

    return pdf.output()
