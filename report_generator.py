import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


# ---------- Data models ----------

@dataclass
class IOCEntry:
    indicator: str
    type: str
    source: str


@dataclass
class TimelineEvent:
    timestamp: str
    event: str
    source: str


# ---------- Loaders ----------

def load_case_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_iocs_csv(path: Path):
    """
    Returns a dict grouped by IOC type:
    {
        "IP": [IOCEntry, ...],
        "DOMAIN": [...],
        "URL": [...],
        "HASH": [...]
    }
    """
    grouped = {
        "IP": [],
        "DOMAIN": [],
        "URL": [],
        "HASH": [],
    }

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            indicator = (row.get("indicator") or "").strip()
            ioc_type = (row.get("type") or "").strip().upper()
            source = (row.get("source") or "").strip()

            if not indicator or not ioc_type:
                continue

            entry = IOCEntry(indicator=indicator, type=ioc_type, source=source)

            if ioc_type in grouped:
                grouped[ioc_type].append(entry)
            else:
                # Unknown type – extend here if needed
                pass

    return grouped


def load_timeline_csv(path: Path):
    events = []

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = (row.get("timestamp") or "").strip()
            ev = (row.get("event") or "").strip()
            src = (row.get("source") or "").strip()

            if not ts or not ev:
                continue

            events.append(TimelineEvent(timestamp=ts, event=ev, source=src))

    # Sort by timestamp if possible
    def parse_ts(e: TimelineEvent):
        try:
            return datetime.strptime(e.timestamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return e.timestamp  # fallback, keeps original order

    events.sort(key=parse_ts)
    return events


# ---------- Report renderer (sin Jinja) ----------

def render_report(case_data, iocs, timeline=None) -> str:
    """
    Generate a Markdown incident report from:
      - case_data: dict
      - iocs: dict[str, list[IOCEntry]]
      - timeline: list[TimelineEvent] | None
    """

    lines: list[str] = []

    # --- Extract case data with defaults ---
    case_id = case_data.get("case_id", "N/A")
    # nuevo: report_id y status
    report_id = case_data.get("report_id", case_id)
    title = case_data.get("title", "Untitled case")
    analyst = case_data.get("analyst", "Unknown analyst")
    date = case_data.get("date", "Unknown date")
    severity = case_data.get("severity", "N/A")
    status = case_data.get("status", "Open")
    summary = (case_data.get("summary") or "").strip()
    environment = case_data.get("environment", "N/A")
    impact = case_data.get("impact", "N/A")

    # Simple severity badge
    sev_icon = "🟢"
    if str(severity).lower().startswith("med"):
        sev_icon = "🟡"
    if str(severity).lower().startswith("h"):
        sev_icon = "🔴"

    # IOC counts
    ip_count = len(iocs.get("IP", []))
    domain_count = len(iocs.get("DOMAIN", []))
    url_count = len(iocs.get("URL", []))
    hash_count = len(iocs.get("HASH", []))

    total_iocs = ip_count + domain_count + url_count + hash_count

    # --- Header block ---
    lines.append(f"# Incident Forensic Report – {report_id}")
    lines.append("")
    lines.append(f"> **Case ID:** `{case_id}`")
    lines.append(f"> **Title:** {title}")
    lines.append(f"> **Analyst:** {analyst}")
    lines.append(f"> **Date:** {date}")
    lines.append(f"> **Status:** {status}")
    lines.append(f"> **Severity:** {sev_icon} {severity}")
    lines.append(
        f"> **Total IOCs identified:** `{total_iocs}` "
        f"(IP: {ip_count}, Domains: {domain_count}, URLs: {url_count}, Hashes: {hash_count})"
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 0. Case Overview (table) ---
    lines.append("## 0. Case Overview")
    lines.append("")
    lines.append("| Field        | Value |")
    lines.append("|-------------|-------|")
    lines.append(f"| Report ID    | `{report_id}` |")
    lines.append(f"| Case ID      | `{case_id}` |")
    lines.append(f"| Title        | {title} |")
    lines.append(f"| Analyst      | {analyst} |")
    lines.append(f"| Date         | {date} |")
    lines.append(f"| Status       | {status} |")
    lines.append(f"| Severity     | {sev_icon} {severity} |")
    lines.append(f"| Environment  | {environment} |")
    lines.append(f"| Impact       | {impact} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 1. Executive Summary ---
    lines.append("## 1. Executive Summary")
    lines.append("")
    if summary:
        lines.append(summary)
    else:
        lines.append("_No executive summary was provided for this case._")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 2. Scope & Environment ---
    lines.append("## 2. Scope & Environment")
    lines.append("")
    lines.append(f"- **Environment:** {environment}")
    lines.append(f"- **Impact:** {impact}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 3. Timeline of Events ---
    lines.append("## 3. Timeline of Events")
    lines.append("")
    if timeline and len(timeline) > 0:
        # Table view for timeline
        lines.append("| Timestamp | Event | Source |")
        lines.append("|-----------|-------|--------|")
        for ev in timeline:
            ev_event = ev.event.replace("|", "\\|")
            ev_source = ev.source.replace("|", "\\|")
            lines.append(f"| {ev.timestamp} | {ev_event} | {ev_source} |")
    else:
        lines.append("No timeline data was provided for this case.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 4. Technical Analysis (High-level) ---
    lines.append("## 4. Technical Analysis (High-level)")
    lines.append("")
    lines.append("> NOTE: This section can be manually expanded with:")
    lines.append("> - Host-based artifacts")
    lines.append("> - Network evidence")
    lines.append("> - Relevant log sources and findings")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 5. IOCs ---
    lines.append("## 5. Extracted Indicators of Compromise (IOCs)")
    lines.append("")
    lines.append(f"- **Total IOCs:** `{total_iocs}`")
    lines.append(f"  - IPs: `{ip_count}`")
    lines.append(f"  - Domains: `{domain_count}`")
    lines.append(f"  - URLs: `{url_count}`")
    lines.append(f"  - File hashes: `{hash_count}`")
    lines.append("")
    lines.append("> All IOCs should be validated and enriched (e.g., sandbox, threat intel, WHOIS) before")
    lines.append("> being used for blocking in production environments.")
    lines.append("")
    lines.append("")

    def add_ioc_section(number: str, label: str, key: str):
        section_title = label
        if key == "HASH":
            section_title = "File Hashes"

        entries = iocs.get(key, [])

        lines.append(f"### 5.{number} {section_title}")
        lines.append("")
        if entries:
            lines.append("| Indicator | Source |")
            lines.append("|-----------|--------|")
            for e in entries:
                src = e.source or ""
                src = src.replace("|", "\\|")
                indicator = e.indicator.replace("|", "\\|")
                lines.append(f"| `{indicator}` | {src} |")
        else:
            lines.append("- None identified in this case.")
        lines.append("")
        lines.append("")

    add_ioc_section("1", "IP Addresses", "IP")
    add_ioc_section("2", "Domains", "DOMAIN")
    add_ioc_section("3", "URLs", "URL")
    add_ioc_section("4", "File Hashes", "HASH")

    lines.append("---")
    lines.append("")

    # --- 6. Tools & Methodology ---
    lines.append("## 6. Tools & Methodology")
    lines.append("")
    lines.append("- **Log sources** (depending on the case):")
    lines.append("  - Firewall / IDS / IPS")
    lines.append("  - Web proxy / DNS logs")
    lines.append("  - AV / EDR telemetry")
    lines.append("  - System and application logs")
    lines.append("- **Analysis steps** (typical DFIR workflow):")
    lines.append("  - Initial alert triage and scoping.")
    lines.append("  - IOC extraction and validation.")
    lines.append("  - Timeline reconstruction and correlation.")
    lines.append("  - Hypothesis testing and root cause analysis.")
    lines.append("- **Tools used**:")
    lines.append("  - Forensix Report Generator (this tool).")
    lines.append("  - Additional DFIR utilities as required (not listed here).")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 7. Conclusions & Recommendations ---
    lines.append("## 7. Conclusions & Recommendations")
    lines.append("")
    lines.append("**Conclusions**")
    lines.append("")
    lines.append("- Summarize the root cause, initial vector (if known), and main findings.")
    lines.append("- Document which assets were affected and how the threat was contained.")
    lines.append("")
    lines.append("**Recommendations**")
    lines.append("")
    lines.append("- **Containment**")
    lines.append("  - Block identified IOCs at firewall / proxy / email gateway level.")
    lines.append("  - Isolate or monitor affected hosts.")
    lines.append("- **Eradication**")
    lines.append("  - Remove or quarantine malicious files and persistence mechanisms.")
    lines.append("  - Re-image compromised systems if necessary.")
    lines.append("- **Recovery**")
    lines.append("  - Restore affected systems from known-good backups.")
    lines.append("  - Monitor closely for signs of reinfection.")
    lines.append("- **Hardening**")
    lines.append("  - Improve logging, monitoring and alerting around similar patterns.")
    lines.append("  - Apply relevant security patches and configuration hardening.")
    lines.append("  - Provide awareness training if social engineering was involved.")
    lines.append("")

    return "\n".join(lines)


# ---------- CLI entry ----------

def main():
    parser = argparse.ArgumentParser(
        description="Generate forensic incident reports from case metadata, IOCs and timeline."
    )
    parser.add_argument(
        "--case",
        required=True,
        help="Path to case metadata JSON file."
    )
    parser.add_argument(
        "--iocs",
        required=True,
        help="Path to IOCs CSV file."
    )
    parser.add_argument(
        "--timeline",
        required=False,
        help="Path to timeline CSV file (optional)."
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output Markdown report file."
    )

    args = parser.parse_args()

    case_path = Path(args.case)
    iocs_path = Path(args.iocs)
    output_path = Path(args.output)

    case_data = load_case_json(case_path)
    iocs = load_iocs_csv(iocs_path)
    timeline = None

    if args.timeline:
        timeline_path = Path(args.timeline)
        if timeline_path.exists():
            timeline = load_timeline_csv(timeline_path)

    report_md = render_report(case_data, iocs, timeline)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_md, encoding="utf-8")

    print(f"[+] Report generated: {output_path}")


if __name__ == "__main__":
    main()
    