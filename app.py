from io import StringIO
import csv
import json
from pathlib import Path

from flask import Flask, render_template, request

from report_generator import (
    IOCEntry,
    TimelineEvent,
    render_report,
)

app = Flask(__name__)


def load_case_from_stream(stream) -> dict:
    """Load JSON from an uploaded file-like object."""
    data = stream.read()
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(data)


def load_iocs_from_stream(stream) -> dict:
    """Load IOCs CSV from uploaded file and group by type."""
    grouped = {"IP": [], "DOMAIN": [], "URL": [], "HASH": []}

    data = stream.read()
    if isinstance(data, bytes):
        data = data.decode("utf-8")

    reader = csv.DictReader(StringIO(data))
    for row in reader:
        indicator = row.get("indicator", "").strip()
        ioc_type = row.get("type", "").strip().upper()
        source = row.get("source", "").strip()

        if not indicator or not ioc_type:
            continue

        entry = IOCEntry(indicator=indicator, type=ioc_type, source=source)
        if ioc_type in grouped:
            grouped[ioc_type].append(entry)
        else:
            # ignore unknown types or extend here
            pass

    return grouped


def load_timeline_from_stream(stream):
    """Load timeline CSV from uploaded file."""
    data = stream.read()
    if isinstance(data, bytes):
        data = data.decode("utf-8")

    reader = csv.DictReader(StringIO(data))
    events = []
    for row in reader:
        ts = row.get("timestamp", "").strip()
        ev = row.get("event", "").strip()
        src = row.get("source", "").strip()
        if not ts or not ev:
            continue
        events.append(TimelineEvent(timestamp=ts, event=ev, source=src))
    return events


@app.route("/", methods=["GET"])
def index():
    return render_template("web_form.html")


@app.route("/generate", methods=["POST"])
def generate_report_web():
    print("[*] Received POST /generate from web form")
    case_file = request.files.get("case_file")
    iocs_file = request.files.get("iocs_file")
    timeline_file = request.files.get("timeline_file")

    if not case_file or not iocs_file:
        return "Case JSON and IOCs CSV are required.", 400

    case_data = load_case_from_stream(case_file.stream)
    iocs = load_iocs_from_stream(iocs_file.stream)
    timeline = None

    if timeline_file and timeline_file.filename:
        timeline = load_timeline_from_stream(timeline_file.stream)

    report_md = render_report(case_data, iocs, timeline)

    print("DEBUG REPORT_MD LENGTH:", len(report_md))
    print("DEBUG REPORT_MD PREVIEW:", repr(report_md[:200]))

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    case_id = case_data.get("case_id", "case")
    output_path = reports_dir / f"{case_id}_report.md"
    output_path.write_text(report_md, encoding="utf-8")

    return render_template("web_preview.html", report_md=report_md)


if __name__ == "__main__":
    print("[+] Starting Forensix Report Generator (Flask web UI)...")
    app.run(debug=True)
