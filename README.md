# Forensix Report Generator

Forensix Report Generator is a small DFIR-focused tool that generates **incident forensic reports in Markdown** from simple, structured inputs:

- **Case metadata (JSON)** – case id, report id, status, environment, impact, etc.
- **Indicators of Compromise (IOCs) (CSV)** – IPs, domains, URLs, file hashes.
- **Timeline of events (CSV, optional)** – key events with timestamps and log sources.

It is designed for **DFIR / SOC analysts, threat hunters and cybersecurity students** who want to standardize and automate the boring part of incident documentation.

The project includes:

- A **CLI** for scriptable report generation.
- A **local web UI (Flask, dark mode)** for interactive use and teaching labs.

---

## Features

- Generate incident reports in **Markdown**, ready to store in repos, tickets or wikis.
- **Dark mode** web UI (Flask) to upload JSON/CSV and preview the report.
- Supports:
  - Case metadata (JSON)
  - IOCs (CSV): `indicator,type,source`
  - Timeline (CSV): `timestamp,event,source`
- Summary section with:
  - Report ID, Case ID, status (Open/Closed/etc.)
  - Severity badge (Low/Medium/High)
  - Environment & impact
  - IOC counts by type
- Report sections:
  - 0. Case Overview
  - 1. Executive Summary
  - 2. Scope & Environment
  - 3. Timeline of Events
  - 4. Technical Analysis (high-level, editable)
  - 5. Extracted IOCs (tables)
  - 6. Tools & Methodology
  - 7. Conclusions & Recommendations

Ideal for:

- DFIR/SOC portfolios
- University labs
- Intro DFIR courses
- Practicing structured incident documentation

---

## Project structure

```text
forensix-report-generator/
├── app.py                    # Local web UI (Flask)
├── report_generator.py       # CLI entry point and report renderer
├── templates/
│   ├── web_form.html         # Dark mode upload form
│   └── web_preview.html      # Report preview page
├── static/
│   └── style.css             # Dark mode styles
├── cases/
│   ├── sample_case.json      # Example case metadata
│   ├── sample_iocs.csv       # Example IOCs list
│   └── sample_timeline.csv   # Example timeline
├── reports/                  # Generated reports (Markdown)
├── HOW_TO_USE.txt            # Quick usage notes
├── README.md                 # This file
└── requirements.txt          # Python dependencies
````
