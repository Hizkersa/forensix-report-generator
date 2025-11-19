# Forensix Report Generator

A Python-based **Forensic Report Generator** designed for DFIR / SOC workflows.  
It takes structured case metadata, extracted Indicators of Compromise (IOCs) and an investigation timeline, and automatically generates a clean, professional incident report.

This tool is intended to:

- Standardize incident reports across cases.
- Reduce manual copy-paste and formatting errors.
- Integrate with existing DFIR workflows (e.g., IOC Extractor outputs).
- Provide both:
  - A **CLI** interface for automation.
  - A **local web UI** (dark mode) for interactive report generation.

---

## Features

- **Case metadata input** via JSON.
- **IOCs input** via CSV (IP, domain, URL, hash, etc.).
- **Timeline of events** via CSV.
- **Template-based report generation** using Jinja2.
- Output as **Markdown** (`.md`), ready to:
  - Commit to a DFIR repo.
  - Share with stakeholders.
  - Convert later to PDF/HTML (Pandoc, etc.).
- **Local web UI** (Flask, dark mode) to:
  - Upload case files.
  - Process data.
  - Preview the generated report.

---

## Project structure

```text
forensix-report-generator/
├── app.py                    # Local web UI (Flask)
├── report_generator.py       # CLI entry point
├── templates/
│   ├── default_report.md.j2  # Jinja2 report template (Markdown)
│   ├── web_form.html         # Upload form (dark mode UI)
│   └── web_preview.html      # Report preview page
├── static/
│   └── style.css             # Dark mode styles
├── cases/
│   ├── sample_case.json      # Example case metadata
│   ├── sample_iocs.csv       # Example IOC list
│   └── sample_timeline.csv   # Example timeline
├── reports/
│   └── .gitkeep              # Folder for generated reports
├── README.md
├── HOW_TO_USE.txt
└── requirements.txt
```