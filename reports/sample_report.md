# Incident Forensic Report – FRG-2024-001

> **Case ID:** `2024-001`
> **Title:** Suspicious outbound traffic from workstation WIN-01
> **Analyst:** Sebastián Fuentes
> **Date:** 2024-11-17
> **Status:** Closed
> **Severity:** 🟡 Medium
> **Total IOCs identified:** `0` (IP: 0, Domains: 0, URLs: 0, Hashes: 0)

---

## 0. Case Overview

| Field        | Value |
|-------------|-------|
| Report ID    | `FRG-2024-001` |
| Case ID      | `2024-001` |
| Title        | Suspicious outbound traffic from workstation WIN-01 |
| Analyst      | Sebastián Fuentes |
| Date         | 2024-11-17 |
| Status       | Closed |
| Severity     | 🟡 Medium |
| Environment  | Home lab / Simulated case |
| Impact       | Potential C2 communication and malware download if not contained. |

---

## 1. Executive Summary

Detection of suspicious outbound connections to a known malicious domain originating from WIN-01 in a home lab environment.

---

## 2. Scope & Environment

- **Environment:** Home lab / Simulated case
- **Impact:** Potential C2 communication and malware download if not contained.

---

## 3. Timeline of Events

| Timestamp | Event | Source |
|-----------|-------|--------|
| 2024-11-16 10:22:45 | Firewall dropped outbound connection to 185.199.110.153 | firewall.log |
| 2024-11-16 10:22:50 | Proxy log shows HTTPS connection to panel.badhost.net | proxy.log |
| 2024-11-16 10:23:10 | AV flagged invoice_2024.exe as suspicious | edr.log |

---

## 4. Technical Analysis (High-level)

> NOTE: This section can be manually expanded with:
> - Host-based artifacts
> - Network evidence
> - Relevant log sources and findings

---

## 5. Extracted Indicators of Compromise (IOCs)

- **Total IOCs:** `0`
  - IPs: `0`
  - Domains: `0`
  - URLs: `0`
  - File hashes: `0`

> All IOCs should be validated and enriched (e.g., sandbox, threat intel, WHOIS) before
> being used for blocking in production environments.


### 5.1 IP Addresses

- None identified in this case.


### 5.2 Domains

- None identified in this case.


### 5.3 URLs

- None identified in this case.


### 5.4 File Hashes

- None identified in this case.


---

## 6. Tools & Methodology

- **Log sources** (depending on the case):
  - Firewall / IDS / IPS
  - Web proxy / DNS logs
  - AV / EDR telemetry
  - System and application logs
- **Analysis steps** (typical DFIR workflow):
  - Initial alert triage and scoping.
  - IOC extraction and validation.
  - Timeline reconstruction and correlation.
  - Hypothesis testing and root cause analysis.
- **Tools used**:
  - Forensix Report Generator (this tool).
  - Additional DFIR utilities as required (not listed here).

---

## 7. Conclusions & Recommendations

**Conclusions**

- Summarize the root cause, initial vector (if known), and main findings.
- Document which assets were affected and how the threat was contained.

**Recommendations**

- **Containment**
  - Block identified IOCs at firewall / proxy / email gateway level.
  - Isolate or monitor affected hosts.
- **Eradication**
  - Remove or quarantine malicious files and persistence mechanisms.
  - Re-image compromised systems if necessary.
- **Recovery**
  - Restore affected systems from known-good backups.
  - Monitor closely for signs of reinfection.
- **Hardening**
  - Improve logging, monitoring and alerting around similar patterns.
  - Apply relevant security patches and configuration hardening.
  - Provide awareness training if social engineering was involved.
