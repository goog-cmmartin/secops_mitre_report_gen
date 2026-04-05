# Google SecOps MITRE ATT&CK Strategic Analysis Report
**Date:** 2026-04-05
**Target Profile:** EU Public Financial Services (2025-2026 Focus)
**Analysis Scope:** Strategic Detection Integrity (Logs + Rules + Context)

---

## 1. Environment & MITRE Context
This analysis was performed against the following environment and MITRE ATT&CK baseline:

### **Tenant Details**
| Field | Value |
| :--- | :--- |
| **Project ID** | `your-project-id` |
| **Region** | `us` |
| **Instance ID** | `your-instance-guid` |

### **MITRE ATT&CK Version Information**
| Field | Value |
| :--- | :--- |
| **Matrix Version** | `v18.1` |
| **Total Techniques in Matrix** | `835` |
| **Total Tactics in Matrix** | `14` |

---

## 2. Executive Summary
This report evaluates the **Detection Integrity** of the Google SecOps environment. Unlike a raw percentage, this score reflects the alignment between available log telemetry and deployed detection logic, weighted by industry-specific risks.

### **Contextual Coverage Score: `4.137`**
*A score above 1.0 indicates a mature detection posture with risk-weighted coverage and redundant (resilient) detections.*

#### **Score Calculation Breakdown**
To ensure transparency, the score is calculated using the following components:
- **Sum of Risk-Weighted Techniques**: `413`
- **Resilience Bonus (Redundancy)**: `+145.5`
- **Total Relevant Baseline (Denominator)**: `135`
- **Formula**: `(Sum_Risk_Weighted_Techniques + Resilience_Bonus) / Total_Relevant_Baseline`

---

## 3. Detection Maturity Metrics

| Metric | Value | Description |
| :--- | :--- | :--- |
| **Total Rules Found** | 5489 | Total YARA-L rules (System + Custom). |
| **Rules Enabled (Live)** | 3533 | Rules currently in "Live" mode (alerting). |
| **Validated Techniques** | 379 | Unique MITRE Techniques with active YARA-L rules. |
| **Detection Coverage (Tactics)** | 14 | Tactics with at least one active detection rule. |
| **Active Telemetry (Tactics)** | 12 | Tactics with both rules AND active log sources. |
| **Firing Techniques (7d)** | 1 | Unique MITRE techniques that triggered alerts in the last 7 days. |

> **Note on Rule-to-Technique Ratio:** You may observe a high ratio of rules to techniques (~10:1). This is by design; while a single technique (e.g., PowerShell) covers a broad category, our rules target specific **Procedures** (the unique "how") to ensure resilient detection across multiple adversary variations.

---

## 4. Telemetry & Log Sources
This section identifies the data sources powering your detections, categorized by high-fidelity groups.

### **EDR Sources**
- `CB_EDR`
- `CS_EDR`
- `FIREEYE_HX`
- `SENTINEL_EDR`
- `WINDOWS_SYSMON`

### **IDENTITY Sources**
- `AZURE_AD`
- `OKTA`
- `WORKSPACE_ACTIVITY`

### **CLOUD Sources**
- `AWS_CLOUDTRAIL`
- `GCP_CLOUDAUDIT`

### **NETWORK Sources**
- `PAN_FIREWALL`
- `ZSCALER_WEBPROXY`

### **Log Visibility Mapping**
The following MITRE Tactics are currently supported by your ingested log sources (Active Telemetry):
- [x] command-and-control
- [x] credential-access
- [x] defense-evasion
- [x] discovery
- [x] execution
- [x] exfiltration
- [x] initial-access
- [x] lateral-movement
- [x] persistence
- [x] privilege-escalation
- [x] reconnaissance
- [x] resource-hijacking

---

## 5. Operational Visibility (Active MITRE Detections)
The following techniques have triggered alerts in your environment over the last **7 days**. High counts may indicate "noisy" rules requiring tuning.

| Technique ID | Name | Alert Count | Tactics |
| :--- | :--- | :--- | :--- |
| T1036 | Masquerading | 10 | defense-evasion |

---

## 6. Detection Resilience
This section highlights techniques where multiple independent detection rules and diverse data sources exist, providing true "Defense in Depth."

### **Top 15 Resilient Detections**
| Technique ID | Name | Rule Count | Data Diversity | Status |
| :--- | :--- | :--- | :--- | :--- |
| T1105 | Ingress Tool Transfer | 181 | 1 (NETWORK) | **RESILIENT** |
| T1204.002 | Malicious File | 161 | 1 (EDR) | **RESILIENT** |
| T1059.001 | PowerShell | 148 | 1 (EDR) | **RESILIENT** |
| T1059.003 | Windows Command Shell | 133 | 1 (EDR) | **RESILIENT** |
| T1071.001 | Web Protocols | 115 | 1 (NETWORK) | **RESILIENT** |
| T1078.004 | Cloud Accounts | 112 | 2 (EDR, IDENTITY) | **RESILIENT** |
| T1059 | Command and Scripting Interpreter | 101 | 1 (EDR) | **RESILIENT** |
| T1562.001 | Disable or Modify Tools | 97 | 1 (EDR) | **RESILIENT** |
| T1580 | Cloud Infrastructure Discovery | 94 | 1 (CLOUD) | **RESILIENT** |
| T1218.011 | Rundll32 | 71 | 1 (EDR) | **RESILIENT** |
| T1098.003 | Additional Cloud Roles | 70 | 1 (EDR) | **RESILIENT** |
| T1053.005 | Scheduled Task | 69 | 1 (EDR) | **RESILIENT** |
| T1190 | Exploit Public-Facing Application | 69 | 1 (IDENTITY) | **RESILIENT** |
| T1078 | Valid Accounts | 66 | 2 (EDR, IDENTITY) | **RESILIENT** |
| T1547.001 | Registry Run Keys / Startup Folder | 57 | 1 (EDR) | **RESILIENT** |

---

## 7. Strategic Gaps & Recommendations
This section highlights critical gaps where your organization has no detection logic for high-risk threats or is missing the telemetry required to power existing rules.

### **High-Risk Technique Gaps**
The following techniques from the **EU Public Financial Services (2025-2026 Focus)** profile currently have no active detection rules.

| Technique ID | Name | Risk Weight | Priority |
| :--- | :--- | :--- | :--- |
| T1566.004 | Spearphishing Voice | 5 | **HIGH** |

---

## 8. Methodology
This report was generated using the **Contextual Coverage Formula**:
$$Coverage\_Score = \frac{\sum (Techniques \times Risk\_Relevance) + Resilience\_Bonus}{\text{Total Relevant Techniques}}$$

- **Validation Source:** Official MITRE ATT&CK Enterprise Matrix (STIX 2.1).
- **Diversity Metric:** "Data Diversity" measures the number of distinct log categories (EDR, Network, Cloud, Identity) supporting a tactic.
