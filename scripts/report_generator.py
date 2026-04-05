import json
from datetime import datetime

def generate_markdown_report(analysis_json, output_path):
    """
    Generate a professional MITRE Coverage Report in Markdown with Strategic Enhancements.
    """
    metrics = analysis_json['metrics']
    profile_name = analysis_json['profile']
    tenant = analysis_json.get('tenant_info', {})
    score_breakdown = analysis_json.get('score_breakdown', {})
    mitre_stats = analysis_json.get('mitre_stats', {})
    gaps = analysis_json.get('gaps', {})
    resilience = analysis_json.get('resilience', {})
    firing = analysis_json.get('firing_detections', [])
    
    md = f"""# Google SecOps MITRE ATT&CK Strategic Analysis Report
**Date:** {datetime.now().strftime('%Y-%m-%d')}
**Target Profile:** {profile_name}
**Analysis Scope:** Strategic Detection Integrity (Logs + Rules + Context)

---

## 1. Environment & MITRE Context
This analysis was performed against the following environment and MITRE ATT&CK baseline:

### **Tenant Details**
| Field | Value |
| :--- | :--- |
| **Project ID** | `{tenant.get('project_id', 'N/A')}` |
| **Region** | `{tenant.get('location', 'N/A')}` |
| **Instance ID** | `{tenant.get('instance_id', 'N/A')}` |

### **MITRE ATT&CK Version Information**
| Field | Value |
| :--- | :--- |
| **Matrix Version** | `v{mitre_stats.get('version', 'Unknown')}` |
| **Total Techniques in Matrix** | `{mitre_stats.get('total_techniques', 'Unknown')}` |
| **Total Tactics in Matrix** | `{mitre_stats.get('total_tactics', 'Unknown')}` |

---

## 2. Executive Summary
This report evaluates the **Detection Integrity** of the Google SecOps environment. Unlike a raw percentage, this score reflects the alignment between available log telemetry and deployed detection logic, weighted by industry-specific risks.

### **Contextual Coverage Score: `{metrics['contextual_coverage_score']}`**
*A score above 1.0 indicates a mature detection posture with risk-weighted coverage and redundant (resilient) detections.*

#### **Score Calculation Breakdown**
To ensure transparency, the score is calculated using the following components:
- **Sum of Risk-Weighted Techniques**: `{score_breakdown.get('sum_risk_weighted_techniques')}`
- **Resilience Bonus (Redundancy)**: `+{score_breakdown.get('resilience_bonus')}`
- **Total Relevant Baseline (Denominator)**: `{score_breakdown.get('total_relevant_baseline')}`
- **Formula**: `{score_breakdown.get('formula')}`

---

## 3. Detection Maturity Metrics

| Metric | Value | Description |
| :--- | :--- | :--- |
| **Total Rules Found** | {metrics['total_rules']} | Total YARA-L rules (System + Custom). |
| **Rules Enabled (Live)** | {metrics['enabled_rules']} | Rules currently in "Live" mode (alerting). |
| **Validated Techniques** | {metrics['validated_technique_count']} | Unique MITRE Techniques with active YARA-L rules. |
| **Detection Coverage (Tactics)** | {metrics['detection_tactics_count']} | Tactics with at least one active detection rule. |
| **Active Telemetry (Tactics)** | {metrics['visibility_tactics_count']} | Tactics with both rules AND active log sources. |
| **Firing Techniques (7d)** | {metrics['firing_techniques_count']} | Unique MITRE techniques that triggered alerts in the last 7 days. |

> **Note on Rule-to-Technique Ratio:** You may observe a high ratio of rules to techniques (~10:1). This is by design; while a single technique (e.g., PowerShell) covers a broad category, our rules target specific **Procedures** (the unique "how") to ensure resilient detection across multiple adversary variations.

---

## 4. Telemetry & Log Sources
This section identifies the data sources powering your detections, categorized by high-fidelity groups.

"""
    cat_logs = metrics.get('categorized_logs', {})
    for category, logs in cat_logs.items():
        if logs:
            md += f"### **{category} Sources**\n"
            for log in sorted(logs):
                md += f"- `{log}`\n"
            md += "\n"

    md += """
### **Log Visibility Mapping**
The following MITRE Tactics are currently supported by your ingested log sources (Active Telemetry):
"""
    if not metrics.get('visibility_tactics'):
        md += "_No active log mapping identified. See Section 6 for Visibility Gaps._\n"
    else:
        for tactic in sorted(metrics.get('visibility_tactics', [])):
            md += f"- [x] {tactic}\n"

    md += """
---

## 5. Operational Visibility (Active MITRE Detections)
The following techniques have triggered alerts in your environment over the last **7 days**. High counts may indicate "noisy" rules requiring tuning.

| Technique ID | Name | Alert Count | Tactics |
| :--- | :--- | :--- | :--- |
"""
    if not firing:
        md += "| N/A | No active detections observed | 0 | - |\n"
    else:
        for det in firing[:15]: # Top 15 firing
            tactics_str = ", ".join(det.get('tactics', []))
            md += f"| {det['id']} | {det['name']} | {det['alert_count']} | {tactics_str} |\n"

    md += """
---

## 6. Detection Resilience
This section highlights techniques where multiple independent detection rules and diverse data sources exist, providing true "Defense in Depth."

### **Top 15 Resilient Detections**
| Technique ID | Name | Rule Count | Data Diversity | Status |
| :--- | :--- | :--- | :--- | :--- |
"""
    all_resilient = resilience.get('detections', [])
    for det in all_resilient[:15]:
        sources = ", ".join(det.get('data_sources', []))
        md += f"| {det['id']} | {det['name']} | {det['rule_count']} | {det['data_diversity']} ({sources}) | **RESILIENT** |\n"

    md += """
### **Bottom 15 (Least Resilient)**
These techniques have minimal redundant coverage and low data diversity.

| Technique ID | Name | Rule Count | Data Diversity | Status |
| :--- | :--- | :--- | :--- | :--- |
"""
    least_resilient = sorted(all_resilient, key=lambda x: (x['data_diversity'], x['rule_count']))
    for det in least_resilient[:15]:
        sources = ", ".join(det.get('data_sources', []))
        md += f"| {det['id']} | {det['name']} | {det['rule_count']} | {det['data_diversity']} ({sources}) | **FRAGILE** |\n"

    md += """
*See [APPENDIX_RESILIENCE.md](./APPENDIX_RESILIENCE.md) for the full list of """ + str(len(all_resilient)) + """ resilient detections.*

---

## 7. Strategic Gaps & Recommendations
This section highlights critical gaps where your organization has no detection logic for high-risk threats or is missing the telemetry required to power existing rules.

### **High-Risk Technique Gaps**
The following techniques from the **""" + profile_name + """** profile currently have no active detection rules.

| Technique ID | Name | Risk Weight | Priority |
| :--- | :--- | :--- | :--- |
"""
    if not gaps['critical_techniques']:
        md += "| N/A | No high-risk gaps identified | - | **LOW** |\n"
    else:
        for gap in gaps['critical_techniques']:
            md += f"| {gap['id']} | {gap['name']} | {gap['risk_weight']} | **HIGH** |\n"

    md += """
### **Visibility Gaps (Detection logic exists, but NO LOGS)**
The following tactics have active detection rules, but **no supporting log data** was observed in the last 7 days. These rules are currently "Blind."
"""
    if not gaps['visibility_gaps']:
        md += "_No visibility gaps identified._\n"
    else:
        for t in gaps['visibility_gaps']:
            md += f"- [ ] `{t}`\n"

    md += """
### **Detection Gaps (Logs exist, but NO RULES)**
The following tactics have active log ingestion but **no corresponding detection rules**.
"""
    if not gaps['detection_gaps']:
        md += "_No detection gaps identified._\n"
    else:
        for t in gaps['detection_gaps']:
            md += f"- [ ] `{t}`\n"

    md += """
### **Blind Tactics (Zero Visibility & Zero Detection)**
The following tactics represent **total organizational blind spots**.

"""
    if not gaps['blind_tactics']:
        md += "_No completely blind tactics identified._\n"
    else:
        for tactic in gaps['blind_tactics']:
            md += f"- [ ] **{tactic}**\n"

    md += """
---

## 8. Methodology
This report was generated using the **Contextual Coverage Formula**:
$$Coverage\\_Score = \\frac{\\sum (Techniques \\times Risk\\_Relevance) + Resilience\\_Bonus}{\\text{Total Relevant Techniques}}$$

- **Validation Source:** Official MITRE ATT&CK Enterprise Matrix (STIX 2.1).
- **Diversity Metric:** "Data Diversity" measures the number of distinct log categories (EDR, Network, Cloud, Identity) supporting a tactic.
"""

    with open(output_path, 'w') as f:
        f.write(md)
    
    generate_appendix(all_resilient, "APPENDIX_RESILIENCE.md")
    print(f"Report successfully generated at: {output_path}")

def generate_appendix(detections, path):
    """Generate an exhaustive list of resilient detections with diversity."""
    md = f"""# Appendix: Full Detection Resilience List
**Generated:** {datetime.now().strftime('%Y-%m-%d')}
**Total Resilient Techniques:** {len(detections)}

| Technique ID | Name | Rule Count | Diversity | Data Sources |
| :--- | :--- | :--- | :--- | :--- |
"""
    for det in detections:
        sources = ", ".join(det.get('data_sources', []))
        md += f"| {det['id']} | {det['name']} | {det['rule_count']} | {det['data_diversity']} | {sources} |\n"
        
    with open(path, 'w') as f:
        f.write(md)
    print(f"Appendix generated at: {path}")

if __name__ == "__main__":
    try:
        with open('analysis_results.json', 'r') as f:
            data = json.load(f)
        generate_markdown_report(data, "MITRE_STRATEGIC_REPORT.md")
    except FileNotFoundError:
        print("analysis_results.json not found. Run strategic_gap_analyzer.py first.")
