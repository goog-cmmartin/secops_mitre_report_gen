# Google SecOps MITRE Strategic Analysis Toolset

This repository contains a production-ready toolset for analyzing MITRE ATT&CK coverage within a Google SecOps (Chronicle) environment. It implements a **"Strategic Mapping"** approach that moves beyond raw percentages to evaluate **Detection Integrity**.

## Features
- **Automated Discovery**: Python scripts to fetch log ingestion status, YARA-L rule catalogs, and active detections using the SecOps `v1alpha` API.
- **Strategic Scoring**: Implements a risk-weighted formula that rewards **Resilience** (redundant rules) and **Data Diversity** (multiple log sources).
- **Local Source of Truth**: Uses the official MITRE Enterprise Matrix (STIX 2.1) for on-disk validation and enrichment.
- **Dynamic Mapping**: Heuristic-based log categorization (EDR, Cloud, Network, Identity) to identify Single Points of Failure (SPOFs).
- **Professional Reporting**: Generates an Executive Markdown Report and a technical Appendix.

## Project Structure
- `scripts/`: Python engine for API interaction and analysis.
- `profiles/`: MITRE STIX data, Threat Profiles, and Custom Mappings.
- `SKILL.md`: The Agent Skill definition for use with Gemini CLI.
- `MITRE_STRATEGIC_REPORT.md`: The primary output report.

## Setup
1. **Authentication**: Ensure you have [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/provide-credentials-adc) configured.
2. **Environment**: Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install google-auth requests
   ```
3. **Configuration**: Update the `PROJECT_ID`, `LOCATION`, and `INSTANCE_ID` in the scripts or `strategic_gap_analyzer.py`.

## Usage
Run the end-to-end analysis:
```bash
./venv/bin/python3 scripts/log_sources_fetcher.py
./venv/bin/python3 scripts/rule_downloader.py
./venv/bin/python3 scripts/detections_fetcher.py
./venv/bin/python3 scripts/strategic_gap_analyzer.py
```

## Methodology: The Contextual Coverage Formula
$$Coverage\_Score = \frac{\sum (Techniques \times Risk\_Relevance) + Resilience\_Bonus}{\text{Total Relevant Techniques}}$$

This tool helps you transition from "Checking a Box" to building a defensible, threat-informed security posture.
