# MITRE Tactics and Technique Analysis Plan

## Objective
Develop a toolset for analyzing MITRE ATT&CK coverage in Google SecOps. This involves:
1. Fetching available log sources to understand data visibility.
2. Downloading all YARA-L rules (system and custom) to identify detection capabilities.
3. Implementing a MITRE coverage scoring model to quantify security posture.

## Key Files & Context
- `scripts/log_sources_fetcher.py`: Python script to fetch ingested log types using `dashboardQueries:execute`.
- `scripts/rule_downloader.py`: Python script to download all YARA-L rules using `rules:list`.
- `scripts/mitre_coverage.py`: Implementation of the MITRE coverage scoring logic.
- `MITRE_ANALYSIS_SKILL.md`: Draft for the Gemini CLI Agent Skill.

## Implementation Steps

### 1. Authentication & API Access
- Use `google-auth` to obtain access tokens.
- Target endpoints:
    - Log Sources: `https://us-chronicle.googleapis.com/v1alpha/projects/{project}/locations/{location}/instances/{instance}/dashboardQueries:execute`
    - Rules: `https://us-chronicle.googleapis.com/v1alpha/projects/{project}/locations/{location}/instances/{instance}/rules`

### 2. Log Source Discovery (`scripts/log_sources_fetcher.py`)
- Implement a request to `dashboardQueries:execute`.
- Query: `ingestion.log_type != "" | match: ingestion.log_type | outcome: $Count = count_distinct(ingestion.log_type)` (or similar ingestion metrics query).
- Parse the response to list active log types.

### 3. Rule Downloader (`scripts/rule_downloader.py`)
- Call `rules:list` with `filter=rule_owner:*` and `view=CONFIG_ONLY`.
- Implement pagination handling for `next_page_token`.
- Save rules locally (e.g., in a JSON or individual `.yaral` files) for analysis.

### 4. MITRE Coverage Scoring (`scripts/mitre_coverage.py`)
- Extract MITRE metadata from the downloaded YARA-L rules (look for `tactic` and `technique` in the `meta` section).
- Implement the formula:
    $$Coverage\_Score = \frac{\sum (Techniques \times Risk\_Relevance)}{\text{Total Relevant Techniques}}$$
- Requirements:
    - `Techniques`: Map of unique techniques covered by the rules.
    - `Risk_Relevance`: A weight (e.g., 1-5) for each technique.
    - `Total Relevant Techniques`: A baseline of relevant techniques (e.g., based on industry or threat profile).

### 5. Skill Creation
- Draft `MITRE_ANALYSIS_SKILL.md` to provide specialized guidance on MITRE analysis within the Gemini CLI.

## Verification & Testing
- Validate API connectivity and data retrieval.
- Ensure YARA-L parsing correctly identifies MITRE tags.
- Sanity check the coverage score against a known set of rules.
