import os

# Google SecOps Tenant Configuration
# Users should update these values or set them as Environment Variables
PROJECT_ID = os.getenv("CHRONICLE_PROJECT_ID", "gus-sdl")
LOCATION = os.getenv("CHRONICLE_LOCATION", "us")
INSTANCE_ID = os.getenv("CHRONICLE_INSTANCE_ID", "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5")

# Analysis Configuration
DEFAULT_PROFILE = "global_baseline"
LOOKBACK_DAYS = 7

# Paths
MITRE_MATRIX_PATH = "profiles/enterprise-attack.json"
THREAT_PROFILES_PATH = "profiles/threat_profiles.json"
CUSTOM_MAPPINGS_PATH = "profiles/custom_mappings.json"

# Output Files
LOGS_FILE = "ingested_logs.json"
RULES_FILE = "downloaded_rules.json"
DETECTIONS_FILE = "active_detections.json"
RESULTS_FILE = "analysis_results.json"
MAIN_REPORT_FILE = "MITRE_STRATEGIC_REPORT.md"
APPENDIX_FILE = "APPENDIX_RESILIENCE.md"
