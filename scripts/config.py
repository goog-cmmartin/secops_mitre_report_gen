import os
import sys

def get_env_var(name, default=None, required=True):
    """Retrieve environment variable or exit if required and missing."""
    val = os.getenv(name, default)
    if required and not val:
        print(f"Error: Environment variable '{name}' is not set.")
        print(f"Please set it using: export {name}='your_value'")
        sys.exit(1)
    return val

# Google SecOps Tenant Configuration
# These are now REQUIRED and have NO hardcoded defaults for security.
PROJECT_ID = get_env_var("CHRONICLE_PROJECT_ID")
LOCATION = get_env_var("CHRONICLE_LOCATION", default="us")
INSTANCE_ID = get_env_var("CHRONICLE_INSTANCE_ID")

# Analysis Configuration
DEFAULT_PROFILE = os.getenv("CHRONICLE_DEFAULT_PROFILE", "global_baseline")
LOOKBACK_DAYS = int(os.getenv("CHRONICLE_LOOKBACK_DAYS", "7"))

# Paths
MITRE_MATRIX_PATH = "profiles/enterprise-attack.json"
THREAT_PROFILES_PATH = "profiles/threat_profiles.json"
CUSTOM_MAPPINGS_PATH = "profiles/custom_mappings.json"

# Output Files (Defined in .gitignore to prevent check-in)
LOGS_FILE = "ingested_logs.json"
RULES_FILE = "downloaded_rules.json"
DETECTIONS_FILE = "active_detections.json"
RESULTS_FILE = "analysis_results.json"
MAIN_REPORT_FILE = "MITRE_STRATEGIC_REPORT.md"
APPENDIX_FILE = "APPENDIX_RESILIENCE.md"
