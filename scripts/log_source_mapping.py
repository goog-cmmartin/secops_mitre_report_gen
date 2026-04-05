import json
import os
import re

# Industry Standard Baseline
LOG_SOURCE_VISIBILITY = {
    "EDR": {
        "patterns": [r".*EDR.*", r".*HX.*", r".*ATP.*", r".*DEFENDER.*", r".*SYSMON.*", r".*TANIUM.*", r".*SENTINEL.*", r".*CROWDSTRIKE.*"],
        "tactics": ["persistence", "privilege-escalation", "execution", "defense-evasion"],
        "description": "Endpoint telemetry."
    },
    "IDENTITY": {
        "patterns": [r".*AD.*", r".*OKTA.*", r".*IAM.*", r".*LDAP.*", r".*DUO.*", r".*WORKSPACE.*", r".*AZURE.*", r".*AUTH.*"],
        "tactics": ["initial-access", "credential-access", "lateral-movement"],
        "description": "Identity and Access events."
    },
    "CLOUD": {
        "patterns": [r".*GCP.*", r".*AWS.*", r".*AZURE.*", r".*CLOUD.*", r".*K8S.*", r".*KUBERNETES.*", r".*S3.*", r".*STORAGE.*"],
        "tactics": ["resource-hijacking", "exfiltration", "discovery"],
        "description": "Cloud infra and API activity."
    },
    "NETWORK": {
        "patterns": [r".*FW.*", r".*FIREWALL.*", r".*WAF.*", r".*DNS.*", r".*PROXY.*", r".*ZEEK.*", r".*IDS.*", r".*IPS.*", r".*TRAFFIC.*"],
        "tactics": ["command-and-control", "exfiltration", "reconnaissance"],
        "description": "Network traffic and flow data."
    }
}

def load_custom_mappings():
    """Load user-defined log mappings from a local file."""
    path = "profiles/custom_mappings.json"
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {}

def categorize_logs(log_list):
    """
    Categorize logs using a 3-tier approach:
    1. Custom Overrides
    2. Pattern-based Heuristics
    3. Industry Standard Map
    """
    custom_map = load_custom_mappings()
    categorized = {cat: [] for cat in LOG_SOURCE_VISIBILITY}
    categorized["OTHER"] = []
    
    for log in log_list:
        log_upper = log.upper()
        found = False
        
        # 1. Check Custom Overrides
        if log_upper in custom_map:
            cat = custom_map[log_upper]
            if cat in categorized:
                categorized[cat].append(log)
                found = True
        
        # 2. Check Patterns
        if not found:
            for category, info in LOG_SOURCE_VISIBILITY.items():
                for pattern in info["patterns"]:
                    if re.match(pattern, log_upper):
                        categorized[category].append(log)
                        found = True
                        break
                if found: break
        
        if not found:
            categorized["OTHER"].append(log)
            
    return categorized

def get_visibility_by_log_type(log_type):
    """Return the tactics covered by a specific log type."""
    # This is used for checking if a specific log type supports a tactic.
    # We'll use the categorization logic to find its parent category.
    categories = categorize_logs([log_type])
    visibility = []
    for cat, logs in categories.items():
        if logs and cat in LOG_SOURCE_VISIBILITY:
            visibility.extend(LOG_SOURCE_VISIBILITY[cat]["tactics"])
    return list(set(visibility))
