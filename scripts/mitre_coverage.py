import json
import re

def load_mitre_data(stix_path):
    """Load and parse MITRE STIX JSON into a mapping of Technique ID -> Metadata and Matrix Stats."""
    with open(stix_path, 'r') as f:
        data = json.load(f)
    
    mapping = {}
    tactics = set()
    collection_version = "Unknown"
    
    # Priority 1: x-mitre-collection (This is the official ATT&CK release version, e.g., 18.1)
    # Priority 2: x-mitre-matrix
    for obj in data.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            collection_version = obj.get("x_mitre_version", collection_version)
        
        if obj.get("type") == "attack-pattern":
            # Extract Technique ID (e.g., T1059)
            external_ids = obj.get("external_references", [])
            tech_id = next((ref["external_id"] for ref in external_ids if ref.get("source_name") == "mitre-attack"), None)
            
            if tech_id:
                tech_tactics = [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])]
                for t in tech_tactics:
                    tactics.add(t)
                    
                mapping[tech_id] = {
                    "name": obj.get("name"),
                    "description": obj.get("description", "")[:200] + "...",
                    "tactics": tech_tactics
                }
    
    # If collection version wasn't found, fallback to matrix version
    if collection_version == "Unknown":
        for obj in data.get("objects", []):
            if obj.get("type") == "x-mitre-matrix":
                collection_version = obj.get("x_mitre_version", collection_version)

    stats = {
        "version": collection_version,
        "total_techniques": len(mapping),
        "total_tactics": len(tactics)
    }
    
    return mapping, stats

def calculate_mitre_coverage(rules_json_path, mitre_mapping, risk_relevance_map, total_relevant_techniques):
    """
    Calculate MITRE Coverage Score using a local MITRE matrix for validation.
    """
    with open(rules_json_path, 'r') as f:
        rules = json.load(f)
    
    covered_techniques = {} # ID -> Count
    
    for rule in rules:
        source_text = rule.get("ruleText", "") + " " + " ".join(rule.get("tags", []))
        techs = re.findall(r'T\d{4}(?:\.\d{3})?', source_text, re.IGNORECASE)
        for t in techs:
            t = t.upper()
            if t in mitre_mapping: # Validate against local matrix
                covered_techniques[t] = covered_techniques.get(t, 0) + 1
            
    weighted_sum = 0
    for tech, count in covered_techniques.items():
        weight = risk_relevance_map.get(tech, 1)
        weighted_sum += weight
        
        # Resilience Bonus
        if count > 1:
            weighted_sum += 0.5
            
    if total_relevant_techniques == 0:
        total_relevant_techniques = len(mitre_mapping)
        
    coverage_score = weighted_sum / total_relevant_techniques
    return coverage_score, covered_techniques

if __name__ == "__main__":
    MITRE_PATH = "profiles/enterprise-attack.json"
    RULES_FILE = "downloaded_rules.json"
    
    try:
        mitre_map, stats = load_mitre_data(MITRE_PATH)
        print(f"Loaded MITRE ATT&CK {stats['version']}")
        print(f"Total Techniques: {stats['total_techniques']}")
        
        RISK_MAP = {"T1059": 5, "T1078": 5, "T1566": 5}
        TOTAL_RELEVANT = 200 
        
        score, covered = calculate_mitre_coverage(RULES_FILE, mitre_map, RISK_MAP, TOTAL_RELEVANT)
        print(f"MITRE Coverage Score: {score:.4f}")
    except FileNotFoundError:
        print("Error: Required files missing.")
