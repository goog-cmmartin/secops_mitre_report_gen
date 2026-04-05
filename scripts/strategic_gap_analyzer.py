import json
import re
import os
from log_source_mapping import get_visibility_by_log_type, categorize_logs, LOG_SOURCE_VISIBILITY
from mitre_coverage import load_mitre_data
from config import (
    PROJECT_ID, LOCATION, INSTANCE_ID, 
    MITRE_MATRIX_PATH, THREAT_PROFILES_PATH,
    LOGS_FILE, RULES_FILE, DETECTIONS_FILE, RESULTS_FILE,
    MAIN_REPORT_FILE
)

def analyze_strategic_gaps(rules_path, logs_path, detections_path, mitre_path, profile_key, tenant_info=None):
    """
    Perform a Strategic MITRE Gap Analysis with Enrichment, Diversity, and Operational Firing Data.
    """
    # Load Data
    mitre_mapping, mitre_stats = load_mitre_data(mitre_path)
    
    all_matrix_tactics = set()
    for meta in mitre_mapping.values():
        all_matrix_tactics.update(meta.get("tactics", []))
    
    with open(rules_path, 'r') as f:
        rules = json.load(f)
    
    with open(logs_path, 'r') as f:
        logs_data = json.load(f)
        
    with open(detections_path, 'r') as f:
        detections_data = json.load(f)

    with open(THREAT_PROFILES_PATH, 'r') as f:
        profiles = json.load(f)
        profile = profiles.get(profile_key, profiles['global_baseline'])

    # 1. Log Visibility
    ingested_logs = []
    if 'results' in logs_data:
        log_type_col = next((c for c in logs_data['results'] if c.get('column') == 'log_type'), None)
        if log_type_col:
            for val_obj in log_type_col.get('values', []):
                log_val = val_obj.get('value', {}).get('stringVal')
                if log_val: ingested_logs.append(log_val)
    
    categorized_logs = categorize_logs(ingested_logs)
    category_visibility = {}
    for cat, logs in categorized_logs.items():
        if logs and cat in LOG_SOURCE_VISIBILITY:
            category_visibility[cat] = LOG_SOURCE_VISIBILITY[cat]['tactics']
            
    visibility_tactics = set()
    for t_list in category_visibility.values():
        visibility_tactics.update(t_list)
        
    # 2. Extract Covered Techniques (Logic)
    technique_counts = {} 
    technique_to_rules = {}
    covered_tactics = set()
    enabled_count = sum(1 for r in rules if r.get("liveModeEnabled", False))

    for rule in rules:
        display_name = rule.get("displayName", "Unnamed Rule")
        tags = rule.get("tags", [])
        techs = re.findall(r'T\d{4}(?:\.\d{3})?', " ".join(tags), re.IGNORECASE)
        for t in techs:
            t = t.upper()
            if t in mitre_mapping:
                technique_counts[t] = technique_counts.get(t, 0) + 1
                covered_tactics.update(mitre_mapping[t].get("tactics", []))
                if t not in technique_to_rules: technique_to_rules[t] = []
                if display_name not in technique_to_rules[t]: technique_to_rules[t].append(display_name)

    # 3. Operational Firing Data
    firing_stats = {}
    if 'results' in detections_data:
        id_col = next((c for c in detections_data['results'] if c.get('column') == 'Technique_ID'), None)
        count_col = next((c for c in detections_data['results'] if c.get('column') == 'Detection_Count'), None)
        if id_col and count_col:
            for i in range(len(id_col['values'])):
                tech_id = id_col['values'][i].get('value', {}).get('stringVal', '').upper()
                count = int(count_col['values'][i].get('value', {}).get('int64Val', 0))
                if tech_id in mitre_mapping:
                    firing_stats[tech_id] = count

    # 4. Resilience & Diversity
    technique_diversity = {}
    for tech in technique_counts:
        t_tactics = mitre_mapping[tech].get("tactics", [])
        supporting_categories = []
        for cat, cat_tactics in category_visibility.items():
            if any(tt in t_tactics for tt in cat_tactics):
                supporting_categories.append(cat)
        technique_diversity[tech] = {"count": len(supporting_categories), "sources": supporting_categories}

    # 5. Strategic Gaps
    visibility_gaps = [t for t in all_matrix_tactics if t not in visibility_tactics]
    detection_gaps = [t for t in all_matrix_tactics if t not in covered_tactics]
    blind_tactics = [t for t in all_matrix_tactics if t not in visibility_tactics and t not in covered_tactics]

    # 6. Coverage Score
    high_risk_map = profile['high_risk_techniques']
    total_relevant = profile['relevant_techniques']
    sum_risk_relevance = sum(high_risk_map.get(tech, 1) for tech in technique_counts)
    resilience_bonus = sum(0.5 for count in technique_counts.values() if count > 1)
    coverage_score = (sum_risk_relevance + resilience_bonus) / total_relevant

    # 7. Final Report Object
    report = {
        "profile": profile['name'],
        "tenant_info": tenant_info or {},
        "mitre_stats": mitre_stats,
        "metrics": {
            "validated_technique_count": len(technique_counts),
            "contextual_coverage_score": round(coverage_score, 4),
            "visibility_tactics_count": len(visibility_tactics),
            "visibility_tactics": sorted(list(visibility_tactics)),
            "detection_tactics_count": len(covered_tactics),
            "total_rules": len(rules),
            "enabled_rules": enabled_count,
            "firing_techniques_count": len(firing_stats),
            "categorized_logs": categorized_logs
        },
        "score_breakdown": {
            "sum_risk_weighted_techniques": sum_risk_relevance,
            "resilience_bonus": resilience_bonus,
            "total_relevant_baseline": total_relevant,
            "formula": "(Sum_Risk_Weighted_Techniques + Resilience_Bonus) / Total_Relevant_Baseline"
        },
        "gaps": {
            "visibility_gaps": sorted(visibility_gaps),
            "detection_gaps": sorted(detection_gaps),
            "blind_tactics": sorted(blind_tactics),
            "critical_techniques": []
        },
        "resilience": {"detections": []},
        "firing_detections": [],
        "technique_to_rules": technique_to_rules
    }
    
    for tech in high_risk_map:
        if tech not in technique_counts:
            meta = mitre_mapping.get(tech, {})
            report["gaps"]["critical_techniques"].append({
                "id": tech, "name": meta.get("name", "Unknown"), "risk_weight": high_risk_map[tech]
            })

    for tech, count in technique_counts.items():
        if count > 1:
            meta = mitre_mapping.get(tech, {})
            div = technique_diversity.get(tech, {"count": 0, "sources": []})
            report["resilience"]["detections"].append({
                "id": tech, "name": meta.get("name"), "rule_count": count, 
                "tactics": meta.get("tactics", []), "data_diversity": div["count"], "data_sources": div["sources"]
            })
    report["resilience"]["detections"] = sorted(report["resilience"]["detections"], key=lambda x: x['rule_count'], reverse=True)

    for tech, count in firing_stats.items():
        meta = mitre_mapping.get(tech, {})
        report["firing_detections"].append({
            "id": tech, "name": meta.get("name"), "alert_count": count, "tactics": meta.get("tactics", [])
        })
    report["firing_detections"] = sorted(report["firing_detections"], key=lambda x: x['alert_count'], reverse=True)

    return report

from report_generator import generate_markdown_report

if __name__ == "__main__":
    TENANT_INFO = {"project_id": PROJECT_ID, "location": LOCATION, "instance_id": INSTANCE_ID}
    
    if all(os.path.exists(f) for f in [RULES_FILE, LOGS_FILE, DETECTIONS_FILE]):
        analysis = analyze_strategic_gaps(RULES_FILE, LOGS_FILE, DETECTIONS_FILE, MITRE_MATRIX_PATH, "eu_public_finance", tenant_info=TENANT_INFO)
        with open(RESULTS_FILE, 'w') as f: json.dump(analysis, f, indent=2)
        generate_markdown_report(analysis, MAIN_REPORT_FILE)
    else:
        print("Missing data files. Run fetchers first.")
