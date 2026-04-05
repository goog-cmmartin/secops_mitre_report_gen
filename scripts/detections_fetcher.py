import os
import json
import requests
import google.auth
from datetime import datetime, timedelta, timezone
from google.auth.transport.requests import Request
from config import PROJECT_ID, LOCATION, INSTANCE_ID, DETECTIONS_FILE, LOOKBACK_DAYS

def get_auth_token():
    """Get a Google Auth token for the Chronicle API."""
    credentials, project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/chronicle-siem"]
    )
    credentials.refresh(Request())
    return credentials.token

def fetch_mitre_detections(project_id, location, instance_id, days=7):
    """Fetch active MITRE detections using dashboardQueries:execute."""
    token = get_auth_token()
    url = f"https://{location}-chronicle.googleapis.com/v1alpha/projects/{project_id}/locations/{location}/instances/{instance_id}/dashboardQueries:execute"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    query_string = """
    $Tactic_ID = detection.collection_elements.references.event.security_result.attack_details.tactics.id
    $Tactic_Name = detection.collection_elements.references.event.security_result.attack_details.tactics.name
    $Tactic_Name != ""
    $Technique_Name = detection.collection_elements.references.event.security_result.attack_details.techniques.name
    $Technique_ID = detection.collection_elements.references.event.security_result.attack_details.techniques.id
    $Sub_Technique = detection.collection_elements.references.event.security_result.attack_details.techniques.subtechnique_name

    match:
        $Tactic_Name, $Tactic_ID, $Technique_Name, $Technique_ID, $Sub_Technique

    outcome: 
        $Ruleset_Count = count_distinct(detection.detection.rule_set_display_name)
        $Detection_Count = count_distinct(detection.id)
        $First_Seen = timestamp.get_timestamp(min(detection.detection_time.seconds), "%F %T")
        $Last_Seen = timestamp.get_timestamp(max(detection.detection_time.seconds), "%F %T")

    order:  
        $Detection_Count desc  
    """
    
    payload = {
        "query": {
            "query": query_string,
            "input": {
                "time_window": {
                    "start_time": start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "end_time": end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                }
            }
        }
    }
    
    print(f"Fetching MITRE detections from {url} ({days}-day window)...")
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None

if __name__ == "__main__":
    result = fetch_mitre_detections(PROJECT_ID, LOCATION, INSTANCE_ID, LOOKBACK_DAYS)
    if result:
        with open(DETECTIONS_FILE, "w") as f:
            json.dump(result, f, indent=2)
        print(f"Active detections saved to {DETECTIONS_FILE}.")
