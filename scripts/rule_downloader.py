import os
import json
import requests
import google.auth
from google.auth.transport.requests import Request
from config import PROJECT_ID, LOCATION, INSTANCE_ID, RULES_FILE

def get_auth_token():
    """Get a Google Auth token for the Chronicle API."""
    credentials, project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/chronicle-siem"]
    )
    credentials.refresh(Request())
    return credentials.token

def download_rules(project_id, location, instance_id):
    """Download all available system and custom YARA-L rules."""
    token = get_auth_token()
    base_url = f"https://{location}-chronicle.googleapis.com/v1alpha/projects/{project_id}/locations/{location}/instances/{instance_id}/rules"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    params = {
        "filter": 'rule_owner:"*"',
        "pageSize": 5000,
        "view": "CONFIG_ONLY"
    }
    
    all_rules = []
    page_token = None
    
    while True:
        if page_token:
            params["pageToken"] = page_token
            
        print(f"Fetching rules (page token: {page_token})...")
        response = requests.get(base_url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            rules = data.get("rules", [])
            all_rules.extend(rules)
            print(f"Downloaded {len(rules)} rules. Total: {len(all_rules)}")
            
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            break
            
    return all_rules

if __name__ == "__main__":
    rules = download_rules(PROJECT_ID, LOCATION, INSTANCE_ID)
    if rules:
        with open(RULES_FILE, "w") as f:
            json.dump(rules, f, indent=2)
        print(f"Saved {len(rules)} rules to {RULES_FILE}.")
