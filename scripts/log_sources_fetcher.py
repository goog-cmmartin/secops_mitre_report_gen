import os
import json
import requests
import google.auth
from datetime import datetime, timedelta, timezone
from google.auth.transport.requests import Request
from config import PROJECT_ID, LOCATION, INSTANCE_ID, LOGS_FILE, LOOKBACK_DAYS

def get_auth_token():
    """Get a Google Auth token for the Chronicle API."""
    credentials, project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/chronicle-siem"]
    )
    credentials.refresh(Request())
    return credentials.token

def fetch_log_sources(project_id, location, instance_id, days=7):
    """Fetch available log sources using dashboardQueries:execute."""
    token = get_auth_token()
    url = f"https://{location}-chronicle.googleapis.com/v1alpha/projects/{project_id}/locations/{location}/instances/{instance_id}/dashboardQueries:execute"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    payload = {
        "query": {
            "query": 'ingestion.log_type != "" match: ingestion.log_type outcome: $Last_Seen = max(ingestion.end_time)',
            "input": {
                "time_window": {
                    "start_time": start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "end_time": end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                }
            }
        }
    }
    
    print(f"Fetching log sources from {url} ({days}-day window)...")
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None

if __name__ == "__main__":
    result = fetch_log_sources(PROJECT_ID, LOCATION, INSTANCE_ID, LOOKBACK_DAYS)
    if result:
        with open(LOGS_FILE, "w") as f:
            json.dump(result, f, indent=2)
        print(f"Log sources saved to {LOGS_FILE}.")
