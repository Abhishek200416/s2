#!/usr/bin/env python3
"""
Fixed Webhook Test Script - Correct URL without double /api/
"""
import requests
import json
import datetime

# --- CONFIGURE THESE ---
API_KEY = "aw_7pmImwLYV7IlDEfgIX52G2IHosxnyqELNDdfie2ABn0"
# FIXED: Removed double /api/api/ - now using single /api/
WEBHOOK_URL = "https://dynamo-db-checker.preview.emergentagent.com/api/webhooks/alerts"

print("=" * 60)
print("Alert Whisperer - Webhook Test (FIXED URL)")
print("=" * 60)
print(f"API Key: {API_KEY}")
print(f"Webhook URL: {WEBHOOK_URL}")
print("=" * 60)

# Example alert payload (customize as needed)
payload = {
    "asset_name": "server-01",
    "signature": "high_cpu_usage",
    "severity": "high",  # Options: "critical", "high", "medium", "low"
    "message": "CPU usage above 90%",
    "tool_source": "Python Monitoring Script",
    "timestamp": datetime.datetime.utcnow().isoformat() + "Z"  # Optional, ISO 8601 UTC
}

print("\nSending alert payload:")
print(json.dumps(payload, indent=2))
print()

# Build the full webhook URL with the API key as a query parameter
url = f"{WEBHOOK_URL}?api_key={API_KEY}"

try:
    # Send the POST request
    response = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=10
    )

    # --- Output Result ---
    print("=" * 60)
    if response.status_code == 200:
        print("✅ SUCCESS: Alert sent successfully!")
        print()
        response_data = response.json()
        print("Response:")
        print(json.dumps(response_data, indent=2))
        print()
        if response_data.get("duplicate"):
            print("⚠️  NOTE: This is a duplicate alert (idempotency working)")
            print(f"   Original alert_id: {response_data.get('alert_id')}")
        else:
            print(f"✅ New alert created with ID: {response_data.get('alert_id')}")
            print(f"   Created at: {response_data.get('created_at')}")
    else:
        print(f"❌ FAILED: Status code {response.status_code}")
        print()
        try:
            error_data = response.json()
            print("Error response:")
            print(json.dumps(error_data, indent=2))
        except Exception:
            print("Raw response:")
            print(response.text)
    print("=" * 60)

except requests.exceptions.ConnectionError as e:
    print(f"❌ CONNECTION ERROR: Could not connect to {WEBHOOK_URL}")
    print(f"   Details: {e}")
except requests.exceptions.Timeout:
    print(f"❌ TIMEOUT ERROR: Request took longer than 10 seconds")
except Exception as e:
    print(f"❌ UNEXPECTED ERROR: {e}")
    import traceback
    traceback.print_exc()
