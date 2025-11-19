#!/usr/bin/env python3
"""Test Search API to find network activities with public IPs"""
import requests
import json
from datetime import datetime, timedelta

API_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiIyOGQ2ZTNkNS05ZTA2LTQ2YzItOWFlNC0wOTM1NGExNThlMzYiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzU2OTg4NjQ1LCJldCI6MTc4ODUyNDY0NCwiaWQiOiJlZjQxNDFhZS0xM2NlLTQ5NTQtOTQ1Yi00Y2Y0MzhlMGU1ZDkiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.vtSV1l6fXmDlfuyayTXt0WWWCtUrksRpBJXvDrYLsKnVte1xzj6vOHyAn20-8x7sgbiUx8j7mEZJapgNYVqasW3Tm7869o34z0O93oGXVxDY7KcPHelc2bSw6Ay10ASbppRMExtHk7xURtQrm6xg3cWIgMkk8RPEay54w5VJNh7i2G8spGb_P7_awp1ySIc0CTaRsUIZ0QrsCjjxrBgl7FERt0H6uL1-fU8XhAWkseY1TTB6CwySz8WQpVHKxnJ7Ap2u4UuWywc9AiNmuzpFkq7dds5OcCT0yFt4PbVhadaLFq5ccrCQMBPiwhB5kXag-C-3VOcWIbAqDCWYRZKFQb1fPBSyOYfxP1ZY5406LXZ339-_-aa5J9c2EWaymQ_2eV8W-gbchdlbZztAipubpa6FGQvdJkxgluzdVZM8sgKevToPQ4nM8-E1RVghru4PmeB0IYABVWxHAtPB7pp5pDNJn_S5IfPyXWzn4AuQRaXaf-3UM0wuWqYoR8bUXbpdX9u8AMhqrqlDKvx1lGH988FNN1sqv3WJgePDVof1rabJNUm-BvQQntVcHECUw2rwl4tJifav1y7Q_lcMhuweOG101KNj3nA1ZbGOGeSlJqtmB2BesiGTl28PNLtbemC9EFDPjkuRlM432SkrF_G8g_1VJ1WS3GmRuL6BmGSOtDk"
BASE_URL = "https://api.eu.xdr.trendmicro.com"

headers = {
    'Authorization': f'Bearer {API_TOKEN}',
    'Content-Type': 'application/json',
    'TMV1-Filter': 'top=10'
}

# Search for network activities
endpoint = "/v3.0/search/networkActivities"
url = BASE_URL + endpoint

# Time range - last 24 hours
end_time = datetime.utcnow()
start_time = end_time - timedelta(hours=24)

payload = {
    "startDateTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "endDateTime": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "top": 10
}

print(f"Searching for network activities (last 24 hours)...")
print(f"URL: {url}")
print(f"Payload: {json.dumps(payload, indent=2)}\n")

try:
    response = requests.post(url, headers=headers, json=payload)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"\nResults found: {len(data.get('items', []))}")
        print(f"\nResponse:\n{json.dumps(data, indent=2)[:1000]}...")
    else:
        print(f"Error: {response.text}")
        
except Exception as e:
    print(f"Exception: {e}")
