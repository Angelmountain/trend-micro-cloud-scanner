#!/usr/bin/env python3
import requests
import json

API_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiIyOGQ2ZTNkNS05ZTA2LTQ2YzItOWFlNC0wOTM1NGExNThlMzYiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzU2OTg4NjQ1LCJldCI6MTc4ODUyNDY0NCwiaWQiOiJlZjQxNDFhZS0xM2NlLTQ5NTQtOTQ1Yi00Y2Y0MzhlMGU1ZDkiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.vtSV1l6fXmDlfuyayTXt0WWWCtUrksRpBJXvDrYLsKnVte1xzj6vOHyAn20-8x7sgbiUx8j7mEZJapgNYVqasW3Tm7869o34z0O93oGXVxDY7KcPHelc2bSw6Ay10ASbppRMExtHk7xURtQrm6xg3cWIgMkk8RPEay54w5VJNh7i2G8spGb_P7_awp1ySIc0CTaRsUIZ0QrsCjjxrBgl7FERt0H6uL1-fU8XhAWkseY1TTB6CwySz8WQpVHKxnJ7Ap2u4UuWywc9AiNmuzpFkq7dds5OcCT0yFt4PbVhadaLFq5ccrCQMBPiwhB5kXag-C-3VOcWIbAqDCWYRZKFQb1fPBSyOYfxP1ZY5406LXZ339-_-aa5J9c2EWaymQ_2eV8W-gbchdlbZztAipubpa6FGQvdJkxgluzdVZM8sgKevToPQ4nM8-E1RVghru4PmeB0IYABVWxHAtPB7pp5pDNJn_S5IfPyXWzn4AuQRaXaf-3UM0wuWqYoR8bUXbpdX9u8AMhqrqlDKvx1lGH988FNN1sqv3WJgePDVof1rabJNUm-BvQQntVcHECUw2rwl4tJifav1y7Q_lcMhuweOG101KNj3nA1ZbGOGeSlJqtmB2BesiGTl28PNLtbemC9EFDPjkuRlM432SkrF_G8g_1VJ1WS3GmRuL6BmGSOtDk"
BASE_URL = "https://api.eu.xdr.trendmicro.com"

headers = {
    'Authorization': f'Bearer {API_TOKEN}',
    'Content-Type': 'application/json'
}

# Try different endpoint possibilities
endpoints_to_test = [
    "/v3.0/attackSurfaceCloudAssets",
    "/v3.0/asrm/cloudAssets",
    "/v3.0/cloudAssets",
    "/v3.0/search/cloudAssets"
]

print("Testing available API endpoints...\n")

for endpoint in endpoints_to_test:
    url = BASE_URL + endpoint
    try:
        response = requests.get(url, headers=headers)
        print(f"✓ {endpoint}")
        print(f"  Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Response: {json.dumps(data, indent=2)[:200]}...")
        else:
            print(f"  Response: {response.text[:100]}")
    except Exception as e:
        print(f"✗ {endpoint}")
        print(f"  Error: {str(e)[:100]}")
    print()
