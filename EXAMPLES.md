# Usage Examples

This document provides detailed examples for using the Trend Micro Cloud Scanner.

## Table of Contents

1. [Basic Scanning](#basic-scanning)
2. [Advanced Filtering](#advanced-filtering)
3. [Output Formats](#output-formats)
4. [Automation Scripts](#automation-scripts)
5. [Real-World Scenarios](#real-world-scenarios)

## Basic Scanning

### Scan All AWS EC2 Instances

```bash
export TREND_MICRO_API_TOKEN="your_api_token"
python cloud_scanner.py --provider AWS
```

### Scan with Specific Region

```bash
python cloud_scanner.py \
  --region eu-central-1 \
  --provider AWS \
  --api-token "your_token"
```

### Scan Azure Virtual Machines

```bash
python cloud_scanner.py \
  --provider Azure \
  --asset-type "Virtual Machine"
```

### Scan GCP Compute Instances

```bash
python cloud_scanner.py \
  --provider GCP \
  --asset-type "Compute Instance"
```

## Advanced Filtering

### Find Only High-Risk Assets

```bash
python cloud_scanner.py \
  --provider AWS \
  --min-risk-score 70 \
  --output high_risk.json
```

### Find Critical Risk Assets

```bash
python cloud_scanner.py \
  --provider AWS \
  --min-risk-score 90 \
  --format markdown \
  --output critical_assets.md
```

### Scan Specific Asset Types

```bash
# AWS RDS Instances
python cloud_scanner.py \
  --provider AWS \
  --asset-type "RDS Instance"

# Azure SQL Databases
python cloud_scanner.py \
  --provider Azure \
  --asset-type "SQL Database"
```

## Output Formats

### JSON Output

```bash
python cloud_scanner.py \
  --provider AWS \
  --format json \
  --output scan_results.json
```

**Example output:**

```json
[
  {
    "asset_name": "production-web-server",
    "asset_id": "i-0a1b2c3d4e5f6g7h8",
    "provider": "AWS",
    "region": "us-east-1",
    "risk_score": 75,
    "public_ip": "203.0.113.10",
    "open_ports": [22, 80, 443, 3306],
    "services": [
      {"port": 22, "protocol": "TCP", "service_name": "SSH"},
      {"port": 80, "protocol": "TCP", "service_name": "HTTP"},
      {"port": 443, "protocol": "TCP", "service_name": "HTTPS"},
      {"port": 3306, "protocol": "TCP", "service_name": "MySQL"}
    ]
  }
]
```

### CSV Output for Spreadsheets

```bash
python cloud_scanner.py \
  --provider AWS \
  --format csv \
  --output assets_report.csv
```

**Opens in Excel, Google Sheets, etc.**

### Markdown Report

```bash
python cloud_scanner.py \
  --provider AWS \
  --format markdown \
  --output security_report.md
```

**Great for documentation and sharing with teams.**

## Automation Scripts

### Daily Security Scan (Bash)

Create `daily_scan.sh`:

```bash
#!/bin/bash

# Daily cloud security scan script

DATE=$(date +%Y%m%d)
REPORT_DIR="/var/reports/cloud-scanner"
mkdir -p "$REPORT_DIR"

# Load API token
export TREND_MICRO_API_TOKEN="your_token_here"

# Scan AWS
echo "Scanning AWS..."
python cloud_scanner.py \
  --provider AWS \
  --format json \
  --output "$REPORT_DIR/aws_scan_$DATE.json"

# Scan Azure
echo "Scanning Azure..."
python cloud_scanner.py \
  --provider Azure \
  --format json \
  --output "$REPORT_DIR/azure_scan_$DATE.json"

# Generate summary report
python cloud_scanner.py \
  --provider AWS \
  --min-risk-score 70 \
  --format markdown \
  --output "$REPORT_DIR/high_risk_summary_$DATE.md"

echo "Scan complete! Reports saved to $REPORT_DIR"
```

Make it executable:

```bash
chmod +x daily_scan.sh
```

Add to crontab:

```bash
# Run daily at 2 AM
0 2 * * * /path/to/daily_scan.sh >> /var/log/cloud-scanner.log 2>&1
```

### Weekly High-Risk Report

Create `weekly_report.sh`:

```bash
#!/bin/bash

WEEK=$(date +%Y-W%V)
REPORT_FILE="weekly_high_risk_$WEEK.md"

python cloud_scanner.py \
  --provider AWS \
  --min-risk-score 80 \
  --format markdown \
  --output "$REPORT_FILE"

# Email the report (requires mailx or similar)
cat "$REPORT_FILE" | mail -s "Weekly High-Risk Assets Report" security-team@example.com
```

### Python Automation Script

Create `automated_scan.py`:

```python
#!/usr/bin/env python3
import subprocess
import os
from datetime import datetime

def run_scan(provider, output_dir="./reports"):
    """Run cloud scanner for a specific provider"""

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/{provider.lower()}_scan_{timestamp}.json"

    cmd = [
        "python", "cloud_scanner.py",
        "--provider", provider,
        "--format", "json",
        "--output", output_file
    ]

    print(f"Scanning {provider}...")
    subprocess.run(cmd, check=True)
    print(f"Results saved to {output_file}")

    return output_file

def main():
    providers = ["AWS", "Azure", "GCP"]

    for provider in providers:
        try:
            run_scan(provider)
        except Exception as e:
            print(f"Error scanning {provider}: {e}")

if __name__ == "__main__":
    main()
```

## Real-World Scenarios

### Scenario 1: Security Audit

**Goal:** Identify all publicly exposed assets for a security audit.

```bash
# Full scan with detailed report
python cloud_scanner.py \
  --provider AWS \
  --format markdown \
  --output security_audit_$(date +%Y%m%d).md \
  --verbose
```

### Scenario 2: Incident Response

**Goal:** Quickly find high-risk assets during an incident.

```bash
# Find critical assets immediately
python cloud_scanner.py \
  --provider AWS \
  --min-risk-score 90 \
  --format json \
  --output incident_assets.json

# Review the output
cat incident_assets.json | jq '.[] | {name: .asset_name, ip: .public_ip, ports: .open_ports}'
```

### Scenario 3: Compliance Reporting

**Goal:** Generate monthly compliance reports.

```bash
# Monthly scan for compliance
MONTH=$(date +%Y-%m)

python cloud_scanner.py \
  --provider AWS \
  --format csv \
  --output "compliance_report_$MONTH.csv"

# Generate summary
python cloud_scanner.py \
  --provider AWS \
  --format markdown \
  --output "compliance_summary_$MONTH.md"
```

### Scenario 4: Multi-Cloud Inventory

**Goal:** Create an inventory of all cloud assets.

```bash
#!/bin/bash

# Scan all cloud providers
for PROVIDER in AWS Azure GCP; do
  echo "Scanning $PROVIDER..."
  python cloud_scanner.py \
    --provider $PROVIDER \
    --format json \
    --output "${PROVIDER}_inventory.json"
done

# Combine results
jq -s '.[0] + .[1] + .[2]' \
  AWS_inventory.json \
  Azure_inventory.json \
  GCP_inventory.json \
  > complete_inventory.json

echo "Complete inventory saved to complete_inventory.json"
```

### Scenario 5: Continuous Monitoring

**Goal:** Set up continuous monitoring with alerts.

Create `monitor.sh`:

```bash
#!/bin/bash

# Continuous monitoring script

ALERT_THRESHOLD=80

# Run scan
python cloud_scanner.py \
  --provider AWS \
  --min-risk-score $ALERT_THRESHOLD \
  --format json \
  --output critical_check.json

# Check if any critical assets found
COUNT=$(jq '. | length' critical_check.json)

if [ "$COUNT" -gt 0 ]; then
  echo "ALERT: $COUNT critical assets found!"

  # Send alert (example using curl to webhook)
  curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
    -H 'Content-Type: application/json' \
    -d "{\"text\":\"⚠️ Found $COUNT critical cloud assets with public exposure!\"}"

  # Generate detailed report
  python cloud_scanner.py \
    --provider AWS \
    --min-risk-score $ALERT_THRESHOLD \
    --format markdown \
    --output "CRITICAL_ALERT_$(date +%Y%m%d_%H%M%S).md"
else
  echo "No critical assets found. All clear!"
fi
```

### Scenario 6: Filtering Specific Ports

**Goal:** Find assets with specific dangerous ports open.

```bash
# Scan and filter for SSH (port 22) exposed
python cloud_scanner.py \
  --provider AWS \
  --format json \
  --output all_assets.json

# Filter for port 22
jq '.[] | select(.open_ports | contains([22]))' all_assets.json > ssh_exposed.json

# Filter for database ports (3306, 5432, 1433)
jq '.[] | select(.open_ports | contains([3306, 5432, 1433]))' all_assets.json > db_exposed.json
```

### Scenario 7: Risk Trend Analysis

**Goal:** Track risk scores over time.

```bash
#!/bin/bash

# Daily risk tracking
DATE=$(date +%Y%m%d)

python cloud_scanner.py \
  --provider AWS \
  --format json \
  --output "trend_data/scan_$DATE.json"

# Extract risk scores
jq '[.[] | {name: .asset_name, score: .risk_score, date: "'$DATE'"}]' \
  "trend_data/scan_$DATE.json" \
  >> risk_history.jsonl
```

## Integration Examples

### Integrate with JIRA

```python
#!/usr/bin/env python3
import subprocess
import json
import requests

def create_jira_ticket(asset):
    """Create JIRA ticket for high-risk asset"""

    jira_url = "https://your-domain.atlassian.net/rest/api/2/issue"
    auth = ("user@example.com", "api_token")

    ticket = {
        "fields": {
            "project": {"key": "SEC"},
            "summary": f"High-Risk Asset: {asset['asset_name']}",
            "description": f"""
                Asset: {asset['asset_name']}
                Provider: {asset['provider']}
                Risk Score: {asset['risk_score']}
                Public IP: {asset['public_ip']}
                Open Ports: {', '.join(map(str, asset['open_ports']))}
            """,
            "issuetype": {"name": "Security Issue"}
        }
    }

    response = requests.post(jira_url, json=ticket, auth=auth)
    return response.json()

# Run scan
subprocess.run(["python", "cloud_scanner.py", "--min-risk-score", "80", "--output", "high_risk.json"])

# Create tickets
with open("high_risk.json") as f:
    assets = json.load(f)
    for asset in assets:
        create_jira_ticket(asset)
```

### Integrate with Slack

```bash
#!/bin/bash

# Run scan
python cloud_scanner.py \
  --provider AWS \
  --min-risk-score 70 \
  --format json \
  --output slack_report.json

# Send to Slack
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

COUNT=$(jq '. | length' slack_report.json)
ASSETS=$(jq -r '.[] | "• \(.asset_name) - Risk: \(.risk_score) - IP: \(.public_ip)"' slack_report.json)

curl -X POST $WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d "{
    \"text\": \"Cloud Security Scan Results\",
    \"attachments\": [{
      \"color\": \"danger\",
      \"title\": \"Found $COUNT high-risk assets\",
      \"text\": \"$ASSETS\"
    }]
  }"
```

## Tips and Best Practices

1. **Always use verbose mode** when troubleshooting: `--verbose`
2. **Save reports with timestamps** for historical tracking
3. **Set up automated scans** with cron for regular monitoring
4. **Filter by risk score** to focus on critical issues first
5. **Use multiple output formats** for different audiences (JSON for automation, Markdown for reports)
6. **Secure your API tokens** - never commit them to git
7. **Monitor rate limits** when scanning large environments

## Need Help?

Check the main README.md for more information or open an issue on GitHub.
