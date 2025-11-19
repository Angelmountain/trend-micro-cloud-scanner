# Trend Micro Cloud Scanner

A Python tool to scan cloud infrastructure for instances with public IPs and open ports using the Trend Vision One API.

## Features

- Scan AWS, Azure, and GCP cloud assets
- Identify instances with public IPs and open ports
- Risk-based filtering and reporting
- Multiple output formats (JSON, CSV, Markdown)
- Pagination support for large environments
- Detailed service information for open ports
- Comprehensive reporting with risk categorization

## Prerequisites

- Python 3.7 or higher
- Trend Vision One account
- Valid Trend Vision One API key with "Run artifact scan" or attack surface permissions

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Angelmountain/trend-micro-cloud-scanner.git
cd trend-micro-cloud-scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API credentials

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and add your Trend Vision One API token:

```bash
TREND_MICRO_API_TOKEN=your_actual_api_token_here
TREND_MICRO_REGION=us-east-1
```

## Usage

### Basic Usage

```bash
# Using environment variable for API token
export TREND_MICRO_API_TOKEN="your_api_token"
python cloud_scanner.py
```

### Command Line Options

```bash
python cloud_scanner.py --help
```

**Available Options:**

- `--api-token` - API token (or set `TREND_MICRO_API_TOKEN` env var)
- `--region` - API region (default: us-east-1)
- `--provider` - Cloud provider (AWS, Azure, GCP)
- `--asset-type` - Asset type to scan (default: EC2 Instance)
- `--min-risk-score` - Minimum risk score to filter (0-100)
- `--output` - Output file path
- `--format` - Output format (json, csv, markdown)
- `--verbose` - Enable verbose logging

### Examples

#### Scan AWS EC2 instances

```bash
python cloud_scanner.py \
  --provider AWS \
  --asset-type "EC2 Instance" \
  --format json \
  --output report.json
```

#### Find high-risk instances only

```bash
python cloud_scanner.py \
  --provider AWS \
  --min-risk-score 70 \
  --format markdown \
  --output high_risk_report.md
```

#### Scan Azure VMs

```bash
python cloud_scanner.py \
  --provider Azure \
  --asset-type "Virtual Machine" \
  --format csv \
  --output azure_instances.csv
```

#### Scan with specific region

```bash
python cloud_scanner.py \
  --region eu-central-1 \
  --provider AWS \
  --format json
```

#### Enable verbose logging

```bash
python cloud_scanner.py \
  --verbose \
  --output detailed_scan.json
```

## Output Formats

### JSON Format

```json
[
  {
    "asset_name": "web-server-prod",
    "asset_id": "i-0123456789abcdef",
    "asset_type": "EC2 Instance",
    "provider": "AWS",
    "risk_score": 85,
    "region": "us-east-1",
    "public_ip": "203.0.113.42",
    "open_ports": [22, 80, 443],
    "protocols": ["TCP", "TCP", "TCP"],
    "services": [
      {
        "port": 22,
        "protocol": "TCP",
        "service_name": "SSH"
      },
      {
        "port": 80,
        "protocol": "TCP",
        "service_name": "HTTP"
      },
      {
        "port": 443,
        "protocol": "TCP",
        "service_name": "HTTPS"
      }
    ],
    "last_seen": "2025-11-19T10:30:00Z",
    "tags": ["production", "web-server"]
  }
]
```

### CSV Format

```csv
Asset Name,Asset ID,Provider,Region,Risk Score,Public IP,Open Ports,Protocols
web-server-prod,i-0123456789abcdef,AWS,us-east-1,85,203.0.113.42,"22|80|443","TCP|TCP|TCP"
```

### Markdown Format

```markdown
# Cloud Security Scanner Report

**Generated:** 2025-11-19 12:30:45
**Total Instances Found:** 1

## Summary

- **High Risk (≥70):** 1
- **Medium Risk (40-69):** 0
- **Low Risk (<40):** 0

## Detailed Results

### 1. web-server-prod
- **Asset ID:** `i-0123456789abcdef`
- **Provider:** AWS
- **Region:** us-east-1
- **Risk Score:** 85
- **Public IP:** `203.0.113.42`
- **Open Ports:** 22, 80, 443
- **Services:**
  - Port 22/TCP: SSH
  - Port 80/TCP: HTTP
  - Port 443/TCP: HTTPS
```

## API Regions

The tool supports the following Trend Vision One regions:

| Region Code | Location | URL |
|------------|----------|-----|
| us-east-1 | United States (default) | api.xdr.trendmicro.com |
| eu-central-1 | Europe | api.eu.xdr.trendmicro.com |
| ap-northeast-1 | Japan | api.xdr.trendmicro.co.jp |
| ap-southeast-1 | Singapore | api.sg.xdr.trendmicro.com |
| ap-southeast-2 | Australia | api.au.xdr.trendmicro.com |
| ap-south-1 | India | api.in.xdr.trendmicro.com |
| me-central-1 | Middle East | api.me.xdr.trendmicro.com |

## Getting Your API Token

1. Log in to [Trend Vision One Console](https://portal.xdr.trendmicro.com/)
2. Navigate to **Administration** → **API Keys**
3. Click **Add API Key**
4. Set permissions (ensure "Attack Surface" or "Run artifact scan" is enabled)
5. Copy the generated API key
6. Store it securely in your `.env` file

## Use Cases

### Security Audit

Identify all cloud instances with public exposure:

```bash
python cloud_scanner.py \
  --provider AWS \
  --format markdown \
  --output security_audit.md
```

### Compliance Reporting

Generate CSV reports for compliance teams:

```bash
python cloud_scanner.py \
  --provider AWS \
  --format csv \
  --output compliance_report.csv
```

### High-Risk Asset Discovery

Find only high-risk assets needing immediate attention:

```bash
python cloud_scanner.py \
  --min-risk-score 80 \
  --format json \
  --output critical_assets.json
```

### Multi-Cloud Scanning

Scan multiple cloud providers:

```bash
# Scan AWS
python cloud_scanner.py --provider AWS --output aws_scan.json

# Scan Azure
python cloud_scanner.py --provider Azure --output azure_scan.json

# Scan GCP
python cloud_scanner.py --provider GCP --output gcp_scan.json
```

## Automation

### Scheduled Scans with Cron

Add to crontab for daily scans:

```bash
# Run daily at 2 AM
0 2 * * * cd /path/to/trend-micro-cloud-scanner && /usr/bin/python3 cloud_scanner.py --output /var/reports/daily_scan_$(date +\%Y\%m\%d).json
```

### CI/CD Integration

GitHub Actions example:

```yaml
name: Cloud Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run security scan
        env:
          TREND_MICRO_API_TOKEN: ${{ secrets.TREND_MICRO_API_TOKEN }}
        run: |
          python cloud_scanner.py \
            --format markdown \
            --output scan_report.md
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: scan_report.md
```

## Troubleshooting

### API Token Issues

```
Error: API token is required
```

**Solution:** Ensure `TREND_MICRO_API_TOKEN` is set:

```bash
export TREND_MICRO_API_TOKEN="your_token"
```

### Authentication Errors

```
Error 403: Forbidden
```

**Solutions:**
- Verify API token is valid and not expired
- Check that token has correct permissions
- Ensure you're using the correct region

### No Results Found

**Possible causes:**
- No instances match the filter criteria
- API token doesn't have permission to view attack surface data
- Wrong region specified

**Solution:** Try running with `--verbose` flag for detailed logs

### Rate Limiting

**Solution:** The scanner handles pagination automatically, but if you hit rate limits:
- Reduce scan frequency
- Contact Trend Micro support for higher rate limits

## Project Structure

```
trend-micro-cloud-scanner/
├── cloud_scanner.py         # Main scanner script
├── requirements.txt         # Python dependencies
├── .env.example            # Example environment variables
├── config.json.example     # Example configuration file
├── README.md               # This file
└── .gitignore             # Git ignore rules
```

## Security Best Practices

1. **Never commit API tokens** to version control
2. **Use environment variables** for sensitive data
3. **Rotate API keys** regularly
4. **Limit API key permissions** to minimum required
5. **Store reports securely** if they contain sensitive information
6. **Review high-risk findings** immediately

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is provided as-is for security testing and monitoring purposes.

## Support

For issues or questions:
- Open an issue on GitHub
- Check [Trend Vision One documentation](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-api-guide)

## Changelog

### Version 1.0.0 (2025-11-19)
- Initial release
- Support for AWS, Azure, and GCP
- Multiple output formats
- Risk-based filtering
- Pagination support
- Comprehensive reporting

## Disclaimer

This tool is for authorized security testing and monitoring only. Ensure you have proper authorization before scanning any cloud infrastructure.

---

**Created:** November 2025
**Author:** Cloud Security Team
**Purpose:** Cloud asset security monitoring and compliance
