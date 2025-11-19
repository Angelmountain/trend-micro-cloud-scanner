# Quick Start Guide

Get started with Trend Micro Cloud Scanner in 5 minutes!

## Prerequisites

- Python 3.7+
- Trend Vision One API token
- Cloud infrastructure to scan (AWS, Azure, or GCP)

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

### 3. Set up your API token

```bash
export TREND_MICRO_API_TOKEN="your_api_token_here"
```

Or create a `.env` file:

```bash
cp .env.example .env
# Edit .env and add your API token
```

## First Scan

Run your first scan:

```bash
python cloud_scanner.py --provider AWS
```

This will:
- Connect to Trend Vision One API
- Retrieve all AWS EC2 instances
- Find instances with public IPs and open ports
- Display results in JSON format

## Common Commands

### Save results to a file

```bash
python cloud_scanner.py --provider AWS --output results.json
```

### Find high-risk instances only

```bash
python cloud_scanner.py --provider AWS --min-risk-score 70
```

### Generate a markdown report

```bash
python cloud_scanner.py --provider AWS --format markdown --output report.md
```

### Scan with verbose logging

```bash
python cloud_scanner.py --provider AWS --verbose
```

## Understanding the Output

### JSON Format

```json
{
  "asset_name": "web-server-prod",
  "risk_score": 85,
  "public_ip": "203.0.113.42",
  "open_ports": [22, 80, 443],
  "services": [
    {"port": 22, "protocol": "TCP", "service_name": "SSH"},
    {"port": 80, "protocol": "TCP", "service_name": "HTTP"},
    {"port": 443, "protocol": "TCP", "service_name": "HTTPS"}
  ]
}
```

**Key fields:**
- `risk_score`: 0-100 (higher = more risk)
- `open_ports`: List of publicly accessible ports
- `services`: Detailed service information for each port

## Risk Score Interpretation

- **90-100**: Critical - Immediate action required
- **70-89**: High - Address soon
- **40-69**: Medium - Review and plan fixes
- **0-39**: Low - Monitor

## Next Steps

1. Review the [README.md](README.md) for full documentation
2. Check [EXAMPLES.md](EXAMPLES.md) for real-world usage scenarios
3. Set up automated scans (see README for cron examples)
4. Integrate with your security workflows

## Troubleshooting

### "API token is required" error

Set the environment variable:
```bash
export TREND_MICRO_API_TOKEN="your_token"
```

### "403 Forbidden" error

- Check your API token is valid
- Verify token has attack surface permissions
- Ensure you're using the correct region

### No results found

- Verify your cloud provider is connected to Trend Vision One
- Check filter criteria (try without `--min-risk-score`)
- Run with `--verbose` to see detailed logs

## Get Help

- Open an issue on [GitHub](https://github.com/Angelmountain/trend-micro-cloud-scanner/issues)
- Check the [full documentation](README.md)
- Review [examples](EXAMPLES.md)

---

Ready to scan? Run: `python cloud_scanner.py --provider AWS --verbose`
