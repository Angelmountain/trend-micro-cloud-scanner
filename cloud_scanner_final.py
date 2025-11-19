#!/usr/bin/env python3
"""
Trend Micro Cloud Scanner - Production Version
Finds cloud instances with public IPs and open ports using Trend Vision One ASRM API
"""

import requests
import json
import os
import sys
import argparse
from datetime import datetime
from typing import List, Dict, Optional
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TrendMicroCloudScanner:
    """Scanner using Trend Vision One ASRM (Attack Surface Risk Management) API"""

    def __init__(self, api_token: str, base_url: str = "https://api.eu.xdr.trendmicro.com"):
        self.api_token = api_token
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }

    def get_public_ips(self, top: int = 100) -> List[Dict]:
        """Get public IP addresses with exposed services"""
        url = f"{self.base_url}/v3.0/asrm/attackSurfacePublicIpAddresses?top={top}"

        try:
            logger.info(f"Fetching public IPs with open ports...")
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            data = response.json()
            items = data.get('items', [])
            logger.info(f"Found {len(items)} public IP(s) with exposed services")
            return items

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching public IPs: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return []

    def get_cloud_assets(self, top: int = 100) -> List[Dict]:
        """Get cloud assets"""
        url = f"{self.base_url}/v3.0/asrm/attackSurfaceCloudAssets?top={top}"

        try:
            logger.info(f"Fetching cloud assets...")
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            data = response.json()
            items = data.get('items', [])
            logger.info(f"Found {len(items)} cloud asset(s)")
            return items

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching cloud assets: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return []

    def get_high_risk_devices(self, top: int = 50) -> List[Dict]:
        """Get high-risk devices"""
        url = f"{self.base_url}/v3.0/asrm/highRiskDevices?top={top}"

        try:
            logger.info(f"Fetching high-risk devices...")
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            data = response.json()
            items = data.get('items', [])
            logger.info(f"Found {len(items)} high-risk device(s)")
            return items

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching high-risk devices: {e}")
            return []

    def generate_report(self, public_ips: List[Dict], cloud_assets: List[Dict],
                       high_risk_devices: List[Dict], output_format: str = "json") -> str:
        """Generate comprehensive report"""

        combined_data = {
            'scan_time': datetime.now().isoformat(),
            'summary': {
                'public_ips_with_open_ports': len(public_ips),
                'total_cloud_assets': len(cloud_assets),
                'high_risk_devices': len(high_risk_devices)
            },
            'public_ips': public_ips,
            'cloud_assets': cloud_assets[:20],  # Limit for readability
            'high_risk_devices': high_risk_devices
        }

        if output_format == "json":
            return json.dumps(combined_data, indent=2)

        elif output_format == "csv":
            csv_lines = ["IP Address,Risk Score,Open Ports,Services,Ports List"]
            for item in public_ips:
                ip = item.get('ipAddress', 'N/A')
                risk = item.get('latestRiskScore', 0)
                services = item.get('services', [])
                ports = '|'.join([str(s.get('port', '')) for s in services])
                service_names = '|'.join([s.get('serviceName', 'Unknown') for s in services])
                csv_lines.append(f'"{ip}",{risk},{len(services)},"{service_names}","{ports}"')
            return "\n".join(csv_lines)

        elif output_format == "markdown":
            md_lines = [
                "# Cloud Security Scan Report",
                f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"\n## Summary\n",
                f"- **Public IPs with Open Ports:** {len(public_ips)}",
                f"- **Total Cloud Assets:** {len(cloud_assets)}",
                f"- **High-Risk Devices:** {len(high_risk_devices)}",
                "\n## Public IPs with Exposed Services\n"
            ]

            for i, item in enumerate(public_ips, 1):
                ip = item.get('ipAddress', 'N/A')
                risk = item.get('latestRiskScore', 0)
                services = item.get('services', [])

                risk_emoji = "🔴" if risk >= 70 else "🟡" if risk >= 40 else "🟢"

                md_lines.append(f"### {i}. IP: {ip}")
                md_lines.append(f"- **Risk Score:** {risk} {risk_emoji}")
                md_lines.append(f"- **Open Ports:** {len(services)}\n")

                if services:
                    md_lines.append("**Services:**")
                    for svc in services:
                        port = svc.get('port', 'N/A')
                        protocol = svc.get('protocol', 'N/A')
                        name = svc.get('serviceName', 'Unknown')
                        md_lines.append(f"- Port {port}/{protocol}: {name}")
                    md_lines.append("")

            # Add cloud assets
            md_lines.append("\n## Cloud Assets (Top 10)\n")
            for i, asset in enumerate(cloud_assets[:10], 1):
                md_lines.append(f"### {i}. {asset.get('assetName', 'Unknown')}")
                md_lines.append(f"- **Type:** {asset.get('assetType', 'N/A')}")
                md_lines.append(f"- **Provider:** {asset.get('provider', 'N/A')}")
                md_lines.append(f"- **Region:** {asset.get('region', 'N/A')}")
                md_lines.append(f"- **Risk Score:** {asset.get('latestRiskScore', 'N/A')}")
                if asset.get('publicIpAddresses'):
                    md_lines.append(f"- **Public IPs:** {', '.join(asset['publicIpAddresses'])}")
                md_lines.append("")

            # Add high-risk devices
            if high_risk_devices:
                md_lines.append("\n## High-Risk Devices\n")
                for i, device in enumerate(high_risk_devices[:10], 1):
                    md_lines.append(f"### {i}. {device.get('deviceName', 'Unknown')}")
                    md_lines.append(f"- **Risk Score:** {device.get('riskScore', 'N/A')} 🔴")
                    if device.get('ipAddresses'):
                        md_lines.append(f"- **IPs:** {', '.join(device['ipAddresses'][:3])}")
                    md_lines.append("")

            return "\n".join(md_lines)

        else:
            return json.dumps(combined_data, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description='Scan cloud infrastructure for instances with public IPs and open ports'
    )
    parser.add_argument(
        '--api-token',
        help='Trend Vision One API token (or set TREND_MICRO_API_KEY env var)',
        default=os.environ.get('TREND_MICRO_API_KEY')
    )
    parser.add_argument(
        '--base-url',
        help='API base URL',
        default=os.environ.get('TREND_MICRO_BASE_URL', 'https://api.eu.xdr.trendmicro.com')
    )
    parser.add_argument(
        '--output',
        help='Output file path',
    )
    parser.add_argument(
        '--format',
        help='Output format',
        choices=['json', 'csv', 'markdown'],
        default='json'
    )
    parser.add_argument(
        '--verbose',
        help='Enable verbose logging',
        action='store_true'
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.api_token:
        logger.error("API token required. Set TREND_MICRO_API_KEY or use --api-token")
        sys.exit(1)

    # Initialize scanner
    scanner = TrendMicroCloudScanner(args.api_token, args.base_url)

    # Run scans
    public_ips = scanner.get_public_ips(top=100)
    cloud_assets = scanner.get_cloud_assets(top=100)
    high_risk_devices = scanner.get_high_risk_devices(top=50)

    # Generate report
    report = scanner.generate_report(public_ips, cloud_assets, high_risk_devices, args.format)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {args.output}")
    else:
        print(report)

    # Summary
    logger.info(f"\n✅ Scan Complete!")
    logger.info(f"Public IPs with open ports: {len(public_ips)}")
    logger.info(f"Cloud assets: {len(cloud_assets)}")
    logger.info(f"High-risk devices: {len(high_risk_devices)}")


if __name__ == "__main__":
    main()
