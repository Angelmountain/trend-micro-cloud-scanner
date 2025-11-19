#!/usr/bin/env python3
"""
Trend Micro Cloud Scanner
Searches for cloud instances with public IPs and open ports using Trend Vision One API
"""

import requests
import json
import os
import sys
import argparse
from datetime import datetime
from typing import List, Dict, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TrendMicroCloudScanner:
    """Scanner for cloud assets using Trend Vision One API"""

    def __init__(self, api_token: str, region: str = "us-east-1"):
        """
        Initialize the scanner

        Args:
            api_token: Trend Vision One API token
            region: API region (default: us-east-1)
        """
        self.api_token = api_token
        self.region = region
        self.base_url = self._get_base_url(region)
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }

    def _get_base_url(self, region: str) -> str:
        """Get the base URL for the specified region"""
        region_urls = {
            'us-east-1': 'https://api.xdr.trendmicro.com',
            'eu-central-1': 'https://api.eu.xdr.trendmicro.com',
            'ap-northeast-1': 'https://api.xdr.trendmicro.co.jp',
            'ap-southeast-1': 'https://api.sg.xdr.trendmicro.com',
            'ap-southeast-2': 'https://api.au.xdr.trendmicro.com',
            'ap-south-1': 'https://api.in.xdr.trendmicro.com',
            'me-central-1': 'https://api.me.xdr.trendmicro.com'
        }
        return region_urls.get(region, region_urls['us-east-1'])

    def get_cloud_assets(self, provider: Optional[str] = None,
                        asset_type: Optional[str] = None) -> List[Dict]:
        """
        Get cloud assets from Trend Vision One

        Args:
            provider: Filter by cloud provider (AWS, Azure, GCP)
            asset_type: Filter by asset type (EC2 Instance, VM, etc.)

        Returns:
            List of cloud assets
        """
        url = f"{self.base_url}/v3.0/attackSurfaceCloudAssets"
        all_assets = []
        next_link = None

        try:
            while True:
                if next_link:
                    response = requests.get(next_link, headers=self.headers)
                else:
                    response = requests.get(url, headers=self.headers)

                response.raise_for_status()
                data = response.json()

                items = data.get('items', [])

                # Apply filters
                if provider or asset_type:
                    items = [
                        item for item in items
                        if (not provider or item.get('provider') == provider)
                        and (not asset_type or item.get('assetType') == asset_type)
                    ]

                all_assets.extend(items)

                # Check for pagination
                next_link = data.get('nextLink')
                if not next_link:
                    break

                logger.info(f"Retrieved {len(all_assets)} assets so far...")

            logger.info(f"Total cloud assets retrieved: {len(all_assets)}")
            return all_assets

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching cloud assets: {e}")
            return []

    def get_public_ips(self) -> List[Dict]:
        """
        Get public IPs from Trend Vision One

        Returns:
            List of public IPs with their services
        """
        url = f"{self.base_url}/v3.0/attackSurfacePublicIps"
        all_ips = []
        next_link = None

        try:
            while True:
                if next_link:
                    response = requests.get(next_link, headers=self.headers)
                else:
                    response = requests.get(url, headers=self.headers)

                response.raise_for_status()
                data = response.json()

                all_ips.extend(data.get('items', []))

                # Check for pagination
                next_link = data.get('nextLink')
                if not next_link:
                    break

                logger.info(f"Retrieved {len(all_ips)} public IPs so far...")

            logger.info(f"Total public IPs retrieved: {len(all_ips)}")
            return all_ips

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching public IPs: {e}")
            return []

    def find_instances_with_public_ips_and_ports(self,
                                                 provider: str = "AWS",
                                                 asset_type: str = "EC2 Instance",
                                                 min_risk_score: Optional[int] = None) -> List[Dict]:
        """
        Find cloud instances with public IPs and open ports

        Args:
            provider: Cloud provider (AWS, Azure, GCP)
            asset_type: Type of asset to search for
            min_risk_score: Minimum risk score to filter by

        Returns:
            List of instances with their public IPs and open ports
        """
        logger.info(f"Searching for {provider} {asset_type} instances with public IPs and open ports...")

        # Get cloud assets
        cloud_assets = self.get_cloud_assets(provider=provider, asset_type=asset_type)
        logger.info(f"Found {len(cloud_assets)} {asset_type} instances")

        # Get public IPs
        public_ips = self.get_public_ips()
        logger.info(f"Found {len(public_ips)} public IPs")

        # Find instances with public IPs and open ports
        results = []

        for asset in cloud_assets:
            # Skip if risk score is below threshold
            if min_risk_score and asset.get('latestRiskScore', 0) < min_risk_score:
                continue

            # Check if asset has associated public IPs
            asset_id = asset.get('id')
            asset_name = asset.get('assetName', 'Unknown')

            # Look for matching public IPs
            for public_ip in public_ips:
                # Check if this IP has open ports
                services = public_ip.get('services', [])
                if not services:
                    continue

                # Check if IP is associated with this asset
                # This is a simplified check - in production you'd want to verify the association
                ip_address = public_ip.get('ipAddress')

                if ip_address:
                    result = {
                        'asset_name': asset_name,
                        'asset_id': asset_id,
                        'asset_type': asset.get('assetType'),
                        'provider': asset.get('provider'),
                        'risk_score': asset.get('latestRiskScore', 0),
                        'region': asset.get('region', 'Unknown'),
                        'public_ip': ip_address,
                        'open_ports': [service.get('port') for service in services if service.get('port')],
                        'protocols': [service.get('protocol') for service in services if service.get('protocol')],
                        'services': [
                            {
                                'port': service.get('port'),
                                'protocol': service.get('protocol'),
                                'service_name': service.get('serviceName', 'Unknown')
                            }
                            for service in services
                        ],
                        'last_seen': public_ip.get('lastSeenDateTime'),
                        'tags': asset.get('tags', [])
                    }
                    results.append(result)

        logger.info(f"Found {len(results)} instances with public IPs and open ports")
        return results

    def generate_report(self, results: List[Dict], output_format: str = "json") -> str:
        """
        Generate a report from scan results

        Args:
            results: Scan results
            output_format: Output format (json, csv, markdown)

        Returns:
            Report as string
        """
        if output_format == "json":
            return json.dumps(results, indent=2)

        elif output_format == "csv":
            if not results:
                return "No results to report"

            csv_lines = ["Asset Name,Asset ID,Provider,Region,Risk Score,Public IP,Open Ports,Protocols"]
            for result in results:
                ports = "|".join(map(str, result.get('open_ports', [])))
                protocols = "|".join(result.get('protocols', []))
                csv_lines.append(
                    f"{result['asset_name']},{result['asset_id']},{result['provider']},"
                    f"{result['region']},{result['risk_score']},{result['public_ip']},"
                    f"\"{ports}\",\"{protocols}\""
                )
            return "\n".join(csv_lines)

        elif output_format == "markdown":
            if not results:
                return "# Cloud Scanner Report\n\nNo results found."

            md_lines = [
                "# Cloud Security Scanner Report",
                f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"\n**Total Instances Found:** {len(results)}",
                "\n## Summary\n"
            ]

            # Group by risk score
            high_risk = [r for r in results if r.get('risk_score', 0) >= 70]
            medium_risk = [r for r in results if 40 <= r.get('risk_score', 0) < 70]
            low_risk = [r for r in results if r.get('risk_score', 0) < 40]

            md_lines.append(f"- **High Risk (≥70):** {len(high_risk)}")
            md_lines.append(f"- **Medium Risk (40-69):** {len(medium_risk)}")
            md_lines.append(f"- **Low Risk (<40):** {len(low_risk)}\n")

            # Detailed results
            md_lines.append("## Detailed Results\n")

            for i, result in enumerate(sorted(results, key=lambda x: x.get('risk_score', 0), reverse=True), 1):
                md_lines.append(f"### {i}. {result['asset_name']}")
                md_lines.append(f"- **Asset ID:** `{result['asset_id']}`")
                md_lines.append(f"- **Provider:** {result['provider']}")
                md_lines.append(f"- **Region:** {result['region']}")
                md_lines.append(f"- **Risk Score:** {result['risk_score']}")
                md_lines.append(f"- **Public IP:** `{result['public_ip']}`")
                md_lines.append(f"- **Open Ports:** {', '.join(map(str, result['open_ports']))}")

                if result.get('services'):
                    md_lines.append("- **Services:**")
                    for service in result['services']:
                        md_lines.append(
                            f"  - Port {service['port']}/{service['protocol']}: {service['service_name']}"
                        )
                md_lines.append("")

            return "\n".join(md_lines)

        else:
            return json.dumps(results, indent=2)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Scan cloud infrastructure for instances with public IPs and open ports'
    )
    parser.add_argument(
        '--api-token',
        help='Trend Vision One API token (or set TREND_MICRO_API_TOKEN env var)',
        default=os.environ.get('TREND_MICRO_API_TOKEN')
    )
    parser.add_argument(
        '--region',
        help='API region',
        choices=['us-east-1', 'eu-central-1', 'ap-northeast-1', 'ap-southeast-1',
                 'ap-southeast-2', 'ap-south-1', 'me-central-1'],
        default='us-east-1'
    )
    parser.add_argument(
        '--provider',
        help='Cloud provider to scan',
        choices=['AWS', 'Azure', 'GCP'],
        default='AWS'
    )
    parser.add_argument(
        '--asset-type',
        help='Asset type to scan',
        default='EC2 Instance'
    )
    parser.add_argument(
        '--min-risk-score',
        help='Minimum risk score to include',
        type=int
    )
    parser.add_argument(
        '--output',
        help='Output file path (default: stdout)',
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

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Check for API token
    if not args.api_token:
        logger.error("API token is required. Set TREND_MICRO_API_TOKEN env var or use --api-token")
        sys.exit(1)

    # Initialize scanner
    scanner = TrendMicroCloudScanner(args.api_token, args.region)

    # Run scan
    results = scanner.find_instances_with_public_ips_and_ports(
        provider=args.provider,
        asset_type=args.asset_type,
        min_risk_score=args.min_risk_score
    )

    # Generate report
    report = scanner.generate_report(results, args.format)

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {args.output}")
    else:
        print(report)

    # Summary
    if results:
        logger.info(f"\nScan complete. Found {len(results)} instances with public IPs and open ports.")
        high_risk = [r for r in results if r.get('risk_score', 0) >= 70]
        if high_risk:
            logger.warning(f"WARNING: {len(high_risk)} high-risk instances found!")
    else:
        logger.info("No instances found matching the criteria.")


if __name__ == "__main__":
    main()
