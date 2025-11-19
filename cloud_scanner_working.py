#!/usr/bin/env python3
"""
Trend Micro Cloud Scanner - Working Version
Uses ASRM (Attack Surface Risk Management) API endpoints
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
    """Scanner using Trend Vision One ASRM API"""

    def __init__(self, api_token: str, base_url: str = "https://api.eu.xdr.trendmicro.com"):
        self.api_token = api_token
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }

    def get_cloud_assets(self, top: int = 50) -> List[Dict]:
        """Get cloud assets from ASRM"""
        url = f"{self.base_url}/v3.0/asrm/attackSurfaceCloudAssets"
        headers = self.headers.copy()
        headers['TMV1-Filter'] = f'top={top}'
        
        try:
            logger.info(f"Fetching cloud assets from ASRM API...")
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            items = data.get('items', [])
            logger.info(f"Retrieved {len(items)} cloud assets")
            return items
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching cloud assets: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return []

    def get_internet_facing_vulnerabilities(self, top: int = 100) -> List[Dict]:
        """Get internet-facing asset vulnerabilities"""
        url = f"{self.base_url}/v3.0/asrm/internetFacingAssetVulnerabilities"
        headers = self.headers.copy()
        headers['TMV1-Filter'] = f'top={top}'
        
        try:
            logger.info(f"Fetching internet-facing vulnerabilities...")
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            items = data.get('items', [])
            logger.info(f"Retrieved {len(items)} internet-facing vulnerabilities")
            return items
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching vulnerabilities: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return []

    def generate_report(self, cloud_assets: List[Dict], vulnerabilities: List[Dict], 
                       output_format: str = "json") -> str:
        """Generate report"""
        
        combined_results = {
            'cloud_assets': cloud_assets,
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total_cloud_assets': len(cloud_assets),
                'total_vulnerabilities': len(vulnerabilities),
                'scan_time': datetime.now().isoformat()
            }
        }
        
        if output_format == "json":
            return json.dumps(combined_results, indent=2)
            
        elif output_format == "markdown":
            md_lines = [
                "# Cloud Asset Security Report",
                f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"\n**Cloud Assets Found:** {len(cloud_assets)}",
                f"\n**Internet-Facing Vulnerabilities:** {len(vulnerabilities)}",
                "\n## Cloud Assets\n"
            ]
            
            if cloud_assets:
                for i, asset in enumerate(cloud_assets[:20], 1):  # Limit to first 20
                    md_lines.append(f"### {i}. {asset.get('assetName', 'Unknown')}")
                    md_lines.append(f"- **ID:** `{asset.get('id', 'N/A')}`")
                    md_lines.append(f"- **Type:** {asset.get('assetType', 'N/A')}")
                    md_lines.append(f"- **Provider:** {asset.get('provider', 'N/A')}")
                    md_lines.append(f"- **Region:** {asset.get('region', 'N/A')}")
                    md_lines.append(f"- **Risk Score:** {asset.get('latestRiskScore', 'N/A')}")
                    if asset.get('publicIpAddresses'):
                        md_lines.append(f"- **Public IPs:** {', '.join(asset['publicIpAddresses'])}")
                    md_lines.append("")
            else:
                md_lines.append("No cloud assets found.\n")
                
            md_lines.append("\n## Internet-Facing Vulnerabilities\n")
            
            if vulnerabilities:
                for i, vuln in enumerate(vulnerabilities[:20], 1):  # Limit to first 20
                    md_lines.append(f"### {i}. {vuln.get('vulnerabilityName', 'Unknown')}")
                    md_lines.append(f"- **ID:** `{vuln.get('id', 'N/A')}`")
                    md_lines.append(f"- **Severity:** {vuln.get('severity', 'N/A')}")
                    md_lines.append(f"- **Affected Assets:** {vuln.get('affectedAssetCount', 0)}")
                    md_lines.append("")
            else:
                md_lines.append("No vulnerabilities found.\n")
                
            return "\n".join(md_lines)
            
        else:
            return json.dumps(combined_results, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description='Scan cloud assets using Trend Vision One ASRM API'
    )
    parser.add_argument(
        '--api-token',
        help='API token (or set TREND_MICRO_API_KEY env var)',
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
        choices=['json', 'markdown'],
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

    scanner = TrendMicroCloudScanner(args.api_token, args.base_url)

    # Get data
    cloud_assets = scanner.get_cloud_assets(top=50)
    vulnerabilities = scanner.get_internet_facing_vulnerabilities(top=100)

    # Generate report
    report = scanner.generate_report(cloud_assets, vulnerabilities, args.format)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {args.output}")
    else:
        print(report)

    logger.info(f"\n✅ Scan complete!")
    logger.info(f"Cloud Assets: {len(cloud_assets)}")
    logger.info(f"Vulnerabilities: {len(vulnerabilities)}")


if __name__ == "__main__":
    main()
