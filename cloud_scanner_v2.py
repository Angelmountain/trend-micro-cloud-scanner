#!/usr/bin/env python3
"""
Trend Micro Cloud Scanner v2
Uses actual Trend Vision One v3.0 API endpoints
"""

import requests
import json
import os
import sys
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TrendMicroScanner:
    """Scanner using Trend Vision One v3.0 API"""

    def __init__(self, api_token: str, base_url: str = "https://api.eu.xdr.trendmicro.com"):
        self.api_token = api_token
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }

    def get_endpoints(self, filter_query: Optional[str] = None, top: int = 100) -> List[Dict]:
        """
        Get endpoints from Trend Vision One
        
        Args:
            filter_query: OData filter query
            top: Number of records to return
            
        Returns:
            List of endpoints
        """
        url = f"{self.base_url}/v3.0/endpointSecurity/endpoints"
        headers = self.headers.copy()
        
        if filter_query:
            headers['TMV1-Filter'] = filter_query
        else:
            headers['TMV1-Filter'] = f'top={top}'
            
        try:
            logger.info(f"Fetching endpoints from {url}")
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            items = data.get('items', [])
            logger.info(f"Retrieved {len(items)} endpoints")
            return items
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching endpoints: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return []

    def search_network_activities(self, start_time: datetime, end_time: datetime, 
                                  top: int = 100) -> List[Dict]:
        """
        Search network activities
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            top: Number of records to return
            
        Returns:
            List of network activities
        """
        url = f"{self.base_url}/v3.0/search/networkActivities"
        headers = self.headers.copy()
        
        # Format times
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Build filter
        filter_query = f"startDateTime eq {start_str} and endDateTime eq {end_str} and top={top}"
        headers['TMV1-Query'] = filter_query
        
        try:
            logger.info(f"Searching network activities from {start_str} to {end_str}")
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            items = data.get('items', [])
            logger.info(f"Found {len(items)} network activities")
            return items
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error searching network activities: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return []

    def find_exposed_endpoints(self, min_risk_score: Optional[int] = None) -> List[Dict]:
        """
        Find endpoints that may be exposed
        
        Returns:
            List of potentially exposed endpoints with details
        """
        logger.info("Searching for potentially exposed endpoints...")
        
        # Get all endpoints
        endpoints = self.get_endpoints(top=1000)
        
        results = []
        for endpoint in endpoints:
            # Extract relevant info
            result = {
                'endpoint_name': endpoint.get('endpointName', 'Unknown'),
                'agent_guid': endpoint.get('agentGuid'),
                'type': endpoint.get('type'),
                'os_name': endpoint.get('osName'),
                'os_platform': endpoint.get('osPlatform'),
                'ip_addresses': endpoint.get('ip', []),
                'mac_addresses': endpoint.get('macAddress', []),
                'edr_sensor_status': endpoint.get('edrSensorStatus'),
                'edr_connectivity': endpoint.get('edrSensorConnectivity'),
                'isolation_status': endpoint.get('isolationStatus'),
                'last_connected': endpoint.get('edrSensorLastConnectedDateTime'),
                'security_features': {
                    'firewall': endpoint.get('eppAgentFirewall'),
                    'intrusion_prevention': endpoint.get('eppAgentIntrusionPreventionSystem'),
                    'vulnerability_protection': endpoint.get('eppAgentVulnerabilityProtection'),
                }
            }
            
            # Calculate a simple risk score based on protections
            risk_score = 0
            if result['edr_sensor_status'] != 'enabled':
                risk_score += 30
            if result['isolation_status'] == 'off':
                risk_score += 20
            if result['security_features']['firewall'] != 'enabled':
                risk_score += 20
            if result['security_features']['intrusion_prevention'] != 'enabled':
                risk_score += 15
            if result['security_features']['vulnerability_protection'] != 'enabled':
                risk_score += 15
                
            result['calculated_risk_score'] = risk_score
            
            # Apply risk filter
            if min_risk_score and risk_score < min_risk_score:
                continue
                
            results.append(result)
        
        logger.info(f"Found {len(results)} endpoints matching criteria")
        return sorted(results, key=lambda x: x['calculated_risk_score'], reverse=True)

    def generate_report(self, results: List[Dict], output_format: str = "json") -> str:
        """Generate report from scan results"""
        
        if output_format == "json":
            return json.dumps(results, indent=2)
            
        elif output_format == "csv":
            if not results:
                return "No results to report"
                
            csv_lines = ["Endpoint Name,Agent GUID,Type,OS,Risk Score,IP Addresses,EDR Status,Firewall,IPS"]
            for result in results:
                ips = "|".join(result.get('ip_addresses', []))
                csv_lines.append(
                    f"{result['endpoint_name']},{result['agent_guid']},{result['type']},"
                    f"{result['os_name']},{result['calculated_risk_score']},\"{ips}\","
                    f"{result['edr_sensor_status']},{result['security_features']['firewall']},"
                    f"{result['security_features']['intrusion_prevention']}"
                )
            return "\n".join(csv_lines)
            
        elif output_format == "markdown":
            if not results:
                return "# Endpoint Security Report\n\nNo results found."
                
            md_lines = [
                "# Endpoint Security Scanner Report",
                f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"\n**Total Endpoints Found:** {len(results)}",
                "\n## Risk Summary\n"
            ]
            
            # Group by risk
            high_risk = [r for r in results if r.get('calculated_risk_score', 0) >= 70]
            medium_risk = [r for r in results if 40 <= r.get('calculated_risk_score', 0) < 70]
            low_risk = [r for r in results if r.get('calculated_risk_score', 0) < 40]
            
            md_lines.append(f"- **High Risk (≥70):** {len(high_risk)}")
            md_lines.append(f"- **Medium Risk (40-69):** {len(medium_risk)}")
            md_lines.append(f"- **Low Risk (<40):** {len(low_risk)}\n")
            
            # Detailed results
            md_lines.append("## Detailed Results\n")
            
            for i, result in enumerate(results, 1):
                md_lines.append(f"### {i}. {result['endpoint_name']}")
                md_lines.append(f"- **Agent GUID:** `{result['agent_guid']}`")
                md_lines.append(f"- **Type:** {result['type']}")
                md_lines.append(f"- **OS:** {result['os_name']} ({result['os_platform']})")
                md_lines.append(f"- **Risk Score:** {result['calculated_risk_score']}")
                
                if result.get('ip_addresses'):
                    md_lines.append(f"- **IP Addresses:** {', '.join(result['ip_addresses'])}")
                    
                md_lines.append(f"- **EDR Sensor:** {result['edr_sensor_status']}")
                md_lines.append(f"- **Connectivity:** {result['edr_connectivity']}")
                md_lines.append(f"- **Isolation Status:** {result['isolation_status']}")
                md_lines.append("- **Security Features:**")
                md_lines.append(f"  - Firewall: {result['security_features']['firewall']}")
                md_lines.append(f"  - Intrusion Prevention: {result['security_features']['intrusion_prevention']}")
                md_lines.append(f"  - Vulnerability Protection: {result['security_features']['vulnerability_protection']}")
                md_lines.append("")
                
            return "\n".join(md_lines)
            
        else:
            return json.dumps(results, indent=2)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Scan endpoints using Trend Vision One API'
    )
    parser.add_argument(
        '--api-token',
        help='Trend Vision One API token (or set TREND_MICRO_API_TOKEN env var)',
        default=os.environ.get('TREND_MICRO_API_TOKEN')
    )
    parser.add_argument(
        '--base-url',
        help='API base URL',
        default=os.environ.get('TREND_MICRO_BASE_URL', 'https://api.eu.xdr.trendmicro.com')
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
    scanner = TrendMicroScanner(args.api_token, args.base_url)

    # Run scan
    results = scanner.find_exposed_endpoints(min_risk_score=args.min_risk_score)

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
        logger.info(f"\nScan complete. Found {len(results)} endpoints.")
        high_risk = [r for r in results if r.get('calculated_risk_score', 0) >= 70]
        if high_risk:
            logger.warning(f"WARNING: {len(high_risk)} high-risk endpoints found!")
    else:
        logger.info("No endpoints found matching the criteria.")


if __name__ == "__main__":
    main()
