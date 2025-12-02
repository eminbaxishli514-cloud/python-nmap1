#!/usr/bin/env python3
"""
Nmap Scanner - A Python wrapper for nmap using python-nmap.

This tool provides an easy-to-use interface for network scanning with
features like OS detection, service scanning, top ports, and JSON export.
"""

import argparse
import json
import sys
from typing import Dict, List, Optional
from tabulate import tabulate
import nmap


class NmapScanner:
    """Wrapper class for nmap scanning operations."""
    
    def __init__(self):
        """Initialize the NmapScanner with an nmap.PortScanner instance."""
        self.scanner = nmap.PortScanner()
    
    def scan_target(
        self,
        target: str,
        ports: Optional[str] = None,
        os_detection: bool = False,
        service_scan: bool = False,
        top_ports: Optional[int] = None,
        arguments: Optional[str] = None
    ) -> Dict:
        """
        Perform a network scan on the specified target.
        
        Args:
            target: IP address or subnet to scan (e.g., '192.168.1.1' or '192.168.1.0/24')
            ports: Port specification (e.g., '22,80,443' or '1-1000')
            os_detection: Enable OS detection (-O flag)
            service_scan: Enable service version detection (-sV flag)
            top_ports: Scan top N most common ports
            arguments: Additional nmap arguments as a string
        
        Returns:
            Dictionary containing scan results
        """
        # Determine ports - if both are specified, prefer explicit ports
        if ports and top_ports:
            # Use explicit ports, ignore top_ports
            scan_ports = ports
            use_top_ports = False
        elif ports:
            scan_ports = ports
            use_top_ports = False
        elif top_ports:
            scan_ports = None
            use_top_ports = True
        else:
            scan_ports = None
            use_top_ports = False
        
        # Build nmap arguments
        nmap_args = []
        
        if use_top_ports:
            nmap_args.append(f'--top-ports {top_ports}')
        
        if os_detection:
            nmap_args.append('-O')
        
        if service_scan:
            nmap_args.append('-sV')
        
        if arguments:
            nmap_args.append(arguments)
        
        # Default scan type if no specific scan type is specified
        if not any(arg.startswith('-s') for arg in nmap_args) and not use_top_ports:
            nmap_args.append('-sS')  # SYN scan by default
        
        # Join arguments
        arguments_string = ' '.join(nmap_args) if nmap_args else None
        
        # Perform scan
        try:
            if scan_ports:
                self.scanner.scan(hosts=target, ports=scan_ports, arguments=arguments_string)
            else:
                # When using --top-ports or no ports specified, let nmap handle it
                self.scanner.scan(hosts=target, arguments=arguments_string)
            
            return self._format_results()
        except nmap.PortScannerError as e:
            raise RuntimeError(f"Nmap scan error: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error during scan: {str(e)}")
    
    def _format_results(self) -> Dict:
        """
        Format scan results into a structured dictionary.
        
        Returns:
            Dictionary with formatted scan results
        """
        results = {
            'scan_info': {},
            'hosts': []
        }
        
        # Extract scan info
        if hasattr(self.scanner, 'scaninfo'):
            results['scan_info'] = self.scanner.scaninfo
        
        # Extract host information
        for host in self.scanner.all_hosts():
            host_data = {
                'host': host,
                'hostname': self._get_hostnames(host),
                'state': self.scanner[host].state(),
                'addresses': dict(self.scanner[host].get('addresses', {})),
                'vendor': dict(self.scanner[host].get('vendor', {})),
                'os': self._get_os_info(host),
                'ports': [],
                'port_count': {
                    'open': 0,
                    'closed': 0,
                    'filtered': 0,
                    'open_filtered': 0
                }
            }
            
            # Extract port information
            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in ports:
                    port_data = self.scanner[host][proto][port]
                    port_info = {
                        'port': port,
                        'protocol': proto,
                        'state': port_data['state'],
                        'name': port_data.get('name', ''),
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', ''),
                        'extrainfo': port_data.get('extrainfo', ''),
                        'cpe': port_data.get('cpe', '')
                    }
                    host_data['ports'].append(port_info)
                    
                    # Count port states
                    state = port_info['state']
                    if state in host_data['port_count']:
                        host_data['port_count'][state] += 1
            
            results['hosts'].append(host_data)
        
        return results
    
    def _get_hostnames(self, host: str) -> List[Dict]:
        """Extract hostname information for a host."""
        hostnames = []
        if 'hostnames' in self.scanner[host]:
            for hostname_data in self.scanner[host]['hostnames']:
                hostnames.append({
                    'name': hostname_data.get('name', ''),
                    'type': hostname_data.get('type', '')
                })
        return hostnames
    
    def _get_os_info(self, host: str) -> Dict:
        """Extract OS detection information for a host."""
        os_info = {
            'matches': [],
            'classes': []
        }
        
        if 'osmatch' in self.scanner[host]:
            for match in self.scanner[host]['osmatch']:
                os_info['matches'].append({
                    'name': match.get('name', ''),
                    'accuracy': match.get('accuracy', '')
                })
        
        if 'osclass' in self.scanner[host]:
            for osclass in self.scanner[host]['osclass']:
                os_info['classes'].append({
                    'type': osclass.get('type', ''),
                    'vendor': osclass.get('vendor', ''),
                    'osfamily': osclass.get('osfamily', ''),
                    'osgen': osclass.get('osgen', ''),
                    'accuracy': osclass.get('accuracy', '')
                })
        
        return os_info


def display_table(results: Dict):
    """
    Display scan results in a clean table format.
    
    Args:
        results: Dictionary containing scan results
    """
    if not results['hosts']:
        print("No hosts found in scan results.")
        return
    
    print("\n" + "="*80)
    print("NMAP SCAN RESULTS")
    print("="*80 + "\n")
    
    for host_data in results['hosts']:
        # Host header
        host = host_data['host']
        state = host_data['state']
        print(f"Host: {host} ({state})")
        
        # Hostnames
        if host_data['hostname']:
            hostnames_str = ', '.join([h['name'] for h in host_data['hostname'] if h['name']])
            if hostnames_str:
                print(f"Hostnames: {hostnames_str}")
        
        # MAC/Vendor
        if 'mac' in host_data['addresses']:
            mac = host_data['addresses']['mac']
            vendor = host_data['vendor'].get(mac, 'Unknown')
            print(f"MAC Address: {mac} ({vendor})")
        
        # OS Detection
        if host_data['os']['matches'] or host_data['os']['classes']:
            print("\nOS Detection:")
            for match in host_data['os']['matches'][:3]:  # Show top 3 matches
                print(f"  - {match['name']} (Accuracy: {match['accuracy']}%)")
        
        # Port summary
        port_counts = host_data['port_count']
        if any(port_counts.values()):
            print(f"\nPort Status: Open: {port_counts['open']}, "
                  f"Closed: {port_counts['closed']}, "
                  f"Filtered: {port_counts['filtered']}")
        
        # Port table
        if host_data['ports']:
            print("\nOpen Ports:")
            table_data = []
            for port_info in sorted(host_data['ports'], key=lambda x: x['port']):
                if port_info['state'] in ['open', 'open|filtered']:
                    row = [
                        f"{port_info['port']}/{port_info['protocol']}",
                        port_info['state'],
                        port_info['name'] or '-',
                        port_info['product'] or '-',
                        port_info['version'] or '-'
                    ]
                    table_data.append(row)
            
            if table_data:
                headers = ["Port", "State", "Service", "Product", "Version"]
                print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        print("\n" + "-"*80 + "\n")


def export_to_json(results: Dict, filename: str):
    """
    Export scan results to a JSON file.
    
    Args:
        results: Dictionary containing scan results
        filename: Output filename for JSON export
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nResults exported to: {filename}")
    except Exception as e:
        print(f"Error exporting to JSON: {str(e)}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for the CLI application."""
    parser = argparse.ArgumentParser(
        description='Nmap Scanner - A Python wrapper for nmap with enhanced features',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single IP
  python nmap_scanner.py 192.168.1.1

  # Scan a subnet with top 10 ports
  python nmap_scanner.py 192.168.1.0/24 --top-ports 10

  # Scan with OS detection and service version
  python nmap_scanner.py 192.168.1.1 --os-detect --service-scan

  # Scan specific ports and export to JSON
  python nmap_scanner.py 192.168.1.1 -p 22,80,443 -o results.json

  # Full featured scan
  python nmap_scanner.py 192.168.1.0/24 --top-ports 100 --os-detect --service-scan -o scan.json
        """
    )
    
    parser.add_argument(
        'target',
        help='Target IP address or subnet (e.g., 192.168.1.1 or 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '-p', '--ports',
        metavar='PORTS',
        help='Port specification (e.g., 22,80,443 or 1-1000)'
    )
    
    parser.add_argument(
        '--top-ports',
        metavar='N',
        type=int,
        help='Scan top N most common ports (e.g., 10, 100, 1000)'
    )
    
    parser.add_argument(
        '-O', '--os-detect',
        action='store_true',
        help='Enable OS detection (requires root/admin privileges)'
    )
    
    parser.add_argument(
        '-sV', '--service-scan',
        action='store_true',
        dest='service_scan',
        help='Enable service version detection'
    )
    
    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Export results to JSON file'
    )
    
    parser.add_argument(
        '--arguments',
        metavar='ARGS',
        help='Additional nmap arguments as a string (e.g., "-T4 -v")'
    )
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = NmapScanner()
    
    # Perform scan
    print(f"Scanning target: {args.target}")
    if args.ports:
        print(f"Ports: {args.ports}")
    if args.top_ports:
        print(f"Top ports: {args.top_ports}")
    if args.os_detect:
        print("OS detection: Enabled")
    if args.service_scan:
        print("Service scan: Enabled")
    print("Please wait...\n")
    
    try:
        results = scanner.scan_target(
            target=args.target,
            ports=args.ports,
            os_detection=args.os_detect,
            service_scan=args.service_scan,
            top_ports=args.top_ports,
            arguments=args.arguments
        )
        
        # Display results
        display_table(results)
        
        # Export to JSON if requested
        if args.output:
            export_to_json(results, args.output)
        
    except RuntimeError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

