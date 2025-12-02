# Nmap Scanner

A powerful Python wrapper for nmap that provides an easy-to-use CLI interface for network scanning with features like OS detection, service scanning, top ports scanning, and JSON export.

## Features

- ✅ Scan single IP addresses or entire subnets
- ✅ OS detection (requires root/admin privileges)
- ✅ Service version detection
- ✅ Top ports scanning (most common ports)
- ✅ Custom port specification
- ✅ Clean table output for easy reading
- ✅ JSON export for programmatic use
- ✅ Full CLI argument support
- ✅ Comprehensive error handling

## Requirements

- Python 3.6 or higher
- nmap installed on your system
- Root/Administrator privileges (optional, for OS detection and some scan types)

### Installing nmap

**Linux:**
```bash
sudo apt-get install nmap  # Debian/Ubuntu
sudo yum install nmap      # CentOS/RHEL
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download and install from [nmap.org](https://nmap.org/download.html)

## Installation

1. Clone or download this repository:
```bash
git clone <repository-url>
cd python-nmap
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Scan a single IP address:
```bash
python nmap_scanner.py 192.168.1.1
```

Scan a subnet:
```bash
python nmap_scanner.py 192.168.1.0/24
```

### Command Line Arguments

```
positional arguments:
  target                Target IP address or subnet (e.g., 192.168.1.1 or 192.168.1.0/24)

optional arguments:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Port specification (e.g., 22,80,443 or 1-1000)
  --top-ports N         Scan top N most common ports (e.g., 10, 100, 1000)
  -O, --os-detect       Enable OS detection (requires root/admin privileges)
  -sV, --service-scan   Enable service version detection
  -o FILE, --output FILE
                        Export results to JSON file
  --arguments ARGS      Additional nmap arguments as a string (e.g., "-T4 -v")
```

### Examples

#### Scan with specific ports:
```bash
python nmap_scanner.py 192.168.1.1 -p 22,80,443
```

#### Scan top 10 most common ports:
```bash
python nmap_scanner.py 192.168.1.1 --top-ports 10
```

#### Scan with OS detection:
```bash
# Linux/macOS - requires sudo
sudo python nmap_scanner.py 192.168.1.1 --os-detect

# Windows - run as Administrator
python nmap_scanner.py 192.168.1.1 --os-detect
```

#### Scan with service version detection:
```bash
python nmap_scanner.py 192.168.1.1 --service-scan
```

#### Full featured scan with all options:
```bash
python nmap_scanner.py 192.168.1.0/24 --top-ports 100 --os-detect --service-scan
```

#### Export results to JSON:
```bash
python nmap_scanner.py 192.168.1.1 -p 22,80,443 -o results.json
```

#### Custom nmap arguments:
```bash
python nmap_scanner.py 192.168.1.1 --arguments "-T4 -v --script vuln"
```

#### Scan a range of ports:
```bash
python nmap_scanner.py 192.168.1.1 -p 1-1000 --service-scan
```

## Output Formats

### Table Output

The default output displays results in a clean, readable table format showing:
- Host information (IP, hostnames, MAC address)
- OS detection results (if enabled)
- Open ports with service information
- Service versions and products (if service scan is enabled)

Example output:
```
================================================================================
NMAP SCAN RESULTS
================================================================================

Host: 192.168.1.1 (up)

Port Status: Open: 3, Closed: 0, Filtered: 0

Open Ports:
┌──────┬──────────┬─────────┬─────────────────────┬──────────┐
│ Port │ State    │ Service │ Product             │ Version  │
├──────┼──────────┼─────────┼─────────────────────┼──────────┤
│ 22   │ open     │ ssh     │ OpenSSH             │ 7.4      │
│ 80   │ open     │ http    │ Apache httpd        │ 2.4.6    │
│ 443  │ open     │ https   │ Apache httpd        │ 2.4.6    │
└──────┴──────────┴─────────┴─────────────────────┴──────────┘
```

### JSON Export

When using the `-o` or `--output` flag, results are exported to a JSON file with a structured format:

```json
{
  "scan_info": {
    "tcp": {
      "method": "syn",
      "services": "22,80,443"
    }
  },
  "hosts": [
    {
      "host": "192.168.1.1",
      "hostname": [...],
      "state": "up",
      "addresses": {...},
      "vendor": {...},
      "os": {...},
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "name": "ssh",
          "product": "OpenSSH",
          "version": "7.4",
          ...
        }
      ],
      "port_count": {
        "open": 3,
        "closed": 0,
        "filtered": 0
      }
    }
  ]
}
```

## JSON Output Structure

The JSON export contains the following structure:

- **scan_info**: General information about the scan
- **hosts**: Array of scanned hosts, each containing:
  - **host**: IP address
  - **hostname**: Array of hostname entries
  - **state**: Host state (up/down)
  - **addresses**: IP and MAC addresses
  - **vendor**: MAC vendor information
  - **os**: OS detection results (matches and classes)
  - **ports**: Array of port information
  - **port_count**: Summary of port states

## Permissions

Some scan types require elevated privileges:

- **OS Detection (`-O`)**: Requires root (Linux/macOS) or Administrator (Windows)
- **SYN Scan**: Requires root (Linux/macOS) or Administrator (Windows)
- **Service Scan (`-sV`)**: Can run without root, but may be less accurate

If you don't have root/administrator privileges, nmap will automatically fall back to a TCP connect scan.

## Troubleshooting

### "Nmap not found" error
- Ensure nmap is installed and available in your system PATH
- On Windows, you may need to add nmap to your system PATH manually

### Permission denied errors
- OS detection and some scan types require root/administrator privileges
- Use `sudo` on Linux/macOS or run as Administrator on Windows

### Slow scans
- Use `--top-ports` to scan fewer ports
- Use the `--arguments "-T4"` flag for faster timing (less reliable)
- Consider scanning smaller subnets or single hosts

### No results found
- Verify the target IP/subnet is correct
- Check network connectivity
- Ensure firewall isn't blocking the scan
- Try with `-p` to scan specific ports first

## Dependencies

- **python-nmap**: Python interface to nmap
- **tabulate**: For formatted table output

## License

This project is open source and available for use.

## Contributing

Contributions, issues, and feature requests are welcome!

## Author

Created as a wrapper for python-nmap to provide enhanced CLI functionality.

