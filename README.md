# NetSweep - Professional Network Scanner

Python Version: 3.7+
License: MIT
Version: 5.0.0

> **NetSweep** is a comprehensive, professional-grade network scanning tool written in Python. Designed as an alternative to Nmap, it combines powerful functionality with an intuitive interface for both educational and authorized network auditing purposes.

---

## Key Features

### LAN Scanner - Local Network Discovery
Automatically discover all active devices on your selected network segment with detailed information.

**Features:**
- **Auto Network Detection**: Automatically discovers available network interfaces and segments
- **Upstream Discovery**: Optionally discover reachable upstream networks beyond the local gateway
- **Multi-threaded Scanning**: Fast, concurrent device discovery for optimal performance
- **Comprehensive Device Information**:
  - IP addresses and MAC addresses
  - Vendor identification via API lookup
  - Device type classification (router, server, IoT, etc.)
  - Open port scanning with service detection
- **Multiple Export Formats**: JSON, CSV, and TXT export capabilities
- **Progress Tracking**: Real-time progress bars with tqdm
- **Professional Tables**: Beautifully formatted results with tabulate

### Host Scanner - Targeted Host Analysis
Perform deep analysis of specific targets with advanced reconnaissance capabilities.

**Features:**
- **Flexible Port Scanning**: Customizable port ranges and high-performance TCP scanning
- **Advanced Service Detection**: Banner grabbing and version identification
- **OS Fingerprinting**: Basic operating system detection based on TTL and port signatures
- **SSL/TLS Analysis**: Certificate analysis for secure services
- **Comprehensive Service Detection**: HTTP, SSH, FTP, SMTP, and 200+ other services
- **Automatic JSON Export**: Structured results with detailed scan information

### Advanced Port Scanner (Library)
A standalone multi-technique port scanner module available for programmatic use.

**Techniques:**
- **TCP Connect Scan**: Standard three-way handshake (no special privileges required)
- **SYN Stealth Scan**: Half-open scanning using Scapy (requires root/admin privileges)
- **UDP Scan**: UDP port scanning using Scapy (requires root/admin privileges)

---

## Project Structure

```
NetSweep/
├── main.py                 # Interactive menu-driven entry point
├── config.py               # Centralized configuration management
├── lan_scanner.py           # Local network scanning CLI
├── host_scanner.py          # Target host scanning CLI
├── port_scanner.py          # Advanced port scanner (SYN/UDP/connect)
├── service_detector.py      # Sophisticated service detection
├── requirements.txt         # Production dependencies
├── requirements-dev.txt     # Development/testing dependencies
├── LICENSE                  # MIT License
├── SECURITY.md              # Security policy
├── README.md                # Documentation
├── scanner/                 # Core scanning modules
│   ├── __init__.py
│   ├── network_scanner.py   # Core LAN scanning logic
│   └── device_info.py       # Device detection and vendor identification
├── utils/                   # Utility modules
│   ├── __init__.py
│   ├── network_utils.py     # Network interface discovery
│   ├── system_utils.py      # System utility functions
│   └── error_handler.py     # Professional error handling system
├── config/                  # Configuration files
│   └── ports.py             # Comprehensive port-to-service mapping
└── tests/                   # Test suite
    ├── conftest.py
    ├── test_config.py
    ├── test_device_info.py
    ├── test_error_handler.py
    ├── test_host_scanner.py
    ├── test_main.py
    ├── test_network_scanner.py
    ├── test_network_utils.py
    ├── test_port_scanner.py
    ├── test_service_detector.py
    └── test_system_utils.py
```

### Core Components

#### **Configuration Management (`config.py`)**
- Professional configuration system with dataclasses
- JSON-based configuration persistence
- Validation and error checking
- Environment-specific settings

#### **Error Handling System (`utils/error_handler.py`)**
- Centralized error management and logging
- Multiple severity levels and custom exception types
- Decorator-based error handling
- Comprehensive error tracking and reporting

#### **Service Detection (`service_detector.py`)**
- Advanced banner grabbing with protocol-specific handling
- SSL/TLS certificate analysis
- Version identification for common services
- Extensible service database

---

## Installation & Setup

### Prerequisites
- Python 3.7 or higher
- Administrative/root privileges for advanced scans (SYN/UDP scans)

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/sondt99/NetSweep.git
cd NetSweep

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Development Installation

```bash
# Clone for development
git clone https://github.com/sondt99/NetSweep.git
cd NetSweep

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install production + development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

---

## Usage Guide

### Interactive Mode (Recommended)

```bash
python main.py
```

The interactive menu provides:
- **Option 1**: Scan Local Network - Discover all active hosts (local)
- **Option 2**: Host Scanner - Scan specific hosts (local & remote)
- **Option 3**: Configuration - View and modify settings
- **Option 0**: Exit

### Command Line Usage

#### **LAN Scanner**
```bash
# Basic local network scan (auto-detects network)
python lan_scanner.py

# Scan a specific network
python lan_scanner.py -n 192.168.1.0/24

# Discover and scan upstream networks
python lan_scanner.py --discover-upstream

# Custom configuration with export
python lan_scanner.py -t 100 -T 0.5 -o json -d results

# Available options:
# -n, --network          Network to scan in CIDR format (auto-detected if omitted)
# --discover-upstream    Auto-discover reachable upstream networks
# -t, --threads          Number of threads (default: 50)
# -T, --timeout          Connection timeout in seconds (default: 0.5)
# --ip-timeout           Maximum time per single IP in seconds (default: 2.0)
# -o, --output           Export format: json, csv, or txt (no export if omitted)
# -d, --output-dir       Output directory (default: scan_results)
```

#### **Host Scanner**
```bash
# Basic host scan
python host_scanner.py -t example.com -p 1-1000

# Advanced scan with all features
python host_scanner.py -t 192.168.1.1 -p 1-65535 --service-detection --os-detection -v

# Available options:
# -t, --target           Target host (IP or domain)
# -p, --ports            Port range (default: 1-1000)
# --service-detection    Enable service detection
# --os-detection         Enable OS fingerprinting
# -v, --verbose          Verbose output
# -T, --threads          Number of threads (default: 100)
# --timeout              Connection timeout in seconds (default: 1.0)
```

#### **Configuration Management**
```bash
# View current configuration
python config.py --show-config

# Validate configuration
python config.py --validate

# Create default config file
python config.py --create-config ~/.netsweep/config.json
```

---

## Example Outputs

### LAN Scanner Results
```
=== Advanced Network Scanner v5.0.0 ===

Available Networks:
1. 192.168.1.0/24 (Interface: wlan0) - Private Network
2. 10.0.0.0/24 (Interface: eth0) - Private Network

> Select network to scan: 1

Scanning 192.168.1.0/24 with 50 threads...
███████████████████████████████████████████████████ 100% (254/254)

Network Scan Results:
+----------------+-------------------+----------------------------+-------------------+---------------------------------------------+
| IP Address     | MAC Address       | Vendor                     | Device Type       | Open Ports                                   |
+================+===================+============================+===================+=============================================+
| 192.168.1.1    | aa:bb:cc:dd:ee:ff | Cisco Systems              | Router            | 53(DNS), 443(HTTPS), 80(HTTP)               |
| 192.168.1.10   | 11:22:33:44:55:66 | Apple Inc.                 | Apple Device      | 5480(Bonjour), 62078(iTunes)                |
| 192.168.1.20   | 77:88:99:aa:bb:cc | Samsung Electronics        | Mobile Device     | 80(HTTP), 443(HTTPS), 5555(ADB)             |
| 192.168.1.100  | dd:ee:ff:aa:bb:cc | Dell Inc.                  | Server            | 22(SSH), 80(HTTP), 443(HTTPS), 3306(MySQL)  |
+----------------+-------------------+----------------------------+-------------------+---------------------------------------------+

Scan completed in 45.2 seconds
Results exported to: scan_results/scan_20250115_143022.json
```

### Host Scanner Results
```json
{
  "target": "192.168.1.1",
  "scan_time": "2025-01-15T14:30:22Z",
  "scan_duration": 12.45,
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "service": "SSH",
      "banner": "SSH-2.0-OpenSSH_7.4",
      "version": "OpenSSH 7.4"
    },
    {
      "port": 80,
      "protocol": "tcp",
      "service": "HTTP",
      "banner": "HTTP/1.1 400 Bad Request",
      "web_server": "nginx/1.18.0"
    },
    {
      "port": 443,
      "protocol": "tcp",
      "service": "HTTPS",
      "ssl_info": {
        "certificate": {
          "subject": "CN=router.local",
          "issuer": "CN=router.local",
          "valid_from": "2024-01-01",
          "valid_to": "2025-01-01",
          "signature_algorithm": "sha256WithRSAEncryption"
        }
      }
    }
  ],
  "os_fingerprint": {
    "likely_os": "Linux",
    "confidence": "medium",
    "ttl": 64
  },
  "summary": {
    "total_ports_scanned": 1000,
    "open_ports_count": 3,
    "services_detected": 3
  }
}
```

---

## Configuration

NetSweep uses a comprehensive configuration system that allows you to customize all aspects of the scanning process. Configuration files are stored in `~/.netsweep/config.json` by default.

### Configuration Sections

#### Scan Configuration
```json
{
  "scan": {
    "timeout": 0.5,
    "max_workers": 50,
    "retry_count": 3,
    "banner_grab_timeout": 1.0,
    "scan_delay": 0.1
  }
}
```

#### Network Configuration
```json
{
  "network": {
    "default_ports": "1-1000",
    "common_ports_range": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995],
    "exclude_ports": [],
    "interface_timeout": 2.0
  }
}
```

#### Output Configuration
```json
{
  "output": {
    "default_output_dir": "scan_results",
    "export_format": "json",
    "verbose": false,
    "show_progress": true,
    "table_style": "grid"
  }
}
```

#### Security Configuration
```json
{
  "security": {
    "max_scan_targets": 1000,
    "max_concurrent_connections": 200,
    "rate_limit_delay": 0.01,
    "require_user_confirmation": true
  }
}
```

---

## Advanced Features

### Service Detection

NetSweep includes sophisticated service detection capabilities:

- **Protocol-Specific Detection**: Custom probes for HTTP, SSH, FTP, SMTP, and more
- **Banner Grabbing**: Extract service banners and version information
- **SSL/TLS Analysis**: Certificate parsing and validation (TLS 1.2+ enforced)
- **Version Detection**: Identify specific software versions when possible

### OS Fingerprinting

Basic OS detection through:
- TTL analysis
- Open port patterns
- Service responses
- Window size analysis

---

## Security & Legal

### Important Security Considerations

**Warning**: NetSweep is designed for authorized network testing and educational purposes only.

#### Legal Usage Guidelines
- **Authorization Only**: Only scan networks and systems you own or have explicit permission to test
- **Compliance**: Ensure compliance with local, national, and international laws
- **Corporate Policy**: Follow organizational security policies and guidelines
- **Rate Limiting**: Use appropriate delays and thread counts to avoid network disruption
- **Documentation**: Document all scanning activities and maintain proper records

#### Technical Security Features
- **Input Validation**: Comprehensive input sanitization and validation
- **Rate Limiting**: Built-in delays to prevent network overload
- **Error Handling**: Secure error handling that doesn't expose sensitive information
- **Logging**: Comprehensive audit logging with sensitive data masking
- **Configuration Security**: Secure configuration management with validation

#### Recommended Best Practices
1. **Start with conservative settings** (low thread counts, longer timeouts)
2. **Scan during maintenance windows** when possible
3. **Monitor network impact** during scans
4. **Keep detailed records** of all scanning activities
5. **Use professional judgment** when determining scan scope and intensity

---

## Contributing

We welcome contributions to NetSweep!

### Development Setup

```bash
# Fork the repository
git clone https://github.com/your-username/NetSweep.git
cd NetSweep

# Create development environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Code Quality Standards

- **PEP 8 Compliance**: Follow Python style guidelines
- **Type Hints**: Include type annotations for new code
- **Error Handling**: Proper exception handling and logging
- **Testing**: Unit tests for new functionality

---

## Changelog

### Version 5.0.0 (Current)
- Professional configuration management system
- Advanced error handling and logging
- Improved security and input validation
- Enhanced documentation and examples
- Optimized performance and resource usage
- Modular architecture improvements
- Better cross-platform compatibility

### Version 3.0
- Service detection enhancements
- SSL/TLS certificate analysis
- Improved OS fingerprinting
- Multiple export formats
- UI/UX improvements

---

## Programmatic Usage

NetSweep modules can be imported directly:

```python
from scanner.network_scanner import NetworkScanner
from config import ScanConfig, NetworkConfig, get_config
from utils.error_handler import handle_errors, NetSweepError
```

### Error Handling

```python
from utils.error_handler import handle_errors

@handle_errors(default_return=None, log_context="MyScan")
def my_scan_function():
    # Your scanning code here
    pass
```

---

## Troubleshooting

### Common Issues

#### Permission Denied Errors
```bash
# SYN and UDP scans require root privileges
sudo python main.py
```

#### Network Interface Not Found
```bash
# Check available interfaces
python -c "from utils.network_utils import get_local_networks; print(get_local_networks())"
```

#### Configuration Issues
```bash
# Validate configuration
python config.py --validate

# Create a fresh default config
python config.py --create-config ~/.netsweep/config.json
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Developed by: Thai Son Dinh**
- **GitHub**: [@sondt99](https://github.com/sondt99)
- **LinkedIn**: [thaisondinh](https://www.linkedin.com/in/thaisondinh/)

---

## Acknowledgments

- **Nmap Team**: For inspiration and scanning methodology
- **Scapy Developers**: For excellent packet manipulation capabilities
- **Python Community**: For amazing networking libraries
- **Security Community**: For feedback and improvement suggestions

---

## Support & Contact

- **Issues**: [GitHub Issues](https://github.com/sondt99/NetSweep/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sondt99/NetSweep/discussions)

---

Knowledge is power, but with power comes responsibility. Use NetSweep ethically and professionally.

NetSweep - Professional Network Scanning for Authorized Testing
