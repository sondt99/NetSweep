# NetSweep - Professional Network Scanner

Python Version: 3.7+
License: MIT
Version: 4.0-Pro

> **NetSweep** is a comprehensive, professional-grade network scanning tool written in Python. Designed as an alternative to Nmap, it combines powerful functionality with an intuitive interface for both educational and authorized network auditing purposes.

---

## Key Features

### LAN Scanner - Local Network Discovery
Automatically discover all active devices on your selected network segment with detailed information.

**Features:**
- **Auto Network Detection**: Automatically discovers available network interfaces and segments
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

---

## Professional Architecture

NetSweep follows a modular, professional architecture designed for maintainability and extensibility:

```
NetSweep/
├── main.py                 # Interactive menu-driven entry point
├── config.py              # Centralized configuration management
├── lan_scanner.py         # Local network scanning CLI
├── host_scanner.py        # Target host scanning CLI
├── port_scanner.py        # Advanced port scanning with SYN/UDP support
├── service_detector.py    # Sophisticated service detection
├── requirements.txt       # Optimized dependencies
├── README.md             # Professional documentation
├── scanner/              # Core scanning modules
│   ├── network_scanner.py # Core LAN scanning logic
│   ├── device_info.py     # Device detection and vendor identification
│   └── port_scanner.py    # Network port scanning utilities
├── utils/                # Utility modules
│   ├── network_utils.py   # Network interface discovery
│   ├── system_utils.py    # System utility functions
│   └── error_handler.py   # Professional error handling system
└── config/               # Configuration files
    └── ports.py          # Comprehensive port-to-service mapping
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
git clone https://github.com/sondt/NetSweep.git
cd NetSweep

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Development Installation

```bash
# Clone for development
git clone https://github.com/sondt/NetSweep.git
cd NetSweep

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with development dependencies
pip install -r requirements.txt

# Create default configuration
python config.py --create-config ~/.netsweep/config.json
```

---

## Usage Guide

### Interactive Mode (Recommended)

```bash
python main.py
```

The interactive menu provides:
- **Option 1**: LAN Scanner for local network discovery
- **Option 2**: Host Scanner for targeted analysis
- **Option 3**: Configuration management and monitoring
- **Option 0**: Exit with session summary

### **Command Line Usage**

#### **LAN Scanner**
```bash
# Basic local network scan
python lan_scanner.py

# Custom configuration
python lan_scanner.py -t 100 -T 0.5 -o json -d results

# Available options:
# -t, --threads       Number of threads (default: 50)
# -T, --timeout       Connection timeout (default: 0.5s)
# -o, --output       Export format: json/csv/txt (default: json)
# -d, --directory    Output directory (default: scan_results)
```

#### **Host Scanner**
```bash
# Basic host scan
python host_scanner.py -t example.com -p 1-1000

# Advanced scan with all features
python host_scanner.py -t 192.168.1.1 -p 1-65535 --service-detection --os-detection -v

# Command line options:
# -t, --target          Target host (IP or domain)
# -p, --ports          Port range (default: 1-1000)
# --service-detection  Enable service detection
# --os-detection       Enable OS fingerprinting
# -v, --verbose        Verbose output
# -T, --threads        Number of threads (default: 100)
# --timeout            Connection timeout (default: 1s)
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
=== NetSweep LAN Scanner ===

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
Results exported to: scan_results/lan_scan_2025-01-15_14-30-22.json
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
    "timeout": 0.5,           // Connection timeout in seconds
    "max_workers": 50,        // Maximum concurrent threads
    "retry_count": 3,         // Number of retry attempts
    "banner_grab_timeout": 1.0, // Banner grabbing timeout
    "scan_delay": 0.1         // Delay between scans (rate limiting)
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
    "export_format": "json",    // json, csv, txt
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

### Port Scanning Techniques

NetSweep supports multiple port scanning techniques:

1. **TCP Connect Scan** (Default)
   - Standard three-way handshake
   - No special privileges required
   - Reliable and universally compatible

2. **SYN Stealth Scan** (Advanced)
   - Half-open scanning technique
   - Requires root/admin privileges
   - Stealthier than connect scan

3. **UDP Scan** (Advanced)
   - UDP port scanning
   - Requires root/admin privileges
   - Slower but comprehensive

### Service Detection

NetSweep includes sophisticated service detection capabilities:

- **Protocol-Specific Detection**: Custom probes for HTTP, SSH, FTP, SMTP, and more
- **Banner Grabbing**: Extract service banners and version information
- **SSL/TLS Analysis**: Certificate parsing and validation
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

Warning: NetSweep is designed for authorized network testing and educational purposes only.

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
- **Logging**: Comprehensive audit logging for accountability
- **Configuration Security**: Secure configuration management with validation

#### Recommended Best Practices
1. **Start with conservative settings** (low thread counts, longer timeouts)
2. **Scan during maintenance windows** when possible
3. **Monitor network impact** during scans
4. **Keep detailed records** of all scanning activities
5. **Use professional judgment** when determining scan scope and intensity

---

## Contributing

We welcome contributions to NetSweep! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork the repository
git clone https://github.com/your-username/NetSweep.git
cd NetSweep

# Create development environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .

# Run tests
python -m pytest tests/

# Run linting
flake8 netsweep/
black netsweep/
```

### Code Quality Standards

- **PEP 8 Compliance**: Follow Python style guidelines
- **Type Hints**: Include type annotations for new code
- **Documentation**: Comprehensive docstrings for all functions
- **Error Handling**: Proper exception handling and logging
- **Testing**: Unit tests for new functionality

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

### Version 4.0-Pro (Current)
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

## API Reference

### Python API Usage

NetSweep can be used as a Python library:

```python
from netsweep import NetSweepScanner, NetworkConfig, ScanConfig

# Initialize scanner
config = ScanConfig(timeout=1.0, max_workers=100)
scanner = NetSweepScanner(config=config)

# Scan local network
results = scanner.scan_network("192.168.1.0/24")
print(f"Found {len(results)} devices")

# Scan specific host
host_results = scanner.scan_host("192.168.1.1", ports="1-1000")
print(f"Open ports: {host_results.open_ports}")
```

### Error Handling

```python
from netsweep import NetSweepError, NetworkError, ConfigurationError
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
# Solution: Run with appropriate privileges
sudo python main.py

# Or use non-privileged scan methods
python main.py --no-privilege
```

#### Network Interface Not Found
```bash
# Check available interfaces
python -c "from utils.network_utils import get_network_interfaces; print(get_network_interfaces())"

# Specify interface manually
python lan_scanner.py --interface wlan0
```

#### Configuration Issues
```bash
# Reset configuration
python config.py --reset-config

# Validate configuration
python config.py --validate
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Enable debug logging
export NETSWEEP_DEBUG=1
python main.py

# Or specify log file
python main.py --log-file debug.log --log-level DEBUG
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

NetSweep uses several third-party libraries. See [requirements.txt](requirements.txt) and individual library licenses for details.

---

## Author

**Developed by: sondt**
- **GitHub**: [@sondt](https://github.com/sondt)
- **Email**: sondt@example.com
- **LinkedIn**: [sondt](https://linkedin.com/in/sondt)

---

## Acknowledgments

- **Nmap Team**: For inspiration and scanning methodology
- **Scapy Developers**: For excellent packet manipulation capabilities
- **Python Community**: For amazing networking libraries
- **Security Community**: For feedback and improvement suggestions

---

## Support & Contact

- **Issues**: [GitHub Issues](https://github.com/sondt/NetSweep/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sondt/NetSweep/discussions)
- **Email**: support@netsweep.dev
- **Documentation**: [NetSweep Docs](https://docs.netsweep.dev)

---

Knowledge is power, but with power comes responsibility. Use NetSweep ethically and professionally.

NetSweep - Professional Network Scanning for Authorized Testing