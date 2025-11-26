
# Advanced Scanner Network Tool

A powerful and flexible Python-based network scanning framework.  
Inspired by Nmap, designed to combine simplicity and effectiveness for both Local Network Scanning and Deep Target Host Analysis.

---

## Key Modules

### 1. LAN Scanner - Scan Local Network
> Auto-discover all active devices on your selected network segment with detailed information.

#### Features
- Auto-detect local networks & interfaces
- Detect live devices in local subnet
- Gather IP, MAC, Vendor info
- Scan open ports & identify common services
- Multi-threaded for fast performance
- Visualize results in table view

---

### 2. Host Scanner - Scan Specific Target
> Deep analysis of a single host (local or remote) for open ports, services, OS fingerprinting and SSL details.

#### Features
- Multi-threaded TCP Port Scanning
- Service Detection & Banner Grabbing
- OS Fingerprinting (basic)
- SSL/TLS Certificate Analysis
- Export Result to JSON

---

## Usage

```bash
python main.py
```

Menu:
```
=== Select an option ===
1. Scan Local Network - Discover all active hosts (local)
2. Host Scanner - Scan specific hosts (local & remote)
0. Exit
```

---

## Requirements

Python 3.6+

Install all required packages:
```bash
pip install -r requirements.txt
```

---

## Example Output

### LAN Scanner
```
### Network Scanner v3.0

#### Available Networks
1. 127.0.0.0/8 (Interface: lo)  
2. 192.168.39.0/24 (Interface: ens160)  
3. 172.17.0.0/16 (Interface: docker0)  
4. 172.18.0.0/16 (Interface: br-810b879b415b)  
5. 192.168.122.0/24 (Interface: virbr0)  

> Select network to scan (enter number): 2  

Scanning results:
+---------------+-------------------+----------------------------------+---------------------+--------------------------------------------------+
| IP            | MAC               | Vendor                           | Device Type         | Open Ports                                       |
+===============+===================+==================================+=====================+==================================================+
| 192.168.39.1  | xx:xx:xx:xx:xx:xx | Routerboard.com                  | Linux/Unix Device   | 53(DNS), 1723(PPTP), 1194(OpenVPN), 8291(API)    |
| 192.168.39.8  | xx:xx:xx:xx:xx:xx | Routerboard.com                  | Linux/Unix Device   | 1194(OpenVPN), 1723(PPTP), 8291(API)             |
| 192.168.39.10 | xx:xx:xx:xx:xx:xx | Hangzhou Ezviz Software Co.,Ltd. | Camera/Media Device | 8000(HTTP-Alt), 554(RTSP)                        |
| 192.168.39.26 | xx:xx:xx:xx:xx:xx | VMware, Inc.                     | Linux/Unix Device   | 7070(RealPlayer)                                 |
| 192.168.39.27 | xx:xx:xx:xx:xx:xx | VMware, Inc.                     | Linux/Unix Device   | 22(SSH), 25565(Minecraft)                        |
| 192.168.39.34 | xx:xx:xx:xx:xx:xx | Hangzhou Ezviz Software Co.,Ltd. | Camera/Media Device | 8000(HTTP-Alt)                                   |
| 192.168.39.35 | xx:xx:xx:xx:xx:xx | Routerboard.com                  | Linux/Unix Device   | N/A                                              |
| 192.168.39.36 | xx:xx:xx:xx:xx:xx | Ubiquiti Inc                     | Linux/Unix Device   | 22(SSH)                                          |
| 192.168.39.42 | xx:xx:xx:xx:xx:xx | Unknown                          | Generic Device      | 135(MSRPC), 445(Microsoft-DS), 902(VMware)       |
...
```

### Host Scanner
```bash
python host_scanner.py -t 192.168.1.1 -p 1-1000 --service-detection --os-detection -v
```

Output:
```
Target: 192.168.1.1
Open Ports:
- 80/tcp (HTTP)
- 443/tcp (HTTPS)
- 22/tcp (SSH)

OS Detected: Linux Kernel 3.x-4.x
SSL Info: Certificate Details Extracted

Result saved to:
results/192.168.1.1/192.168.1.1_2025-04-12_21-25-30.json
```

---

## Command Line Options (Host Scanner)

| Option                | Description                                              |
|----------------------|----------------------------------------------------------|
| -t, --target         | Target host (IP or domain)                               |
| -p, --ports          | Port range (default: 1-1000)                            |
| --service-detection  | Enable service detection                                |
| --os-detection       | Enable OS detection                                     |
| -T, --threads        | Number of threads (default: 100)                        |
| -v, --verbose        | Verbose output                                          |
| --timeout            | Connection timeout (default: 1s)                        |

---

## Folder Structure
```
/
├── main.py                 → Entry script (menu)
├── lan_scanner.py          → LAN scanning logic
├── host_scanner.py         → Targeted host scanning logic
└── README.md
```

---

## Disclaimer
> This tool is for educational & authorized testing only. Unauthorized usage may violate laws.

---

## Author
Developed by: sondt  
Version: 4.0  

> _"Privacy is not about hiding. It's about control."_
