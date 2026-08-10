#!/bin/bash
# ============================================================
#  NetScan - Network Device Scanner + MAC Vendor Lookup
#  Usage: sudo ./netscan.sh [subnet]
# ============================================================

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Config ──
SUBNET="${1:-}"
TOP_PORTS="22,23,53,80,443,554,1900,3389,5000,8080,8443,8888,9000"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
REPORT_FILE="netscan_report_${TIMESTAMP}.txt"
CSV_FILE="netscan_report_${TIMESTAMP}.csv"

# ── Local OUI database ──
declare -A LOCAL_OUI=(
    ["14:49:BC"]="DrayTek"
    ["08:CC:81"]="Hikvision"
    ["0C:75:D2"]="Hikvision"
    ["84:94:59"]="TP-Link (Omada)"
    ["8C:86:DD"]="TP-Link"
    ["3C:6A:D2"]="TP-Link Systems"
    ["78:EE:4C"]="Espressif (IoT/ESP32)"
    ["08:8A:F1"]="Mercusys (TP-Link)"
    ["AC:1C:26"]="Unknown IoT"
    ["00:0C:29"]="VMware"
    ["00:50:56"]="VMware"
    ["DC:A6:32"]="Raspberry Pi"
    ["B8:27:EB"]="Raspberry Pi"
    ["44:19:B6"]="Hikvision"
    ["4C:BD:8F"]="Hikvision"
    ["54:C4:15"]="Hikvision"
    ["BC:AD:28"]="Hikvision"
    ["C0:56:E3"]="Hikvision"
    ["A4:14:37"]="Hikvision"
    ["18:68:CB"]="Hikvision"
    ["28:57:BE"]="Hikvision"
    ["10:12:FB"]="Hikvision"
    ["24:48:45"]="Hikvision"
    ["FC:7C:02"]="Dahua"
    ["3C:EF:8C"]="Dahua"
    ["40:16:9F"]="TP-Link"
    ["50:C7:BF"]="TP-Link"
    ["E8:48:B8"]="TP-Link"
    ["60:32:B1"]="TP-Link"
    ["AC:84:C6"]="TP-Link"
    ["30:DE:4B"]="TP-Link"
    ["B0:BE:76"]="TP-Link"
    ["F4:EC:38"]="Espressif"
    ["24:0A:C4"]="Espressif"
    ["24:6F:28"]="Espressif"
    ["30:AE:A4"]="Espressif"
    ["A4:CF:12"]="Espressif"
    ["CC:50:E3"]="Espressif"
    ["48:3F:DA"]="Espressif"
    ["7C:DF:A1"]="Espressif"
    ["94:B9:7E"]="Espressif"
    ["84:94:59"]="TP-Link (Omada)"
)

classify_device() {
    local vendor="$1"
    local ports="$2"
    case "$vendor" in
        *Hikvision*|*Dahua*)
            if echo "$ports" | grep -qE "554|8000"; then echo "📹 Camera/NVR"
            else echo "📹 Camera Infra"; fi ;;
        *Espressif*|*Tuya*)       echo "🚪 IoT Device" ;;
        *DrayTek*|*Cisco*|*Ubiquiti*|*MikroTik*)  echo "🌐 Gateway" ;;
        *Omada*|*Ruckus*|*Aruba*) echo "📡 Access Point" ;;
        *TP-Link*|*Mercusys*|*Tenda*|*Netgear*)
            if echo "$ports" | grep -qE "80|443"; then echo "🏠 Room Router"
            else echo "🏠 Network Device"; fi ;;
        *VMware*)   echo "🖥️  VM" ;;
        *Raspberry*) echo "🍓 RPi" ;;
        *Apple*)    echo "🍎 Apple" ;;
        *Samsung*|*Xiaomi*|*Huawei*) echo "📱 Mobile" ;;
        *Intel*|*Dell*|*HP*|*Lenovo*) echo "💻 Computer" ;;
        *local\ machine*) echo "💻 This Machine" ;;
        *)
            if echo "$ports" | grep -q "554"; then echo "📹 Camera (probable)"
            elif echo "$ports" | grep -qE "80|443"; then echo "🌐 Web Device"
            else echo "❓ Unknown"; fi ;;
    esac
}

lookup_vendor() {
    local mac="$1"
    local oui
    oui=$(echo "${mac:0:8}" | tr '[:lower:]' '[:upper:]')

    # Local DB first
    if [[ -n "${LOCAL_OUI[$oui]:-}" ]]; then
        echo "${LOCAL_OUI[$oui]}"
        return
    fi

    # API fallback
    local result
    result=$(curl -s --max-time 3 "https://api.macvendors.com/${mac}" 2>/dev/null || true)
    if [[ -n "$result" && "$result" != *"Not Found"* && "$result" != *"error"* && "$result" != *"Too Many"* ]]; then
        echo "${result:0:40}"
        sleep 1
        return
    fi

    echo "Unknown"
}

port_desc() {
    case "$1" in
        22) echo "SSH";;  23) echo "Telnet";;  53) echo "DNS";;
        80) echo "HTTP";; 443) echo "HTTPS";; 554) echo "RTSP";;
        1900) echo "UPnP";; 3389) echo "RDP";; 5000) echo "UPnP/NAS";;
        8080) echo "HTTP-Alt";; 8443) echo "HTTPS-Alt";;
        8888) echo "HTTP-Alt";; 9000) echo "Mgmt";; *) echo "";;
    esac
}

check_security() {
    local ports="$1" flags=""
    echo "$ports" | grep -q "\b23\b"   && flags+="⚠️ Telnet "
    echo "$ports" | grep -q "\b554\b"  && flags+="📹 RTSP "
    echo "$ports" | grep -q "\b1900\b" && flags+="⚠️ UPnP "
    echo "$ports" | grep -q "\b3389\b" && flags+="⚠️ RDP "
    echo "$flags"
}

# ── Header ──
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║               NetScan - Network Device Scanner             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Cần sudo để lấy MAC. Usage: sudo $0 [subnet]${NC}"
    exit 1
fi

# Check deps
for cmd in nmap curl; do
    command -v "$cmd" &>/dev/null || { echo -e "${RED}Missing: $cmd${NC}"; exit 1; }
done

# Auto-detect subnet
if [[ -z "$SUBNET" ]]; then
    gw=$(ip route | grep default | head -1 | awk '{print $3}')
    SUBNET="${gw%.*}.0/24"
fi
echo -e "  Subnet: ${BOLD}$SUBNET${NC}"
echo -e "  Ports:  ${DIM}$TOP_PORTS${NC}"
echo ""

# ═══════════════════════════════════
#  Phase 1: Host Discovery + MAC
# ═══════════════════════════════════
echo -e "${BOLD}[1/3] Discovering hosts...${NC}"
NMAP_DISCOVERY=$(nmap -sn "$SUBNET" 2>/dev/null)

declare -A HOSTS  # IP -> MAC
declare -A NAMES  # IP -> hostname

CURRENT_IP=""
while IFS= read -r line; do
    if [[ "$line" == *"Nmap scan report for"* ]]; then
        CURRENT_IP=$(echo "$line" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        name=$(echo "$line" | grep -oP 'for \K[^ ]+(?= \()' || true)
        [[ -n "$name" ]] && NAMES["$CURRENT_IP"]="$name"
        HOSTS["$CURRENT_IP"]=""
    fi
    if [[ "$line" == *"MAC Address:"* && -n "$CURRENT_IP" ]]; then
        mac=$(echo "$line" | grep -oP 'MAC Address: \K[0-9A-F:]+')
        HOSTS["$CURRENT_IP"]="$mac"
    fi
done <<< "$NMAP_DISCOVERY"

TOTAL=${#HOSTS[@]}
echo -e "  ${GREEN}Found $TOTAL hosts${NC}"
echo ""

# ═══════════════════════════════════
#  Phase 2: Port Scan
# ═══════════════════════════════════
echo -e "${BOLD}[2/3] Scanning ports...${NC}"
declare -A PORTS
CNT=0
for ip in $(printf '%s\n' "${!HOSTS[@]}" | sort -t. -k4 -n); do
    CNT=$((CNT + 1))
    printf "\r  [%d/%d] %-15s" "$CNT" "$TOTAL" "$ip"
    open=$(nmap -T4 --host-timeout 10s --open -p "$TOP_PORTS" "$ip" 2>/dev/null \
           | grep "^[0-9]" | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
    PORTS["$ip"]="${open:-none}"
done
echo -e "\r  ${GREEN}✓ Done                                    ${NC}"
echo ""

# ═══════════════════════════════════
#  Phase 3: Vendor Lookup
# ═══════════════════════════════════
echo -e "${BOLD}[3/3] Looking up vendors...${NC}"
declare -A VENDORS
CNT=0
for ip in $(printf '%s\n' "${!HOSTS[@]}" | sort -t. -k4 -n); do
    CNT=$((CNT + 1))
    mac="${HOSTS[$ip]}"
    if [[ -n "$mac" ]]; then
        printf "\r  [%d/%d] %-17s" "$CNT" "$TOTAL" "$mac"
        VENDORS["$ip"]=$(lookup_vendor "$mac")
    else
        VENDORS["$ip"]="(this machine)"
    fi
done
echo -e "\r  ${GREEN}✓ Done                                    ${NC}"
echo ""

# ═══════════════════════════════════
#  Results
# ═══════════════════════════════════
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESULTS${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# CSV header
echo "IP,MAC,Vendor,Type,Hostname,Open_Ports,Security" > "$CSV_FILE"

# Text report header
{
    echo "NetScan Report — $(date)"
    echo "Subnet: $SUBNET | Hosts: $TOTAL"
    echo "================================================"
    echo ""
} > "$REPORT_FILE"

for ip in $(printf '%s\n' "${!HOSTS[@]}" | sort -t. -k4 -n); do
    mac="${HOSTS[$ip]}"
    vendor="${VENDORS[$ip]}"
    ports="${PORTS[$ip]}"
    hostname="${NAMES[$ip]:-}"
    dtype=$(classify_device "$vendor" "$ports")
    sec=$(check_security "$ports")

    # Format ports with descriptions
    pdisplay=""
    if [[ "$ports" != "none" ]]; then
        IFS=',' read -ra PA <<< "$ports"
        for p in "${PA[@]}"; do
            d=$(port_desc "$p")
            [[ -n "$d" ]] && pdisplay+="${p}($d) " || pdisplay+="${p} "
        done
    else
        pdisplay="none"
    fi

    # Console
    echo -e "  ${BOLD}${GREEN}$ip${NC}  ${DIM}${mac:-N/A}${NC}"
    [[ -n "$hostname" ]] && echo -e "    hostname: $hostname"
    echo -e "    vendor:   ${YELLOW}$vendor${NC}"
    echo -e "    type:     $dtype"
    echo -e "    ports:    ${CYAN}$pdisplay${NC}"
    [[ -n "$sec" ]] && echo -e "    ${RED}$sec${NC}"
    echo ""

    # Text file
    printf "%-15s  %-17s  %-30s  %-20s  %s\n" "$ip" "${mac:-N/A}" "$vendor" "$dtype" "$pdisplay" >> "$REPORT_FILE"

    # CSV
    echo "\"$ip\",\"${mac:-N/A}\",\"$vendor\",\"$dtype\",\"$hostname\",\"$ports\",\"$sec\"" >> "$CSV_FILE"
done

# ── Summary ──
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SUMMARY${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}By vendor:${NC}"
declare -A VC
for ip in "${!VENDORS[@]}"; do
    v="${VENDORS[$ip]}"
    VC["$v"]=$(( ${VC["$v"]:-0} + 1 ))
done
for v in $(for k in "${!VC[@]}"; do printf '%d\t%s\n' "${VC[$k]}" "$k"; done | sort -rn | cut -f2-); do
    printf "    %-35s %d\n" "$v" "${VC[$v]}"
done

echo ""
echo -e "  ${BOLD}Security warnings:${NC}"
WCNT=0
for ip in "${!PORTS[@]}"; do
    s=$(check_security "${PORTS[$ip]}")
    if [[ -n "$s" ]]; then
        echo -e "    ${RED}$ip${NC}: $s"
        WCNT=$((WCNT + 1))
    fi
done
[[ $WCNT -eq 0 ]] && echo -e "    ${GREEN}No warnings${NC}"

echo ""
echo -e "  ${DIM}Saved: $REPORT_FILE / $CSV_FILE${NC}"
echo ""
