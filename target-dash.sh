#!/bin/bash

# Colors for display
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Target information
TARGET_IP="10.10.222.240"
PORTS_FILE="/tmp/target_known_ports.txt"
UPDATE_INTERVAL=5  # Update interval in seconds

# Static line positions
HEADER_LINE=1
STATUS_LINE=4
INFO_LINE=5 
PORTS_LINE=7
MENU_LINE=11
CHOICE_LINE=16
FEEDBACK_LINE=17
DATE_LINE=18

# Create the ports file if it doesn't exist
if [ ! -f "$PORTS_FILE" ]; then
    # Create empty ports file
    touch "$PORTS_FILE"
fi

# Store current terminal state to restore at exit
cleanup() {
    tput cnorm  # Show cursor
    echo -e "\n${BLUE}[*] Exiting dashboard...${NC}"
    exit 0
}
trap cleanup EXIT

# Function to center text
center_text() {
    local text="$1"
    local width=$(tput cols)
    local padding=$(( (width - ${#text}) / 2 ))
    printf "%${padding}s" '' 
    printf "%s\n" "$text"
}

# Draw fancy header at specific position
draw_header() {
    tput cup $HEADER_LINE 0
    printf "${PURPLE}"
    center_text "╔═══════════════════════════════════════════════════════════════╗"
    center_text "║                      TARGET DASHBOARD                         ║"
    center_text "╚═══════════════════════════════════════════════════════════════╝"
    printf "${NC}"
}

# Function to check if target is online
check_target() {
    # Position cursor at status line
    tput cup $STATUS_LINE 0
    tput el  # Clear line
    
    if ping -c 1 -W 1000 $TARGET_IP 2>/dev/null | grep -q "64 bytes from"; then
        printf "${GREEN}[✓] Target $TARGET_IP is ONLINE${NC}"
        status=0
    else
        printf "${RED}[✗] Target $TARGET_IP is OFFLINE${NC}"
        status=1
    fi
    
    return $status
}

# Display target information
display_info() {
    # Position cursor
    tput cup $INFO_LINE 0
    tput el  # Clear line
    printf "${BLUE}[*] TARGET INFORMATION:${NC}"
    
    # Position cursor for IP
    tput cup $((INFO_LINE + 1)) 0
    tput el  # Clear line
    printf "${YELLOW}[+] IP Address:${NC} $TARGET_IP"
    
    # Position cursor for ports header
    tput cup $PORTS_LINE 0
    tput el  # Clear line
    printf "${YELLOW}[+] Open Ports:${NC}"
    
    # Display known ports
    local line_offset=1
    if [ -s "$PORTS_FILE" ]; then
        cat "$PORTS_FILE" | while read line
        do
            tput cup $((PORTS_LINE + line_offset)) 0
            tput el  # Clear line
            port=$(echo "$line" | awk '{print $1}')
            service=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ *//')
            printf "    ${CYAN}➤ $port${NC} - $service"
            line_offset=$((line_offset + 1))
        done
    else
        tput cup $((PORTS_LINE + line_offset)) 0
        tput el  # Clear line
        printf "    No ports discovered yet"
    fi
}

# Function to scan a single port
scan_port() {
    local port=$1
    
    # Clear the feedback area first
    tput cup $FEEDBACK_LINE 0
    tput el  # Clear line
    printf "${YELLOW}[*] Scanning port $port...${NC}"
    
    # Check if port is already in the list
    if grep -q "^$port/tcp" "$PORTS_FILE" 2>/dev/null; then
        tput cup $((FEEDBACK_LINE + 1)) 0
        tput el  # Clear line
        printf "${BLUE}[i] Port $port already in the database${NC}"
        sleep 2
        # Clear the message
        tput cup $((FEEDBACK_LINE + 1)) 0
        tput el
        return 0
    fi
    
    # Scan the port using nmap with service detection
    local temp_file="/tmp/nmap_scan_$$.txt"
    nmap -Pn -p $port -sV --version-intensity 1 $TARGET_IP > "$temp_file"
    
    # Extract the result
    local result=$(grep -E "^$port/tcp" "$temp_file")
    
    # Check if port is open
    tput cup $((FEEDBACK_LINE + 1)) 0
    tput el  # Clear line
    
    if [ -n "$result" ] && ! echo "$result" | grep -q "closed"; then
        printf "${GREEN}[+] Port $port is OPEN: $result${NC}"
        echo "$result" >> "$PORTS_FILE"
        # Update the ports display
        display_info
        sleep 2
    else
        printf "${RED}[✗] Port $port is CLOSED${NC}"
        sleep 2
    fi
    
    # Clear messages
    tput cup $FEEDBACK_LINE 0
    tput el  # Clear line
    tput cup $((FEEDBACK_LINE + 1)) 0
    tput el  # Clear line
    
    # Clean up
    rm -f "$temp_file"
}

# Function to scan multiple ports
scan_port_range() {
    local range=$1
    
    # Clear the feedback area first
    tput cup $FEEDBACK_LINE 0
    tput el  # Clear line
    printf "${YELLOW}[*] Scanning port range $range...${NC}"
    
    # Scan the port range using nmap with service detection
    local temp_file="/tmp/nmap_scan_$$.txt"
    tput cup $((FEEDBACK_LINE + 1)) 0
    tput el  # Clear line
    printf "${YELLOW}[*] Running nmap scan (this may take a moment)...${NC}"
    
    nmap -Pn -p $range -sV --version-intensity 1 $TARGET_IP > "$temp_file"
    
    # Extract open ports and add them to the database
    local open_ports=$(grep -E "^[0-9]+/tcp" "$temp_file" | grep -v "closed" | grep -v "filtered")
    
    # Clear feedback area
    tput cup $FEEDBACK_LINE 0
    tput el  # Clear line
    tput cup $((FEEDBACK_LINE + 1)) 0
    tput el  # Clear line
    
    if [ -n "$open_ports" ]; then
        tput cup $FEEDBACK_LINE 0
        printf "${GREEN}[+] Found open ports:${NC}"
        
        local port_count=0
        echo "$open_ports" | while read line; do
            local port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
            port_count=$((port_count + 1))
            
            tput cup $((FEEDBACK_LINE + port_count)) 0
            tput el  # Clear line
            printf "${CYAN}    ➤ $line${NC}"
            
            # Check if port is already in the list before adding
            if ! grep -q "^$port/tcp" "$PORTS_FILE" 2>/dev/null; then
                echo "$line" >> "$PORTS_FILE"
            fi
        done
        
        # Update the ports display
        display_info
        sleep 3
    else
        tput cup $FEEDBACK_LINE 0
        tput el  # Clear line
        printf "${RED}[✗] No open ports found in range $range${NC}"
        sleep 3
    fi
    
    # Clear all feedback messages
    for i in $(seq 0 5); do
        tput cup $((FEEDBACK_LINE + i)) 0
        tput el  # Clear line
    done
    
    # Clean up
    rm -f "$temp_file"
}

# Display interactive menu
display_menu() {
    # Position cursor at menu line
    tput cup $MENU_LINE 0
    printf "${WHITE}=== COMMANDS ====${NC}"
    
    tput cup $((MENU_LINE + 1)) 0
    printf "${WHITE}[p]${NC} - Scan a specific port"
    
    tput cup $((MENU_LINE + 2)) 0
    printf "${WHITE}[r]${NC} - Scan a port range"
    
    tput cup $((MENU_LINE + 3)) 0
    printf "${WHITE}[c]${NC} - Clear screen (full refresh)"
    
    tput cup $((MENU_LINE + 4)) 0
    printf "${WHITE}[q]${NC} - Quit"
    
    tput cup $((MENU_LINE + 5)) 0
    printf "${WHITE}Choice:${NC} "
}

# Function to update timestamp
update_timestamp() {
    tput cup $DATE_LINE 0
    tput el  # Clear line
    printf "${YELLOW}[*] Last updated:${NC} $(date '+%Y-%m-%d %H:%M:%S')"
}

# Initial dashboard setup
initial_display() {
    clear
    tput civis  # Hide cursor
    
    # Draw all static elements
    draw_header
    check_target
    display_info
    display_menu
    update_timestamp
}

# Main dashboard loop
while true; do
    # First time or after clear command, do full display
    if [ -z "$LAST_UPDATE" ]; then
        initial_display
        LAST_UPDATE=$(date '+%Y-%m-%d %H:%M:%S')
    else
        # Just update the status line and timestamp
        check_target
        update_timestamp
    fi
    
    # Position cursor at choice input
    tput cup $CHOICE_LINE 0
    tput el
    echo -n -e "${WHITE}Choice:${NC} "
    
    # Read user input with timeout
    read -t $UPDATE_INTERVAL choice || true
    
    # Process user input
    case "$choice" in
        p|P)
            tput cup $CHOICE_LINE 0
            tput el  # Clear line
            echo -n -e "Enter port number to scan: "
            read port_num
            
            if [[ $port_num =~ ^[0-9]+$ ]]; then
                scan_port $port_num
            else
                tput cup $FEEDBACK_LINE 0
                tput el  # Clear line
                printf "${RED}[!] Invalid port number${NC}"
                sleep 2
                tput cup $FEEDBACK_LINE 0
                tput el  # Clear line
            fi
            ;;
        r|R)
            tput cup $CHOICE_LINE 0
            tput el  # Clear line
            echo -n -e "Enter port range (e.g., 20-25 or 80,443): "
            read port_range
            
            if [[ $port_range =~ ^[0-9,\-]+$ ]]; then
                scan_port_range $port_range
            else
                tput cup $FEEDBACK_LINE 0
                tput el  # Clear line
                printf "${RED}[!] Invalid port range${NC}"
                sleep 2
                tput cup $FEEDBACK_LINE 0
                tput el  # Clear line
            fi
            ;;
        c|C)
            # Full screen refresh
            LAST_UPDATE=""  # Reset to trigger full redraw
            ;;
        q|Q)
            # Will trigger the cleanup function via trap
            exit 0
            ;;
        "")
            # Silent timeout refresh
            ;;
        *)
            tput cup $FEEDBACK_LINE 0
            tput el  # Clear line
            printf "${RED}[!] Invalid choice${NC}"
            sleep 1
            tput cup $FEEDBACK_LINE 0
            tput el  # Clear line
            ;;
    esac
done
