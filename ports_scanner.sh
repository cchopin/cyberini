#!/bin/bash
# Définition des couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration timeout
TIMEOUT=${TIMEOUT:-1}  # 1 seconde par défaut

# Vérification que l'hôte est fourni
if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <host> [port]${NC}"
    echo "Example: $0 localhost"
    echo "Example: $0 localhost 80"
    exit 1
fi

# Récupération de l'hôte
HOST=$1

# Liste des ports et services (version compatible macOS)
PORTS_DEFAULT="80 443 22 21 25 53 3306 3389 8080 445"
get_service() {
    case $1 in
        80) echo "HTTP";;
        443) echo "HTTPS";;
        22) echo "SSH";;
        21) echo "FTP";;
        25) echo "SMTP";;
        53) echo "DNS";;
        3306) echo "MySQL";;
        3389) echo "RDP";;
        8080) echo "HTTP-ALT";;
        445) echo "SMB";;
        *) echo "Unknown";;
    esac
}

# Si un port est fourni en argument, on ne scanne que celui-là
if [ $# -eq 2 ]; then
    PORTS=$2
else
    PORTS=$PORTS_DEFAULT
fi

# En-tête
echo -e "\n${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Port Scanner - Version 1.0         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo -e "\n${YELLOW}Target Host:${NC} $HOST"
echo -e "${YELLOW}Timeout:${NC} $TIMEOUT seconds"
echo -e "${YELLOW}Starting scan at:${NC} $(date)\n"
echo -e "${YELLOW}PORT\tSTATE\t\tSERVICE${NC}"
echo "─────────────────────────────────────────"

# Fonction de scan compatible macOS
scan_port() {
    local host=$1
    local port=$2
    local service=$(get_service $port)
    
    # Version compatible macOS avec timeout
    (echo >/dev/tcp/$host/$port) 2>/dev/null &
    local pid=$!
    
    # Attente avec timeout
    local count=0
    local interval=0.1
    while [ $count -lt $(echo "$TIMEOUT/0.1" | bc) ] && kill -0 $pid 2>/dev/null; do
        sleep $interval
        count=$((count + 1))
    done
    
    if kill -0 $pid 2>/dev/null; then
        kill $pid 2>/dev/null
        echo -e "${port}\t${RED}closed\t\t${NC}${service}"
    else
        wait $pid
        if [ $? -eq 0 ]; then
            echo -e "${port}\t${GREEN}open\t\t${NC}${service}"
        else
            echo -e "${port}\t${RED}closed\t\t${NC}${service}"
        fi
    fi
}

# Boucle de scan
for PORT in $PORTS; do
    scan_port $HOST $PORT
done

# Pied de page
echo -e "\n${YELLOW}Scan completed at:${NC} $(date)"
