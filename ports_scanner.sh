#!/bin/bash

# Définition des couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Vérification que l'hôte est fourni
if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <host> [port]${NC}"
    echo "Example: $0 localhost"
    echo "Example: $0 localhost 80"
    exit 1
fi

# Récupération de l'hôte
HOST=$1

# Liste des ports par défaut avec leur service
declare -A PORT_SERVICES=(
    [80]="HTTP"
    [443]="HTTPS"
    [22]="SSH"
    [21]="FTP"
    [25]="SMTP"
    [53]="DNS"
    [3306]="MySQL"
    [3389]="RDP"
    [8080]="HTTP-ALT"
    [445]="SMB"
)

# Si un port est fourni en argument, on ne scanne que celui-là
if [ $# -eq 2 ]; then
    PORTS=($2)
else
    PORTS=(${!PORT_SERVICES[@]})
fi

# En-tête
echo -e "\n${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Port Scanner - Version 1.0          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo -e "\n${YELLOW}Target Host:${NC} $HOST"
echo -e "${YELLOW}Starting scan at:${NC} $(date)\n"
echo -e "${YELLOW}PORT\tSTATE\t\tSERVICE${NC}"
echo "─────────────────────────────────────────"

# Fonction de scan
scan_port() {
    local host=$1
    local port=$2
    local service=${PORT_SERVICES[$port]}
    if (echo >/dev/tcp/$host/$port) 2>/dev/null; then
        echo -e "${port}\t${GREEN}open\t\t${NC}${service}"
    else
        echo -e "${port}\t${RED}closed\t\t${NC}${service}"
    fi
}

# Boucle de scan
for PORT in "${PORTS[@]}"; do
    scan_port $HOST $PORT
done

# Pied de page
echo -e "\n${YELLOW}Scan completed at:${NC} $(date)"
