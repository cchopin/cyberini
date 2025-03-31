#!/bin/bash

set -e  # Stop en cas d’erreur
JOHN_DIR="/opt/john"

echo "[*] Installation des dépendances nécessaires..."
sudo apt update && sudo apt install -y \
    build-essential \
    libssl-dev \
    libz-dev \
    libbz2-dev \
    libpcap-dev \
    libnss3-dev \
    libkrb5-dev \
    libgmp-dev \
    git \
    yasm \
    pkg-config \
    python3

# Suppression propre si John est déjà présent
if [ -d "$JOHN_DIR" ]; then
    echo "[!] Une ancienne version de John a été trouvée à $JOHN_DIR"
    read -p "Souhaitez-vous la supprimer ? [o/N] " reponse
    if [[ "$reponse" =~ ^[Oo]$ ]]; then
        echo "[*] Suppression de l'ancienne version..."
        sudo rm -rf "$JOHN_DIR"
    else
        echo "[✘] Installation annulée. Supprimez manuellement $JOHN_DIR si besoin."
        exit 1
    fi
fi

echo "[*] Clonage de John the Ripper (jumbo)..."
sudo git clone https://github.com/openwall/john.git "$JOHN_DIR"
sudo chown -R "$USER:$USER" "$JOHN_DIR"

echo "[*] Compilation de John..."
cd "$JOHN_DIR/src"
./configure
make -sj"$(nproc)"

ZSHRC="$HOME/.zshrc"

echo "[*] Ajout des alias dans $ZSHRC (si absents)..."
if ! grep -q 'alias john=' "$ZSHRC"; then
    echo "alias john='$JOHN_DIR/run/john'" >> "$ZSHRC"
    echo "alias john2john='ls $JOHN_DIR/run/*2john.py'" >> "$ZSHRC"
    echo "[*] Aliases ajoutés à $ZSHRC."
else
    echo "[✓] Les alias semblent déjà présents dans $ZSHRC."
fi

echo "[*] Rechargement de Zsh..."
source "$ZSHRC"

echo -e "\n[✔] Installation de John the Ripper Jumbo terminée !"
echo "→ Tu peux utiliser la commande 'john' depuis n'importe où 🧠🔓"
