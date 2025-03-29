
## English
Local Network Scanner - Python Script
This Python script is designed to scan a local network (e.g., 192.168.1.0/24) to discover active hosts and identify open TCP ports. It uses multi-threading for efficient scanning and supports various options for flexibility.
How It Works
Host Discovery: Performs a ping sweep to identify active IP addresses within the local network range (1-254).
Port Scanning: Scans specified TCP ports on active hosts to determine which ones are open.
Hostname Resolution: Attempts to resolve the hostname for each active IP address.
Output: Displays results in a tabulated format and saves them to both a CSV file and a text file with a timestamp (e.g., resultats_scan_20250329_123456.csv).
Features
Ping Sweep: Uses ICMP ping to detect live hosts.
Port Options:
###common: Scans well-known ports (e.g., 21, 22, 80, 443, etc.).
all: Scans all ports from 1 to 65535.
specific: Scans a user-defined port.
Exclusions: Allows excluding specific IP addresses or ranges (e.g., 192.168.1.10 or 192.168.1.10-192.168.1.20).
Multi-threading: Speeds up scanning with concurrent threads for pinging and port scanning.
Service Mapping: Maps open ports to common services (e.g., 80 → HTTP).
Usage
Run the script with command-line arguments:
bash
python script.py --scan [common|all|specific] --port PORT --exclude IP_OR_RANGE
--scan: Type of scan (default: common).
--port: Specific port to scan (required for --scan=specific).
--exclude: IPs or ranges to exclude (can be used multiple times).
Example
Scan common ports, excluding an IP:
bash
python script.py --scan common --exclude 192.168.1.100
Scan a specific port:
bash
python script.py --scan specific --port 8080
Requirements
Python 3.x
Modules: socket, subprocess, platform, threading, queue, tabulate, csv, netifaces, datetime, argparse, ipaddress
## Français
Scanner de Réseau Local - Script Python
Ce script Python est conçu pour scanner un réseau local (par exemple, 192.168.1.0/24) afin de découvrir les hôtes actifs et identifier les ports TCP ouverts. Il utilise le multi-threading pour un scan efficace et offre plusieurs options pour une utilisation flexible.
Fonctionnement
Découverte des Hôtes : Effectue un balayage par ping pour identifier les adresses IP actives dans la plage du réseau local (1-254).
Scan des Ports : Vérifie les ports TCP spécifiés sur les hôtes actifs pour déterminer lesquels sont ouverts.
Résolution des Noms d’Hôte : Tente de résoudre le nom d’hôte pour chaque adresse IP active.
Sortie : Affiche les résultats sous forme de tableau et les enregistre dans un fichier CSV et un fichier texte avec un horodatage (par exemple, resultats_scan_20250329_123456.csv).
Fonctionnalités
Balayage Ping : Utilise ICMP ping pour détecter les hôtes actifs.
Options de Ports :
common : Scanne les ports bien connus (par exemple, 21, 22, 80, 443, etc.).
all : Scanne tous les ports de 1 à 65535.
specific : Scanne un port spécifié par l’utilisateur.
Exclusions : Permet d’exclure des adresses IP ou des plages spécifiques (par exemple, 192.168.1.10 ou 192.168.1.10-192.168.1.20).
Multi-threading : Accélère le scan avec des threads simultanés pour le ping et le scan des ports.
Mappage des Services : Associe les ports ouverts à des services courants (par exemple, 80 → HTTP).
Utilisation
Exécutez le script avec des arguments en ligne de commande :
bash
python script.py --scan [common|all|specific] --port PORT --exclude IP_OU_PLAGE
--scan : Type de scan (par défaut : common).
--port : Port spécifique à scanner (requis pour --scan=specific).
--exclude : IPs ou plages à exclure (peut être utilisé plusieurs fois).
Exemple
Scanner les ports courants en excluant une IP :
bash
python script.py --scan common --exclude 192.168.1.100
Scanner un port spécifique :
bash
python script.py --scan specific --port 8080
Prérequis
Python 3.x
Modules : socket, subprocess, platform, threading, queue, tabulate, csv, netifaces, datetime, argparse, ipaddress
Vous pouvez copier ces sections directement dans votre README.md pour fournir une documentation claire et concise à vos utilisateurs !
