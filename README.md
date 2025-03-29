
## English
Local Network Scanner - Python Script <br>
This Python script is designed to scan a local network (e.g., 192.168.1.0/24) to discover active hosts and identify open TCP ports. It uses multi-threading for efficient scanning and supports various options for flexibility. <br>
How It Works<br>
Host Discovery: Performs a ping sweep to identify active IP addresses within the local network range (1-254).<br>
Port Scanning: Scans specified TCP ports on active hosts to determine which ones are open.<br>
Hostname Resolution: Attempts to resolve the hostname for each active IP address.<br>
Output: Displays results in a tabulated format and saves them to both a CSV file and a text file with a timestamp (e.g., resultats_scan_20250329_123456.csv).<br>
Features<br>
Ping Sweep: Uses ICMP ping to detect live hosts.<br>
Port Options:
###common: Scans well-known ports (e.g., 21, 22, 80, 443, etc.).<br>
all: Scans all ports from 1 to 65535.<br>
specific: Scans a user-defined port.<br>
Exclusions: Allows excluding specific IP addresses or ranges (e.g., 192.168.1.10 or 192.168.1.10-192.168.1.20).<br>
Multi-threading: Speeds up scanning with concurrent threads for pinging and port scanning.<br>
Service Mapping: Maps open ports to common services (e.g., 80 → HTTP).<br>
Usage<br>
Run the script with command-line arguments:<br>
bash<br>
python script.py --scan [common|all|specific] --port PORT --exclude IP_OR_RANGE<br>
--scan: Type of scan (default: common).<br>
--port: Specific port to scan (required for --scan=specific).<br>
--exclude: IPs or ranges to exclude (can be used multiple times).<br>
Example<br>
Scan common ports, excluding an IP:<br>
bash<br>
python script.py --scan common --exclude 192.168.1.100<br>
Scan a specific port:<br>
bash<br>
python script.py --scan specific --port 8080<br>
Requirements<br>
Python 3.x<br>
Modules: socket, subprocess, platform, threading, queue, tabulate, csv, netifaces, datetime, argparse, ipaddress<br>
## Français
Scanner de Réseau Local - Script Python<br>
Ce script Python est conçu pour scanner un réseau local (par exemple, 192.168.1.0/24) afin de découvrir les hôtes actifs et identifier les ports TCP ouverts. Il utilise le multi-threading pour un scan efficace et offre plusieurs options pour une utilisation flexible.<br>
Fonctionnement<br>
Découverte des Hôtes : Effectue un balayage par ping pour identifier les adresses IP actives dans la plage du réseau local (1-254).<br>
Scan des Ports : Vérifie les ports TCP spécifiés sur les hôtes actifs pour déterminer lesquels sont ouverts.<br>
Résolution des Noms d’Hôte : Tente de résoudre le nom d’hôte pour chaque adresse IP active.<br>
Sortie : Affiche les résultats sous forme de tableau et les enregistre dans un fichier CSV et un fichier texte avec un horodatage (par exemple, resultats_scan_20250329_123456.csv).<br>
Fonctionnalités<br>
Balayage Ping : Utilise ICMP ping pour détecter les hôtes actifs.<br>
Options de Ports : <br>
common : Scanne les ports bien connus (par exemple, 21, 22, 80, 443, etc.).<br>
all : Scanne tous les ports de 1 à 65535.<br>
specific : Scanne un port spécifié par l’utilisateur.<br>
Exclusions : Permet d’exclure des adresses IP ou des plages spécifiques (par exemple, 192.168.1.10 ou 192.168.1.10-192.168.1.20). <br>
Multi-threading : Accélère le scan avec des threads simultanés pour le ping et le scan des ports.<br>
Mappage des Services : Associe les ports ouverts à des services courants (par exemple, 80 → HTTP).<br>
Utilisation<br>
Exécutez le script avec des arguments en ligne de commande :<br>
bash<br>
python script.py --scan [common|all|specific] --port PORT --exclude IP_OU_PLAGE<br>
--scan : Type de scan (par défaut : common).<br>
--port : Port spécifique à scanner (requis pour --scan=specific).<br>
--exclude : IPs ou plages à exclure (peut être utilisé plusieurs fois).<br>
Exemple<br>
Scanner les ports courants en excluant une IP :<br>
bash<br>
<h3>python script.py --scan common --exclude 192.168.1.100<br>
Scanner un port spécifique :<br>
bash<br>
python script.py --scan specific --port 8080<br>
Prérequis<br>
Python 3.x<br>
Modules : socket, subprocess, platform, threading, queue, tabulate, csv, netifaces, datetime, argparse, ipaddress<br>

