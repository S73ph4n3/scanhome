import socket
import subprocess
import platform
import threading
from queue import Queue
from tabulate import tabulate
import csv
import netifaces
from datetime import datetime
import argparse
import ipaddress

# Dictionnaire des ports bien connus avec leurs services associés
well_known_ports = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3389: "RDP"
}

# Fonction pour envoyer un ping à une adresse IP
def ping(ip, timeout=1):
    """
    Vérifie si une adresse IP répond au ping.
    Retourne True si l’hôte répond, False sinon.
    """
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

# Fonction pour scanner un port TCP sur une adresse IP
def scan_port(ip, port):
    """
    Vérifie si un port TCP est ouvert sur une adresse IP.
    Retourne True si le port est ouvert, False sinon.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

# Fonction pour résoudre le nom d’hôte d’une adresse IP
def get_hostname(ip):
    """
    Résout le nom d’hôte à partir d’une adresse IP.
    Retourne "Inconnu" si la résolution échoue.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Inconnu"

# Worker pour le ping sweep (découverte des hôtes actifs)
def worker_ping(queue, results):
    while not queue.empty():
        ip = queue.get()
        if ping(ip):
            results.append(ip)
        queue.task_done()

# Worker pour le scan des ports
def worker_scan_ports(ip, ports_queue, open_ports):
    while not ports_queue.empty():
        port = ports_queue.get()
        if scan_port(ip, port):
            open_ports.append(port)
        ports_queue.task_done()

# Obtenir le préfixe du réseau local
def get_local_network_prefix():
    """
    Détermine le préfixe du réseau local (ex. "192.168.1.").
    Retourne le préfixe trouvé ou lève une exception si aucun réseau local n’est détecté.
    """
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for addr in addresses[netifaces.AF_INET]:
                ip = addr['addr']
                if ip.startswith("192.168."):
                    return ".".join(ip.split(".")[:3]) + "."
    raise Exception("Aucun réseau en 192.168.x.x trouvé.")

# Fonction pour parser les exclusions (adresses IP ou plages)
def parse_exclusions(exclude_list):
    """
    Parse les exclusions et retourne un ensemble d’adresses IP à exclure.
    - Accepte des adresses IP (ex. "192.168.1.10") ou des plages (ex. "192.168.1.10-192.168.1.20").
    - Valide les entrées et génère les adresses à exclure.
    """
    excluded_ips = set()
    for exclude in exclude_list:
        if '-' in exclude:  # Cas d’une plage d’adresses IP
            start_ip, end_ip = exclude.split('-')
            try:
                start_ip = ipaddress.ip_address(start_ip.strip())
                end_ip = ipaddress.ip_address(end_ip.strip())
                if start_ip > end_ip:
                    raise ValueError(f"Plage invalide : {start_ip} > {end_ip}")
                current_ip = start_ip
                while current_ip <= end_ip:
                    excluded_ips.add(str(current_ip))
                    current_ip = int(current_ip) + 1
                    current_ip = ipaddress.ip_address(current_ip)
            except ValueError as e:
                print(f"Erreur : {e}")
                exit(1)
        else:  # Cas d’une seule adresse IP
            try:
                ip = ipaddress.ip_address(exclude.strip())
                excluded_ips.add(str(ip))
            except ValueError:
                print(f"Erreur : Adresse IP invalide : {exclude}")
                exit(1)
    return excluded_ips

# Fonction principale pour scanner le réseau
def scan_network(prefix, scan_option, specific_port=None, exclude_list=[]):
    """
    Orchestre le scan du réseau.
    - prefix : préfixe du réseau (ex. "192.168.1.")
    - scan_option : "common", "all", ou "specific"
    - specific_port : port à scanner si scan_option est "specific"
    - exclude_list : liste des adresses IP ou plages à exclure
    """
    # Parser les exclusions
    excluded_ips = parse_exclusions(exclude_list)
    print(f"Adresses exclues : {excluded_ips}")

    # Générer la liste des IP à scanner (1 à 254), en excluant celles spécifiées
    ips = [prefix + str(i) for i in range(1, 255) if prefix + str(i) not in excluded_ips]

    # File pour les IP à scanner
    queue = Queue()
    for ip in ips:
        queue.put(ip)

    # Liste des hôtes actifs
    active_hosts = []

    # Lancer les threads pour le ping sweep
    num_threads = 20
    for _ in range(num_threads):
        thread = threading.Thread(target=worker_ping, args=(queue, active_hosts))
        thread.start()
    queue.join()

    # Choix des ports à scanner
    if scan_option == "common":
        ports_to_scan = list(well_known_ports.keys())
    elif scan_option == "all":
        ports_to_scan = range(1, 65536)
    elif scan_option == "specific" and specific_port:
        ports_to_scan = [specific_port]
    else:
        raise ValueError("Option de scan invalide ou port non spécifié.")

    # Scanner les ports pour chaque hôte actif
    results = []
    for ip in active_hosts:
        hostname = get_hostname(ip)
        ports_queue = Queue()
        for port in ports_to_scan:
            ports_queue.put(port)
        open_ports = []
        num_port_threads = 10
        for _ in range(num_port_threads):
            thread = threading.Thread(target=worker_scan_ports, args=(ip, ports_queue, open_ports))
            thread.start()
        ports_queue.join()
        open_ports_with_services = [
            f"{port} ({well_known_ports.get(port, 'Inconnu')})" for port in sorted(open_ports)
        ]
        open_ports_str = ", ".join(open_ports_with_services) if open_ports else "Aucun"
        results.append([ip, hostname, open_ports_str])

    # Afficher les résultats
    print("\nRésultats du scan :")
    print(tabulate(results, headers=["Adresse IP", "Nom d’hôte", "Ports ouverts"], tablefmt="grid"))

    # Générer un nom de fichier avec timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = f"resultats_scan_{timestamp}.csv"
    txt_file = f"resultats_scan_{timestamp}.txt"

    # Enregistrer les résultats dans un fichier CSV
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Adresse IP", "Nom d’hôte", "Ports ouverts"])
        writer.writerows(results)

    # Enregistrer les résultats dans un fichier texte
    with open(txt_file, 'w') as f:
        f.write("Résultats du scan\n")
        f.write(f"Réseau scanné : {prefix}1-254 (exclusions : {', '.join(exclude_list)})\n")
        f.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(tabulate(results, headers=["Adresse IP", "Nom d’hôte", "Ports ouverts"], tablefmt="grid"))

    print(f"\nRésultats enregistrés dans '{csv_file}' et '{txt_file}'.")

# Gestion des arguments en ligne de commande
def main():
    parser = argparse.ArgumentParser(description="Scanner de réseau local")
    parser.add_argument("--scan", choices=["common", "all", "specific"], default="common",
                        help="Type de scan : common (ports courants), all (tous les ports), specific (port spécifique)")
    parser.add_argument("--port", type=int, help="Port spécifique (requis si --scan=specific)")
    parser.add_argument("--exclude", action="append", default=[],
                        help="Adresses IP ou plages à exclure (ex. 192.168.1.10 ou 192.168.1.10-192.168.1.20)")
    args = parser.parse_args()

    if args.scan == "specific" and args.port is None:
        print("Erreur : spécifiez un port avec --port pour --scan=specific.")
        return

    prefix = get_local_network_prefix()
    scan_network(prefix, args.scan, args.port, args.exclude)

if __name__ == "__main__":
    main()
