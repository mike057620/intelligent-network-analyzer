"""
INTELLIGENT NETWORK ANALYZER
Analyseur réseau intelligent - Sprint Python 3

Objectif :
- Détecter les informations réseau de la machine
- Préparer l'analyse des paquets réseau avec Scapy
"""

import socket
import platform
import ipaddress
from datetime import datetime
from scapy.all import get_if_list
from scapy.all import sniff
from scapy.all import IP, IPv6, TCP, UDP, ICMP
from collections import Counter


def afficher_entete():
    """Affiche l'en-tête de l'application."""
    print("=" * 60)
    print("           INTELLIGENT NETWORK ANALYZER")
    print("=" * 60)
    print()


def obtenir_adresses_locales():
    """
    Récupère les adresses IP locales détectées sur la machine.
    """
    adresses = set()

    try:
        nom_machine = socket.gethostname()

        # Récupération des adresses IPv4 associées au nom de la machine
        for adresse in socket.gethostbyname_ex(nom_machine)[2]:
            if adresse and not adresse.startswith("127."):
                adresses.add(adresse)

    except socket.error:
        pass

    return sorted(adresses)


def afficher_informations_systeme():
    """Affiche quelques informations sur la machine."""
    print("Informations système")
    print("-" * 30)
    print(f"Système : {platform.system()} {platform.release()}")
    print(f"Machine : {platform.machine()}")
    print(f"Nom réseau : {socket.gethostname()}")
    print(f"Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def afficher_adresses():
    """Affiche les adresses IP locales détectées."""
    adresses = obtenir_adresses_locales()

    print("Adresses locales détectées")
    print("-" * 30)

    if not adresses:
        print("  Aucune adresse IPv4 détectée.")
    else:
        for adresse in adresses:
            print(f"  - {adresse}")

    print()

def capturer_paquets(duree=10):
    """Capture et analyse les paquets réseau."""

    print("Capture réseau")
    print("-" * 30)
    print(f"Capture pendant {duree} secondes...")
    print("Génère un peu de trafic : ouvre une page web ou fais un ping.")
    print()

    try:
        paquets = sniff(timeout=duree)

        print(f"Capture terminée : {len(paquets)} paquet(s) détecté(s).")
        print()

        print("Analyse des paquets")
        print("-" * 100)

        for numero, paquet in enumerate(paquets[:20], start=1):

            infos = analyser_paquet(paquet)

            print(
                f"{numero:>3} | "
                f"{infos['source']}:{infos['port_source']} → "
                f"{infos['destination']}:{infos['port_destination']} | "
                f"{infos['protocole']:<10} | "
                f"{infos['taille']:>5} octets"
            )

        if len(paquets) > 20:
            print()
            print(f"... {len(paquets) - 20} autre(s) paquet(s) non affiché(s).")

            afficher_statistiques(paquets)
            analyser_securite(paquets)

    except Exception as erreur:
        print(f"Erreur pendant la capture : {erreur}")

    print()


def analyser_paquet(paquet):
    """
    Extrait les informations importantes d'un paquet réseau.
    Fonctionne avec IPv4 et IPv6.
    """

    source = "Inconnue"
    destination = "Inconnue"
    protocole = "Autre"
    port_source = "-"
    port_destination = "-"

    # Analyse IPv4
    if paquet.haslayer(IP):
        couche_ip = paquet[IP]
        source = couche_ip.src
        destination = couche_ip.dst

        if paquet.haslayer(TCP):
            protocole = "TCP"
            port_source = paquet[TCP].sport
            port_destination = paquet[TCP].dport

        elif paquet.haslayer(UDP):
            protocole = "UDP"
            port_source = paquet[UDP].sport
            port_destination = paquet[UDP].dport

        elif paquet.haslayer(ICMP):
            protocole = "ICMP"

        else:
            protocole = f"IPv4/{couche_ip.proto}"

    # Analyse IPv6
    elif paquet.haslayer(IPv6):
        couche_ip = paquet[IPv6]
        source = couche_ip.src
        destination = couche_ip.dst

        if paquet.haslayer(TCP):
            protocole = "TCP"
            port_source = paquet[TCP].sport
            port_destination = paquet[TCP].dport

        elif paquet.haslayer(UDP):
            protocole = "UDP"
            port_source = paquet[UDP].sport
            port_destination = paquet[UDP].dport

        else:
            protocole = f"IPv6/{couche_ip.nh}"

    return {
        "source": source,
        "destination": destination,
        "protocole": protocole,
        "port_source": port_source,
        "port_destination": port_destination,
        "taille": len(paquet),
    }


def nom_service(port):
        """
        Retourne le nom d'un service réseau connu.
        """

        services = {
            20: "FTP-DATA",
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            587: "SMTP",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5353: "mDNS",
            8080: "HTTP-ALT",
        }

        return services.get(port, "Port dynamique/inconnu")

def analyser_securite(paquets):
    """
    Analyse le trafic réseau et sépare :
    - les observations normales ;
    - les anomalies ;
    - les menaces potentielles.

    La détection des scans repose principalement sur les SYN TCP.
    """

    score = 0

    observations = []
    anomalies = []
    menaces = []

    ports_detectes = Counter()
    destinations = Counter()

    # (source, destination) -> ports ciblés par des SYN
    syn_ports_par_connexion = {}

    # (source, destination) -> nombre de SYN
    syn_par_connexion = {}

    # Services réseau connus.
    # Leur présence seule n'est PAS une menace.
    services_connus = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
    }

    # =========================================================
    # 1. ANALYSE DES PAQUETS
    # =========================================================

    for paquet in paquets:

        source = None
        destination = None

        # -----------------------------------------------------
        # IPv4
        # -----------------------------------------------------

        if paquet.haslayer(IP):

            source = paquet[IP].src
            destination = paquet[IP].dst

        # -----------------------------------------------------
        # IPv6
        # -----------------------------------------------------

        elif paquet.haslayer(IPv6):

            source = paquet[IPv6].src
            destination = paquet[IPv6].dst

        if not source or not destination:
            continue

        destinations[destination] += 1

        # -----------------------------------------------------
        # TCP
        # -----------------------------------------------------

        if paquet.haslayer(TCP):

            port_source = paquet[TCP].sport
            port_destination = paquet[TCP].dport

            ports_detectes[port_source] += 1
            ports_detectes[port_destination] += 1

            flags = int(paquet[TCP].flags)

            # SYN sans ACK = tentative initiale de connexion
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)

            if syn and not ack:

                cle = (source, destination)

                if cle not in syn_ports_par_connexion:
                    syn_ports_par_connexion[cle] = set()

                if cle not in syn_par_connexion:
                    syn_par_connexion[cle] = 0

                syn_ports_par_connexion[cle].add(
                    port_destination
                )

                syn_par_connexion[cle] += 1

        # -----------------------------------------------------
        # UDP
        # -----------------------------------------------------

        elif paquet.haslayer(UDP):

            port_source = paquet[UDP].sport
            port_destination = paquet[UDP].dport

            ports_detectes[port_source] += 1
            ports_detectes[port_destination] += 1

    # =========================================================
    # 2. OBSERVATIONS DU TRAFIC
    # =========================================================

    total_paquets = len(paquets)

    observations.append(
        f"{total_paquets} paquet(s) réseau analysé(s)"
    )

    observations.append(
        f"{len(ports_detectes)} port(s) différents observés"
    )

    observations.append(
        f"{len(destinations)} destination(s) observée(s)"
    )

    # Services courants observés
    services_observes = []

    for port, nom in services_connus.items():

        if port in ports_detectes:

            services_observes.append(
                f"{nom} ({port})"
            )

    if services_observes:

        observations.append(
            "Services réseau observés : "
            + ", ".join(services_observes)
        )

    # =========================================================
    # 3. DÉTECTION DES SCANS TCP
    # =========================================================

    scans_detectes = []

    for (source, destination), ports in syn_ports_par_connexion.items():

        nombre_ports = len(ports)
        nombre_syn = syn_par_connexion[(source, destination)]

        if nombre_ports < 10:
            continue

        # Vérification IPv6 link-local
        try:

            source_ip = ipaddress.ip_address(source)
            destination_ip = ipaddress.ip_address(destination)

            trafic_link_local = (
                source_ip.is_link_local
                and destination_ip.is_link_local
            )

        except ValueError:

            trafic_link_local = False

        # Un grand nombre de ports link-local peut correspondre
        # à du fonctionnement normal du réseau local.
        if trafic_link_local:

            if nombre_ports >= 20:

                scans_detectes.append(
                    (
                        source,
                        destination,
                        nombre_ports,
                        nombre_syn,
                        "faible"
                    )
                )

        else:

            scans_detectes.append(
                (
                    source,
                    destination,
                    nombre_ports,
                    nombre_syn,
                    "normale"
                )
            )

    # =========================================================
    # 4. CLASSIFICATION DES SCANS
    # =========================================================

    for (
        source,
        destination,
        nombre_ports,
        nombre_syn,
        confiance
    ) in scans_detectes:

        ports = sorted(
            syn_ports_par_connexion[
                (source, destination)
            ]
        )

        apercu_ports = ", ".join(
            str(port)
            for port in ports[:15]
        )

        if len(ports) > 15:
            apercu_ports += ", ..."

        # -----------------------------------------------------
        # Trafic local IPv6
        # -----------------------------------------------------

        if confiance == "faible":

            anomalies.append(
                f"Activité locale inhabituelle : "
                f"{source} → {destination} | "
                f"{nombre_ports} ports ciblés"
            )

            score += 5

        # -----------------------------------------------------
        # Scan massif
        # -----------------------------------------------------

        elif nombre_ports >= 50:

            menaces.append(
                f"Scan de ports fortement suspect : "
                f"{source} → {destination} | "
                f"{nombre_ports} ports ciblés"
            )

            score += 50

        # -----------------------------------------------------
        # Scan probable
        # -----------------------------------------------------

        elif nombre_ports >= 20:

            menaces.append(
                f"Scan de ports probable : "
                f"{source} → {destination} | "
                f"{nombre_ports} ports ciblés"
            )

            score += 35

        # -----------------------------------------------------
        # Scan potentiel
        # -----------------------------------------------------

        else:

            anomalies.append(
                f"Scan de ports potentiel : "
                f"{source} → {destination} | "
                f"{nombre_ports} ports ciblés"
            )

            score += 20

        # -----------------------------------------------------
        # Services sensibles ciblés
        # -----------------------------------------------------

        services_cibles = [
            port
            for port in ports
            if port in services_connus
        ]

        services_cibles = set(services_cibles)

        if len(services_cibles) >= 3:

            menaces.append(
                f"Plusieurs services connus ciblés "
                f"({len(services_cibles)}) par "
                f"{source}"
            )

            score += 10

    # =========================================================
    # 5. GRANDE DIVERSITÉ DE PORTS
    # =========================================================

    ports_uniques = len(ports_detectes)

    # Une grande diversité de ports n'est PAS suffisante
    # pour parler d'un scan.
    if ports_uniques >= 100:

        anomalies.append(
            f"Grande diversité de ports observés : "
            f"{ports_uniques}"
        )

        score += 5

    # =========================================================
    # 6. NOMBRE IMPORTANT DE DESTINATIONS
    # =========================================================

    destinations_uniques = len(destinations)

    if destinations_uniques >= 100:

        anomalies.append(
            f"Nombre très élevé de destinations : "
            f"{destinations_uniques}"
        )

        score += 20

    elif destinations_uniques >= 50:

        anomalies.append(
            f"Nombre élevé de destinations : "
            f"{destinations_uniques}"
        )

        score += 10

    # =========================================================
    # 7. TRAFIC IMPORTANT
    # =========================================================

    # Un grand volume vers une destination n'est pas
    # automatiquement une menace.
    #
    # On le conserve comme observation.
    for destination, nombre in destinations.items():

        if nombre >= 500:

            observations.append(
                f"Trafic important vers {destination} : "
                f"{nombre} paquets"
            )

    # =========================================================
    # 8. LIMITATION DU SCORE
    # =========================================================

    score = min(score, 100)

    # =========================================================
    # 9. NIVEAU DE RISQUE
    # =========================================================

    if score == 0:

        niveau = "FAIBLE"
        symbole = "🟢"

    elif score <= 30:

        niveau = "MODÉRÉ"
        symbole = "🟡"

    elif score <= 60:

        niveau = "ÉLEVÉ"
        symbole = "🟠"

    else:

        niveau = "CRITIQUE"
        symbole = "🔴"

    # =========================================================
    # 10. AFFICHAGE
    # =========================================================

    print()
    print("ANALYSE DE SÉCURITÉ")
    print("=" * 60)

    print(f"Score de risque : {score}/100")
    print(f"Niveau          : {symbole} {niveau}")

    # ---------------------------------------------------------
    # Observations
    # ---------------------------------------------------------

    print()
    print("📊 OBSERVATIONS")
    print("-" * 60)

    for observation in observations:

        print(f"  • {observation}")

    # ---------------------------------------------------------
    # Anomalies
    # ---------------------------------------------------------

    print()
    print("⚠️ ANOMALIES")
    print("-" * 60)

    if anomalies:

        for anomalie in anomalies:

            print(f"  ⚠ {anomalie}")

    else:

        print("  ✓ Aucune anomalie significative détectée.")

    # ---------------------------------------------------------
    # Menaces
    # ---------------------------------------------------------

    print()
    print("🚨 MENACES POTENTIELLES")
    print("-" * 60)

    if menaces:

        for menace in menaces:

            print(f"  🚨 {menace}")

    else:

        print("  ✓ Aucune menace potentielle détectée.")

    # ---------------------------------------------------------
    # Résumé
    # ---------------------------------------------------------

    print()
    print("RÉSUMÉ")
    print("-" * 60)

    print(f"  Paquets analysés       : {total_paquets}")
    print(f"  Ports observés        : {ports_uniques}")
    print(f"  Destinations observées: {destinations_uniques}")
    print(f"  Anomalies              : {len(anomalies)}")
    print(f"  Menaces potentielles   : {len(menaces)}")
    print(f"  Scans potentiels       : {len(scans_detectes)}")

    return {
        "score": score,
        "niveau": niveau,
        "observations": observations,
        "anomalies": anomalies,
        "menaces": menaces,
        "ports": ports_uniques,
        "destinations": destinations_uniques,
        "scans": len(scans_detectes),
    }

def afficher_statistiques(paquets):
    """
    Calcule, affiche et retourne les statistiques du trafic capturé.
    """

    protocoles = Counter()
    ports = Counter()
    versions_ip = Counter()

    for paquet in paquets:

        # IPv4
        if paquet.haslayer(IP):
            versions_ip["IPv4"] += 1

        # IPv6
        elif paquet.haslayer(IPv6):
            versions_ip["IPv6"] += 1

        # TCP
        if paquet.haslayer(TCP):
            protocoles["TCP"] += 1
            ports[paquet[TCP].sport] += 1
            ports[paquet[TCP].dport] += 1

        # UDP
        elif paquet.haslayer(UDP):
            protocoles["UDP"] += 1
            ports[paquet[UDP].sport] += 1
            ports[paquet[UDP].dport] += 1

        # ICMP
        elif paquet.haslayer(ICMP):
            protocoles["ICMP"] += 1

    # --------------------------------------------------------
    # Affichage dans le terminal
    # --------------------------------------------------------

    print()
    print("STATISTIQUES DU TRAFIC")
    print("=" * 60)

    print(f"Total de paquets : {len(paquets)}")
    print()

    print("Protocoles")
    print("-" * 30)

    for protocole, nombre in protocoles.most_common():
        print(f"  {protocole:<10} : {nombre}")

    print()

    print("Versions IP")
    print("-" * 30)

    for version, nombre in versions_ip.most_common():
        print(f"  {version:<10} : {nombre}")

    print()

    print("Ports les plus utilisés")
    print("-" * 30)

    for port, nombre in ports.most_common(10):
        service = nom_service(port)

        print(
            f"  Port {port:<5} : "
            f"{nombre:<5} → {service}"
        )

    print()

    # --------------------------------------------------------
    # Résultat structuré pour FastAPI
    # --------------------------------------------------------

    statistiques = {
        "total_paquets": len(paquets),

        "protocoles": dict(protocoles),

        "versions_ip": dict(versions_ip),

        "ports": [
            {
                "port": port,
                "nombre": nombre,
                "service": nom_service(port)
            }
            for port, nombre in ports.most_common(10)
        ]
    }

    return statistiques

def main():
    """Point d'entrée principal du programme."""
    afficher_entete()
    afficher_informations_systeme()
    afficher_adresses()
    afficher_interfaces_scapy()
    capturer_paquets()

    print("Analyseur prêt.")
    print("=" * 60)

def afficher_interfaces_scapy():
    """Affiche les interfaces réseau détectées par Scapy."""
    print("Interfaces réseau détectées par Scapy")
    print("-" * 40)

    try:
        interfaces = get_if_list()

        if not interfaces:
            print("  Aucune interface détectée.")
        else:
            for numero, interface in enumerate(interfaces, start=1):
                print(f"  {numero}. {interface}")

    except Exception as erreur:
        print(f"  Erreur Scapy : {erreur}")

    print()

if __name__ == "__main__":
    main()