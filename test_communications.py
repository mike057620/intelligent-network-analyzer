"""
Test du moteur d'identification des communications.

IMPORTANT :
Aucun paquet n'est envoyé sur le réseau.
Tout est créé en mémoire avec Scapy.
"""

from scapy.all import IP, TCP, UDP

from communications import identifier_communications


def creer_paquet_tcp(source, destination, port_source, port_destination, flags, timestamp):
    """
    Crée un paquet TCP synthétique avec un timestamp contrôlé.
    """

    paquet = (
        IP(src=source, dst=destination)
        / TCP(
            sport=port_source,
            dport=port_destination,
            flags=flags,
        )
    )

    paquet.time = timestamp

    return paquet


def creer_paquet_udp(source, destination, port_source, port_destination, timestamp):
    """
    Crée un paquet UDP synthétique.
    """

    paquet = (
        IP(src=source, dst=destination)
        / UDP(
            sport=port_source,
            dport=port_destination,
        )
    )

    paquet.time = timestamp

    return paquet


def main():
    print("=" * 60)
    print("TEST DU MOTEUR DE COMMUNICATIONS")
    print("=" * 60)

    ip_client = "192.0.2.10"
    ip_serveur = "192.0.2.20"

    paquets = [
        # Début TCP : SYN
        creer_paquet_tcp(
            ip_client,
            ip_serveur,
            51000,
            443,
            "S",
            100.0,
        ),

        # Réponse du serveur : SYN-ACK
        creer_paquet_tcp(
            ip_serveur,
            ip_client,
            443,
            51000,
            "SA",
            101.0,
        ),

        # Confirmation : ACK
        creer_paquet_tcp(
            ip_client,
            ip_serveur,
            51000,
            443,
            "A",
            102.0,
        ),

        # Communication
        creer_paquet_tcp(
            ip_client,
            ip_serveur,
            51000,
            443,
            "PA",
            103.0,
        ),

        # Fermeture
        creer_paquet_tcp(
            ip_client,
            ip_serveur,
            51000,
            443,
            "FA",
            105.0,
        ),

        # Deuxième communication distincte : UDP/DNS
        creer_paquet_udp(
            ip_client,
            ip_serveur,
            53000,
            53,
            200.0,
        ),
    ]

    communications = identifier_communications(paquets)

    print()
    print(f"Communications détectées : {len(communications)}")
    print()

    for communication in communications:
        print(
            f"[{communication['id']}] "
            f"{communication['source_endpoint']} "
            f"↔ "
            f"{communication['destination_endpoint']}"
        )

        print(f"    Protocole : {communication['protocole']}")
        print(f"    État      : {communication['etat']}")
        print(
            f"    Paquets   : "
            f"{communication['nombre_paquets']}"
        )
        print(
            f"    Octets    : "
            f"{communication['octets']}"
        )
        print(
            f"    Durée     : "
            f"{communication['duree_secondes']}"
        )
        print(
            f"    Directions: "
            f"{communication['directions']}"
        )

        for evenement in communication["evenements"]:
            print(f"    Événement : {evenement}")

        print()

    # -----------------------------
    # Vérifications
    # -----------------------------

    assert len(communications) == 2, (
        "Le moteur devait identifier exactement "
        "2 communications."
    )

    tcp = next(
        communication
        for communication in communications
        if communication["protocole"] == "TCP"
    )

    assert tcp["nombre_paquets"] == 5
    assert tcp["duree_secondes"] == 5.0
    assert tcp["etat"] == "FERMETURE"
    assert tcp["directions"]["retour"] == 1
    assert "Début de connexion TCP détecté" in tcp["evenements"]
    assert "Fermeture TCP détectée" in tcp["evenements"]

    udp = next(
        communication
        for communication in communications
        if communication["protocole"] == "UDP"
    )

    assert udp["nombre_paquets"] == 1
    assert udp["etat"] == "OBSERVÉE"

    print("=" * 60)
    print("✅ TEST RÉUSSI")
    print("Le moteur regroupe correctement les paquets")
    print("et identifie les communications.")
    print("=" * 60)


if __name__ == "__main__":
    main()