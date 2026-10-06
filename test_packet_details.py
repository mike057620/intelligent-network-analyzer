"""
Test du module packet_details.py.

Aucun paquet n'est envoyé sur le réseau.
Les paquets sont créés uniquement en mémoire avec Scapy.
"""

from scapy.all import IP, TCP, UDP

from packet_details import (
    extraire_information_paquet,
    extraire_paquets,
)


def main():
    print("=" * 60)
    print("TEST DU MODULE DÉTAILS DES PAQUETS")
    print("=" * 60)

    paquet_tcp = (
        IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(
            sport=51000,
            dport=443,
            flags="S",
        )
    )

    paquet_tcp.time = 100.0

    paquet_udp = (
        IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(
            sport=53000,
            dport=53,
        )
    )

    paquet_udp.time = 101.0

    # Test TCP
    tcp = extraire_information_paquet(
        paquet_tcp,
        1,
    )

    print()
    print("PAQUET TCP")
    print(f"Source       : {tcp['source']}")
    print(f"Destination  : {tcp['destination']}")
    print(f"Protocole    : {tcp['protocole']}")
    print(f"Port source  : {tcp['port_source']}")
    print(f"Port dest.   : {tcp['port_destination']}")
    print(f"Taille       : {tcp['taille_octets']} octets")
    print(f"Timestamp    : {tcp['timestamp']}")
    print(f"Couches      : {tcp['couches']}")
    print(f"Flags TCP    : {tcp['flags_tcp']}")

    assert tcp["source"] == "192.0.2.10"
    assert tcp["destination"] == "192.0.2.20"
    assert tcp["protocole"] == "TCP"
    assert tcp["port_source"] == 51000
    assert tcp["port_destination"] == 443
    assert tcp["flags_tcp"] == "S"

    # Test UDP
    udp = extraire_information_paquet(
        paquet_udp,
        2,
    )

    print()
    print("PAQUET UDP")
    print(f"Source       : {udp['source']}")
    print(f"Destination  : {udp['destination']}")
    print(f"Protocole    : {udp['protocole']}")
    print(f"Port source  : {udp['port_source']}")
    print(f"Port dest.   : {udp['port_destination']}")
    print(f"Taille       : {udp['taille_octets']} octets")
    print(f"Couches      : {udp['couches']}")

    assert udp["source"] == "192.0.2.10"
    assert udp["destination"] == "192.0.2.53"
    assert udp["protocole"] == "UDP"
    assert udp["port_source"] == 53000
    assert udp["port_destination"] == 53

    # Test extraction de plusieurs paquets
    resultat = extraire_paquets(
        [paquet_tcp, paquet_udp],
        limite=100,
    )

    assert len(resultat) == 2
    assert resultat[0]["numero"] == 1
    assert resultat[1]["numero"] == 2

    print()
    print("=" * 60)
    print("✅ TEST RÉUSSI")
    print("Les informations essentielles des paquets")
    print("sont correctement extraites.")
    print("=" * 60)


if __name__ == "__main__":
    main()
