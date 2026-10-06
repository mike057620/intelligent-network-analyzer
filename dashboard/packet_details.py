"""
Extraction des informations essentielles de chaque paquet réseau.

Ce module ne conserve pas le contenu brut du paquet.
Il extrait uniquement les métadonnées utiles à l'analyse :
- source ;
- destination ;
- protocole ;
- ports ;
- taille ;
- timestamp ;
- couches réseau ;
- informations TCP/UDP/ICMP disponibles.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, ICMP


def _formater_timestamp(timestamp: float | None) -> str | None:
    """Transforme le timestamp Scapy en date lisible."""

    if timestamp is None:
        return None

    try:
        return datetime.fromtimestamp(timestamp).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _extraire_couches(paquet) -> list[str]:
    """
    Retourne les noms des couches présentes dans le paquet.

    Exemple :
        Ether / IP / TCP
        -> ["Ether", "IP", "TCP"]
    """

    couches = []

    try:
        for couche in paquet.layers():
            nom = getattr(couche, "__name__", str(couche))

            if nom not in couches:
                couches.append(nom)

    except Exception:
        return []

    return couches


def extraire_information_paquet(paquet, numero: int) -> dict[str, Any]:
    """
    Extrait les informations essentielles d'un paquet.

    Le contenu brut du paquet n'est volontairement pas retourné.
    """

    version_ip = None
    source = None
    destination = None
    protocole = "AUTRE"

    # -----------------------------
    # Couche IP
    # -----------------------------

    if IP in paquet:
        couche_ip = paquet[IP]
        version_ip = "IPv4"

        source = str(couche_ip.src)
        destination = str(couche_ip.dst)

    elif IPv6 in paquet:
        couche_ip = paquet[IPv6]
        version_ip = "IPv6"

        source = str(couche_ip.src)
        destination = str(couche_ip.dst)

    # -----------------------------
    # Protocole + ports
    # -----------------------------

    port_source = None
    port_destination = None

    if TCP in paquet:
        protocole = "TCP"

        port_source = int(paquet[TCP].sport)
        port_destination = int(paquet[TCP].dport)

    elif UDP in paquet:
        protocole = "UDP"

        port_source = int(paquet[UDP].sport)
        port_destination = int(paquet[UDP].dport)

    elif ICMP in paquet:
        protocole = "ICMP"

    # -----------------------------
    # Timestamp
    # -----------------------------

    timestamp = None

    try:
        if hasattr(paquet, "time"):
            timestamp = float(paquet.time)
    except (TypeError, ValueError):
        timestamp = None

    # -----------------------------
    # Taille
    # -----------------------------

    try:
        taille = len(paquet)
    except Exception:
        taille = 0

    # -----------------------------
    # Informations TCP
    # -----------------------------

    flags_tcp = None

    if TCP in paquet:
        try:
            flags_tcp = str(paquet[TCP].flags)
        except Exception:
            flags_tcp = None

    # -----------------------------
    # Informations ICMP
    # -----------------------------

    type_icmp = None
    code_icmp = None

    if ICMP in paquet:
        try:
            type_icmp = int(paquet[ICMP].type)
            code_icmp = int(paquet[ICMP].code)
        except (TypeError, ValueError, AttributeError):
            type_icmp = None
            code_icmp = None

    return {
        "numero": numero,
        "timestamp": _formater_timestamp(timestamp),
        "timestamp_unix": timestamp,
        "version_ip": version_ip,
        "source": source,
        "destination": destination,
        "protocole": protocole,
        "port_source": port_source,
        "port_destination": port_destination,
        "taille_octets": taille,
        "couches": _extraire_couches(paquet),
        "flags_tcp": flags_tcp,
        "icmp_type": type_icmp,
        "icmp_code": code_icmp,
    }


def extraire_paquets(paquets, limite: int = 100) -> list[dict[str, Any]]:
    """
    Extrait un nombre limité de paquets.

    La limite évite de créer des réponses HTTP énormes lorsque
    la capture contient beaucoup de trafic.

    Par défaut :
        maximum 100 paquets.
    """

    try:
        limite = int(limite)
    except (TypeError, ValueError):
        limite = 100

    # Protection contre les valeurs absurdes.
    limite = max(1, min(limite, 500))

    resultat = []

    for numero, paquet in enumerate(paquets[:limite], start=1):
        resultat.append(
            extraire_information_paquet(
                paquet,
                numero,
            )
        )

    return resultat