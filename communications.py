"""
Moteur d'identification et de regroupement des communications réseau.

Objectif :
- regrouper les paquets appartenant à une même communication ;
- reconnaître les communications TCP, UDP et ICMP ;
- identifier les deux extrémités ;
- calculer la durée ;
- compter les paquets et les octets ;
- donner un état lisible à la communication.

Aucune donnée n'est envoyée sur le réseau par ce module.
Il analyse uniquement les paquets déjà capturés.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
from typing import Any

from scapy.all import ICMP, IP, IPv6, TCP, UDP


def _extraire_informations_paquet(paquet) -> dict[str, Any] | None:
    """
    Extrait les informations réseau essentielles d'un paquet.

    Retourne None si le paquet ne contient pas de couche IP exploitable.
    """

    # Détection IPv4
    if IP in paquet:
        couche_ip = paquet[IP]
        version_ip = "IPv4"

    # Détection IPv6
    elif IPv6 in paquet:
        couche_ip = paquet[IPv6]
        version_ip = "IPv6"

    # Paquet non exploitable pour notre regroupement
    else:
        return None

    source = str(couche_ip.src)
    destination = str(couche_ip.dst)

    protocole = "AUTRE"
    port_source = None
    port_destination = None

    # TCP
    if TCP in paquet:
        protocole = "TCP"
        port_source = int(paquet[TCP].sport)
        port_destination = int(paquet[TCP].dport)

    # UDP
    elif UDP in paquet:
        protocole = "UDP"
        port_source = int(paquet[UDP].sport)
        port_destination = int(paquet[UDP].dport)

    # ICMP / ICMPv6
    elif ICMP in paquet:
        protocole = "ICMP"

    # Timestamp réellement présent dans le paquet
    timestamp = None

    try:
        if hasattr(paquet, "time"):
            timestamp = float(paquet.time)
    except (TypeError, ValueError):
        timestamp = None

    # Taille réellement observée
    try:
        taille = len(paquet)
    except Exception:
        taille = 0

    return {
        "version_ip": version_ip,
        "source": source,
        "destination": destination,
        "protocole": protocole,
        "port_source": port_source,
        "port_destination": port_destination,
        "timestamp": timestamp,
        "taille": taille,
    }


def _creer_cle_communication(informations: dict[str, Any]) -> tuple:
    """
    Crée une clé bidirectionnelle.

    Exemple :
        A:50000 -> B:443
    et
        B:443 -> A:50000

    appartiennent à la même communication.
    """

    source_endpoint = (
        informations["source"],
        informations["port_source"],
    )

    destination_endpoint = (
        informations["destination"],
        informations["port_destination"],
    )

    # La communication est indépendante du sens.
    endpoints = tuple(
        sorted(
            [source_endpoint, destination_endpoint],
            key=lambda valeur: (str(valeur[0]), str(valeur[1])),
        )
    )

    return (
        informations["version_ip"],
        informations["protocole"],
        endpoints,
    )


def _formater_timestamp(timestamp: float | None) -> str | None:
    """Transforme un timestamp Unix en date lisible."""

    if timestamp is None:
        return None

    try:
        return datetime.fromtimestamp(timestamp).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _formater_endpoint(adresse: str, port: int | None) -> str:
    """Construit une représentation lisible d'une extrémité."""

    if port is None:
        return adresse

    # Une adresse IPv6 contient déjà des « : ».
    # Les crochets permettent de distinguer clairement l'adresse du port.
    if ":" in adresse:
        return f"[{adresse}]:{port}"

    return f"{adresse}:{port}"


def identifier_communications(paquets) -> list[dict[str, Any]]:
    """
    Regroupe les paquets en communications.

    Paramètre :
        paquets : ensemble/list/PacketList Scapy

    Retour :
        liste de dictionnaires représentant les communications détectées.
    """

    communications: OrderedDict[tuple, dict[str, Any]] = OrderedDict()

    for paquet in paquets:
        informations = _extraire_informations_paquet(paquet)

        # On ignore proprement les paquets sans couche IP exploitable.
        if informations is None:
            continue

        cle = _creer_cle_communication(informations)

        if cle not in communications:
            communications[cle] = {
                "version_ip": informations["version_ip"],
                "protocole": informations["protocole"],
                "source": informations["source"],
                "port_source": informations["port_source"],
                "destination": informations["destination"],
                "port_destination": informations["port_destination"],
                "premier_timestamp": informations["timestamp"],
                "dernier_timestamp": informations["timestamp"],
                "nombre_paquets": 0,
                "octets": 0,
                "directions": {
                    "aller": 0,
                    "retour": 0,
                },
                "tcp_syn": False,
                "tcp_syn_ack": False,
                "tcp_fin": False,
                "tcp_rst": False,
                "evenements": [],
            }

        communication = communications[cle]

        communication["nombre_paquets"] += 1
        communication["octets"] += informations["taille"]

        timestamp = informations["timestamp"]

        # Mise à jour du premier timestamp
        if timestamp is not None:
            if (
                communication["premier_timestamp"] is None
                or timestamp < communication["premier_timestamp"]
            ):
                communication["premier_timestamp"] = timestamp

            if (
                communication["dernier_timestamp"] is None
                or timestamp > communication["dernier_timestamp"]
            ):
                communication["dernier_timestamp"] = timestamp

        # Identification du sens de la communication.
        meme_direction = (
            informations["source"] == communication["source"]
            and informations["port_source"]
            == communication["port_source"]
            and informations["destination"]
            == communication["destination"]
            and informations["port_destination"]
            == communication["port_destination"]
        )

        if meme_direction:
            communication["directions"]["aller"] += 1
        else:
            communication["directions"]["retour"] += 1

        # Analyse des flags TCP.
        if informations["protocole"] == "TCP" and TCP in paquet:
            flags = int(paquet[TCP].flags)

            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            fin = bool(flags & 0x01)
            rst = bool(flags & 0x04)

            if syn and not ack:
                communication["tcp_syn"] = True

            if syn and ack:
                communication["tcp_syn_ack"] = True

            if fin:
                communication["tcp_fin"] = True

            if rst:
                communication["tcp_rst"] = True

    resultat = []

    for identifiant, communication in enumerate(
        communications.values(),
        start=1,
    ):
        premier_timestamp = communication["premier_timestamp"]
        dernier_timestamp = communication["dernier_timestamp"]

        # Calcul de la durée uniquement si les deux timestamps existent.
        if (
            premier_timestamp is not None
            and dernier_timestamp is not None
        ):
            duree = max(0.0, dernier_timestamp - premier_timestamp)
        else:
            duree = None

        # Détermination de l'état de la communication.
        evenements = []

        if communication["protocole"] == "TCP":
            if communication["tcp_syn"]:
                evenements.append("Début de connexion TCP détecté")

            if communication["tcp_syn_ack"]:
                evenements.append("Réponse SYN-ACK détectée")

            if communication["tcp_rst"]:
                evenements.append("Réinitialisation TCP détectée")

            if communication["tcp_fin"]:
                evenements.append("Fermeture TCP détectée")

            if communication["tcp_rst"]:
                etat = "FERMÉE / RÉINITIALISÉE"

            elif communication["tcp_fin"]:
                etat = "FERMETURE"

            elif communication["tcp_syn"] or communication["nombre_paquets"] > 1:
                etat = "EN COURS"

            else:
                etat = "OBSERVÉE"

        else:
            etat = "OBSERVÉE"

        # Déterminer une réponse lisible.
        source = _formater_endpoint(
            communication["source"],
            communication["port_source"],
        )

        destination = _formater_endpoint(
            communication["destination"],
            communication["port_destination"],
        )

        resultat.append(
            {
                "id": identifiant,
                "version_ip": communication["version_ip"],
                "protocole": communication["protocole"],
                "source": communication["source"],
                "port_source": communication["port_source"],
                "destination": communication["destination"],
                "port_destination": communication["port_destination"],
                "source_endpoint": source,
                "destination_endpoint": destination,
                "premier_paquet": _formater_timestamp(
                    premier_timestamp
                ),
                "dernier_paquet": _formater_timestamp(
                    dernier_timestamp
                ),
                "duree_secondes": duree,
                "nombre_paquets": communication["nombre_paquets"],
                "octets": communication["octets"],
                "directions": communication["directions"],
                "etat": etat,
                "evenements": evenements,
            }
        )

    # Les communications les plus volumineuses apparaissent en premier.
    resultat.sort(
        key=lambda communication: (
            communication["nombre_paquets"],
            communication["octets"],
        ),
        reverse=True,
    )

    return resultat