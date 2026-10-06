"""
Enrichissement d'une adresse IP via une API externe.

API utilisée :
    https://ipwho.is/

Seules les IP publiques sont envoyées à l'API.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


API_BASE_URL = "https://ipwho.is/"
TIMEOUT_SECONDS = 5


def est_ip_publique(adresse_ip: str) -> bool:
    """Vérifie qu'une adresse IP est publique."""

    try:
        adresse = ipaddress.ip_address(adresse_ip)

        return (
            adresse.is_global
            and not adresse.is_private
            and not adresse.is_loopback
            and not adresse.is_link_local
            and not adresse.is_multicast
            and not adresse.is_reserved
            and not adresse.is_unspecified
        )

    except ValueError:
        return False


def enrichir_ip(adresse_ip: str) -> dict[str, Any]:
    """Interroge l'API externe et retourne les informations utiles."""

    adresse_ip = str(adresse_ip).strip()

    if not adresse_ip:
        return {
            "success": False,
            "error": "Adresse IP vide.",
        }

    try:
        ipaddress.ip_address(adresse_ip)
    except ValueError:
        return {
            "success": False,
            "error": "Adresse IP invalide.",
        }

    # Ne jamais envoyer une IP locale ou privée à une API externe.
    if not est_ip_publique(adresse_ip):
        return {
            "success": False,
            "error": "Adresse IP non publique. Enrichissement externe ignoré.",
            "ip": adresse_ip,
        }

    ip_encodee = quote(adresse_ip, safe="")
    url = f"{API_BASE_URL}{ip_encodee}"

    requete = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Intelligent-Network-Analyzer/1.0",
        },
        method="GET",
    )

    try:
        with urlopen(
            requete,
            timeout=TIMEOUT_SECONDS,
        ) as reponse:
            statut_http = reponse.status
            contenu = reponse.read().decode(
                "utf-8",
                errors="replace",
            )

        try:
            donnees = json.loads(contenu)
        except json.JSONDecodeError:
            return {
                "success": False,
                "error": "Réponse JSON invalide reçue depuis l'API.",
                "status_code": statut_http,
                "ip": adresse_ip,
            }

        if not donnees.get("success", False):
            return {
                "success": False,
                "error": donnees.get(
                    "message",
                    "L'API n'a pas pu enrichir cette adresse IP.",
                ),
                "status_code": statut_http,
                "ip": adresse_ip,
            }

        connection = donnees.get("connection") or {}

        return {
            "success": True,
            "status_code": statut_http,
            "ip": donnees.get("ip", adresse_ip),
            "type": donnees.get("type"),
            "continent": donnees.get("continent"),
            "country": donnees.get("country"),
            "country_code": donnees.get("country_code"),
            "region": donnees.get("region"),
            "city": donnees.get("city"),
            "asn": connection.get("asn"),
            "organisation": connection.get("org"),
            "isp": connection.get("isp"),
            "domain": connection.get("domain"),
        }

    except HTTPError as erreur:
        return {
            "success": False,
            "error": f"Erreur HTTP de l'API : {erreur.code}",
            "status_code": erreur.code,
            "ip": adresse_ip,
        }

    except URLError as erreur:
        return {
            "success": False,
            "error": "Impossible de joindre l'API externe.",
            "detail_type": type(erreur.reason).__name__,
            "ip": adresse_ip,
        }

    except TimeoutError:
        return {
            "success": False,
            "error": "L'API externe a dépassé le délai maximum.",
            "ip": adresse_ip,
        }

    except OSError as erreur:
        return {
            "success": False,
            "error": "Erreur réseau lors de l'appel à l'API externe.",
            "detail_type": type(erreur).__name__,
            "ip": adresse_ip,
        }

    except Exception as erreur:
        print(
            f"[ERREUR API EXTERNE] "
            f"{type(erreur).__name__}: {erreur}"
        )

        return {
            "success": False,
            "error": "Une erreur interne est survenue pendant l'enrichissement.",
            "ip": adresse_ip,
        }
