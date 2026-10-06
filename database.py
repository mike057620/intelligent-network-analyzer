"""
Gestion de l'historique des analyses réseau.

Supabase est utilisé comme stockage distant principal.
SQLite reste disponible comme solution de secours locale.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from supabase_client import obtenir_client_supabase


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "network_analyzer.db"


def obtenir_connexion():
    """Ouvre une connexion SQLite locale."""

    connexion = sqlite3.connect(DATABASE_PATH)
    connexion.row_factory = sqlite3.Row
    return connexion


def initialiser_base():
    """Crée la table SQLite locale si elle n'existe pas."""

    connexion = obtenir_connexion()

    connexion.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            duree_capture_secondes INTEGER NOT NULL,
            resultat_json TEXT NOT NULL
        )
        """
    )

    connexion.commit()
    connexion.close()


def enregistrer_analyse(resultat):
    """
    Enregistre une analyse dans SQLite et Supabase.

    SQLite conserve une copie locale.
    Supabase conserve la version distante.
    """

    # =========================================================
    # 1. Sauvegarde locale SQLite
    # =========================================================

    connexion = obtenir_connexion()

    curseur = connexion.execute(
        """
        INSERT INTO analyses (
            timestamp,
            duree_capture_secondes,
            resultat_json
        )
        VALUES (?, ?, ?)
        """,
        (
            resultat["timestamp"],
            resultat["duree_capture_secondes"],
            json.dumps(
                resultat,
                ensure_ascii=False,
            ),
        ),
    )

    connexion.commit()

    identifiant_local = curseur.lastrowid

    connexion.close()

    # =========================================================
    # 2. Sauvegarde distante Supabase
    # =========================================================

    try:
        client = obtenir_client_supabase()

        statistiques = resultat.get(
            "statistiques",
            {},
        )

        securite = resultat.get(
            "securite",
            {},
        )

        communications = resultat.get(
            "communications",
            [],
        )

        ports = statistiques.get(
            "ports",
            [],
        )

        destinations = securite.get(
            "destinations",
            [],
        )

        ligne_supabase = {
            "duration_seconds": int(
                resultat.get(
                    "duree_capture_secondes",
                    0,
                )
            ),
            "risk_score": int(
                securite.get(
                    "score",
                    0,
                )
            ),
            "risk_level": str(
                securite.get(
                    "niveau",
                    "inconnu",
                )
            ),
            "total_packets": int(
                statistiques.get(
                    "total_paquets",
                    0,
                )
            ),
            "total_communications": len(
                communications
            ),
            "total_ports": len(
                ports
            ),
            "total_destinations": len(
                destinations
            ),
            "result": resultat,
        }

        client.table(
            "analyses"
        ).insert(
            ligne_supabase
        ).execute()

        print(
            "[SUPABASE] Analyse enregistrée avec succès."
        )

    except Exception as erreur:
        # Une panne Supabase ne bloque pas
        # l'enregistrement local.
        print(
            "[SUPABASE] Enregistrement distant échoué : "
            f"{type(erreur).__name__}"
        )

    return identifiant_local


def obtenir_analyses():
    """
    Récupère l'historique.

    Supabase est prioritaire.
    SQLite est utilisé comme secours si Supabase
    n'est pas disponible.
    """

    # =========================================================
    # 1. Lecture depuis Supabase
    # =========================================================

    try:
        client = obtenir_client_supabase()

        resultat_supabase = (
            client.table("analyses")
            .select(
                "id, created_at, duration_seconds, "
                "risk_score, risk_level, total_packets, "
                "total_communications, total_ports, "
                "total_destinations, result"
            )
            .order("id", desc=False)
            .execute()
        )

        analyses = []

        for ligne in resultat_supabase.data:
            resultat = ligne.get(
                "result",
                {},
            )

            # Sécurité : on s'assure d'avoir un dictionnaire.
            if not isinstance(resultat, dict):
                resultat = {}

            resultat["id"] = ligne["id"]

            # Si l'ancien résultat ne possède pas certains
            # champs, on peut reconstruire les informations
            # importantes depuis les colonnes Supabase.
            resultat.setdefault(
                "timestamp",
                ligne.get("created_at"),
            )

            resultat.setdefault(
                "duree_capture_secondes",
                ligne.get("duration_seconds", 0),
            )

            statistiques = resultat.setdefault(
                "statistiques",
                {},
            )

            statistiques.setdefault(
                "total_paquets",
                ligne.get("total_packets", 0),
            )

            securite = resultat.setdefault(
                "securite",
                {},
            )

            securite.setdefault(
                "score",
                ligne.get("risk_score", 0),
            )

            securite.setdefault(
                "niveau",
                ligne.get("risk_level", "inconnu"),
            )

            resultat.setdefault(
                "communications",
                [],
            )

            analyses.append(resultat)

        print(
            "[SUPABASE] Historique récupéré : "
            f"{len(analyses)} analyse(s)."
        )

        return analyses

    except Exception as erreur:
        print(
            "[SUPABASE] Lecture échouée : "
            f"{type(erreur).__name__}"
        )

    # =========================================================
    # 2. Secours SQLite
    # =========================================================

    print(
        "[SQLITE] Utilisation de l'historique local."
    )

    connexion = obtenir_connexion()

    lignes = connexion.execute(
        """
        SELECT
            id,
            timestamp,
            duree_capture_secondes,
            resultat_json
        FROM analyses
        ORDER BY id ASC
        """
    ).fetchall()

    connexion.close()

    analyses = []

    for ligne in lignes:
        resultat = json.loads(
            ligne["resultat_json"]
        )

        resultat["id"] = ligne["id"]

        analyses.append(resultat)

    return analyses


def obtenir_derniere_analyse():
    """Retourne la dernière analyse disponible."""

    analyses = obtenir_analyses()

    if not analyses:
        return None

    return analyses[-1]


# Initialisation automatique de SQLite.
initialiser_base()