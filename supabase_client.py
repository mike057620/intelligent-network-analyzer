"""
Connexion au projet Supabase.

La clé secrète est lue depuis une variable d'environnement.
Elle n'est jamais écrite en dur dans le code.
"""

from __future__ import annotations

import os

from supabase import Client, create_client


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY")


def obtenir_client_supabase() -> Client:
    """Crée et retourne le client Supabase côté serveur."""

    if not SUPABASE_URL:
        raise RuntimeError(
            "La variable SUPABASE_URL est manquante."
        )

    if not SUPABASE_SECRET_KEY:
        raise RuntimeError(
            "La variable SUPABASE_SECRET_KEY est manquante."
        )

    return create_client(
        SUPABASE_URL,
        SUPABASE_SECRET_KEY,
    )
