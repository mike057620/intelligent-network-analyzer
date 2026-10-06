"""
Security Insight Engine
=======================

Transforme les résultats du moteur de détection
en explications et recommandations compréhensibles.

Ce module ne capture aucun paquet et ne détecte rien
par lui-même : il interprète uniquement les résultats
réels produits par analyzer.py.
"""


def generer_insights(securite):
    """
    Génère des explications et recommandations
    à partir du résultat de analyser_securite().
    """

    score = int(securite.get("score", 0))
    niveau = securite.get("niveau", "INCONNU")

    observations = securite.get("observations", [])
    anomalies = securite.get("anomalies", [])
    menaces = securite.get("menaces", [])

    insights = []

    # ============================================================
    # 1. ÉTAT NORMAL
    # ============================================================

    if score == 0 and not anomalies and not menaces:

        insights.append({
            "type": "normal",
            "niveau": "FAIBLE",
            "titre": "Système réseau normal",
            "message": (
                "Aucune anomalie ou menace potentielle "
                "n'a été détectée pendant cette analyse."
            ),
            "recommandation": (
                "Continuez la surveillance du trafic réseau "
                "et relancez régulièrement une analyse."
            )
        })

    # ============================================================
    # 2. ANOMALIES
    # ============================================================

    for anomalie in anomalies:

        insights.append({
            "type": "anomalie",
            "niveau": niveau,
            "titre": "Comportement réseau inhabituel",
            "message": anomalie,
            "recommandation": (
                "Vérifiez la machine concernée et recherchez "
                "d'autres connexions inhabituelles."
            )
        })

    # ============================================================
    # 3. MENACES
    # ============================================================

    for menace in menaces:

        recommandation = (
            "Identifiez la machine source et vérifiez si "
            "ce comportement correspond à une activité légitime."
        )

        texte = menace.lower()

        # --------------------------------------------------------
        # Scan de ports
        # --------------------------------------------------------

        if "scan" in texte or "ports ciblés" in texte:

            recommandation = (
                "Vérifiez la machine source, recherchez "
                "d'autres tentatives de connexion et examinez "
                "les journaux réseau."
            )

        # --------------------------------------------------------
        # Services multiples
        # --------------------------------------------------------

        elif "services connus" in texte:

            recommandation = (
                "Vérifiez les services exposés sur la machine "
                "cible et confirmez qu'ils sont nécessaires."
            )

        insights.append({
            "type": "menace",
            "niveau": niveau,
            "titre": "Menace potentielle détectée",
            "message": menace,
            "recommandation": recommandation
        })

    # ============================================================
    # 4. OBSERVATIONS IMPORTANTES
    # ============================================================

    for observation in observations:

        texte = observation.lower()

        # Les observations sont informatives.
        # Elles ne deviennent pas automatiquement des menaces.

        if (
            "trafic important" in texte
            or "volume élevé" in texte
            or "beaucoup de paquets" in texte
        ):
            insights.append({
                "type": "observation",
                "niveau": "INFO",
                "titre": "Volume réseau important",
                "message": observation,
                "recommandation": (
                    "Vérifiez si ce volume correspond à une "
                    "activité normale sur votre réseau."
                )
            })

    # ============================================================
    # 5. RÉSUMÉ GLOBAL
    # ============================================================

    if score >= 70:

        resume = (
            "Niveau de risque élevé. "
            "Une investigation approfondie est recommandée."
        )

    elif score >= 40:

        resume = (
            "Niveau de risque modéré à élevé. "
            "Une vérification du trafic suspect est recommandée."
        )

    elif score > 0:

        resume = (
            "Quelques comportements inhabituels ont été détectés. "
            "Une surveillance complémentaire est recommandée."
        )

    else:

        resume = (
            "Le trafic analysé ne présente actuellement "
            "aucun indicateur de menace détecté."
        )

    return {
        "score": score,
        "niveau": niveau,
        "resume": resume,
        "total_insights": len(insights),
        "insights": insights
    }