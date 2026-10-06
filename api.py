import os
import csv
import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from fastapi import FastAPI, Query
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from datetime import datetime
from pathlib import Path

from analyzer import analyser_securite, afficher_statistiques
from communications import identifier_communications
from packet_details import extraire_paquets
from ip_enrichment import est_ip_publique, enrichir_ip
from database import (
    enregistrer_analyse,
    obtenir_analyses,
    obtenir_derniere_analyse,
)
from security_insights import generer_insights
from scapy.all import sniff


BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BASE_DIR / "dashboard"


app = FastAPI(
    title="Intelligent Network Analyzer",
    description="API d'analyse et de détection des anomalies réseau",
    version="1.3.0"
)


# ============================================================
# DASHBOARD
# ============================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        return response


app.add_middleware(SecurityHeadersMiddleware)

app.mount(
    "/dashboard",
    StaticFiles(directory=DASHBOARD_DIR),
    name="dashboard"
)


@app.get("/", include_in_schema=False)
def accueil():
    """
    Affiche le dashboard principal.
    """
    return FileResponse(DASHBOARD_DIR / "index.html")


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    """
    Vérifie que l'API fonctionne.
    """
    return {
        "status": "ok",
        "application": "Intelligent Network Analyzer",
        "timestamp": datetime.now().isoformat()
    }


# ============================================================
# ANALYSE RÉSEAU
# ============================================================

def enrichir_destinations_publiques(
    paquets_details,
    limite: int = 3,
):
    """
    Sélectionne quelques IP publiques observées et les enrichit
    via l'API externe.

    Les adresses privées, locales, multicast et link-local
    ne sont jamais envoyées à l'extérieur.
    """

    enrichissements = []
    ips_deja_traitees = set()

    for paquet in paquets_details:
        adresse_ip = paquet.get("destination")

        if not adresse_ip:
            continue

        if adresse_ip in ips_deja_traitees:
            continue

        if not est_ip_publique(adresse_ip):
            continue

        ips_deja_traitees.add(adresse_ip)

        enrichissement = enrichir_ip(adresse_ip)

        enrichissements.append(enrichissement)

        if len(enrichissements) >= limite:
            break

    return enrichissements

@app.get("/analyze")
def analyser_reseau(
    duree: int = Query(
        default=10,
        ge=1,
        le=60,
        description="Durée de capture réseau en secondes"
    )
):
    """
    Capture le trafic réseau et réalise une analyse complète.
    """

    try:

        # ----------------------------------------------------
        # 1. Capture réseau
        # ----------------------------------------------------

        paquets = sniff(timeout=duree)

        # Analyse générale des paquets
        statistiques = afficher_statistiques(paquets)

        # Extraction des détails des paquets capturés
        # Maximum 100 paquets exposés dans la réponse.
        paquets_details = extraire_paquets(
            paquets,
            limite=100,
        )

        enrichissements = enrichir_destinations_publiques(
    paquets_details,
    limite=3,
        )
        # Regroupement des paquets en communications
        communications = identifier_communications(paquets)

        # Analyse de sécurité
        securite = analyser_securite(paquets)

        # Explications et recommandations
        insights = generer_insights(securite)
        # ----------------------------------------------------
        # 5. Construction du résultat
        # ----------------------------------------------------

        resultat = {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "duree_capture_secondes": duree,
            "statistiques": statistiques,
            "paquets": paquets_details,
            "communications": communications,
            "enrichissements": enrichissements,
            "securite": {
                "score": securite["score"],
                "niveau": securite["niveau"],
                "observations": securite["observations"],
                "anomalies": securite["anomalies"],
                "menaces": securite["menaces"],
                "scans": securite["scans"],
                "ports": securite["ports"],
                "destinations": securite["destinations"]
            },

            "insights": insights
        }


        # ----------------------------------------------------
        # 6. Sauvegarde SQLite
        # ----------------------------------------------------

        identifiant = enregistrer_analyse(resultat)

        resultat["id"] = identifiant


        # ----------------------------------------------------
        # 7. Réponse API
        # ----------------------------------------------------

        return resultat


    except Exception as erreur:
        # Le détail technique reste uniquement dans le terminal serveur.
        print(
            f"[ERREUR] Échec de l'analyse réseau : "
            f"{type(erreur).__name__}: {erreur}"
        )

        if os.getenv("PUBLIC_HOSTING") == "true":
            return {
                "success": False,
                "error": (
                    "La capture réseau réelle n'est pas disponible "
                    "sur l'hébergement public. Effectuez la capture "
                    "depuis l'environnement local autorisé."
                )
            }

        return {
            "success": False,
            "error": "Une erreur interne est survenue pendant l'analyse."
        }

# ============================================================
# HISTORIQUE COMPLET
# ============================================================

@app.get("/history")
def obtenir_historique():
    """
    Retourne toutes les analyses enregistrées dans SQLite.
    """

    analyses = obtenir_analyses()

    return {
        "success": True,
        "count": len(analyses),
        "analyses": analyses
    }


# ============================================================
# RÉSUMÉ DE L'HISTORIQUE
# ============================================================

@app.get("/history/summary")
def obtenir_resume_historique():
    """
    Retourne uniquement les informations nécessaires
    à l'évolution du score de sécurité.
    """

    analyses = obtenir_analyses()

    resume = []

    for analyse in analyses:

        securite = analyse.get("securite", {})

        resume.append({
            "id": analyse.get("id"),
            "timestamp": analyse.get("timestamp"),
            "score": securite.get("score", 0),
            "niveau": securite.get("niveau", "INCONNU"),
            "paquets": analyse.get(
                "statistiques",
                {}
            ).get(
                "total_paquets",
                0
            )
        })

    return {
        "success": True,
        "count": len(resume),
        "analyses": resume
    }


# ============================================================
# DERNIÈRE ANALYSE
# ============================================================

@app.get("/history/latest")
def obtenir_derniere():
    """
    Retourne la dernière analyse enregistrée.
    """

    analyse = obtenir_derniere_analyse()

    return {
        "success": True,
        "analysis": analyse
    }

@app.get("/export/json")
def exporter_json():
    """
    Exporte la dernière analyse au format JSON.
    """
    from fastapi.responses import JSONResponse

    analyse = obtenir_derniere_analyse()

    if analyse is None:
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "error": "Aucune analyse disponible."
            }
        )

    return JSONResponse(
        content=analyse,
        headers={
            "Content-Disposition": (
                'attachment; filename="network-analysis.json"'
            )
        }
    )

@app.get("/export/csv")
def exporter_csv():
    """
    Exporte l'historique des analyses au format CSV.
    """
    from fastapi.responses import StreamingResponse

    analyses = obtenir_analyses()

    if not analyses:
        return {
            "success": False,
            "error": "Aucune analyse disponible."
        }

    sortie = io.StringIO()

    writer = csv.writer(sortie)

    writer.writerow([
        "ID",
        "Date",
        "Durée (secondes)",
        "Paquets",
        "Ports",
        "Destinations",
        "Scans",
        "Score",
        "Niveau"
    ])

    for analyse in analyses:
        statistiques = analyse.get("statistiques", {})
        securite = analyse.get("securite", {})

        writer.writerow([
            analyse.get("id", ""),
            analyse.get("timestamp", ""),
            analyse.get("duree_capture_secondes", ""),
            statistiques.get("total_paquets", 0),
            securite.get("ports", 0),
            securite.get("destinations", 0),
            securite.get("scans", 0),
            securite.get("score", 0),
            securite.get("niveau", "")
        ])

    contenu = sortie.getvalue()

    return StreamingResponse(
        iter([contenu]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                'attachment; filename="network-analysis-history.csv"'
            )
        }
    )

@app.get("/export/pdf")
def exporter_pdf():
    """
    Exporte l'historique des analyses au format PDF.
    """
    from fastapi.responses import Response

    analyses = obtenir_analyses()

    if not analyses:
        return {
            "success": False,
            "error": "Aucune analyse disponible."
        }

    analyse = analyses[-1]

    statistiques = analyse.get("statistiques", {})
    securite = analyse.get("securite", {})
    insights = analyse.get("insights", {})

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
        title="Intelligent Network Analyzer - Rapport de sécurité"
    )

    styles = getSampleStyleSheet()

    titre_style = ParagraphStyle(
        "Titre",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=8,
    )

    sous_titre_style = ParagraphStyle(
        "SousTitre",
        parent=styles["Normal"],
        fontSize=10,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=20,
    )

    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "NormalCustom",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    story = []

    # En-tête
    story.append(
        Paragraph(
            "INTELLIGENT NETWORK ANALYZER",
            titre_style
        )
    )

    story.append(
        Paragraph(
            "Rapport d'analyse et de sécurité réseau",
            sous_titre_style
        )
    )

    # Informations générales
    story.append(
        Paragraph(
            "1. Informations de l'analyse",
            section_style
        )
    )

    informations = [
        ["Identifiant", str(analyse.get("id", "-"))],
        ["Date", str(analyse.get("timestamp", "-"))],
        [
            "Durée de capture",
            f'{analyse.get("duree_capture_secondes", 0)} seconde(s)'
        ],
        [
            "Nombre de paquets",
            str(statistiques.get("total_paquets", 0))
        ],
    ]

    table = Table(
        informations,
        colWidths=[160, 320]
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#e2e8f0")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, -1),
                colors.HexColor("#334155")
            ),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(table)

    # Score de sécurité
    story.append(
        Paragraph(
            "2. Évaluation de la sécurité",
            section_style
        )
    )

    score = securite.get("score", 0)
    niveau = securite.get("niveau", "INCONNU")

    score_data = [
        ["Score de risque", f"{score}/100"],
        ["Niveau de sécurité", str(niveau)],
        ["Scans potentiels", str(securite.get("scans", 0))],
        ["Ports détectés", str(securite.get("ports", 0))],
        ["Destinations", str(securite.get("destinations", 0))],
    ]

    score_table = Table(
        score_data,
        colWidths=[200, 280]
    )

    score_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#f1f5f9")
            ),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(score_table)

    # Observations
    observations = securite.get("observations", [])

    story.append(
        Paragraph(
            "3. Observations",
            section_style
        )
    )

    if observations:
        for observation in observations:
            story.append(
                Paragraph(
                    f"• {observation}",
                    normal_style
                )
            )
            story.append(Spacer(1, 4))
    else:
        story.append(
            Paragraph(
                "Aucune observation particulière.",
                normal_style
            )
        )

    # Anomalies
    anomalies = securite.get("anomalies", [])

    story.append(
        Paragraph(
            "4. Anomalies détectées",
            section_style
        )
    )

    if anomalies:
        for anomalie in anomalies:
            story.append(
                Paragraph(
                    f"• {anomalie}",
                    normal_style
                )
            )
            story.append(Spacer(1, 4))
    else:
        story.append(
            Paragraph(
                "Aucune anomalie détectée.",
                normal_style
            )
        )

    # Menaces
    menaces = securite.get("menaces", [])

    story.append(
        Paragraph(
            "5. Menaces potentielles",
            section_style
        )
    )

    if menaces:
        for menace in menaces:
            story.append(
                Paragraph(
                    f"• {menace}",
                    normal_style
                )
            )
            story.append(Spacer(1, 4))
    else:
        story.append(
            Paragraph(
                "Aucune menace potentielle détectée.",
                normal_style
            )
        )

    # Insights / recommandations
    liste_insights = insights.get("insights", [])

    story.append(
        Paragraph(
            "6. Recommandations de sécurité",
            section_style
        )
    )

    if liste_insights:
        for insight in liste_insights:
            titre = insight.get(
                "titre",
                "Recommandation"
            )

            message = insight.get(
                "message",
                ""
            )

            recommandation = insight.get(
                "recommandation",
                ""
            )

            story.append(
                Paragraph(
                    f"<b>{titre}</b>",
                    normal_style
                )
            )

            if message:
                story.append(
                    Paragraph(
                        message,
                        normal_style
                    )
                )

            if recommandation:
                story.append(
                    Paragraph(
                        f"<b>Action :</b> {recommandation}",
                        normal_style
                    )
                )

            story.append(Spacer(1, 8))
    else:
        story.append(
            Paragraph(
                "Aucune recommandation supplémentaire.",
                normal_style
            )
        )

    # Pied de rapport
    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Rapport généré automatiquement par Intelligent Network Analyzer.",
            sous_titre_style
        )
    )

    document.build(story)

    contenu = buffer.getvalue()

    return Response(
        content=contenu,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                'attachment; filename="network-analysis-report.pdf"'
            )
        }
    )