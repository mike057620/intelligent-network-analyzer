// ============================================================
// INTELLIGENT NETWORK ANALYZER
// Moteur JavaScript du dashboard SOC
// ============================================================

const API_BASE_URL = "";

// ------------------------------------------------------------
// Éléments du dashboard
// ------------------------------------------------------------

const packetsList = document.getElementById("packetsList");
const packetsDetailsCount = document.getElementById("packetsDetailsCount");
const packetDetail = document.getElementById("packetDetail");
const scoreRing = document.getElementById("scoreRing");
const securityScore = document.getElementById("securityScore");
const securityLevel = document.getElementById("securityLevel");
const securityIcon = document.getElementById("securityIcon");
const securityTitle = document.getElementById("securityTitle");
const securityMessage = document.getElementById("securityMessage");
const enrichmentList = document.getElementById("enrichmentList");
const enrichmentCount = document.getElementById("enrichmentCount");

const packetsCount = document.getElementById("packetsCount");
const portsCount = document.getElementById("portsCount");
const destinationsCount = document.getElementById("destinationsCount");
const scansCount = document.getElementById("scansCount");

const protocolsList = document.getElementById("protocolsList");
const portsList = document.getElementById("portsList");
const securityEvents = document.getElementById("securityEvents");
const eventCount = document.getElementById("eventCount");
const historyList = document.getElementById("historyList");
const historyCount = document.getElementById("historyCount");
const riskHistoryCount =
    document.getElementById("riskHistoryCount");

const riskChartBars =
    document.getElementById("riskChartBars");

const riskChartLabels =
    document.getElementById("riskChartLabels");

const riskChartEmpty =
    document.getElementById("riskChartEmpty");

const duration = document.getElementById("duration");
const analyzeButton = document.getElementById("analyzeButton");
const buttonIcon = document.getElementById("buttonIcon");
const buttonText = document.getElementById("buttonText");

const lastAnalysis = document.getElementById("lastAnalysis");

// ------------------------------------------------------------
// Utilitaires
// ------------------------------------------------------------

function formaterDate(dateString) {
    const date = new Date(dateString);

    if (Number.isNaN(date.getTime())) {
        return "Date inconnue";
    }

    return date.toLocaleString("fr-FR");
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

// ------------------------------------------------------------
// Couleur du score
// ------------------------------------------------------------

function obtenirCouleurScore(score) {
    if (score >= 70) {
        return "#ff4d67";
    }

    if (score >= 30) {
        return "#ffb84d";
    }

    return "#00e5a0";
}

// ------------------------------------------------------------
// Affichage du score
// ------------------------------------------------------------

function afficherScore(score, niveau) {
    const valeur = Math.max(0, Math.min(100, Number(score) || 0));
    const couleur = obtenirCouleurScore(valeur);

    if (securityScore) {
        securityScore.textContent = valeur;
    }

    if (securityLevel) {
        securityLevel.textContent = niveau || "INCONNU";
    }

    if (scoreRing) {
        scoreRing.style.setProperty(
            "--score",
            `${valeur * 3.6}deg`
        );

        scoreRing.style.setProperty(
            "--score-color",
            couleur
        );
    }
}

// ------------------------------------------------------------
// État général de sécurité
// ------------------------------------------------------------

function afficherEtatSecurite(securite) {
    const score = Number(securite.score) || 0;

    if (score >= 70) {
        if (securityIcon) {
            securityIcon.textContent = "🛡️";
        }

        if (securityTitle) {
            securityTitle.textContent = "Menace potentielle détectée";
        }

        if (securityMessage) {
            securityMessage.textContent =
                "Le moteur d'analyse a détecté une activité réseau présentant un niveau de risque élevé.";
        }

        return;
    }

    if (score >= 30) {
        if (securityIcon) {
            securityIcon.textContent = "🛡️";
        }

        if (securityTitle) {
            securityTitle.textContent = "Activité réseau suspecte";
        }

        if (securityMessage) {
            securityMessage.textContent =
                "Certaines activités réseau nécessitent une surveillance.";
        }

        return;
    }

    if (securityIcon) {
        securityIcon.textContent = "🛡️";
    }

    if (securityTitle) {
        securityTitle.textContent = "Réseau sécurisé";
    }

    if (securityMessage) {
        securityMessage.textContent =
            "Aucune menace significative n'a été détectée pendant cette analyse.";
    }
}

// ------------------------------------------------------------
// Statistiques générales
// ------------------------------------------------------------

function afficherStatistiques(statistiques, securite) {
    if (packetsCount) {
        packetsCount.textContent =
            statistiques.total_paquets ?? 0;
    }

    if (portsCount) {
        portsCount.textContent =
            securite.ports ?? 0;
    }

    if (destinationsCount) {
        destinationsCount.textContent =
            securite.destinations ?? 0;
    }

    if (scansCount) {
        scansCount.textContent =
            securite.scans ?? 0;
    }

    afficherProtocoles(statistiques.protocoles || {});
    afficherPorts(statistiques.ports || []);
}

// ------------------------------------------------------------
// Protocoles
// ------------------------------------------------------------

function afficherProtocoles(protocoles) {
    if (!protocolsList) {
        return;
    }

    const entries = Object.entries(protocoles);

    if (entries.length === 0) {
        protocolsList.innerHTML = `
            <div class="empty-state">
                Aucun protocole détecté.
            </div>
        `;

        return;
    }

    const total = entries.reduce(
        (somme, [, nombre]) => somme + Number(nombre),
        0
    );

    protocolsList.innerHTML = entries
        .sort((a, b) => Number(b[1]) - Number(a[1]))
        .map(([protocole, nombre]) => {
            const pourcentage =
                total > 0
                    ? Math.round((Number(nombre) / total) * 100)
                    : 0;

            return `
                <div class="protocol-row">
                    <div class="protocol-header">
                        <span>${escapeHtml(protocole)}</span>
                        <strong>${nombre}</strong>
                    </div>

                    <div class="protocol-bar">
                        <div
                            class="protocol-bar-fill"
                            style="width: ${pourcentage}%"
                        ></div>
                    </div>

                    <div class="protocol-percent">
                        ${pourcentage}%
                    </div>
                </div>
            `;
        })
        .join("");
}

// ------------------------------------------------------------
// Ports
// ------------------------------------------------------------

function afficherPorts(ports) {
    if (!portsList) {
        return;
    }

    if (!Array.isArray(ports) || ports.length === 0) {
        portsList.innerHTML = `
            <div class="empty-state">
                Aucun port détecté.
            </div>
        `;

        return;
    }

    portsList.innerHTML = ports
        .map((element) => {
            const port = element.port ?? "?";
            const nombre = element.nombre ?? 0;
            const service = element.service ?? "Inconnu";

            return `
                <div class="port-row">
                    <div class="port-number">
                        ${escapeHtml(port)}
                    </div>

                    <div class="port-info">
                        <strong>${escapeHtml(service)}</strong>
                        <span>${escapeHtml(nombre)} paquet(s)</span>
                    </div>
                </div>
            `;
        })
        .join("");
}

// ------------------------------------------------------------
// Événements de sécurité
// ------------------------------------------------------------

function afficherEvenements(securite, insights) {

    if (!securityEvents) {
        return;
    }

    // ------------------------------------------------------------
    // Récupération des données du moteur de sécurité
    // ------------------------------------------------------------

    const evenements =
        Array.isArray(insights?.insights)
            ? insights.insights
            : [];

    // ------------------------------------------------------------
    // Aucun événement
    // ------------------------------------------------------------

    if (evenements.length === 0) {

        securityEvents.innerHTML = `
            <div class="empty-state">

                <div class="event-icon">
                    ✓
                </div>

                <div class="event-content">

                    <strong>
                        Système en attente
                    </strong>

                    <p>
                        Les anomalies et menaces détectées
                        apparaîtront ici.
                    </p>

                </div>

            </div>
        `;

        if (eventCount) {
            eventCount.textContent = "0 ÉVÉNEMENT";
        }

        return;
    }

    // ------------------------------------------------------------
    // Compteur
    // ------------------------------------------------------------

    if (eventCount) {

        eventCount.textContent =
            `${evenements.length} ÉVÉNEMENT${
                evenements.length > 1 ? "S" : ""
            }`;

    }

    // ------------------------------------------------------------
    // Affichage des Insights
    // ------------------------------------------------------------

    securityEvents.innerHTML = evenements
        .map((event) => {

            const type =
                event.type || "observation";

            const danger =
                type === "menace";

            const anomalie =
                type === "anomalie";

            const normal =
                type === "normal";

            let classe = "warning";
            icone = "ℹ️";

            if (danger) {
                classe = "danger";
                icone = "🚨";
            }
            else if (normal) {
                classe = "normal";
                icone = "✓";
            }
            else if (anomalie) {
                classe = "warning";
                icone = "ℹ️";
            }
            else {
                classe = "info";
                icone = "ℹ️";
            }

            return `
                <div class="security-event ${classe}">

                    <div class="event-icon">
                        ${icone}
                    </div>

                    <div class="event-content">

                        <strong>
                            ${escapeHtml(
                                event.titre || "Information de sécurité"
                            )}
                        </strong>

                        <p>
                            ${escapeHtml(
                                event.message || ""
                            )}
                        </p>

                        ${
                            event.recommandation
                                ? `
                                    <div class="event-recommendation">

                                        <span>
                                            💡 RECOMMANDATION
                                        </span>

                                        <p>
                                            ${escapeHtml(
                                                event.recommandation
                                            )}
                                        </p>

                                    </div>
                                `
                                : ""
                        }

                    </div>

                </div>
            `;
        })
        .join("");
}

function formaterDureeCommunication(duree) {
    if (typeof duree !== "number" || !Number.isFinite(duree)) {
        return "N/D";
    }

    if (duree < 1) {
        return `${duree.toFixed(3)} s`;
    }

    return `${duree.toFixed(2)} s`;
}

function formaterOctets(octets) {
    if (typeof octets !== "number" || !Number.isFinite(octets)) {
        return "N/D";
    }

    if (octets >= 1024 * 1024) {
        return `${(octets / (1024 * 1024)).toFixed(2)} Mo`;
    }

    if (octets >= 1024) {
        return `${(octets / 1024).toFixed(2)} Ko`;
    }

    return `${octets} octets`;
}

function afficherDetailCommunication(communication) {
    if (!communicationDetail || !communication) {
        return;
    }

    const evenements = Array.isArray(communication.evenements)
        ? communication.evenements
        : [];

    const htmlEvenements = evenements.length
        ? evenements
              .map(
                  (evenement) => `
                    <div class="communication-event">
                        ${escapeHtml(evenement)}
                    </div>
                `
              )
              .join("")
        : `
            <div class="communication-event">
                Aucun événement TCP particulier observé.
            </div>
        `;

    communicationDetail.innerHTML = `
        <h3 class="communication-detail-title">
            Communication #${escapeHtml(communication.id)}
        </h3>

        <p class="communication-detail-subtitle">
            ${escapeHtml(communication.source_endpoint)}
            <span class="communication-arrow">↔</span>
            ${escapeHtml(communication.destination_endpoint)}
        </p>

        <div class="communication-detail-grid">
            <div class="communication-detail-card">
                <span class="communication-detail-label">Protocole</span>
                <span class="communication-detail-value">
                    ${escapeHtml(communication.protocole)}
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">Version IP</span>
                <span class="communication-detail-value">
                    ${escapeHtml(communication.version_ip)}
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">État</span>
                <span class="communication-detail-value">
                    ${escapeHtml(communication.etat)}
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">Durée</span>
                <span class="communication-detail-value">
                    ${formaterDureeCommunication(
                        communication.duree_secondes
                    )}
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">Paquets</span>
                <span class="communication-detail-value">
                    ${escapeHtml(communication.nombre_paquets)}
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">Volume</span>
                <span class="communication-detail-value">
                    ${formaterOctets(communication.octets)}
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">Premier paquet</span>
                <span class="communication-detail-value">
                    ${escapeHtml(
                        communication.premier_paquet || "N/D"
                    )}
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">Dernier paquet</span>
                <span class="communication-detail-value">
                    ${escapeHtml(
                        communication.dernier_paquet || "N/D"
                    )}
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">
                    Direction aller
                </span>
                <span class="communication-detail-value">
                    ${escapeHtml(
                        communication.directions?.aller ?? 0
                    )} paquet(s)
                </span>
            </div>

            <div class="communication-detail-card">
                <span class="communication-detail-label">
                    Direction retour
                </span>
                <span class="communication-detail-value">
                    ${escapeHtml(
                        communication.directions?.retour ?? 0
                    )} paquet(s)
                </span>
            </div>
        </div>

        <div class="communication-events">
            <div class="communication-events-title">
                Événements observés
            </div>

            ${htmlEvenements}
        </div>
    `;
}

function afficherCommunications(communications) {
    if (!communicationsList || !communicationsCount) {
        return;
    }

    if (!Array.isArray(communications) || communications.length === 0) {
        communicationsCount.textContent = "0 communication";

        communicationsList.innerHTML = `
            <div class="empty-state">
                Aucune communication exploitable n'a été observée.
            </div>
        `;

        if (communicationDetail) {
            communicationDetail.innerHTML = `
                <div class="detail-empty">
                    <div class="detail-empty-icon">↔</div>
                    <h3>Aucune communication</h3>
                    <p>
                        Les paquets capturés ne permettent pas
                        d'identifier une communication.
                    </p>
                </div>
            `;
        }

        return;
    }

    communicationsCount.textContent =
        communications.length === 1
            ? "1 communication"
            : `${communications.length} communications`;

    communicationsList.innerHTML = communications
        .map(
            (communication, index) => `
                <button
                    type="button"
                    class="communication-item ${index === 0 ? "active" : ""}"
                    data-communication-index="${index}"
                >
                    <div class="communication-top">
                        <div class="communication-flow">
                            <div class="communication-endpoints">
                                ${escapeHtml(
                                    communication.source_endpoint
                                )}
                                <span class="communication-arrow">↔</span>
                                ${escapeHtml(
                                    communication.destination_endpoint
                                )}
                            </div>

                            <div class="communication-meta">
                                <span class="communication-badge">
                                    ${escapeHtml(
                                        communication.protocole
                                    )}
                                </span>

                                <span class="communication-badge">
                                    ${escapeHtml(
                                        communication.nombre_paquets
                                    )} paquets
                                </span>

                                <span class="communication-badge">
                                    ${formaterDureeCommunication(
                                        communication.duree_secondes
                                    )}
                                </span>

                                <span class="communication-badge">
                                    ${escapeHtml(
                                        communication.etat
                                    )}
                                </span>
                            </div>
                        </div>

                        <span class="communication-state">
                            #${escapeHtml(communication.id)}
                        </span>
                    </div>
                </button>
            `
        )
        .join("");

    const items = communicationsList.querySelectorAll(
        ".communication-item"
    );

    items.forEach((item) => {
        item.addEventListener("click", () => {
            items.forEach((element) => {
                element.classList.remove("active");
            });

            item.classList.add("active");

            const index = Number(
                item.dataset.communicationIndex
            );

            const communication = communications[index];

            afficherDetailCommunication(communication);
        });
    });

    afficherDetailCommunication(communications[0]);
}

// ------------------------------------------------------------
// Lancement de l'analyse
// ------------------------------------------------------------

function formaterTaillePaquet(taille) {
    if (typeof taille !== "number" || !Number.isFinite(taille)) {
        return "N/D";
    }

    if (taille >= 1024 * 1024) {
        return `${(taille / (1024 * 1024)).toFixed(2)} Mo`;
    }

    if (taille >= 1024) {
        return `${(taille / 1024).toFixed(2)} Ko`;
    }

    return `${taille} octets`;
}

function afficherDetailPaquet(paquet) {
    if (!packetDetail || !paquet) {
        return;
    }

    const couches = Array.isArray(paquet.couches)
        ? paquet.couches
        : [];

    const couchesHtml = couches.length
        ? couches
              .map(
                  (couche) => `
                    <span class="packet-layer">
                        ${escapeHtml(couche)}
                    </span>
                `
              )
              .join("")
        : `
            <span class="packet-layer">
                Information non disponible
            </span>
        `;

    packetDetail.innerHTML = `
        <h3 class="packet-detail-title">
            Paquet #${escapeHtml(paquet.numero)}
        </h3>

        <p class="packet-detail-subtitle">
            ${escapeHtml(paquet.source || "Source inconnue")}
            <span class="packet-flow-arrow">→</span>
            ${escapeHtml(paquet.destination || "Destination inconnue")}
        </p>

        <div class="packet-detail-grid">

            <div class="packet-detail-card">
                <span class="packet-detail-label">
                    Protocole
                </span>
                <span class="packet-detail-value">
                    ${escapeHtml(paquet.protocole || "AUTRE")}
                </span>
            </div>

            <div class="packet-detail-card">
                <span class="packet-detail-label">
                    Version IP
                </span>
                <span class="packet-detail-value">
                    ${escapeHtml(paquet.version_ip || "N/D")}
                </span>
            </div>

            <div class="packet-detail-card">
                <span class="packet-detail-label">
                    Port source
                </span>
                <span class="packet-detail-value">
                    ${escapeHtml(
                        paquet.port_source ?? "N/D"
                    )}
                </span>
            </div>

            <div class="packet-detail-card">
                <span class="packet-detail-label">
                    Port destination
                </span>
                <span class="packet-detail-value">
                    ${escapeHtml(
                        paquet.port_destination ?? "N/D"
                    )}
                </span>
            </div>

            <div class="packet-detail-card">
                <span class="packet-detail-label">
                    Taille
                </span>
                <span class="packet-detail-value">
                    ${formaterTaillePaquet(
                        paquet.taille_octets
                    )}
                </span>
            </div>

            <div class="packet-detail-card">
                <span class="packet-detail-label">
                    Timestamp
                </span>
                <span class="packet-detail-value">
                    ${escapeHtml(
                        paquet.timestamp || "N/D"
                    )}
                </span>
            </div>

            <div class="packet-detail-card">
                <span class="packet-detail-label">
                    Flags TCP
                </span>
                <span class="packet-detail-value">
                    ${escapeHtml(
                        paquet.flags_tcp || "N/D"
                    )}
                </span>
            </div>

            <div class="packet-detail-card">
                <span class="packet-detail-label">
                    ICMP
                </span>
                <span class="packet-detail-value">
                    ${
                        paquet.icmp_type !== null &&
                        paquet.icmp_type !== undefined
                            ? `Type ${escapeHtml(
                                  paquet.icmp_type
                              )} / Code ${escapeHtml(
                                  paquet.icmp_code ?? "N/D"
                              )}`
                            : "N/D"
                    }
                </span>
            </div>

        </div>

        <div class="packet-layers">
            <div class="packet-layers-title">
                Couches réseau
            </div>

            <div class="packet-layer-list">
                ${couchesHtml}
            </div>
        </div>
    `;
}

function afficherPaquets(paquets) {
    if (!packetsList || !packetsDetailsCount) {
        return;
    }

    if (!Array.isArray(paquets) || paquets.length === 0) {
        packetsDetailsCount.textContent = "0 paquet";

        packetsList.innerHTML = `
            <div class="empty-state">
                Aucun paquet exploitable dans cette analyse.
            </div>
        `;

        if (packetDetail) {
            packetDetail.innerHTML = `
                <div class="detail-empty">
                    <div class="detail-empty-icon">◈</div>
                    <h3>Aucun paquet</h3>
                    <p>
                        Les informations détaillées
                        apparaîtront après une analyse.
                    </p>
                </div>
            `;
        }

        return;
    }

    packetsDetailsCount.textContent =
        paquets.length === 1
            ? "1 paquet"
            : `${paquets.length} paquets`;

    packetsList.innerHTML = paquets
        .map(
            (paquet, index) => `
                <button
                    type="button"
                    class="packet-item ${index === 0 ? "active" : ""}"
                    data-packet-index="${index}"
                >
                    <div class="packet-top">

                        <div class="packet-flow">
                            ${escapeHtml(
                                paquet.source ||
                                    "Source inconnue"
                            )}

                            <span class="packet-flow-arrow">
                                →
                            </span>

                            ${escapeHtml(
                                paquet.destination ||
                                    "Destination inconnue"
                            )}

                            <div class="packet-meta">
                                <span class="packet-badge">
                                    ${escapeHtml(
                                        paquet.protocole ||
                                            "AUTRE"
                                    )}
                                </span>

                                <span class="packet-badge">
                                    ${formaterTaillePaquet(
                                        paquet.taille_octets
                                    )}
                                </span>

                                ${
                                    paquet.port_destination !==
                                    null &&
                                    paquet.port_destination !==
                                        undefined
                                        ? `
                                            <span class="packet-badge">
                                                Port ${escapeHtml(
                                                    paquet.port_destination
                                                )}
                                            </span>
                                        `
                                        : ""
                                }
                            </div>
                        </div>

                        <span class="packet-number">
                            #${escapeHtml(paquet.numero)}
                        </span>

                    </div>
                </button>
            `
        )
        .join("");

    const items = packetsList.querySelectorAll(
        ".packet-item"
    );

    items.forEach((item) => {
        item.addEventListener("click", () => {
            items.forEach((element) => {
                element.classList.remove("active");
            });

            item.classList.add("active");

            const index = Number(
                item.dataset.packetIndex
            );

            afficherDetailPaquet(paquets[index]);
        });
    });

    afficherDetailPaquet(paquets[0]);
}

async function lancerAnalyse() {
    const duree = Number(duration?.value || 5);

    if (analyzeButton) {
        analyzeButton.disabled = true;
        analyzeButton.classList.add("analyzing");
    }

    if (buttonIcon) {
        buttonIcon.textContent = "⏳";
    }

    if (buttonText) {
        buttonText.textContent =
            `ANALYSE EN COURS (${duree}s)...`;
    }

    try {
        const response = await fetch(
            `${API_BASE_URL}/analyze?duree=${duree}`
        );

        if (!response.ok) {
            throw new Error(
                `Erreur HTTP ${response.status}`
            );
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(
                data.error || "L'analyse a échoué."
            );
        }

        const statistiques =
            data.statistiques || {};

        const securite =
            data.securite || {};

        const insights =
            data.insights || {};

        afficherScore(
            securite.score,
            securite.niveau
        );

        afficherEtatSecurite(securite);

        afficherStatistiques(
            statistiques,
            securite
        );

        afficherCommunications(
    data.communications || []
     );

     afficherPaquets(
    data.paquets || []
  );

  afficherEnrichissements(
    data.enrichissements || []
);
        afficherEvenements(
             securite,
             insights
    );

        if (lastAnalysis) {
            lastAnalysis.textContent =
                formaterDate(data.timestamp);
        }

        console.log(
            "Analyse réseau reçue :",
            data
        );
    } catch (erreur) {
        console.error(
            "Erreur pendant l'analyse :",
            erreur
        );

        if (securityTitle) {
            securityTitle.textContent =
                "Erreur d'analyse";
        }

        if (securityMessage) {
            securityMessage.textContent =
                erreur.message;
        }

        if (securityIcon) {
            securityIcon.textContent = "🛡️";
        }
    } finally {
        if (analyzeButton) {
            analyzeButton.disabled = false;
            analyzeButton.classList.remove("analyzing");
        }

        if (buttonIcon) {
            buttonIcon.textContent = "▶";
        }

        if (buttonText) {
            buttonText.textContent =
                "LANCER L'ANALYSE";
        }
    }
}

// ------------------------------------------------------------
// Événement du bouton
// ------------------------------------------------------------

function afficherEnrichissements(enrichissements) {
    if (!enrichmentList || !enrichmentCount) {
        return;
    }

    if (
        !Array.isArray(enrichissements) ||
        enrichissements.length === 0
    ) {
        enrichmentCount.textContent = "0 IP";

        enrichmentList.innerHTML = `
            <div class="empty-state">
                Aucune IP publique n'a pu être enrichie
                pendant cette analyse.
            </div>
        `;

        return;
    }

    enrichmentCount.textContent =
        enrichissements.length === 1
            ? "1 IP"
            : `${enrichissements.length} IP`;

    enrichmentList.innerHTML = enrichissements
        .map((item) => {
            if (!item || !item.success) {
                return `
                    <article class="enrichment-card">
                        <div class="enrichment-card-header">
                            <div class="enrichment-ip">
                                ${escapeHtml(item?.ip || "IP inconnue")}
                            </div>

                            <div class="enrichment-status">
                                ÉCHEC
                            </div>
                        </div>

                        <div class="enrichment-rows">
                            <div class="enrichment-row">
                                <span class="enrichment-label">
                                    Message
                                </span>

                                <span class="enrichment-value">
                                    ${escapeHtml(
                                        item?.error ||
                                        "Enrichissement indisponible."
                                    )}
                                </span>
                            </div>
                        </div>

                        <div class="enrichment-source">
                            API externe • non enrichie
                        </div>
                    </article>
                `;
            }

            return `
                <article class="enrichment-card">
                    <div class="enrichment-card-header">
                        <div class="enrichment-ip">
                            ${escapeHtml(item.ip || "IP inconnue")}
                        </div>

                        <div class="enrichment-status">
                            HTTP ${escapeHtml(
                                item.status_code ?? "N/D"
                            )}
                        </div>
                    </div>

                    <div class="enrichment-rows">
                        <div class="enrichment-row">
                            <span class="enrichment-label">
                                Pays
                            </span>

                            <span class="enrichment-value">
                                ${escapeHtml(
                                    item.country || "N/D"
                                )}
                                ${
                                    item.country_code
                                        ? ` (${escapeHtml(
                                              item.country_code
                                          )})`
                                        : ""
                                }
                            </span>
                        </div>

                        <div class="enrichment-row">
                            <span class="enrichment-label">
                                Région
                            </span>

                            <span class="enrichment-value">
                                ${escapeHtml(
                                    item.region || "N/D"
                                )}
                            </span>
                        </div>

                        <div class="enrichment-row">
                            <span class="enrichment-label">
                                Ville
                            </span>

                            <span class="enrichment-value">
                                ${escapeHtml(
                                    item.city || "N/D"
                                )}
                            </span>
                        </div>

                        <div class="enrichment-row">
                            <span class="enrichment-label">
                                ASN
                            </span>

                            <span class="enrichment-value">
                                ${escapeHtml(
                                    item.asn ?? "N/D"
                                )}
                            </span>
                        </div>

                        <div class="enrichment-row">
                            <span class="enrichment-label">
                                Organisation
                            </span>

                            <span class="enrichment-value">
                                ${escapeHtml(
                                    item.organisation || "N/D"
                                )}
                            </span>
                        </div>

                        <div class="enrichment-row">
                            <span class="enrichment-label">
                                FAI
                            </span>

                            <span class="enrichment-value">
                                ${escapeHtml(
                                    item.isp || "N/D"
                                )}
                            </span>
                        </div>

                        <div class="enrichment-row">
                            <span class="enrichment-label">
                                Domaine
                            </span>

                            <span class="enrichment-value">
                                ${escapeHtml(
                                    item.domain || "N/D"
                                )}
                            </span>
                        </div>
                    </div>

                    <div class="enrichment-source">
                        Source : API externe ipwho.is
                    </div>
                </article>
            `;
        })
        .join("");
}

if (analyzeButton) {
    analyzeButton.addEventListener(
        "click",
        lancerAnalyse
    );
} else {
    console.error(
        "Bouton d'analyse introuvable dans index.html."
    );
}

// ------------------------------------------------------------
// Initialisation
// ------------------------------------------------------------

console.log(
    "Intelligent Network Analyzer - Dashboard chargé."
);

// ------------------------------------------------------------
// HISTORIQUE DES ANALYSES
// ------------------------------------------------------------

async function chargerEvolutionRisque() {

    if (!riskChartBars || !riskChartLabels) {
        return;
    }

    try {

        const response = await fetch(
            `${API_BASE_URL}/history/summary`
        );

        if (!response.ok) {
            throw new Error(
                `Erreur HTTP ${response.status}`
            );
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(
                "Impossible de récupérer les données de risque."
            );
        }

        const analyses =
            Array.isArray(data.analyses)
                ? data.analyses
                : [];

        if (riskHistoryCount) {
            riskHistoryCount.textContent =
                `${analyses.length} analyse${
                    analyses.length > 1 ? "s" : ""
                }`;
        }

        if (analyses.length === 0) {

            riskChartBars.innerHTML = "";

            riskChartLabels.innerHTML = "";

            if (riskChartEmpty) {
                riskChartEmpty.style.display = "block";
            }

            return;
        }

        if (riskChartEmpty) {
            riskChartEmpty.style.display = "none";
        }

        /*
         * On affiche les analyses dans l'ordre chronologique.
         * Chaque analyse devient une barre du graphique.
         */

        riskChartBars.innerHTML =
            analyses
                .map((analyse) => {

                    const score =
                        Math.max(
                            0,
                            Math.min(
                                100,
                                Number(analyse.score) || 0
                            )
                        );

                    let classe = "";

                    if (score >= 70) {
                        classe = "critical";
                    }
                    else if (score >= 40) {
                        classe = "high";
                    }
                    else if (score > 0) {
                        classe = "moderate";
                    }

                    return `
                        <div class="risk-bar-column">

                            <div class="risk-bar-value">
                                ${score}
                            </div>

                            <div
                                class="risk-bar ${classe}"
                                style="height: ${Math.max(score, 2)}%;"
                                title="Analyse #${escapeHtml(
                                    analyse.id
                                )} — Score ${score}/100"
                            ></div>

                        </div>
                    `;
                })
                .join("");

        riskChartLabels.innerHTML =
            analyses
                .map((analyse) => {

                    const date =
                        formaterDate(
                            analyse.timestamp
                        );

                    return `
                        <div
                            class="risk-chart-label"
                            title="${escapeHtml(date)}"
                        >
                            #${escapeHtml(analyse.id)}
                        </div>
                    `;
                })
                .join("");

    }
    catch (erreur) {

        console.error(
            "Erreur lors du chargement de l'évolution du risque :",
            erreur
        );

        riskChartBars.innerHTML = "";

        riskChartLabels.innerHTML = "";

        if (riskChartEmpty) {
            riskChartEmpty.style.display = "block";
            riskChartEmpty.textContent =
                "❌ Impossible de charger l'évolution du risque.";
        }
    }
}
async function chargerHistorique() {
    if (!historyList) {
        return;
    }

    try {
        const response = await fetch(
            `${API_BASE_URL}/history`
        );

        if (!response.ok) {
            throw new Error(
                `Erreur HTTP ${response.status}`
            );
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(
                "Impossible de récupérer l'historique."
            );
        }

        const analyses = Array.isArray(data.analyses)
            ? data.analyses
            : [];

        // ----------------------------------------------------
        // Compteur
        // ----------------------------------------------------

        if (historyCount) {
            historyCount.textContent =
                `${analyses.length} analyse${analyses.length > 1 ? "s" : ""}`;
        }

        // ----------------------------------------------------
        // Aucune analyse
        // ----------------------------------------------------

        if (analyses.length === 0) {
            historyList.innerHTML = `
                <div class="empty-state">
                    Aucune analyse enregistrée.
                </div>
            `;

            return;
        }

        // ----------------------------------------------------
        // Affichage de la timeline
        // ----------------------------------------------------

        historyList.innerHTML = [...analyses]
            .reverse()
            .map((analyse) => {

                const score =
                    Number(analyse.securite?.score) || 0;

                const niveau =
                    analyse.securite?.niveau || "INCONNU";

                const paquets =
                    analyse.statistiques?.total_paquets || 0;

                const ports =
                    analyse.securite?.ports || 0;

                const destinations =
                    analyse.securite?.destinations || 0;

                const scans =
                    analyse.securite?.scans || 0;

                const date =
                    formaterDate(analyse.timestamp);

                return `
                    <div class="history-item">

                        <div class="history-main">

                            <div class="history-id">
                                #${escapeHtml(analyse.id)}
                            </div>

                            <div class="history-date">
                                ${escapeHtml(date)}
                            </div>

                        </div>

                        <div class="history-metrics">

                            <div class="history-metric">
                                <span>PAQUETS</span>
                                <strong>${paquets}</strong>
                            </div>

                            <div class="history-metric">
                                <span>PORTS</span>
                                <strong>${ports}</strong>
                            </div>

                            <div class="history-metric">
                                <span>DEST.</span>
                                <strong>${destinations}</strong>
                            </div>

                            <div class="history-metric">
                                <span>SCANS</span>
                                <strong>${scans}</strong>
                            </div>

                        </div>

                        <div class="history-score">

                            <strong>${score}/100</strong>

                            <span class="history-level">
                                ${escapeHtml(niveau)}
                            </span>

                        </div>

                    </div>
                `;
            })
            .join("");
        // ----------------------------------------------------
        // Charger la dernière analyse dans le dashboard
        // ----------------------------------------------------

        const derniereAnalyse =
            analyses[analyses.length - 1];

        if (derniereAnalyse) {
            const statistiques =
                derniereAnalyse.statistiques || {};

            const securite =
                derniereAnalyse.securite || {};

            const insights =
                derniereAnalyse.insights || {};

            afficherScore(
                securite.score,
                securite.niveau
            );

            afficherEtatSecurite(
                securite
            );

            afficherStatistiques(
                statistiques,
                securite
            );

            afficherEvenements(
                securite,
                insights
            );

            afficherCommunications(
                derniereAnalyse.communications || []
            );

            afficherPaquets(
                derniereAnalyse.paquets || []
            );

            afficherEnrichissements(
                derniereAnalyse.enrichissements || []
            );

            if (lastAnalysis) {
                lastAnalysis.textContent =
                    formaterDate(
                        derniereAnalyse.timestamp
                    );
            }
        }


    } catch (erreur) {

        console.error(
            "Erreur lors du chargement de l'historique :",
            erreur
        );

        historyList.innerHTML = `
            <div class="empty-state">
                âŒ Impossible de charger l'historique.
            </div>
        `;
    }
}

// Chargement initial de l'historique
chargerHistorique();

// Chargement initial de l'évolution du risque
chargerEvolutionRisque();





