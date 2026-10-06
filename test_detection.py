from scapy.all import IP, TCP
from analyzer import analyser_securite


print("=" * 70)
print("TEST DU MOTEUR DE DÉTECTION")
print("=" * 70)


# ============================================================
# TEST 1 : TRAFIC NORMAL
# ============================================================

print("\n")
print("TEST 1 : TRAFIC NORMAL")
print("-" * 70)

paquets_normaux = [
    IP(src="192.0.2.10", dst="192.0.2.20")
    / TCP(sport=40000, dport=443, flags="S"),

    IP(src="192.0.2.20", dst="192.0.2.10")
    / TCP(sport=443, dport=40000, flags="SA"),

    IP(src="192.0.2.10", dst="192.0.2.20")
    / TCP(sport=40000, dport=443, flags="A"),
]

resultat_normal = analyser_securite(paquets_normaux)

print()
print("Résultat attendu :")
print("  ✓ Aucun scan détecté")


# ============================================================
# TEST 2 : TRAFIC RESSEMBLANT À UN SCAN
# ============================================================

print("\n")
print("TEST 2 : TRAFIC SYN SYNTHÉTIQUE")
print("-" * 70)

paquets_scan = []

# Adresses réservées à la documentation.
# Aucun paquet ne sera envoyé sur le réseau.
source = "192.0.2.10"
destination = "192.0.2.20"

ports_test = [
    21, 22, 23, 25, 53,
    80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432
]

for i, port in enumerate(ports_test):
    paquet = (
        IP(src=source, dst=destination)
        / TCP(
            sport=40000 + i,
            dport=port,
            flags="S"
        )
    )

    paquets_scan.append(paquet)


resultat_scan = analyser_securite(paquets_scan)

print()
print("Résultat attendu :")
print("  ⚠ Un scan potentiel doit être détecté.")
print(f"  Ports synthétiques testés : {len(ports_test)}")


# ============================================================
# VÉRIFICATION AUTOMATIQUE
# ============================================================

print("\n")
print("=" * 70)
print("VÉRIFICATION")
print("=" * 70)

scan_detecte = resultat_scan["scans"] > 0

if scan_detecte:
    print("✅ TEST RÉUSSI")
    print("Le moteur a correctement détecté le trafic ressemblant à un scan.")
else:
    print("❌ TEST ÉCHOUÉ")
    print("Le moteur n'a pas détecté le scan synthétique.")

print("=" * 70)